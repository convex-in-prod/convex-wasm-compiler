from pathlib import Path
import sys
import re,shutil
root=Path(sys.argv[1]).resolve()
source=root/'hermes';upstream=root/'upstream'
impl=source/'lib/Platform/Intl/impl_icu_provider';impl.mkdir(exist_ok=True)
for name in ['hermes_icu.h','icu_types.h']:
 shutil.copyfile(upstream/'include/hermes/Platform/Intl'/name,source/'include/hermes/Platform/Intl'/name)
text=(upstream/'lib/Platform/Intl/impl_win/PlatformIntlWin.cpp').read_text()
text=text.replace('#include "IcuProviderRegistry.h"','#include "IcuProviderStatic.h"').replace('#include "PlatformIntlWinGlob.h"\n','').replace('WinIntlUtils.h','IcuProviderUtils.h')
text=re.sub(r'  if \(!icu\)\n    return winglob::[^;]+;\n','',text)
text,n=re.subn(r'  if \(!icu\) \{\n.*?\n  \}\n','',text,flags=re.S);assert n==3,n
# Retain the ICU construction body; remove provider selection and Windows fallback.
for name in ['Collator','DateTimeFormat','NumberFormat']:
 start=text.index(f'vm::CallResult<std::unique_ptr<{name}>> {name}::create(')
 end=text.index('\n}\n',start)+2
 function=text[start:end]
 prefix,body=function.split('  if (icu) {\n',1)
 body=body.split('\n  }\n  auto instance = std::make_unique<winglob::',1)[0]
 body=body.replace('    instance->usesIcu_ = true;\n','')
 body='\n'.join(line[2:] if line.startswith('  ') else line for line in body.splitlines())
 text=text[:start]+prefix+body+'\n}'+text[end:]
text,n=re.subn(r'  if \(usesIcu_\)\n    (return static_cast<[^\n]+;)\n  return static_cast<winglob::.*?;\n',r'  \1\n',text,flags=re.S);assert n==8,n
assert 'winglob::' not in text and 'usesIcu_' not in text
text=text.replace('CollatorWindows','CollatorIcuProvider').replace('DateTimeFormatWindows','DateTimeFormatIcuProvider').replace('NumberFormatWindows','NumberFormatIcuProvider')
text=text.replace('Windows Intl implementation using hermes_icu_vtable dispatch.','Portable Intl implementation using a statically linked ICU provider.')
text=text.replace(' * When no ICU provider is available (vtable is nullptr), falls back to\n * WinGlob NLS-based stubs.\n *\n * Phase 2: Full Collator, NumberFormat, locale resolution implementations.',' * The ICU provider is required; provider discovery and platform fallbacks are\n * excluded from this build.')
(impl/'PlatformIntlIcuProvider.cpp').write_text(text)
for extension in ['h','cpp']:
 text=(upstream/f'lib/Platform/Intl/impl_win/WinIntlUtils.{extension}').read_text().replace('WinIntlUtils.h','IcuProviderUtils.h').replace('HERMES_PLATFORM_INTL_WIN_INTL_UTILS_H','HERMES_PLATFORM_INTL_ICU_PROVIDER_UTILS_H')
 (impl/f'IcuProviderUtils.{extension}').write_text(text)
(impl/'IcuProviderStatic.h').write_text('''/* Copyright (c) Microsoft Corporation. Licensed under the MIT License. */
#pragma once
#include "hermes/Platform/Intl/hermes_icu.h"
namespace hermes { namespace vm { class Runtime; }
namespace platform_intl {
const hermes_icu_vtable *getIcuVtableForRuntime(vm::Runtime &runtime);
}}
''')
(impl/'IcuProviderStatic.cpp').write_text('''/* Copyright (c) Microsoft Corporation. Licensed under the MIT License. */
#include "IcuProviderStatic.h"
#include <cassert>
extern "C" const hermes_icu_vtable *hermes_icu_get_vtable(void);
namespace hermes { namespace platform_intl {
const hermes_icu_vtable *getIcuVtableForRuntime(vm::Runtime &) {
  const auto *provider = hermes_icu_get_vtable();
  assert(provider && "Static ICU provider is required");
  return provider;
}
}}
''')
icu=source/'external/icu-small'
shutil.copytree(upstream/'external/icu-small',icu,dirs_exist_ok=True)
glue=(icu/'hermes_icu_glue.cpp').read_text().replace('__declspec(dllexport)','HERMES_ICU_API')
(icu/'hermes_icu_glue.cpp').write_text(glue)
(icu/'CMakeLists.txt').write_text('''# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
# Experimental static build of the unchanged ICU source and locale dataset.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(ICU_DAT "${CMAKE_CURRENT_BINARY_DIR}/icudt78l.dat")
if(NOT EXISTS "${ICU_DAT}")
  execute_process(COMMAND ${Python3_EXECUTABLE} -c
    "import bz2,sys;open(sys.argv[2],'wb').write(bz2.open(sys.argv[1]).read())"
    "${CMAKE_CURRENT_SOURCE_DIR}/source/data/in/icudt78l.dat.bz2" "${ICU_DAT}"
    COMMAND_ERROR_IS_FATAL ANY)
endif()
file(GLOB ICU_COMMON_SOURCES source/common/*.cpp source/common/*.c)
file(GLOB ICU_I18N_SOURCES source/i18n/*.cpp source/i18n/*.c)
add_library(hermesStaticIcu STATIC ${ICU_COMMON_SOURCES} ${ICU_I18N_SOURCES}
  hermes_icu_glue.cpp)
target_include_directories(hermesStaticIcu BEFORE PRIVATE source/common source/i18n ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(hermesStaticIcu PRIVATE U_STATIC_IMPLEMENTATION=1 U_DISABLE_RENAMING=1
  U_ENABLE_DYLOAD=0 UCONFIG_NO_SERVICE=1 U_HAVE_STD_STRING=1 U_ATTRIBUTE_DEPRECATED=)
set_property(SOURCE ${ICU_COMMON_SOURCES} APPEND PROPERTY COMPILE_DEFINITIONS U_COMMON_IMPLEMENTATION=1)
set_property(SOURCE ${ICU_I18N_SOURCES} APPEND PROPERTY COMPILE_DEFINITIONS U_I18N_IMPLEMENTATION=1)
target_compile_options(hermesStaticIcu PRIVATE -fexceptions -frtti -fwasm-exceptions
  -Wno-deprecated-declarations -Wno-sign-compare -Wno-unused-variable)
''')
p=source/'lib/Platform/Intl/CMakeLists.txt';text=p.read_text();key='  else()\n    add_hermes_library(hermesPlatformIntl\n'
assert text.count(key)==1
text=text.replace(key,'''  elseif(HERMES_USE_STATIC_INTL_PROVIDER)
    add_subdirectory(${CMAKE_SOURCE_DIR}/external/icu-small ${CMAKE_BINARY_DIR}/external/icu-small)
    add_hermes_library(hermesPlatformIntl
      impl_icu_provider/PlatformIntlIcuProvider.cpp
      impl_icu_provider/IcuProviderUtils.cpp
      impl_icu_provider/IcuProviderStatic.cpp
      LINK_LIBS hermesStaticIcu
      LINK_OBJLIBS hermesBCP47Parser hermesPublic)
  else()
    add_hermes_library(hermesPlatformIntl)
'''.replace('add_hermes_library(hermesPlatformIntl)\n','add_hermes_library(hermesPlatformIntl\n'))
p.write_text(text)
print('portable source prepared')
