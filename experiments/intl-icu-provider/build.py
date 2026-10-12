"""Build the standalone experiment with explicit caller-owned toolchains."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("phase", choices=["runtime", "smoke", "probe", "contracts", "dates", "bindings", "construction", "locales", "ranges", "date-ranges", "collator"])
parser.add_argument("--root", required=True, type=Path)
parser.add_argument("--host-build", required=True, type=Path)
parser.add_argument("--emsdk", required=True, type=Path)
parser.add_argument("--binaryen", required=True, type=Path)
parser.add_argument("--standalone", action="store_true", help="Link a WASI reactor for the Wasmtime diagnostic runner")
args = parser.parse_args()
if args.standalone and args.phase == "runtime":
    parser.error("--standalone applies to a probe, not the runtime archive")
root = args.root.resolve()
sdk = args.emsdk.resolve()
host = args.host_build.resolve()
build = root / "build-wasm"
source = root / "hermes"
em = sdk / "upstream/emscripten"
scripts = Path(__file__).parent
env = {
    **os.environ,
    "EM_CONFIG": str(sdk / ".emscripten"),
    "EMSDK": str(sdk),
    "EM_BINARYEN_ROOT": str(args.binaryen.resolve()),
    "EMCC_CORES": "2",
    "BINARYEN_CORES": "2",
    "PATH": str(em) + ":" + str(sdk / "upstream/bin") + ":" + os.environ["PATH"],
}
commands = []
artifact = args.phase + ("-standalone" if args.standalone else "")


def run(label, arguments):
    arguments = list(map(str, arguments))
    start = time.monotonic()
    print("start", label, flush=True)
    with (root / (label + ".log")).open("w") as log:
        result = subprocess.run(
            arguments, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=2400,
        )
    commands.append({
        "label": label, "arguments": arguments,
        "seconds": time.monotonic() - start, "exitCode": result.returncode,
    })
    (root / (artifact + "-commands.json")).write_text(
        json.dumps(commands, indent=2) + "\n"
    )
    if result.returncode:
        print((root / (label + ".log")).read_text()[-8000:], flush=True)
    result.check_returncode()
    print("pass", label, round(time.monotonic() - start, 2), flush=True)


if args.phase == "runtime":
    run("configure", [
        em / "emcmake", "cmake", "-S", source, "-B", build, "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release", "-DHERMES_ENABLE_INTL=ON",
        "-DHERMES_USE_STATIC_INTL_PROVIDER=ON", "-DHERMES_ENABLE_NAPI=OFF",
        "-DHERMES_ENABLE_TOOLS=OFF", "-DHERMES_UNICODE_LITE=ON",
        "-DHERMES_ENABLE_TEST_SUITE=OFF",
        "-DCMAKE_C_FLAGS=-fwasm-exceptions -sWASM_LEGACY_EXCEPTIONS=0",
        "-DCMAKE_CXX_FLAGS=-fwasm-exceptions -sWASM_LEGACY_EXCEPTIONS=0",
        "-DIMPORT_HOST_COMPILERS=" + str(host / "ImportHostCompilers.cmake"),
        "-DHERMESVM_INTERNAL_JAVASCRIPT_NATIVE=ON",
    ])
    run("compile", [
        "cmake", "--build", build, "--target", "hermesvm_a", "jsi",
        "hermesStaticIcu", "--parallel", "4",
    ])
else:
    variant = args.phase
    shutil.copyfile(scripts / "main.cpp", root / "main.cpp")
    common = [
        "-O2", "-DNDEBUG", "-DSTATIC_HERMES", "-DHERMES_ENABLE_INTL",
        "-DU_DISABLE_RENAMING=1", "-DU_STATIC_IMPLEMENTATION=1", "-DHERMES_USE_STATIC_INTL_PROVIDER",
        "-fwasm-exceptions", "-sWASM_LEGACY_EXCEPTIONS=0",
        "-fno-strict-aliasing", "-fno-strict-overflow",
    ]
    includes = ["-I" + str(path) for path in [
        source / "include", source / "public", source / "API", source / "API/jsi",
        build / "lib/config", source / "external/llvh/include",
        source / "external/llvh/gen/include", build / "external/llvh/include",
        source / "external/icu-small/source/common",
        source / "external/icu-small/source/i18n",
    ]]
    run(variant + "-generate", [
        host / "bin/shermes", "-O", "-emit-c", "-exported-unit=intl_probe",
        "-o=" + str(root / (variant + ".c")), root / (variant + ".js"),
    ])
    run(variant + "-compile", [
        em / "emcc", *common, *includes, "-c", root / (variant + ".c"),
        "-o", root / (variant + ".o"),
    ])
    main_object = root / ("main-standalone.o" if args.standalone else "main.o")
    run("main-standalone-compile" if args.standalone else "main-compile", [
        em / "em++", *common, "-std=c++17", *includes,
        *(["-DINTL_PROBE_STANDALONE"] if args.standalone else []),
        "-c", root / "main.cpp", "-o", main_object,
    ])
    # Keep data assembly explicit: the parent Hermes project does not enable ASM.
    data = build / "external/icu-small/icudt78l.dat"
    (root / "icudata.s").write_text(
        '.section .rodata.icudt78_dat,"",@\n.p2align 4\n.globl icudt78_dat\n'
        '.type icudt78_dat,@object\nicudt78_dat:\n.incbin "' + str(data) +
        '"\n.size icudt78_dat, .-icudt78_dat\n'
    )
    run("data-compile", [em / "emcc", "-c", root / "icudata.s", "-o", root / "icudata.o"])
    link_mode = [
        "--no-entry", "-sSTANDALONE_WASM=1", "-sFILESYSTEM=0",
        "-sSUPPORT_LONGJMP=wasm", "-Wl,--export=intl_probe_run",
        "-Wl,--export=intl_probe_lifecycle_run",
    ] if args.standalone else ["-sENVIRONMENT=node", "-sEXIT_RUNTIME=1"]
    run(artifact + "-link", [
        em / "em++", *common, main_object, root / (variant + ".o"),
        root / "icudata.o", build / "lib/libhermesvm_a.a", build / "jsi/libjsi.a",
        build / "external/icu-small/libhermesStaticIcu.a",
        "-sALLOW_MEMORY_GROWTH=1", "-sSTACK_SIZE=8388608",
        "-sINITIAL_MEMORY=134217728", "-sMAXIMUM_MEMORY=536870912",
        *link_mode, "-o", root / (artifact + (".wasm" if args.standalone else ".mjs")),
    ])
    print("wasm bytes", (root / (artifact + ".wasm")).stat().st_size, flush=True)
