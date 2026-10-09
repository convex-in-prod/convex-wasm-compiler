#pragma once

#include "jsi/jsi.h"

namespace convex_wasm {

// The support unit captures and deletes this bootstrap before application code.
void installNativeUrl(facebook::jsi::Runtime &runtime);

} // namespace convex_wasm
