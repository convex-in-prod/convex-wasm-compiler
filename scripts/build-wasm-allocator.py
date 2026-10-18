"""Build the pinned allocator with an optional free-payload enumeration API."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emscripten", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    emscripten = args.emscripten.resolve(strict=True)
    output = args.output.resolve()
    source = Path(__file__).resolve().parent / "lib" / "convex-wasm-allocator.c"

    # The SDK owns allocator build flags. Use its exact PIC, single-threaded
    # system-library variant without replacing any file in its shared cache.
    # Bind the tools and headers whose bytes setup authenticates, independently
    # of ambient SDK overrides. Frozen cache makes missing prerequisites fail.
    os.environ.update({
        "EM_CONFIG": str(emscripten.parent.parent / ".emscripten"),
        "EM_LLVM_ROOT": str(emscripten.parent / "bin"),
        "EM_CACHE": str(emscripten / "cache"),
        "EM_FROZEN_CACHE": "1",
        "EM_COMPILER_WRAPPER": "0",
        "EM_LLVM_ADD_VERSION": "0",
        "EM_CLANG_ADD_VERSION": "0",
    })
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".allocator-", dir=output.parent) as stage:
        stage = Path(stage)
        # A same-size source edit within one timestamp second can leave a valid
        # but stale SDK .pyc. Read the authenticated sources, not shared bytecode;
        # -B alone only disables writes and would still read the stale cache.
        sys.pycache_prefix = str(stage / "pycache")
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(emscripten))
        from tools import system_libs
        from tools.settings import settings

        settings.MAIN_MODULE = 2
        allocator = system_libs.libmalloc(
            malloc="dlmalloc", is_mt=False, is_ww=False, is_debug=False,
            is_tracing=False, memvalidate=False, verbose=False,
        )
        originals = [Path(path) for path in allocator.get_files()]
        if originals != [emscripten / "system/lib/dlmalloc.c",
                         emscripten / "system/lib/libc/sbrk.c"]:
            raise RuntimeError("Pinned allocator source selection changed")
        allocator.build_dir = str(stage)
        env = system_libs.clean_env()
        flags = [*allocator.get_cflags(),
                 "-I" + str(emscripten / "system/lib"),
                 # The SDK maps its own sources, but not this extension.
                 f"-ffile-prefix-map={source.parent}=/convex-wasm-allocator"]
        objects = []
        for path in [source, originals[1]]:
            obj = stage / (path.stem + ".o")
            subprocess.run(
                [sys.executable, "-E", "-B", "-X", f"pycache_prefix={sys.pycache_prefix}",
                 str(emscripten / "emcc.py"), *flags,
                 "-c", str(path), "-o", str(obj)],
                check=True, timeout=300, env=env,
            )
            objects.append(str(obj))
        archive = stage / output.name
        subprocess.run(
            [str(emscripten.parent / "bin/llvm-ar"), "rcsD", str(archive), *objects],
            check=True, timeout=60, env=env,
        )
        archive.replace(output)


if __name__ == "__main__":
    main()
