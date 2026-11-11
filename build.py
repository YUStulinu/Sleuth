"""Builds the Sleuth controller and every target, in two flavours, with clang.

    python build.py                 # everything
    python build.py --targets png   # some targets only
    python build.py --no-libfuzzer  # skip the libFuzzer builds (e.g. no libFuzzer runtime)

Outputs, under build/:
    sleuth(.exe)                    the fuzzer controller (fuzzer/src)
    <target>/sleuth(.exe)           target + Sleuth runtime: SanitizerCoverage trace-pc-guard and
                                    trace-cmp callbacks, AddressSanitizer
    <target>/libfuzzer(.exe)        target + libFuzzer (-fsanitize=fuzzer,address)

The runtime and the bug canaries are compiled without coverage instrumentation, so they add no
edges of their own. On Windows the AddressSanitizer DLL is copied next to the executables.
"""
import argparse
import glob
import os
import platform
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(ROOT, "build")
TARGETS = ["png", "xml", "der", "json", "vm"]
WIN = platform.system() == "Windows"
EXE = ".exe" if WIN else ""
CXX = os.environ.get("CXX", "clang++")
COMMON = ["-std=c++17", "-O1", "-g", "-fno-omit-frame-pointer"]
COVERAGE = ["-fsanitize-coverage=trace-pc-guard,trace-cmp"]
if WIN:
    # The default MSVC target needs these for a console program using the C++ library.
    # The libFuzzer runtime is built without the MSVC STL's ASan container annotations, and
    # the linker refuses to mix the two settings; turn them off everywhere for consistency.
    COMMON += ["-D_CRT_SECURE_NO_WARNINGS", "-D_DISABLE_STRING_ANNOTATION", "-D_DISABLE_VECTOR_ANNOTATION"]


def run(cmd):
    print(" ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def obj(src, out, flags):
    run([CXX, *COMMON, *flags, "-I", os.path.join(ROOT, "runtime"), "-c", src, "-o", out])
    return out


def asan_dll_dir():
    """Where clang keeps the AddressSanitizer runtime DLL (Windows)."""
    res = subprocess.run([CXX, "-print-resource-dir"], capture_output=True, text=True, check=True).stdout.strip()
    for d in glob.glob(os.path.join(res, "lib", "*")):
        if glob.glob(os.path.join(d, "clang_rt.asan_dynamic-*.dll")):
            return d
    return None


def build_controller():
    srcs = sorted(glob.glob(os.path.join(ROOT, "fuzzer", "src", "*.cpp")))
    out = os.path.join(BUILD, "sleuth" + EXE)
    flags = ["-std=c++17", "-O2", "-g"]
    if WIN:
        flags += ["-D_CRT_SECURE_NO_WARNINGS"]
    else:
        flags += ["-pthread"]
    run([CXX, *flags, *srcs, "-o", out])
    return out


def build_tests():
    """The controller's unit tests (fuzzer/tests), linked with every source but main.cpp."""
    srcs = [s for s in sorted(glob.glob(os.path.join(ROOT, "fuzzer", "src", "*.cpp"))) if not s.endswith("main.cpp")]
    out = os.path.join(BUILD, "test_fuzzer" + EXE)
    flags = ["-std=c++17", "-O1", "-g"] + (["-D_CRT_SECURE_NO_WARNINGS"] if WIN else ["-pthread"])
    run([CXX, *flags, *srcs, os.path.join(ROOT, "fuzzer", "tests", "test_fuzzer.cpp"), "-o", out])
    return out


def build_target(name, libfuzzer):
    src = os.path.join(ROOT, "targets", name, f"{name}.cpp")
    out_dir = os.path.join(BUILD, name)
    os.makedirs(out_dir, exist_ok=True)
    o = lambda base: os.path.join(out_dir, base + (".obj" if WIN else ".o"))
    asan = ["-fsanitize=address"]
    canary = obj(os.path.join(ROOT, "runtime", "canary.cpp"), o("canary"), asan)
    # Sleuth flavour.
    tgt = obj(src, o("target_sleuth"), asan + COVERAGE)
    rt = obj(os.path.join(ROOT, "runtime", "sleuth_rt.cpp"), o("sleuth_rt"), asan)
    run([CXX, *asan, tgt, rt, canary, "-o", os.path.join(out_dir, "sleuth" + EXE)])
    # libFuzzer flavour.
    if libfuzzer:
        tgt_lf = obj(src, o("target_libfuzzer"), ["-fsanitize=fuzzer-no-link,address"])
        run([CXX, "-fsanitize=fuzzer,address", tgt_lf, canary, "-o", os.path.join(out_dir, "libfuzzer" + EXE)])
    for f in glob.glob(os.path.join(out_dir, "*.o")) + glob.glob(os.path.join(out_dir, "*.obj")):
        os.remove(f)
    for f in glob.glob(os.path.join(out_dir, "*.ilk")) + glob.glob(os.path.join(out_dir, "*.lib")) + glob.glob(os.path.join(out_dir, "*.exp")):
        os.remove(f)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", nargs="*", default=TARGETS)
    ap.add_argument("--no-libfuzzer", action="store_true")
    ap.add_argument("--no-controller", action="store_true")
    ap.add_argument("--tests", action="store_true", help="also build the controller's unit tests")
    args = ap.parse_args()
    os.makedirs(BUILD, exist_ok=True)
    if not args.no_controller and glob.glob(os.path.join(ROOT, "fuzzer", "src", "*.cpp")):
        build_controller()
    if args.tests:
        build_tests()
    for t in args.targets:
        if t not in TARGETS:
            sys.exit(f"unknown target {t}")
        build_target(t, not args.no_libfuzzer)
    if WIN:
        d = asan_dll_dir()
        if d:
            for dll in glob.glob(os.path.join(d, "clang_rt.asan_dynamic-*.dll")):
                for t in args.targets:
                    shutil.copy2(dll, os.path.join(BUILD, t))
    print("built:", ", ".join(args.targets))


if __name__ == "__main__":
    main()
