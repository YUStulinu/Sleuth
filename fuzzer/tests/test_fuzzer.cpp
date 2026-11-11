// Unit tests for the controller's pure parts: dictionary parsing, mutations, input-to-state and
// repair candidates, crash signatures and minimization. (The executor and the fuzz loop are
// tested end to end against real targets by tests/test_integration.py.)
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#include "../src/crash.hpp"
#include "../src/minimize.hpp"
#include "../src/mutator.hpp"
#include "../src/util.hpp"

using namespace sleuth;

static int g_failed = 0, g_checks = 0;
#define CHECK(c)                                                                \
    do {                                                                        \
        ++g_checks;                                                             \
        if (!(c)) {                                                             \
            ++g_failed;                                                         \
            std::fprintf(stderr, "FAILED %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                                       \
    } while (0)

static Bytes B(const char* s) { return Bytes(s, s + std::strlen(s)); }

static bool contains(const Bytes& hay, const Bytes& needle) {
    if (needle.size() > hay.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
        if (std::memcmp(hay.data() + i, needle.data(), needle.size()) == 0) return true;
    return false;
}

static void test_dictionary() {
    auto d = parse_dictionary("# comment\n\"IHDR\"\nkw1=\"\\x89PNG\"\n\n\"a\\\"b\\\\c\"\nbad line\n");
    CHECK(d.size() == 3);
    CHECK(d[0] == B("IHDR"));
    CHECK(d[1].size() == 4 && d[1][0] == 0x89 && d[1][1] == 'P');
    CHECK(d[2] == B("a\"b\\c"));
}

static void test_rng() {
    Rng a(42), b(42), c(43);
    bool same = true, differs = false;
    for (int i = 0; i < 100; ++i) {
        uint64_t x = a.next(), y = b.next(), z = c.next();
        same &= x == y;
        differs |= x != z;
    }
    CHECK(same);
    CHECK(differs);
    Rng r(1);
    for (int i = 0; i < 1000; ++i) CHECK(r.below(7) < 7);
}

static void test_havoc() {
    Rng rng(7);
    Mutator m(rng, 64);
    m.set_dictionary({B("MAGIC")});
    Bytes base = B("hello world, this is a test input");
    int changed = 0, has_magic = 0;
    for (int i = 0; i < 2000; ++i) {
        Bytes d = base;
        m.havoc(d, nullptr);
        CHECK(d.size() <= 64);
        changed += d != base;
        has_magic += contains(d, B("MAGIC"));
    }
    CHECK(changed > 1900);
    CHECK(has_magic > 50);  // dictionary tokens are used
    Bytes empty;
    m.havoc(empty, nullptr);
    CHECK(!empty.empty());
    // Splice: a prefix of a, a suffix of b.
    Bytes s = m.splice(B("AAAAAAAA"), B("BBBBBBBB"));
    CHECK(!s.empty() && s[0] == 'A' && s.back() == 'B');
}

static void test_input_to_state() {
    Rng rng(1);
    Mutator m(rng, 4096);
    // The target compared the input's 32-bit little-endian word 0x11223344 with 0xdeadbeef.
    Bytes d = {'x', 0x44, 0x33, 0x22, 0x11, 'y'};
    std::vector<CmpPair> cmps = {{0x11223344, 0xdeadbeef, 4, true}};
    auto c = m.input_to_state(d, cmps, {}, 100);
    Bytes want = {'x', 0xef, 0xbe, 0xad, 0xde, 'y'};
    bool found = false;
    for (auto& x : c) found |= x == want;
    CHECK(found);
    // Big-endian too.
    Bytes dbe = {0x11, 0x22, 0x33, 0x44};
    c = m.input_to_state(dbe, cmps, {}, 100);
    found = false;
    for (auto& x : c) found |= x == Bytes({0xde, 0xad, 0xbe, 0xef});
    CHECK(found);
    // Strings: the input has "<![CDAT" where the target wanted "<![CDATA[".
    std::vector<StrPair> strs = {{B("<![CDAT"), B("<![CDATA[")}};
    c = m.input_to_state(B("<a><![CDATxyz"), {}, strs, 100);
    found = false;
    for (auto& x : c) found |= contains(x, B("<![CDATA["));
    CHECK(found);
    // Limit and no duplicates of the input itself.
    c = m.input_to_state(d, cmps, {}, 1);
    CHECK(c.size() == 1);
}

static void test_repair() {
    Rng rng(1);
    Mutator m(rng, 4096);
    // A stored big-endian checksum 0x01020304 compared with the computed 0xa0b0c0d0.
    Bytes d = {'d', 'a', 't', 'a', 0x01, 0x02, 0x03, 0x04};
    auto c = m.repair(d, {{0xa0b0c0d0, 0x01020304, 4, false}}, 4);
    bool found = false;
    for (auto& x : c) found |= x == Bytes({'d', 'a', 't', 'a', 0xa0, 0xb0, 0xc0, 0xd0});
    CHECK(found);
    // Comparisons against constants are not checksums: no repair.
    CHECK(m.repair(d, {{0xa0b0c0d0, 0x01020304, 4, true}}, 4).empty());
    // A value that occurs twice is ambiguous: no repair.
    Bytes twice = {1, 2, 3, 4, 1, 2, 3, 4};
    CHECK(m.repair(twice, {{0x01020304, 0x05060708, 4, false}}, 4).empty());
}

static void test_learn() {
    Rng rng(1);
    Mutator m(rng, 4096);
    m.learn({{5, 0x50415448, 4, true}}, {{B("abc"), B("needle")}});
    CHECK(m.learned() >= 2);
}

static const char* LINUX_REPORT = R"(=================================================================
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000015 at pc 0x55 bp 0x7ff sp 0x7fe
WRITE of size 4 at 0x602000000015 thread T0
    #0 0x4f5a2b in __asan_memcpy /src/llvm/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63:3
    #1 0x52a1f0 in (anonymous namespace)::Parser::element() /home/u/Sleuth/targets/xml/xml.cpp:184:29
    #2 0x52b0aa in (anonymous namespace)::Parser::parse() /home/u/Sleuth/targets/xml/xml.cpp:265:22
    #3 0x52b3cc in LLVMFuzzerTestOneInput /home/u/Sleuth/targets/xml/xml.cpp:290:15
    #4 0x52c000 in (anonymous namespace)::child_loop() /home/u/Sleuth/runtime/sleuth_rt.cpp:166:9
    #5 0x7f00 in main /home/u/Sleuth/runtime/sleuth_rt.cpp:245:5

0x602000000015 is located 5 bytes to the right of 16-byte region
allocated by thread T0 here:
    #0 0x4f6 in malloc
    #1 0x52a in Other::thing() /x/y.cpp:1:1
SUMMARY: AddressSanitizer: heap-buffer-overflow
)";

static const char* WINDOWS_REPORT = R"(==9==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12 at pc 0x7ff bp 0x00 sp 0x00
READ of size 1 at 0x123 thread T0
    #0 0x7ff6 in `anonymous namespace'::Vm::run C:\VSCode\Sleuth\targets\vm\vm.cpp:52
    #1 0x7ff6 in LLVMFuzzerTestOneInput C:\VSCode\Sleuth\targets\vm\vm.cpp:186
    #2 0x7ff6 in `anonymous namespace'::child_loop C:\VSCode\Sleuth\runtime\sleuth_rt.cpp:166
    #3 0x7ff6 in main C:\VSCode\Sleuth\runtime\sleuth_rt.cpp:245
)";

static void test_crash_signature() {
    CrashSignature s = parse_crash(LINUX_REPORT, 1);
    CHECK(s.kind == "heap-buffer-overflow WRITE");
    CHECK(s.frames.size() == 3);
    CHECK(s.frames[0] == "(anonymous namespace)::Parser::element xml.cpp:184");
    CHECK(s.frames[1] == "(anonymous namespace)::Parser::parse");
    CHECK(s.frames[2] == "LLVMFuzzerTestOneInput");
    CrashSignature w = parse_crash(WINDOWS_REPORT, 1);
    CHECK(w.kind == "heap-buffer-overflow READ");
    CHECK(w.frames.size() == 2);  // the runtime and main are not part of it
    CHECK(w.frames[0] == "`anonymous namespace'::Vm::run vm.cpp:52");
    // Same code built elsewhere: same key.
    std::string moved = LINUX_REPORT;
    size_t at;
    while ((at = moved.find("/home/u/")) != std::string::npos) moved.replace(at, 8, "/build/");
    CHECK(parse_crash(moved, 1).key() == s.key());
    // No report at all.
    CrashSignature n = parse_crash("Segmentation fault\n", 139);
    CHECK(n.kind == "exit-code-139" && n.frames.empty());
    CrashSignature fpe = parse_crash("==1==ERROR: AddressSanitizer: FPE on unknown address 0x1\n    #0 0x1 in f /a/b.c:3:1\n", 1);
    CHECK(fpe.kind == "FPE" && fpe.frames.size() == 1 && fpe.frames[0] == "f b.c:3");
    // Recursion: the same bug at two depths has one signature.
    std::string deep = R"(==1==ERROR: AddressSanitizer: SEGV on unknown address
    #0 0x1 in leaf /a/t.c:9:1
    #1 0x1 in walk /a/t.c:20:1
    #2 0x1 in walk /a/t.c:25:1
    #3 0x1 in walk /a/t.c:25:1
    #4 0x1 in LLVMFuzzerTestOneInput /a/t.c:40:1
)";
    std::string shallow = R"(==1==ERROR: AddressSanitizer: SEGV on unknown address
    #0 0x1 in leaf /a/t.c:9:1
    #1 0x1 in walk /a/t.c:20:1
    #2 0x1 in LLVMFuzzerTestOneInput /a/t.c:40:1
)";
    CHECK(parse_crash(deep, 1).key() == parse_crash(shallow, 1).key());
    // Unsymbolized frames (symbolize=0), Linux style with build ids, Windows style without.
    CrashSignature ul = parse_crash(R"(==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2
READ of size 1 at 0x1 thread T0
    #0 0x55e0 (/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.asan-x86_64.so+0x1a) (BuildId: 12ab)
    #1 0x55e1 (/home/u/build/xml/sleuth+0x5f3a1) (BuildId: 34cd)
    #2 0x55e2 (/home/u/build/xml/sleuth+0x5f400) (BuildId: 34cd)
)", 1);
    CHECK(ul.kind == "heap-buffer-overflow READ");
    CHECK(ul.frames.size() == 2 && ul.frames[0] == "sleuth+0x5f3a1");
    CrashSignature uw = parse_crash(R"(==9==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12
    #0 0x7ff6cb983ca0  (C:\VSCode\Sleuthuildm\sleuth.exe+0x140003ca0)
    #1 0x7ffc7af4dda6  (C:\WINDOWS\System32\KERNEL32.DLL+0x18002dda6)
)", 1);
    CHECK(uw.frames.size() == 1 && uw.frames[0] == "sleuth.exe+0x140003ca0");
    // A symbolized Linux libc frame with a build id is dropped like any C library frame.
    CrashSignature sl = parse_crash(R"(==7==ERROR: AddressSanitizer: SEGV on unknown address 0x0
    #0 0x1 in f /src/a.c:3:1
    #1 0x2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e40) (BuildId: 4f7b)
)", 1);
    CHECK(sl.frames.size() == 1 && sl.frames[0] == "f a.c:3");
}

static void test_minimize() {
    // "Crashes" when the input contains both 'X' and 'Y' with an 'X' before a 'Y'.
    auto fails = [](const Bytes& d) {
        auto x = std::find(d.begin(), d.end(), 'X');
        return x != d.end() && std::find(x, d.end(), 'Y') != d.end();
    };
    Bytes in = B("aaaaaaaXbbbbbbbbbbbbbbbbbbbbbbYcccccccc");
    MinimizeStats st;
    Bytes m = minimize(in, fails, 10000, &st);
    CHECK(m == B("XY"));
    CHECK(st.from == in.size() && st.to == 2 && st.execs > 0);
    // Normalization: bytes that do not matter become '0'.
    auto first_is_z = [](const Bytes& d) { return d.size() >= 3 && d[0] == 'Z'; };
    CHECK(minimize(B("Zqqqqq"), first_is_z, 10000) == B("Z00"));
    // Budget respected.
    size_t calls = 0;
    minimize(in, [&](const Bytes& d) { ++calls; return fails(d); }, 5);
    CHECK(calls <= 5);
}

int main() {
    test_dictionary();
    test_rng();
    test_havoc();
    test_input_to_state();
    test_repair();
    test_learn();
    test_crash_signature();
    test_minimize();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
