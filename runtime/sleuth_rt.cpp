// The Sleuth runtime, linked into a target built with
//   clang -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp
// It implements the SanitizerCoverage callbacks (edge counters and comparison operands) and a
// main() that runs the target's LLVMFuzzerTestOneInput in one of three modes:
//
//   target --sleuth-child        persistent mode: inputs arrive on stdin as frames, results
//                                (edges hit, comparison operands) go back on the original stdout;
//                                stdout itself is redirected to the null device so the target's
//                                prints cannot corrupt the protocol
//   target --replay FILE...      run each file once and print, per file, the edges it covers
//                                (used to measure coverage the same way for every fuzzer)
//   target FILE                  run one input (reproduce a crash)
//
// Protocol (little-endian):
//   in:  [u32 n | mode << 30][n bytes]   mode: which comparisons to report for this input:
//        0 none, 1 "light" (only the first 32 between two run-time values of 4 or 8 bytes:
//        what checksum repair needs), 2 all (and the string comparisons)
//   out: [u32 total][u32 n_edges][n_edges x u32 (edge id << 3 | count bucket)]
//        [u32 n_cmps][n_cmps x (u64 a, u64 b, u8 size | 0x80 if b is a compile-time constant)]
//        [u32 n_strs][n_strs x (u8 len_a, a bytes, u8 len_b, b bytes)]
// The last section holds operands of memcmp/strcmp/strncmp/strstr calls (up to 32 bytes each),
// captured through the sanitizer interceptors' weak hooks, which trace-cmp cannot see.
// A crash ends the process before it answers; the controller sees end of file and reads the
// sanitizer report from stderr.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#define DUP _dup
#define DUP2 _dup2
#define READ _read
#define WRITE _write
#define OPEN _open
#define NULLDEV "NUL"
#else
#include <fcntl.h>
#include <unistd.h>
#define DUP dup
#define DUP2 dup2
#define READ read
#define WRITE write
#define OPEN open
#define NULLDEV "/dev/null"
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
extern "C" __attribute__((weak)) int LLVMFuzzerInitialize(int* argc, char*** argv);

namespace {
// Plain pointers, not std::vector: the coverage init callback runs from a module constructor,
// possibly before this file's own globals would be constructed.
uint32_t g_guards = 0;
uint8_t* g_counters = nullptr;   // hit counts per edge (saturating)
uint32_t* g_touched = nullptr;   // edges hit in this run
uint32_t g_ntouched = 0;
constexpr size_t MAX_CMPS = 512;
struct Cmp {
    uint64_t a, b;
    uint8_t size;
};
Cmp g_cmps[MAX_CMPS];
size_t g_ncmps = 0;
bool g_collect = false;
int g_cmp_mode = 2;  // see the protocol: 0 none, 1 light, 2 all
constexpr size_t MAX_STRS = 128, MAX_STR = 32;
struct StrCmp {
    uint8_t la, lb;
    uint8_t a[MAX_STR], b[MAX_STR];
};
StrCmp g_strs[MAX_STRS];
size_t g_nstrs = 0;

void record_str(const void* a, size_t la, const void* b, size_t lb) {
    if (!g_collect || g_cmp_mode != 2 || g_nstrs >= MAX_STRS || la < 2 || lb < 2) return;
    StrCmp& s = g_strs[g_nstrs++];
    s.la = (uint8_t)(la < MAX_STR ? la : MAX_STR);
    s.lb = (uint8_t)(lb < MAX_STR ? lb : MAX_STR);
    std::memcpy(s.a, a, s.la);
    std::memcpy(s.b, b, s.lb);
}

size_t bounded_strlen(const char* s, size_t max) {
    size_t n = 0;
    while (n < max && s[n]) ++n;
    return n;
}

inline void record_cmp(uint64_t a, uint64_t b, uint8_t size) {
    if (!g_collect || !g_cmp_mode || a == b || g_ncmps >= MAX_CMPS) return;
    // Light mode: the first 32 such comparisons are all the controller looks at.
    if (g_cmp_mode == 1 && ((size & 0x80) || size < 4 || g_ncmps >= 32)) return;
    // Skip the many comparisons with small constants (loop bounds, flags): useless as tokens.
    if (a < 256 && b < 256) return;
    g_cmps[g_ncmps++] = {a, b, size};
}

uint8_t bucket(uint8_t c) {
    // AFL-style hit-count classes: 1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+
    if (c <= 3) return c - 1;
    if (c < 8) return 3;
    if (c < 16) return 4;
    if (c < 32) return 5;
    if (c < 128) return 6;
    return 7;
}

void begin_run() {
    for (uint32_t i = 0; i < g_ntouched; ++i) g_counters[g_touched[i]] = 0;
    g_ntouched = 0;
    g_ncmps = 0;
    g_nstrs = 0;
}

bool read_all(int fd, void* buf, size_t n) {
    char* p = (char*)buf;
    while (n) {
        int r = READ(fd, p, (unsigned)n);
        if (r <= 0) return false;
        p += r;
        n -= (size_t)r;
    }
    return true;
}

void write_all(int fd, const void* buf, size_t n) {
    const char* p = (const char*)buf;
    while (n) {
        int r = WRITE(fd, p, (unsigned)n);
        if (r <= 0) std::exit(3);
        p += r;
        n -= (size_t)r;
    }
}

std::vector<uint8_t> read_file(const char* path) {
    std::vector<uint8_t> d;
    FILE* f = std::fopen(path, "rb");
    if (!f) return d;
    uint8_t buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) d.insert(d.end(), buf, buf + n);
    std::fclose(f);
    return d;
}

int child_loop() {
    int proto = DUP(1);
    int nul = OPEN(NULLDEV, O_WRONLY);
    DUP2(nul, 1);  // the target's own stdout goes nowhere
#ifdef _WIN32
    _setmode(0, _O_BINARY);
    _setmode(proto, _O_BINARY);
#endif
    std::vector<uint8_t> in, out;
    g_collect = true;
    // Announce readiness and the number of edges.
    write_all(proto, &g_guards, 4);
    for (;;) {
        uint32_t n;
        if (!read_all(0, &n, 4)) return 0;
        g_cmp_mode = (int)(n >> 30);
        n &= 0x3fffffff;
        in.resize(n);
        if (n && !read_all(0, in.data(), n)) return 0;
        begin_run();
        // A copy the target cannot keep pointers into across runs (as libFuzzer does).
        std::vector<uint8_t> copy(in);
        LLVMFuzzerTestOneInput(copy.data(), copy.size());
        out.clear();
        auto put32 = [&](uint32_t v) { out.insert(out.end(), (uint8_t*)&v, (uint8_t*)&v + 4); };
        auto put64 = [&](uint64_t v) { out.insert(out.end(), (uint8_t*)&v, (uint8_t*)&v + 8); };
        put32(0);  // total, patched below
        put32(g_ntouched);
        for (uint32_t i = 0; i < g_ntouched; ++i) put32(g_touched[i] << 3 | bucket(g_counters[g_touched[i]]));
        put32((uint32_t)g_ncmps);
        for (size_t i = 0; i < g_ncmps; ++i) {
            put64(g_cmps[i].a);
            put64(g_cmps[i].b);
            out.push_back(g_cmps[i].size);
        }
        put32((uint32_t)g_nstrs);
        for (size_t i = 0; i < g_nstrs; ++i) {
            out.push_back(g_strs[i].la);
            out.insert(out.end(), g_strs[i].a, g_strs[i].a + g_strs[i].la);
            out.push_back(g_strs[i].lb);
            out.insert(out.end(), g_strs[i].b, g_strs[i].b + g_strs[i].lb);
        }
        uint32_t total = (uint32_t)out.size() - 4;
        std::memcpy(out.data(), &total, 4);
        write_all(proto, out.data(), out.size());
    }
}
}  // namespace

extern "C" {
void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {
    if (start == stop || *start) return;
    uint32_t first = g_guards;
    for (uint32_t* x = start; x < stop; x++) *x = ++g_guards;
    // Modules may register in several calls: grow the arrays.
    g_counters = (uint8_t*)std::realloc(g_counters, g_guards + 1);
    g_touched = (uint32_t*)std::realloc(g_touched, sizeof(uint32_t) * (g_guards + 1));
    std::memset(g_counters + first, 0, g_guards + 1 - first);
}

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
    uint32_t e = *guard;
    if (!e) return;
    uint8_t& c = g_counters[e];
    if (c == 0) g_touched[g_ntouched++] = e;
    if (c != 255) ++c;
}

void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { record_cmp(a, b, 1); }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { record_cmp(a, b, 2); }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { record_cmp(a, b, 4); }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { record_cmp(a, b, 8); }
void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { record_cmp(b, a, 1 | 0x80); }
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { record_cmp(b, a, 2 | 0x80); }
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { record_cmp(b, a, 4 | 0x80); }
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { record_cmp(b, a, 8 | 0x80); }
void __sanitizer_cov_trace_switch(uint64_t val, uint64_t* cases) {
    // cases[0] = number of cases, cases[1] = bit width, then the case values.
    for (uint64_t i = 0; i < cases[0] && i < 16; ++i) record_cmp(val, cases[2 + i], (uint8_t)(cases[1] / 8) | 0x80);
}
// Called by the AddressSanitizer interceptors after the real function (only while collecting:
// the C runtime calls these functions during start-up too, before anything is initialised).
void __sanitizer_weak_hook_memcmp(void*, const void* s1, const void* s2, size_t n, int result) {
    if (result != 0 && n >= 2) record_str(s1, n, s2, n);
}
void __sanitizer_weak_hook_strncmp(void*, const char* s1, const char* s2, size_t n, int result) {
    if (result != 0) record_str(s1, bounded_strlen(s1, n < MAX_STR ? n : MAX_STR), s2, bounded_strlen(s2, n < MAX_STR ? n : MAX_STR));
}
void __sanitizer_weak_hook_strcmp(void*, const char* s1, const char* s2, int result) {
    if (result != 0) record_str(s1, bounded_strlen(s1, MAX_STR), s2, bounded_strlen(s2, MAX_STR));
}
void __sanitizer_weak_hook_strstr(void*, const char* s1, const char* s2, char* result) {
    if (!result) record_str(s1, bounded_strlen(s1, MAX_STR), s2, bounded_strlen(s2, MAX_STR));
}
void __sanitizer_cov_trace_div4(uint32_t) {}
void __sanitizer_cov_trace_div8(uint64_t) {}
void __sanitizer_cov_trace_gep(uintptr_t) {}
}

int main(int argc, char** argv) {
    if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
    if (argc >= 2 && std::strcmp(argv[1], "--sleuth-child") == 0) return child_loop();
    if (argc >= 3 && std::strcmp(argv[1], "--replay") == 0) {
        // One line per file: "<file> <edge> <edge> ..." (edges are cumulative per file run).
        for (int i = 2; i < argc; ++i) {
            begin_run();
            auto d = read_file(argv[i]);
            LLVMFuzzerTestOneInput(d.data(), d.size());
            std::printf("%s", argv[i]);
            for (uint32_t k = 0; k < g_ntouched; ++k) std::printf(" %u", g_touched[k]);
            std::printf("\n");
            std::fflush(stdout);
        }
        return 0;
    }
    if (argc == 2 && std::strcmp(argv[1], "--edges") == 0) {
        std::printf("%u\n", g_guards);
        return 0;
    }
    if (argc == 2) {
        auto d = read_file(argv[1]);
        LLVMFuzzerTestOneInput(d.data(), d.size());
        std::fprintf(stderr, "ran %zu bytes: no crash\n", d.size());
        return 0;
    }
    std::fprintf(stderr, "usage: %s --sleuth-child | --replay FILE... | --edges | FILE\n", argv[0]);
    return 2;
}
