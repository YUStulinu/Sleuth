// Bug canary log (see sleuth_canary.h). Built without coverage instrumentation.
#include "sleuth_canary.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>

namespace {
FILE* g_log = nullptr;
bool g_init = false;
bool g_reached[256], g_triggered[256];

long long now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void event(char kind, int id) {
    if (!g_init) {
        g_init = true;
        const char* p = std::getenv("SLEUTH_BUG_LOG");
        if (p && *p) g_log = std::fopen(p, "a");
    }
    if (!g_log) return;
    std::fprintf(g_log, "%c %d %lld\n", kind, id, now_ms());
    std::fflush(g_log);  // the process may be about to crash
}
}  // namespace

extern "C" void sleuth_bug(int id, int triggered) {
    if (id < 0 || id >= 256) return;
    if (!g_reached[id]) {
        g_reached[id] = true;
        event('R', id);
    }
    if (triggered && !g_triggered[id]) {
        g_triggered[id] = true;
        event('T', id);
    }
}

// AddressSanitizer defaults for every build of the targets (Sleuth and libFuzzer alike, since
// both link this file): 128-byte redzones, so the planted out-of-bounds reads that land up to
// 128 bytes before or after a buffer are always caught, and no leak checking (the targets free
// what they allocate; leak reports at exit would only add noise). ASAN_OPTIONS still overrides.
extern "C" const char* __asan_default_options() { return "redzone=128:detect_leaks=0"; }
