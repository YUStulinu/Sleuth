#include "minimize.hpp"

#include <algorithm>

namespace sleuth {

Bytes minimize(const Bytes& input, const std::function<bool(const Bytes&)>& still_fails, size_t max_execs, MinimizeStats* stats) {
    Bytes best = input;
    size_t execs = 0;
    auto test = [&](const Bytes& c) {
        if (execs >= max_execs) return false;
        ++execs;
        return still_fails(c);
    };
    bool shrank = true;
    while (shrank && execs < max_execs) {
        shrank = false;
        for (size_t block = best.size() / 2; block >= 1 && execs < max_execs; block /= 2) {
            for (size_t at = 0; at < best.size() && execs < max_execs;) {
                size_t len = std::min(block, best.size() - at);
                Bytes c(best.begin(), best.begin() + (std::ptrdiff_t)at);
                c.insert(c.end(), best.begin() + (std::ptrdiff_t)(at + len), best.end());
                if (test(c)) {
                    best.swap(c);
                    shrank = true;  // retry the same position: new bytes moved into it
                } else {
                    at += len;
                }
            }
            if (block == 1) break;
        }
    }
    // Normalize bytes that do not matter.
    for (size_t i = 0; i < best.size() && execs < max_execs; ++i) {
        if (best[i] == '0') continue;
        Bytes c(best);
        c[i] = '0';
        if (test(c)) best.swap(c);
    }
    if (stats) {
        stats->execs = execs;
        stats->from = input.size();
        stats->to = best.size();
    }
    return best;
}

}  // namespace sleuth
