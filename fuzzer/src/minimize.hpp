// Test-case minimization: shrinks an input while a predicate (here: "still crashes with the same
// signature") keeps holding. Delta debugging in the style of afl-tmin: remove blocks of
// decreasing size (n/2, n/4, ..., 1 byte), repeat while anything shrank, then replace each byte
// with '0' where possible so what remains is easier to read.
#pragma once
#include <functional>

#include "util.hpp"

namespace sleuth {

struct MinimizeStats {
    size_t execs = 0;
    size_t from = 0, to = 0;
};

Bytes minimize(const Bytes& input, const std::function<bool(const Bytes&)>& still_fails, size_t max_execs, MinimizeStats* stats = nullptr);

}  // namespace sleuth
