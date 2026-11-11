// Crash signatures for deduplication. A crash is identified by the kind of error the sanitizer
// reported (heap-buffer-overflow READ of size 1, negative-size-param, ...) and the top frames of
// its stack that belong to the program, skipping sanitizer and C library frames (memcpy, the
// interceptors). Two inputs that overflow the same buffer from the same code get the same
// signature, whatever their bytes; the same function reached from a different caller does not.
#pragma once
#include <string>
#include <vector>

namespace sleuth {

struct CrashSignature {
    std::string kind;                 // "heap-buffer-overflow READ 1", "SEGV", "timeout", ...
    std::vector<std::string> frames;  // "function file:line", innermost first
    std::string key() const;          // kind + frames, the dedup key
};

// Parses an AddressSanitizer report (the child's stderr). Without one, falls back to the exit
// code. `top` is how many program frames make up the signature.
CrashSignature parse_crash(const std::string& report, int exit_code, int top = 3);

}  // namespace sleuth
