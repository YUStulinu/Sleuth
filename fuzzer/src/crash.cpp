#include "crash.hpp"

#include <cstdio>
#include <sstream>

namespace sleuth {

std::string CrashSignature::key() const {
    std::string k = kind;
    for (auto& f : frames) k += " | " + f;
    return k;
}

namespace {

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

// Frames inside the sanitizer runtime or the C library are not where the bug is.
bool is_runtime_frame(const std::string& func, const std::string& loc) {
    // Whole names (C library functions the interceptors wrap, program entry points).
    static const char* exact[] = {"memcpy", "memmove", "memset", "memcmp", "strlen", "strnlen", "strcmp", "strncmp", "strstr", "strcpy",
                                  "strncpy", "strcat", "malloc", "calloc", "realloc", "free", "abort", "raise", "main", "invoke_main",
                                  "_start", "BaseThreadInitThunk", "RtlUserThreadStart", "KiUserExceptionDispatcher", "RtlDispatchException"};
    for (auto* f : exact)
        if (func == f) return true;
    // Prefixes (sanitizer internals, the runtimes that call the target).
    static const char* prefixes[] = {"__asan", "__interceptor", "___interceptor", "__sanitizer", "_asan_", "wrap_", "operator new",
                                     "operator delete", "std::__", "__libc_", "__GI_", "__scrt_", "fuzzer::",
                                     "`anonymous namespace'::child_loop", "(anonymous namespace)::child_loop"};
    for (auto* f : prefixes)
        if (func.rfind(f, 0) == 0) return true;
    static const char* locs[] = {"compiler-rt", "sanitizer_common", "clang_rt.", "libc.so", "ntdll", "ucrtbase", "KERNELBASE", "KERNEL32", "libc++", "libstdc++",
                                 "libclang_rt", "ld-linux",
                                 "\\include\\", "/include/c++", "sleuth_rt.cpp", "exe_common.inl"};
    for (auto* l : locs)
        if (loc.find(l) != std::string::npos) return true;
    return false;
}

// Keeps "file:line" but drops the column and the directories, so the same code built in two
// places gives the same signature.
std::string short_location(std::string loc) {
    size_t paren = loc.find(" (");
    if (paren != std::string::npos) loc = loc.substr(0, paren);
    size_t slash = loc.find_last_of("/\\");
    if (slash != std::string::npos) loc = loc.substr(slash + 1);
    // file:line:col -> file:line
    size_t c1 = loc.find(':');
    if (c1 != std::string::npos) {
        size_t c2 = loc.find(':', c1 + 1);
        if (c2 != std::string::npos) loc = loc.substr(0, c2);
    }
    return loc;
}

}  // namespace

CrashSignature parse_crash(const std::string& report, int exit_code, int top) {
    CrashSignature sig;
    std::istringstream in(report);
    std::string line;
    bool in_stack = false, stack_done = false;
    std::string last_func;
    while (std::getline(in, line)) {
        line = trim(line);
        size_t e = line.find("ERROR: AddressSanitizer: ");
        if (sig.kind.empty() && e != std::string::npos) {
            std::string rest = line.substr(e + 25);
            // "heap-buffer-overflow on address 0x... at pc ..." -> "heap-buffer-overflow"
            size_t sp = rest.find(' ');
            sig.kind = sp == std::string::npos ? rest : rest.substr(0, sp);
            if (sig.kind.back() == ':') sig.kind.pop_back();
            continue;
        }
        if (!sig.kind.empty() && sig.frames.empty() && !in_stack && (line.rfind("READ of size", 0) == 0 || line.rfind("WRITE of size", 0) == 0)) {
            // "READ of size 4 at 0x... thread T0" -> "READ". The size is left out: the same bug
            // read through strlen or memcpy gives a different size with every input.
            sig.kind += line[0] == 'R' ? " READ" : " WRITE";
            continue;
        }
        if (stack_done || sig.kind.empty()) continue;
        if (line.rfind("#", 0) == 0) {
            in_stack = true;
            // Linux reports may end a frame with " (BuildId: ...)".
            size_t bid = line.find(" (BuildId:");
            if (bid != std::string::npos) line = trim(line.substr(0, bid));
            // "#0 0x7ff6... in func(args) file:line:col"
            size_t in_pos = line.find(" in ");
            if (in_pos == std::string::npos) {
                // Unsymbolized (symbolize=0): "#0 0x7ff6...  (C:\dir\target.exe+0x140003ca0)".
                // The frame is the module and offset; that is enough to tell crashes apart.
                size_t open = line.find('('), close = open == std::string::npos ? open : line.find(')', open);
                if (open == std::string::npos || close == std::string::npos || close < open) continue;
                std::string modoff = line.substr(open + 1, close - open - 1);
                if (is_runtime_frame("", modoff)) continue;
                size_t slash = modoff.find_last_of("/\\");
                std::string frame = slash == std::string::npos ? modoff : modoff.substr(slash + 1);
                if ((int)sig.frames.size() < top) sig.frames.push_back(frame);
                continue;
            }
            std::string rest = line.substr(in_pos + 4);
            // The function name may contain spaces ("operator new", "anonymous namespace");
            // the location is the last space-separated token.
            size_t last = rest.find_last_of(' ');
            std::string func = last == std::string::npos ? rest : rest.substr(0, last);
            std::string loc = last == std::string::npos ? "" : rest.substr(last + 1);
            // Drop the parameter list: the parenthesis that closes at the end of the name
            // ("(anonymous namespace)::f(int)" keeps its first parenthesised part).
            if (!func.empty() && func.back() == ')') {
                int bal = 0;
                for (size_t k = func.size(); k-- > 0;) {
                    if (func[k] == ')') ++bal;
                    else if (func[k] == '(' && --bal == 0) {
                        if (k > 0) func = func.substr(0, k);
                        break;
                    }
                }
            }
            if (is_runtime_frame(func, loc)) continue;
            // The faulting frame with its line; the callers by name only, with recursion
            // collapsed, so the same bug reached at another recursion depth or from another
            // line of the same caller keeps its signature.
            if ((int)sig.frames.size() >= top) continue;
            if (sig.frames.empty()) {
                sig.frames.push_back(func + " " + short_location(loc));
                last_func = func;
            } else if (func != last_func) {
                sig.frames.push_back(func);
                last_func = func;
            }
        } else if (in_stack) {
            stack_done = true;  // the first stack (the faulting access) is the one that matters
        }
    }
    if (sig.kind.empty()) {
        char buf[64];
        std::snprintf(buf, sizeof buf, "exit-code-%d", exit_code);
        sig.kind = buf;
    }
    return sig;
}

}  // namespace sleuth
