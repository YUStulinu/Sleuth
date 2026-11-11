// Runs inputs through a target built with the Sleuth runtime, in persistent mode: the target is
// started once with --sleuth-child and fed one framed input after another over a pipe, and
// answers each with the edges it hit and the comparison operands it saw (see
// runtime/sleuth_rt.cpp for the protocol). A crash ends the child: the executor notices end of
// file, collects the sanitizer report from the child's stderr and starts a new child. An input
// that takes longer than the timeout kills the child (a hang).
#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "util.hpp"

namespace sleuth {

struct CmpPair {
    uint64_t a, b;       // for a comparison with a constant, b is the constant
    uint8_t size;        // operand size in bytes
    bool is_const = false;
};

struct StrPair {
    Bytes a, b;
};

struct ExecResult {
    enum Status { Ok, Crash, Timeout, Error } status = Error;
    std::vector<uint32_t> edges;  // edge id << 3 | hit-count bucket
    std::vector<CmpPair> cmps;
    std::vector<StrPair> strs;
    uint64_t us = 0;              // wall time of this run
    std::string report;           // stderr of the child when it crashed
    int exit_code = 0;
};

class Process;  // platform-specific child process with three pipes

class Executor {
public:
    Executor(std::vector<std::string> argv, int timeout_ms);
    ~Executor();
    Executor(const Executor&) = delete;
    Executor& operator=(const Executor&) = delete;

    // Starts the child and reads its greeting (the number of edges). False if it fails.
    bool start(std::string* error = nullptr);
    // Which comparisons the child reports (see runtime/sleuth_rt.cpp): none, only those
    // between two run-time values of 4 or 8 bytes (checksum repair), or all of them.
    enum CmpMode { CmpNone = 0, CmpLight = 1, CmpFull = 2 };
    ExecResult run(const uint8_t* data, size_t size, CmpMode mode = CmpFull);
    ExecResult run(const Bytes& d, CmpMode mode = CmpFull) { return run(d.data(), d.size(), mode); }
    uint32_t num_edges() const { return num_edges_; }
    // Children report crashes unsymbolized (module+offset frames: about 40% cheaper per crash
    // on Windows). Call before start().
    void set_symbolize(bool on) { symbolize_ = on; }
    // Runs one input in a fresh process with symbolization on and returns its stderr (used to
    // describe a crash the first time its unsymbolized signature is seen). `scratch` is a file
    // path the input can be written to.
    std::string symbolized_report(const Bytes& data, const std::string& scratch);
    uint64_t restarts() const { return restarts_; }

private:
    bool read_exact(void* buf, size_t n);
    void stop_child();
    void watchdog();
    void set_env(bool symbolize);

    std::vector<std::string> argv_;
    int timeout_ms_;
    bool symbolize_ = true;
    std::string asan_options_;  // ASAN_OPTIONS as we found it
    uint32_t num_edges_ = 0;
    uint64_t restarts_ = 0;

    std::mutex proc_mu_;  // guards proc_ against the watchdog
    std::unique_ptr<Process> proc_;
    std::atomic<uint64_t> deadline_{0};  // of the input running now (0 = none)
    std::atomic<bool> timed_out_{false};
    std::atomic<bool> wd_quit_{false};
    std::thread wd_thread_;

    // The protocol pipe is read directly by the calling thread.
    std::vector<uint8_t> rbuf_ = std::vector<uint8_t>(1 << 16);
    size_t rpos_ = 0, rlen_ = 0;
    Bytes frame_, body_;

    std::mutex mu_;
    std::string err_;  // the child's stderr (the tail, bounded), filled by a thread
    std::thread err_thread_;
};

}  // namespace sleuth
