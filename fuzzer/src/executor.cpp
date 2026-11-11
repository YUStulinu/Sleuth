#include "executor.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <csignal>
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace sleuth {

constexpr size_t MAX_STDERR = 256 * 1024;

// ------------------------------------------------------------------ platform layer

#ifdef _WIN32

static std::string quote_arg(const std::string& a) {
    if (!a.empty() && a.find_first_of(" \t\"") == std::string::npos) return a;
    std::string q = "\"";
    size_t bs = 0;
    for (char c : a) {
        if (c == '\\') {
            ++bs;
        } else if (c == '"') {
            q.append(bs * 2 + 1, '\\');
            q += '"';
            bs = 0;
        } else {
            q.append(bs, '\\');
            q += c;
            bs = 0;
        }
    }
    q.append(bs * 2, '\\');
    q += '"';
    return q;
}

class Process {
public:
    bool spawn(const std::vector<std::string>& argv) {
        SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, TRUE};
        HANDLE in_r, in_w, out_r, out_w, err_r, err_w;
        if (!CreatePipe(&in_r, &in_w, &sa, 1 << 16)) return false;
        if (!CreatePipe(&out_r, &out_w, &sa, 1 << 16)) return false;
        if (!CreatePipe(&err_r, &err_w, &sa, 1 << 16)) return false;
        SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);
        STARTUPINFOA si{};
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = in_r;
        si.hStdOutput = out_w;
        si.hStdError = err_w;
        std::string cmd;
        for (auto& a : argv) cmd += (cmd.empty() ? "" : " ") + quote_arg(a);
        PROCESS_INFORMATION pi{};
        // No error dialogs from the child (a crash must end it, not wait for a click).
        UINT old = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        BOOL ok = CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        SetErrorMode(old);
        CloseHandle(in_r);
        CloseHandle(out_w);
        CloseHandle(err_w);
        if (!ok) {
            CloseHandle(in_w);
            CloseHandle(out_r);
            CloseHandle(err_r);
            return false;
        }
        CloseHandle(pi.hThread);
        proc_ = pi.hProcess;
        in_ = in_w;
        out_ = out_r;
        err_ = err_r;
        return true;
    }
    bool write(const void* p, size_t n) {
        const char* c = (const char*)p;
        while (n) {
            DWORD w = 0;
            if (!WriteFile(in_, c, (DWORD)n, &w, nullptr) || w == 0) return false;
            c += w;
            n -= w;
        }
        return true;
    }
    // Blocking read from the protocol (which = 1) or stderr (which = 2) pipe; 0 at end.
    long read(int which, void* p, size_t n) {
        DWORD r = 0;
        if (!ReadFile(which == 1 ? out_ : err_, p, (DWORD)n, &r, nullptr)) return 0;
        return (long)r;
    }
    void kill() {
        if (proc_) TerminateProcess(proc_, 9);
    }
    void close_input() {
        if (in_) CloseHandle(in_);
        in_ = nullptr;
    }
    // Waits for exit; returns the exit code (or -1 if it does not exit in time).
    int wait(int ms) {
        if (!proc_) return -1;
        if (WaitForSingleObject(proc_, (DWORD)ms) != WAIT_OBJECT_0) return -1;
        DWORD code = 0;
        GetExitCodeProcess(proc_, &code);
        return (int)code;
    }
    ~Process() {
        kill();
        wait(5000);
        close_input();
        if (out_) CloseHandle(out_);
        if (err_) CloseHandle(err_);
        if (proc_) CloseHandle(proc_);
    }

private:
    HANDLE proc_ = nullptr, in_ = nullptr, out_ = nullptr, err_ = nullptr;
};

#else

class Process {
public:
    bool spawn(const std::vector<std::string>& argv) {
        int in[2], out[2], err[2];
        if (pipe(in) || pipe(out) || pipe(err)) return false;
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_adddup2(&fa, in[0], 0);
        posix_spawn_file_actions_adddup2(&fa, out[1], 1);
        posix_spawn_file_actions_adddup2(&fa, err[1], 2);
        for (int fd : {in[0], in[1], out[0], out[1], err[0], err[1]}) posix_spawn_file_actions_addclose(&fa, fd);
        std::vector<char*> av;
        for (auto& a : argv) av.push_back(const_cast<char*>(a.c_str()));
        av.push_back(nullptr);
        int rc = posix_spawn(&pid_, av[0], &fa, nullptr, av.data(), environ);
        posix_spawn_file_actions_destroy(&fa);
        close(in[0]);
        close(out[1]);
        close(err[1]);
        if (rc != 0) {
            close(in[1]);
            close(out[0]);
            close(err[0]);
            pid_ = -1;
            return false;
        }
        for (int fd : {in[1], out[0], err[0]}) fcntl(fd, F_SETFD, FD_CLOEXEC);
        in_ = in[1];
        out_ = out[0];
        err_ = err[0];
        return true;
    }
    bool write(const void* p, size_t n) {
        const char* c = (const char*)p;
        while (n) {
            ssize_t w = ::write(in_, c, n);
            if (w <= 0) return false;
            c += w;
            n -= (size_t)w;
        }
        return true;
    }
    long read(int which, void* p, size_t n) {
        ssize_t r = ::read(which == 1 ? out_ : err_, p, n);
        return r < 0 ? 0 : (long)r;
    }
    void kill() {
        if (pid_ > 0 && !reaped_) ::kill(pid_, SIGKILL);
    }
    void close_input() {
        if (in_ >= 0) close(in_);
        in_ = -1;
    }
    int wait(int ms) {
        if (pid_ <= 0) return -1;
        if (reaped_) return code_;
        for (int waited = 0;; waited += 5) {
            int st = 0;
            pid_t r = waitpid(pid_, &st, WNOHANG);
            if (r == pid_) {
                reaped_ = true;
                code_ = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
                return code_;
            }
            if (waited >= ms) return -1;
            usleep(5000);
        }
    }
    ~Process() {
        kill();
        wait(5000);
        close_input();
        if (out_ >= 0) close(out_);
        if (err_ >= 0) close(err_);
    }

private:
    pid_t pid_ = -1;
    int in_ = -1, out_ = -1, err_ = -1;
    bool reaped_ = false;
    int code_ = 0;
};

#endif

// ------------------------------------------------------------------ executor

Executor::Executor(std::vector<std::string> argv, int timeout_ms) : argv_(std::move(argv)), timeout_ms_(timeout_ms) {
    // An absolute, native path: CreateProcess does not search relative paths with '/' well,
    // and posix_spawn does not search PATH at all.
    std::error_code ec;
    if (!argv_.empty() && std::filesystem::exists(argv_[0], ec)) argv_[0] = std::filesystem::absolute(argv_[0], ec).make_preferred().string();
    const char* o = std::getenv("ASAN_OPTIONS");
    asan_options_ = o ? o : "";
}

// Children inherit our environment; ASAN_OPTIONS is set just before each spawn (later flags
// override earlier ones, so the user's own options are kept).
void Executor::set_env(bool symbolize) {
    std::string v = asan_options_;
    if (!symbolize) v += (v.empty() ? "" : ":") + std::string("symbolize=0");
#ifdef _WIN32
    _putenv_s("ASAN_OPTIONS", v.c_str());
#else
    if (v.empty()) unsetenv("ASAN_OPTIONS");
    else setenv("ASAN_OPTIONS", v.c_str(), 1);
#endif
}

std::string Executor::symbolized_report(const Bytes& data, const std::string& scratch) {
    if (!write_file(scratch, data)) return "";
    Process p;
    set_env(true);
    bool ok = p.spawn({argv_[0], scratch});
    set_env(symbolize_);
    if (!ok) return "";
    p.close_input();
    std::string err;
    char buf[8192];
    std::thread out([&p] {
        char b[4096];
        while (p.read(1, b, sizeof b) > 0) {
        }
    });
    for (long n; (n = p.read(2, buf, sizeof buf)) > 0;) err.append(buf, (size_t)n);
    out.join();
    p.wait(10000);
    std::remove(scratch.c_str());
    return err;
}

Executor::~Executor() {
    wd_quit_ = true;
    if (wd_thread_.joinable()) wd_thread_.join();
    stop_child();
}

// The watchdog wakes every few milliseconds and kills the child when the input it is running
// has passed its deadline; the blocked read in run() then returns end of file. Polling (rather
// than a condition variable signalled per input) keeps every execution free of thread wake-ups.
void Executor::watchdog() {
    while (!wd_quit_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        uint64_t d = deadline_.load();
        if (d && now_us() >= d) {
            std::lock_guard<std::mutex> g(proc_mu_);
            if (deadline_.load() == d && proc_) {
                timed_out_ = true;
                proc_->kill();
            }
        }
    }
}

void Executor::stop_child() {
    std::unique_ptr<Process> p;
    {
        std::lock_guard<std::mutex> g(proc_mu_);
        p = std::move(proc_);
    }
    if (!p) return;
    p->kill();
    p->wait(5000);
    if (err_thread_.joinable()) err_thread_.join();
}

bool Executor::start(std::string* error) {
    stop_child();
    if (!wd_thread_.joinable()) wd_thread_ = std::thread([this] { watchdog(); });
    {
        std::lock_guard<std::mutex> g(mu_);
        err_.clear();
    }
    rpos_ = rlen_ = 0;
    auto p = std::make_unique<Process>();
    std::vector<std::string> argv = argv_;
    argv.push_back("--sleuth-child");
    set_env(symbolize_);
    if (!p->spawn(argv)) {
        if (error) *error = "cannot start " + argv_[0];
        return false;
    }
    Process* raw = p.get();
    {
        std::lock_guard<std::mutex> g(proc_mu_);
        proc_ = std::move(p);
    }
    // stderr is drained continuously (a full pipe would block the child); it is only read
    // when the child crashes.
    err_thread_ = std::thread([this, raw] {
        char buf[8192];
        for (;;) {
            long n = raw->read(2, buf, sizeof buf);
            if (n <= 0) return;
            std::lock_guard<std::mutex> g(mu_);
            err_.append(buf, (size_t)n);
            if (err_.size() > MAX_STDERR) err_.erase(0, err_.size() - MAX_STDERR / 2);
        }
    });
    uint32_t guards = 0;
    // Start-up (loading the sanitizer runtime) can be slow on a busy machine.
    timed_out_ = false;
    deadline_ = now_us() + 30'000'000ull;
    bool ok = read_exact(&guards, 4);
    deadline_ = 0;
    if (!ok) {
        if (error) {
            stop_child();
            std::lock_guard<std::mutex> g(mu_);
            *error = "the target did not answer the handshake; stderr:\n" + err_;
        } else {
            stop_child();
        }
        return false;
    }
    num_edges_ = guards;
    return true;
}

bool Executor::read_exact(void* buf, size_t n) {
    uint8_t* p = (uint8_t*)buf;
    while (n) {
        if (rpos_ == rlen_) {
            long got = proc_->read(1, rbuf_.data(), rbuf_.size());
            if (got <= 0) return false;
            rpos_ = 0;
            rlen_ = (size_t)got;
        }
        size_t k = std::min(n, rlen_ - rpos_);
        std::memcpy(p, rbuf_.data() + rpos_, k);
        rpos_ += k;
        p += k;
        n -= k;
    }
    return true;
}

ExecResult Executor::run(const uint8_t* data, size_t size, CmpMode mode) {
    ExecResult r;
    if (!proc_ && !start()) return r;
    uint64_t t0 = now_us();
    uint32_t n = (uint32_t)size | (uint32_t)mode << 30;
    {
        std::lock_guard<std::mutex> g(mu_);
        err_.clear();  // keep only what this input produces
    }
    // One write for the frame: header and data together.
    frame_.resize(4 + size);
    std::memcpy(frame_.data(), &n, 4);
    if (size) std::memcpy(frame_.data() + 4, data, size);
    timed_out_ = false;
    deadline_ = t0 + (uint64_t)timeout_ms_ * 1000;
    bool sent = proc_->write(frame_.data(), frame_.size());
    uint32_t total = 0;
    bool ok = sent && read_exact(&total, 4);
    if (ok) {
        body_.resize(total);
        ok = read_exact(body_.data(), total);
    }
    deadline_ = 0;
    r.us = now_us() - t0;
    if (ok) {
        // The watchdog may have fired just as the answer came in; once it has let go of the
        // lock it will not fire for this input again.
        { std::lock_guard<std::mutex> g(proc_mu_); }
        if (timed_out_) {
            stop_child();
            ++restarts_;
            start();
        }
    }
    if (!ok) {
        // The child is gone: killed by the watchdog (a hang) or crashed.
        bool hang = timed_out_.load();
        {
            std::lock_guard<std::mutex> g(proc_mu_);
            r.exit_code = proc_ ? proc_->wait(10000) : -1;
        }
        if (err_thread_.joinable()) err_thread_.join();  // the rest of the report
        {
            std::lock_guard<std::mutex> g(mu_);
            r.report = err_;
        }
        r.status = hang ? ExecResult::Timeout : ExecResult::Crash;
        stop_child();
        ++restarts_;
        start();
        return r;
    }
    r.status = ExecResult::Ok;
    const uint8_t* p = body_.data();
    const uint8_t* end = p + body_.size();
    auto get32 = [&](uint32_t& v) {
        if (end - p < 4) return false;
        std::memcpy(&v, p, 4);
        p += 4;
        return true;
    };
    uint32_t ne = 0, nc = 0, ns = 0;
    if (!get32(ne) || (size_t)(end - p) < (size_t)ne * 4) return r.status = ExecResult::Error, r;
    r.edges.resize(ne);
    std::memcpy(r.edges.data(), p, (size_t)ne * 4);
    p += (size_t)ne * 4;
    if (!get32(nc) || (size_t)(end - p) < (size_t)nc * 17) return r.status = ExecResult::Error, r;
    r.cmps.resize(nc);
    for (uint32_t i = 0; i < nc; ++i) {
        std::memcpy(&r.cmps[i].a, p, 8);
        std::memcpy(&r.cmps[i].b, p + 8, 8);
        r.cmps[i].size = p[16] & 0x7f;
        r.cmps[i].is_const = (p[16] & 0x80) != 0;
        p += 17;
    }
    if (!get32(ns)) return r;
    for (uint32_t i = 0; i < ns && p < end; ++i) {
        StrPair s;
        uint8_t la = *p++;
        if (end - p < la) break;
        s.a.assign(p, p + la);
        p += la;
        if (p >= end) break;
        uint8_t lb = *p++;
        if (end - p < lb) break;
        s.b.assign(p, p + lb);
        p += lb;
        r.strs.push_back(std::move(s));
    }
    return r;
}

}  // namespace sleuth
