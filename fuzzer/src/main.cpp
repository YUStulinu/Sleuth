// sleuth: a coverage-guided fuzzer for targets built with the Sleuth runtime (see build.py).
//
//   sleuth fuzz   -t TARGET -i SEEDS [-i SEEDS...] -o OUT [options]
//   sleuth tmin   -t TARGET -i CRASH -o OUT [--max-execs N]
//   sleuth triage -t TARGET FILE...
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "crash.hpp"
#include "executor.hpp"
#include "fuzzer.hpp"
#include "minimize.hpp"

using namespace sleuth;

namespace {

Fuzzer* g_fuzzer = nullptr;

void on_signal(int) {
    if (g_fuzzer) g_fuzzer->stop();
}

int usage() {
    std::fprintf(stderr,
                 "usage:\n"
                 "  sleuth fuzz -t TARGET -i SEEDS... -o OUT [options]\n"
                 "      --time S          stop after S seconds\n"
                 "      --execs N         stop after N executions\n"
                 "      --max-len N       longest input (default 4096)\n"
                 "      --timeout MS      per-input timeout (default 500)\n"
                 "      --dict FILE       AFL/libFuzzer dictionary\n"
                 "      --blind           ignore coverage (baseline)\n"
                 "      --no-cmp          no input-to-state stage, no learned tokens\n"
                 "      --minimize        minimize each new unique crash right away\n"
                 "      --seed N          random seed\n"
                 "      --sync-dir D --worker-id K   parallel mode (see parallel/)\n"
                 "      --quiet\n"
                 "  sleuth tmin -t TARGET -i CRASH -o OUT [--max-execs N]\n"
                 "  sleuth triage -t TARGET FILE...      (one JSON line per file)\n");
    return 2;
}

int cmd_fuzz(int argc, char** argv) {
    Options o;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "%s needs a value\n", a.c_str());
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "-t") o.target = val();
        else if (a == "-i") o.seed_dirs.push_back(val());
        else if (a == "-o") o.out_dir = val();
        else if (a == "--time") o.max_time_s = std::atof(val().c_str());
        else if (a == "--execs") o.max_execs = std::strtoull(val().c_str(), nullptr, 10);
        else if (a == "--max-len") o.max_len = (size_t)std::strtoull(val().c_str(), nullptr, 10);
        else if (a == "--timeout") o.timeout_ms = std::atoi(val().c_str());
        else if (a == "--dict") o.dict = val();
        else if (a == "--blind") o.blind = true;
        else if (a == "--no-cmp") o.cmp = false;
        else if (a == "--minimize") o.minimize_crashes = true;
        else if (a == "--seed") o.seed = std::strtoull(val().c_str(), nullptr, 10);
        else if (a == "--sync-dir") o.sync_dir = val();
        else if (a == "--worker-id") o.worker_id = std::atoi(val().c_str());
        else if (a == "--quiet") o.quiet = true;
        else {
            std::fprintf(stderr, "unknown option %s\n", a.c_str());
            return usage();
        }
    }
    if (o.target.empty() || o.max_len == 0) return usage();
    if (o.max_len > (1u << 24)) o.max_len = 1u << 24;  // the protocol carries sizes below 2^30
    if (!o.sync_dir.empty() && o.worker_id < 0) {
        std::fprintf(stderr, "--sync-dir needs --worker-id\n");
        return 2;
    }
    Fuzzer f(o);
    g_fuzzer = &f;
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    int rc = f.run();
    g_fuzzer = nullptr;
    return rc;
}

int cmd_tmin(int argc, char** argv) {
    std::string target, in, out;
    size_t max_execs = 2000;
    for (int i = 0; i + 1 < argc; i += 2) {
        std::string a = argv[i];
        if (a == "-t") target = argv[i + 1];
        else if (a == "-i") in = argv[i + 1];
        else if (a == "-o") out = argv[i + 1];
        else if (a == "--max-execs") max_execs = (size_t)std::strtoull(argv[i + 1], nullptr, 10);
        else return usage();
    }
    if (target.empty() || in.empty() || out.empty()) return usage();
    Bytes data;
    if (!read_file(in, data)) {
        std::fprintf(stderr, "cannot read %s\n", in.c_str());
        return 2;
    }
    Executor ex({target}, 2000);
    std::string err;
    if (!ex.start(&err)) {
        std::fprintf(stderr, "%s\n", err.c_str());
        return 2;
    }
    ExecResult r = ex.run(data);
    if (r.status != ExecResult::Crash) {
        std::fprintf(stderr, "%s does not crash the target\n", in.c_str());
        return 1;
    }
    std::string key = parse_crash(r.report, r.exit_code).key();
    std::fprintf(stderr, "signature: %s\n", key.c_str());
    MinimizeStats st;
    Bytes m = minimize(
        data,
        [&](const Bytes& c) {
            ExecResult rr = ex.run(c);
            return rr.status == ExecResult::Crash && parse_crash(rr.report, rr.exit_code).key() == key;
        },
        max_execs, &st);
    write_file(out, m);
    std::fprintf(stderr, "minimized %zu -> %zu bytes in %zu executions\n", st.from, st.to, st.execs);
    return 0;
}

int cmd_triage(int argc, char** argv) {
    if (argc < 3 || std::strcmp(argv[0], "-t") != 0) return usage();
    Executor ex({argv[1]}, 5000);
    std::string err;
    if (!ex.start(&err)) {
        std::fprintf(stderr, "%s\n", err.c_str());
        return 2;
    }
    for (int i = 2; i < argc; ++i) {
        Bytes d;
        if (!read_file(argv[i], d)) continue;
        ExecResult r = ex.run(d);
        std::printf("{\"file\": \"%s\", \"status\": \"%s\"", json_escape(argv[i]).c_str(),
                    r.status == ExecResult::Crash ? "crash" : r.status == ExecResult::Timeout ? "timeout" : r.status == ExecResult::Ok ? "ok" : "error");
        if (r.status == ExecResult::Crash) {
            CrashSignature s = parse_crash(r.report, r.exit_code);
            std::printf(", \"kind\": \"%s\", \"key\": \"%s\", \"frames\": [", json_escape(s.kind).c_str(), json_escape(s.key()).c_str());
            for (size_t j = 0; j < s.frames.size(); ++j) std::printf("%s\"%s\"", j ? ", " : "", json_escape(s.frames[j]).c_str());
            std::printf("]");
        }
        std::printf("}\n");
        std::fflush(stdout);
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);  // a crashed child closes its pipe; we see the error instead
#endif
    if (argc < 2) return usage();
    std::string cmd = argv[1];
    if (cmd == "fuzz") return cmd_fuzz(argc - 2, argv + 2);
    if (cmd == "tmin") return cmd_tmin(argc - 2, argv + 2);
    if (cmd == "triage") return cmd_triage(argc - 2, argv + 2);
    return usage();
}
