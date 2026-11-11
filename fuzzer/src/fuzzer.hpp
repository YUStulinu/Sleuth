// The coverage-guided fuzzing loop.
//
// Feedback: an input is kept in the corpus when it hits an edge, or an edge hit-count bucket,
// that no earlier input hit (AFL's "virgin bits"). Scheduling: like AFL, a "favored" subset that
// covers every edge seen so far with the fastest and smallest entries is fuzzed first; every
// entry gets an energy (number of mutations per turn) from its speed and from how rare its
// rarest edge is across all executions so far (rare edges are the frontier). An entry's first
// turn starts with the input-to-state stage. Blind mode keeps the same mutations but ignores
// coverage (the corpus stays the seeds): the "no guidance" baseline.
//
// Parallel mode (--sync-dir, --worker-id): each worker also writes its new entries, with their
// edges, to <sync>/worker-<id>/queue/ and imports whatever the supervisor (parallel/, Rust)
// publishes in <sync>/shared/.
#pragma once
#include <atomic>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

#include "crash.hpp"
#include "executor.hpp"
#include "mutator.hpp"
#include "util.hpp"

namespace sleuth {

struct Options {
    std::string target;
    std::vector<std::string> seed_dirs;
    std::string out_dir = "out";
    std::string dict;
    double max_time_s = 0;      // 0 = no limit
    uint64_t max_execs = 0;     // 0 = no limit
    size_t max_len = 4096;
    int timeout_ms = 500;
    bool blind = false;         // no coverage feedback
    bool cmp = true;            // input-to-state stage and learned tokens
    bool minimize_crashes = false;
    uint64_t seed = 0;          // 0 = from the clock
    std::string sync_dir;
    int worker_id = -1;
    int sync_interval_ms = 3000;
    bool quiet = false;
};

struct Entry {
    uint32_t id = 0;
    Bytes data;
    std::vector<uint32_t> edges;  // edge << 3 | bucket
    std::vector<CmpPair> cmps;
    std::vector<StrPair> strs;
    uint64_t us = 0;
    bool favored = false;
    bool i2s_done = false;
    uint32_t fuzzed = 0;          // turns so far
    uint64_t mut_execs = 0, mut_crashes = 0;  // executions of its mutants, and how many crashed
    std::string origin;           // seed, havoc, splice, i2s, sync
    double found_s = 0;
};

struct CrashRecord {
    int id = 0;
    CrashSignature sig;
    std::string file, min_file;
    size_t size = 0, min_size = 0;
    double found_s = 0;
    uint64_t found_execs = 0;
    uint64_t hits = 0;
};

class Fuzzer {
public:
    explicit Fuzzer(Options o);
    // Runs until a limit is reached or stop() is called. Returns a process exit code.
    int run();
    void stop() { stop_ = true; }

    // For tests and stats.
    uint64_t execs() const { return execs_; }
    size_t corpus_size() const { return queue_.size(); }
    size_t edges_covered() const { return covered_; }
    const std::vector<CrashRecord>& crashes() const { return crashes_; }

private:
    double elapsed() const { return (double)(now_us() - start_us_) / 1e6; }
    // Runs one input and handles what happens; returns true if it was added to the corpus.
    bool execute(const Bytes& data, const char* origin, bool add_if_new = true);
    int novelty(const std::vector<uint32_t>& edges, bool commit);
    void add_entry(const Bytes& data, ExecResult&& r, const char* origin);
    // Returns true if the crash was new (a new signature).
    bool handle_crash(const Bytes& data, const ExecResult& r);
    void cull();
    size_t pick();
    uint32_t energy(const Entry& e);
    void fuzz_one(size_t idx);
    void load_seeds();
    void sync();
    void write_stats(bool final);

    Options o_;
    Rng rng_;
    Executor exec_;
    Mutator mut_;
    std::atomic<bool> stop_{false};

    uint64_t start_us_ = 0, start_epoch_ms_ = 0;
    uint64_t execs_ = 0, last_new_us_ = 0, timeouts_ = 0, crash_execs_ = 0;
    uint64_t total_us_ = 0;
    std::vector<uint8_t> virgin_;     // per edge: buckets seen (bit set)
    std::vector<uint64_t> edge_hits_;  // per edge: executions that hit it
    size_t covered_ = 0;
    std::vector<Entry> queue_;
    std::vector<int32_t> top_rated_;  // per edge: best entry covering it
    bool cull_dirty_ = true;
    size_t pending_favored_ = 0, cursor_ = 0;
    std::map<std::string, size_t> crash_index_;  // signature key -> crashes_ index
    std::map<std::string, std::string> raw_to_key_;  // unsymbolized key -> symbolized key
    std::vector<CrashRecord> crashes_;
    std::unordered_set<uint64_t> hang_hashes_;
    std::unordered_set<std::string> imported_;
    uint64_t last_sync_us_ = 0, last_stats_us_ = 0, last_plot_us_ = 0;
    std::string plot_;
    int depth_ = 0;  // > 0 while executing repaired variants
    bool last_crashed_ = false;
    uint64_t blind_saved_ = 0;  // the last execute() crashed with a known signature
};

}  // namespace sleuth
