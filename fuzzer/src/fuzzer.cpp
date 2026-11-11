#include "fuzzer.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <sstream>

#include "minimize.hpp"

namespace sleuth {

constexpr size_t I2S_LIMIT = 512;     // input-to-state candidates per entry
constexpr size_t MAX_HANGS_SAVED = 20;

Fuzzer::Fuzzer(Options o)
    : o_(std::move(o)), rng_(o_.seed ? o_.seed : now_us() ^ (uint64_t)(o_.worker_id + 1) * 0x9e3779b97f4a7c15ull), exec_({o_.target}, o_.timeout_ms), mut_(rng_, o_.max_len) {}

int Fuzzer::novelty(const std::vector<uint32_t>& edges, bool commit) {
    int level = 0;
    for (uint32_t x : edges) {
        uint32_t e = x >> 3;
        uint8_t bit = (uint8_t)(1u << (x & 7));
        if (e >= virgin_.size()) continue;
        uint8_t v = virgin_[e];
        if (v & bit) continue;
        level = std::max(level, v == 0 ? 2 : 1);
        if (commit) {
            if (v == 0) ++covered_;
            virgin_[e] = v | bit;
        }
    }
    return level;
}

void Fuzzer::add_entry(const Bytes& data, ExecResult&& r, const char* origin) {
    Entry e;
    e.id = (uint32_t)queue_.size();
    e.data = data;
    e.edges = std::move(r.edges);
    e.cmps = std::move(r.cmps);
    e.strs = std::move(r.strs);
    e.us = r.us;
    e.origin = origin;
    e.found_s = elapsed();
    if (!o_.cmp) {
        e.cmps.clear();
        e.strs.clear();
    }
    for (uint32_t x : e.edges) {
        uint32_t edge = x >> 3;
        if (edge >= top_rated_.size()) continue;
        int32_t& t = top_rated_[edge];
        if (t < 0 || e.us * e.data.size() < queue_[(size_t)t].us * queue_[(size_t)t].data.size()) t = (int32_t)e.id;
    }
    cull_dirty_ = true;
    last_new_us_ = now_us();
    char name[64];
    std::snprintf(name, sizeof name, "id-%06u-%s", e.id, origin);
    write_file(join(join(o_.out_dir, "queue"), name), e.data);
    if (!o_.sync_dir.empty() && e.origin != "sync") {
        // The edges first, then the input (renamed into place): the supervisor takes an input
        // only once both exist.
        std::string dir = join(join(o_.sync_dir, "worker-" + std::to_string(o_.worker_id)), "queue");
        std::ostringstream es;
        for (uint32_t x : e.edges) es << x << ' ';
        write_text(join(dir, std::string(name) + ".edges"), es.str());
        std::string tmp = join(dir, std::string(name) + ".tmp");
        write_file(tmp, e.data);
        std::rename(tmp.c_str(), join(dir, name).c_str());
    }
    queue_.push_back(std::move(e));
}

bool Fuzzer::handle_crash(const Bytes& data, const ExecResult& r) {
    ++crash_execs_;
    // The children run unsymbolized; the readable signature is worked out once per distinct
    // unsymbolized one, by running the input again with symbolization.
    std::string raw = parse_crash(r.report, r.exit_code).key();
    std::string report = r.report, key;
    CrashSignature sig;
    auto rk = raw_to_key_.find(raw);
    if (rk != raw_to_key_.end()) {
        key = rk->second;
    } else {
        std::string sym = exec_.symbolized_report(data, join(join(o_.out_dir, "crashes"), ".symbolize"));
        if (sym.find("ERROR: AddressSanitizer") != std::string::npos) {
            report = sym;
            sig = parse_crash(sym, r.exit_code);
        } else {
            sig = parse_crash(r.report, r.exit_code);  // did not reproduce alone
        }
        key = sig.key();
        raw_to_key_[raw] = key;
    }
    auto it = crash_index_.find(key);
    if (it != crash_index_.end()) {
        crashes_[it->second].hits++;
        return false;
    }
    CrashRecord c;
    c.id = (int)crashes_.size();
    c.sig = sig;
    c.size = data.size();
    c.found_s = elapsed();
    c.found_execs = execs_;
    c.hits = 1;
    char name[64];
    std::snprintf(name, sizeof name, "crash-%03d-%s", c.id, hex64(hash64(key)).substr(0, 8).c_str());
    c.file = join(join(o_.out_dir, "crashes"), name);
    write_file(c.file, data);
    write_text(c.file + ".txt", key + "\n\n" + r.report);
    if (o_.minimize_crashes) {
        auto still = [&](const Bytes& cand) {
            ExecResult rr = exec_.run(cand, Executor::CmpNone);
            ++execs_;
            if (rr.status != ExecResult::Crash) return false;
            auto m = raw_to_key_.find(parse_crash(rr.report, rr.exit_code).key());
            return m != raw_to_key_.end() && m->second == key;
        };
        Bytes m = minimize(data, still, 300);
        c.min_file = c.file + ".min";
        c.min_size = m.size();
        write_file(c.min_file, m);
    }
    if (!o_.quiet) std::fprintf(stderr, "[%7.1fs] new crash #%d: %s\n", c.found_s, c.id, key.c_str());
    crash_index_[key] = crashes_.size();
    crashes_.push_back(std::move(c));
    return true;
}

bool Fuzzer::execute(const Bytes& data, const char* origin, bool add_if_new) {
    // Only the comparisons checksum repair needs; the full set is fetched below for the few
    // inputs that are kept.
    ExecResult r = exec_.run(data, o_.cmp && !o_.blind ? Executor::CmpLight : Executor::CmpNone);
    ++execs_;
    total_us_ += r.us;
    last_crashed_ = false;
    switch (r.status) {
        case ExecResult::Crash:
            last_crashed_ = !handle_crash(data, r);
            return false;
        case ExecResult::Timeout: {
            ++timeouts_;
            if (hang_hashes_.size() < MAX_HANGS_SAVED && hang_hashes_.insert(hash64(data)).second)
                write_file(join(join(o_.out_dir, "hangs"), "hang-" + hex64(hash64(data)).substr(0, 8)), data);
            return false;
        }
        case ExecResult::Error:
            return false;
        case ExecResult::Ok:
            break;
    }
    for (uint32_t x : r.edges)
        if ((x >> 3) < edge_hits_.size()) ++edge_hits_[x >> 3];
    // Blind mode: coverage only counted (for the statistics), never used.
    int level = novelty(r.edges, true);
    if (level == 0 && o_.cmp && !o_.blind && add_if_new && depth_ == 0) {
        // Nothing new: perhaps a checksum or length field no longer matches what the mutation
        // did to the data. Try the repaired variants (they are not repaired again).
        auto fixes = mut_.repair(data, r.cmps, 2);
        ++depth_;
        bool added = false;
        for (auto& f : fixes) added |= execute(f, "repair");
        --depth_;
        return added;
    }
    if (level > 0 && o_.blind) {
        // Not used for fuzzing, only kept so coverage can be measured the same way as for the
        // other fuzzers (by replaying what each one saved).
        char name[64];
        std::snprintf(name, sizeof name, "id-%06llu-blind", (unsigned long long)blind_saved_++);
        write_file(join(join(o_.out_dir, "queue"), name), data);
    }
    if (level == 0 || o_.blind || !add_if_new) return false;
    if (o_.cmp) {
        ExecResult full = exec_.run(data, Executor::CmpFull);
        ++execs_;
        if (full.status == ExecResult::Ok) {
            r.cmps = std::move(full.cmps);
            r.strs = std::move(full.strs);
        }
        mut_.learn(r.cmps, r.strs);
    }
    add_entry(data, std::move(r), origin);
    return true;
}

void Fuzzer::cull() {
    if (!cull_dirty_) return;
    cull_dirty_ = false;
    std::vector<uint8_t> done(virgin_.size(), 0);
    for (auto& e : queue_) e.favored = false;
    pending_favored_ = 0;
    for (size_t edge = 0; edge < top_rated_.size(); ++edge) {
        if (top_rated_[edge] < 0 || done[edge]) continue;
        Entry& e = queue_[(size_t)top_rated_[edge]];
        if (e.favored) continue;
        e.favored = true;
        if (e.fuzzed == 0) ++pending_favored_;
        for (uint32_t x : e.edges)
            if ((x >> 3) < done.size()) done[x >> 3] = 1;
    }
}

size_t Fuzzer::pick() {
    // AFL's skipping rules: favored and fresh entries first.
    for (int tries = 0; tries < 1000; ++tries) {
        size_t i = cursor_++ % queue_.size();
        const Entry& e = queue_[i];
        // Entries whose mutants mostly crash in known ways waste time on restarts.
        if (e.mut_execs >= 64 && rng_.below(1000) < 1000 * e.mut_crashes / e.mut_execs) continue;
        if (pending_favored_ > 0) {
            if ((!e.favored || e.fuzzed > 0) && rng_.chance(99)) continue;
        } else if (!e.favored) {
            if (e.fuzzed > 0 ? rng_.chance(95) : rng_.chance(75)) continue;
        }
        return i;
    }
    return (size_t)rng_.below(queue_.size());
}

uint32_t Fuzzer::energy(const Entry& e) {
    double avg_us = execs_ ? (double)total_us_ / (double)execs_ : 1.0;
    double score = 1.0;
    // Faster than average: more turns; slower: fewer.
    double speed = avg_us / std::max<double>((double)e.us, 1.0);
    score *= std::clamp(speed, 0.25, 3.0);
    // Rarity of the entry's rarest edge, relative to the average edge.
    uint64_t rarest = UINT64_MAX, sum = 0;
    for (uint32_t x : e.edges) {
        uint64_t h = edge_hits_[x >> 3];
        rarest = std::min(rarest, h);
        sum += h;
    }
    if (!e.edges.empty()) {
        double avg = (double)sum / (double)e.edges.size();
        score *= std::clamp(std::sqrt(avg / std::max<double>((double)rarest, 1.0)), 0.5, 8.0);
    }
    if (e.fuzzed == 0) score *= 2;
    if (e.mut_execs >= 32) {
        double ok = 1.0 - (double)e.mut_crashes / (double)e.mut_execs;
        score *= std::max(0.05, ok * ok);
    }
    return (uint32_t)std::clamp(64.0 * score, 16.0, 2048.0);
}

void Fuzzer::fuzz_one(size_t idx) {
    // Copy what we need: the queue may grow (and reallocate) while we fuzz this entry.
    Bytes base = queue_[idx].data;
    if (!queue_[idx].i2s_done && o_.cmp && !o_.blind) {
        queue_[idx].i2s_done = true;
        auto cands = mut_.input_to_state(base, queue_[idx].cmps, queue_[idx].strs, I2S_LIMIT);
        for (auto& c : cands) {
            if (stop_) break;
            execute(c, "i2s");
        }
    }
    uint32_t n = energy(queue_[idx]);
    for (uint32_t k = 0; k < n && !stop_; ++k) {
        const Bytes* other = queue_.size() > 1 ? &queue_[(size_t)rng_.below(queue_.size())].data : nullptr;
        Bytes c;
        const char* origin = "havoc";
        if (other && rng_.chance(15)) {
            c = mut_.splice(base, *other);
            origin = "splice";
        } else {
            c = base;
        }
        Bytes other_copy = other ? *other : Bytes();
        mut_.havoc(c, other ? &other_copy : nullptr);
        execute(c, origin);
        queue_[idx].mut_execs++;
        if (last_crashed_) queue_[idx].mut_crashes++;
        if (o_.max_execs && execs_ >= o_.max_execs) stop_ = true;
        if (o_.max_time_s > 0 && elapsed() >= o_.max_time_s) stop_ = true;
        if ((k & 63) == 0) write_stats(false);
    }
    if (queue_[idx].favored && queue_[idx].fuzzed == 0 && pending_favored_) --pending_favored_;
    queue_[idx].fuzzed++;
}

void Fuzzer::load_seeds() {
    std::vector<std::string> files;
    for (auto& d : o_.seed_dirs)
        for (auto& f : list_files(d)) files.push_back(f);
    for (auto& f : files) {
        Bytes data;
        if (!read_file(f, data)) continue;
        if (data.size() > o_.max_len) data.resize(o_.max_len);
        ExecResult r = exec_.run(data, o_.cmp ? Executor::CmpFull : Executor::CmpNone);
        ++execs_;
        total_us_ += r.us;
        if (r.status == ExecResult::Crash) {
            handle_crash(data, r);
            continue;
        }
        if (r.status != ExecResult::Ok) continue;
        for (uint32_t x : r.edges) ++edge_hits_[x >> 3];
        novelty(r.edges, true);
        // Every seed is kept (even without new coverage), as AFL does.
        if (o_.cmp) mut_.learn(r.cmps, r.strs);
        add_entry(data, std::move(r), "seed");
    }
    if (queue_.empty()) {
        Bytes d{'0'};
        ExecResult r = exec_.run(d, Executor::CmpNone);
        ++execs_;
        if (r.status == ExecResult::Ok) {
            novelty(r.edges, true);
            add_entry(d, std::move(r), "seed");
        }
    }
}

void Fuzzer::sync() {
    std::string shared = join(o_.sync_dir, "shared");
    std::string mine = "-w" + std::to_string(o_.worker_id) + "-";
    for (auto& f : list_files(shared)) {
        std::string name = basename(f);
        if (name.size() > 4 && (name.substr(name.size() - 4) == ".tmp" || name.find(".edges") != std::string::npos)) continue;
        if (!imported_.insert(name).second) continue;
        if (name.find(mine) != std::string::npos) continue;  // our own entry, published back
        Bytes d;
        if (!read_file(f, d)) continue;
        if (d.size() > o_.max_len) d.resize(o_.max_len);
        execute(d, "sync");
        if (stop_) break;
    }
}

void Fuzzer::write_stats(bool final) {
    uint64_t now = now_us();
    if (!final && now - last_stats_us_ < 1'000'000) return;
    last_stats_us_ = now;
    double t = elapsed();
    std::ostringstream s;
    s.precision(6);
    s << "{\"mode\": \"" << (o_.blind ? "blind" : o_.cmp ? "sleuth" : "sleuth-nocmp") << "\", \"worker_id\": " << o_.worker_id
      << ", \"start_ms\": " << start_epoch_ms_ << ", \"elapsed_s\": " << t << ", \"execs\": " << execs_
      << ", \"execs_per_s\": " << (t > 0 ? (double)execs_ / t : 0) << ", \"corpus\": " << queue_.size()
      << ", \"favored\": " << std::count_if(queue_.begin(), queue_.end(), [](const Entry& e) { return e.favored; })
      << ", \"edges_covered\": " << covered_ << ", \"edges_total\": " << exec_.num_edges()
      << ", \"crashes_unique\": " << crashes_.size() << ", \"crash_execs\": " << crash_execs_ << ", \"timeouts\": " << timeouts_
      << ", \"restarts\": " << exec_.restarts() << ", \"learned_tokens\": " << mut_.learned()
      << ", \"last_new_s\": " << (last_new_us_ ? (double)(last_new_us_ - start_us_) / 1e6 : 0) << ", \"done\": " << (final ? "true" : "false") << "}\n";
    write_atomic(join(o_.out_dir, "stats.json"), s.str());

    std::ostringstream c;
    c << "[";
    for (size_t i = 0; i < crashes_.size(); ++i) {
        auto& k = crashes_[i];
        c << (i ? ",\n " : "\n ") << "{\"id\": " << k.id << ", \"kind\": \"" << json_escape(k.sig.kind) << "\", \"frames\": [";
        for (size_t j = 0; j < k.sig.frames.size(); ++j) c << (j ? ", " : "") << "\"" << json_escape(k.sig.frames[j]) << "\"";
        c << "], \"file\": \"" << json_escape(basename(k.file)) << "\", \"size\": " << k.size << ", \"found_s\": " << k.found_s
          << ", \"found_execs\": " << k.found_execs << ", \"hits\": " << k.hits;
        if (!k.min_file.empty()) c << ", \"min_file\": \"" << json_escape(basename(k.min_file)) << "\", \"min_size\": " << k.min_size;
        c << "}";
    }
    c << "\n]\n";
    write_atomic(join(o_.out_dir, "crashes.json"), c.str());

    if (final || now - last_plot_us_ >= 5'000'000) {
        last_plot_us_ = now;
        char line[160];
        std::snprintf(line, sizeof line, "%.1f,%llu,%zu,%zu,%zu\n", t, (unsigned long long)execs_, covered_, queue_.size(), crashes_.size());
        plot_ += line;
        write_atomic(join(o_.out_dir, "plot.csv"), "elapsed_s,execs,edges,corpus,unique_crashes\n" + plot_);
    }
    if (!o_.quiet && !final)
        std::fprintf(stderr, "[%7.1fs] execs %llu (%.0f/s) corpus %zu edges %zu/%u crashes %zu timeouts %llu\n", t, (unsigned long long)execs_,
                     t > 0 ? (double)execs_ / t : 0, queue_.size(), covered_, exec_.num_edges(), crashes_.size(), (unsigned long long)timeouts_);
}

int Fuzzer::run() {
    for (auto sub : {"queue", "crashes", "hangs"}) make_dirs(join(o_.out_dir, sub));
    if (!o_.sync_dir.empty()) {
        make_dirs(join(join(o_.sync_dir, "worker-" + std::to_string(o_.worker_id)), "queue"));
        make_dirs(join(o_.sync_dir, "shared"));
    }
    if (!o_.dict.empty()) {
        Bytes d;
        if (!read_file(o_.dict, d)) {
            std::fprintf(stderr, "cannot read dictionary %s\n", o_.dict.c_str());
            return 2;
        }
        mut_.set_dictionary(parse_dictionary(std::string(d.begin(), d.end())));
    }
    std::string err;
    exec_.set_symbolize(false);
    if (!exec_.start(&err)) {
        std::fprintf(stderr, "%s\n", err.c_str());
        return 2;
    }
    uint32_t n = exec_.num_edges();
    virgin_.assign(n + 1, 0);
    edge_hits_.assign(n + 1, 0);
    top_rated_.assign(n + 1, -1);
    start_us_ = now_us();
    start_epoch_ms_ = epoch_ms();
    load_seeds();
    if (!o_.quiet)
        std::fprintf(stderr, "[%7.1fs] %zu seeds, %zu edges of %u, %zu dictionary tokens, mode %s\n", elapsed(), queue_.size(), covered_, n,
                     mut_.dictionary().size(), o_.blind ? "blind" : "coverage");
    while (!stop_) {
        if (o_.max_time_s > 0 && elapsed() >= o_.max_time_s) break;
        if (o_.max_execs && execs_ >= o_.max_execs) break;
        if (!o_.sync_dir.empty() && now_us() - last_sync_us_ >= (uint64_t)o_.sync_interval_ms * 1000) {
            last_sync_us_ = now_us();
            sync();
        }
        cull();
        fuzz_one(pick());
    }
    write_stats(true);
    if (!o_.quiet)
        std::fprintf(stderr, "done: %.1fs, %llu execs, corpus %zu, edges %zu/%u, unique crashes %zu\n", elapsed(), (unsigned long long)execs_,
                     queue_.size(), covered_, n, crashes_.size());
    return 0;
}

}  // namespace sleuth
