// Small shared helpers: random numbers, clocks, files, hashing, JSON string escaping.
#pragma once
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace sleuth {

using Bytes = std::vector<uint8_t>;

// xoshiro256** (Blackman & Vigna): fast, good enough for mutation choices, seedable.
class Rng {
public:
    explicit Rng(uint64_t seed = 1) { reseed(seed); }
    void reseed(uint64_t seed) {
        for (auto& x : s_) {
            seed += 0x9e3779b97f4a7c15ull;  // splitmix64
            uint64_t z = seed;
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
            z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
            x = z ^ (z >> 31);
        }
    }
    uint64_t next() {
        uint64_t r = rotl(s_[1] * 5, 7) * 9, t = s_[1] << 17;
        s_[2] ^= s_[0];
        s_[3] ^= s_[1];
        s_[1] ^= s_[2];
        s_[0] ^= s_[3];
        s_[2] ^= t;
        s_[3] = rotl(s_[3], 45);
        return r;
    }
    // Uniform in [0, n); n > 0.
    uint64_t below(uint64_t n) { return n ? next() % n : 0; }
    bool chance(unsigned percent) { return below(100) < percent; }

private:
    static uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
    uint64_t s_[4];
};

inline uint64_t now_us() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

inline uint64_t epoch_ms() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

// 64-bit FNV-1a.
inline uint64_t hash64(const uint8_t* p, size_t n, uint64_t h = 1469598103934665603ull) {
    for (size_t i = 0; i < n; ++i) h = (h ^ p[i]) * 1099511628211ull;
    return h;
}
inline uint64_t hash64(const Bytes& b) { return hash64(b.data(), b.size()); }
inline uint64_t hash64(const std::string& s) { return hash64((const uint8_t*)s.data(), s.size()); }

bool read_file(const std::string& path, Bytes& out);
bool write_file(const std::string& path, const Bytes& data);
bool write_text(const std::string& path, const std::string& text);
// Writes to path.tmp and renames over path, so readers never see a half-written file.
bool write_atomic(const std::string& path, const std::string& text);
bool make_dirs(const std::string& path);
std::vector<std::string> list_files(const std::string& dir);  // regular files, sorted by name
bool file_exists(const std::string& path);
std::string join(const std::string& a, const std::string& b);
std::string basename(const std::string& path);
std::string json_escape(const std::string& s);
std::string hex64(uint64_t v);

}  // namespace sleuth
