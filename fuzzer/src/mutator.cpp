#include "mutator.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <unordered_set>

namespace sleuth {

constexpr size_t AUTO_DICT = 256;

std::vector<Bytes> parse_dictionary(const std::string& text) {
    std::vector<Bytes> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        size_t q = line.find('"');
        if (q == std::string::npos) continue;
        size_t hash = line.find('#');
        if (hash != std::string::npos && hash < q) continue;
        size_t end = line.rfind('"');
        if (end <= q) continue;
        Bytes tok;
        for (size_t i = q + 1; i < end; ++i) {
            char c = line[i];
            if (c == '\\' && i + 1 < end) {
                char n = line[i + 1];
                auto hex = [](char h) { return h >= '0' && h <= '9' ? h - '0' : h >= 'a' && h <= 'f' ? h - 'a' + 10 : h >= 'A' && h <= 'F' ? h - 'A' + 10 : -1; };
                if (n == 'x' && i + 3 < end && hex(line[i + 2]) >= 0 && hex(line[i + 3]) >= 0) {
                    tok.push_back((uint8_t)(hex(line[i + 2]) * 16 + hex(line[i + 3])));
                    i += 3;
                } else {
                    tok.push_back((uint8_t)n);
                    i += 1;
                }
            } else {
                tok.push_back((uint8_t)c);
            }
        }
        if (!tok.empty()) out.push_back(tok);
    }
    return out;
}

static Bytes int_bytes(uint64_t v, int size, bool big_endian) {
    Bytes b((size_t)size);
    for (int i = 0; i < size; ++i) b[(size_t)(big_endian ? size - 1 - i : i)] = (uint8_t)(v >> (8 * i));
    return b;
}

void Mutator::learn(const std::vector<CmpPair>& cmps, const std::vector<StrPair>& strs) {
    auto add = [&](Bytes t) {
        if (t.size() < 2 || t.size() > 32) return;
        if (std::find(auto_.begin(), auto_.end(), t) != auto_.end()) return;
        if (auto_.size() < AUTO_DICT) {
            auto_.push_back(std::move(t));
        } else {
            auto_[auto_next_] = std::move(t);
            auto_next_ = (auto_next_ + 1) % AUTO_DICT;
        }
    };
    // Only a few per run: the pool is for the operands that keep coming back.
    size_t taken = 0;
    for (auto& c : cmps) {
        if (taken >= 4) break;
        if (c.size < 2) continue;
        uint64_t v = c.b;  // usually the constant side of `x == CONST`
        if (v == 0 || v == ~0ull) continue;
        add(int_bytes(v, c.size, rng_.chance(50)));
        ++taken;
    }
    for (auto& s : strs) {
        if (taken >= 8) break;
        add(s.b);
        add(s.a);
        ++taken;
    }
}

void Mutator::put_token(Bytes& d, const Bytes& tok, bool insert) {
    if (insert || d.size() < tok.size()) {
        if (d.size() + tok.size() > max_len_) return;
        size_t at = (size_t)rng_.below(d.size() + 1);
        d.insert(d.begin() + (std::ptrdiff_t)at, tok.begin(), tok.end());
    } else {
        size_t at = (size_t)rng_.below(d.size() - tok.size() + 1);
        std::copy(tok.begin(), tok.end(), d.begin() + (std::ptrdiff_t)at);
    }
}

void Mutator::one_edit(Bytes& d, const Bytes* other) {
    static const int8_t i8[] = {-128, -1, 0, 1, 16, 32, 64, 100, 127};
    static const int16_t i16[] = {-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767};
    static const int32_t i32[] = {INT32_MIN, -100663046, -32769, 32768, 65535, 65536, 100663045, INT32_MAX};
    size_t n = d.size();
    switch (rng_.below(16)) {
        case 0:  // flip a bit
            if (n) d[rng_.below(n)] ^= (uint8_t)(1u << rng_.below(8));
            break;
        case 1:  // interesting byte
            if (n) d[rng_.below(n)] = (uint8_t)i8[rng_.below(sizeof i8)];
            break;
        case 2: {  // interesting 16-bit value, either byte order
            if (n < 2) break;
            uint16_t v = (uint16_t)i16[rng_.below(sizeof i16 / 2)];
            Bytes b = int_bytes(v, 2, rng_.chance(50));
            std::copy(b.begin(), b.end(), d.begin() + (std::ptrdiff_t)rng_.below(n - 1));
            break;
        }
        case 3: {  // interesting 32-bit value
            if (n < 4) break;
            uint32_t v = (uint32_t)i32[rng_.below(sizeof i32 / 4)];
            Bytes b = int_bytes(v, 4, rng_.chance(50));
            std::copy(b.begin(), b.end(), d.begin() + (std::ptrdiff_t)rng_.below(n - 3));
            break;
        }
        case 4:  // add / subtract a small number to a byte
            if (n) d[rng_.below(n)] += (uint8_t)(rng_.chance(50) ? 1 + rng_.below(35) : 256 - 1 - rng_.below(35));
            break;
        case 5: {  // ... to a 16- or 32-bit word, either byte order
            int size = rng_.chance(50) ? 2 : 4;
            if (n < (size_t)size) break;
            size_t at = (size_t)rng_.below(n - (size_t)size + 1);
            bool be = rng_.chance(50);
            uint64_t v = 0;
            for (int i = 0; i < size; ++i) v |= (uint64_t)d[at + (size_t)(be ? size - 1 - i : i)] << (8 * i);
            v += rng_.chance(50) ? 1 + rng_.below(35) : (uint64_t)-(int64_t)(1 + rng_.below(35));
            Bytes b = int_bytes(v, size, be);
            std::copy(b.begin(), b.end(), d.begin() + (std::ptrdiff_t)at);
            break;
        }
        case 6:  // random byte
            if (n) d[rng_.below(n)] = (uint8_t)rng_.next();
            break;
        case 7:
        case 8: {  // delete a block
            if (n < 2) break;
            size_t len = 1 + (size_t)rng_.below(std::min<size_t>(n - 1, rng_.chance(80) ? 8 : 128));
            size_t at = (size_t)rng_.below(n - len + 1);
            d.erase(d.begin() + (std::ptrdiff_t)at, d.begin() + (std::ptrdiff_t)(at + len));
            break;
        }
        case 9: {  // duplicate a block of the input (or insert a run of one byte)
            if (n == 0 || n >= max_len_) break;
            size_t len = 1 + (size_t)rng_.below(std::min<size_t>({n, (size_t)(rng_.chance(80) ? 8 : 128), max_len_ - n}));
            size_t from = (size_t)rng_.below(n - len + 1), to = (size_t)rng_.below(n + 1);
            Bytes block = rng_.chance(75) ? Bytes(d.begin() + (std::ptrdiff_t)from, d.begin() + (std::ptrdiff_t)(from + len)) : Bytes(len, (uint8_t)rng_.next());
            d.insert(d.begin() + (std::ptrdiff_t)to, block.begin(), block.end());
            break;
        }
        case 10: {  // overwrite with a block from elsewhere in the input
            if (n < 2) break;
            size_t len = 1 + (size_t)rng_.below(std::min<size_t>(n - 1, 32));
            size_t from = (size_t)rng_.below(n - len + 1), to = (size_t)rng_.below(n - len + 1);
            std::memmove(d.data() + to, d.data() + from, len);
            break;
        }
        case 11:
        case 12:  // a dictionary token, overwrite or insert
            if (!dict_.empty()) put_token(d, dict_[rng_.below(dict_.size())], rng_.chance(50));
            else if (!auto_.empty()) put_token(d, auto_[rng_.below(auto_.size())], rng_.chance(50));
            break;
        case 13:
        case 14:  // a learned comparison operand
            if (!auto_.empty()) put_token(d, auto_[rng_.below(auto_.size())], rng_.chance(30));
            else if (n) d[rng_.below(n)] = (uint8_t)rng_.next();
            break;
        case 15: {  // a block from another corpus entry
            if (!other || other->empty()) break;
            size_t len = 1 + (size_t)rng_.below(std::min<size_t>(other->size(), 64));
            size_t from = (size_t)rng_.below(other->size() - len + 1);
            Bytes block(other->begin() + (std::ptrdiff_t)from, other->begin() + (std::ptrdiff_t)(from + len));
            put_token(d, block, rng_.chance(50));
            break;
        }
    }
}

void Mutator::havoc(Bytes& d, const Bytes* other) {
    if (d.empty()) d.push_back((uint8_t)rng_.next());
    int stack = 1 << (1 + rng_.below(4));  // 2, 4, 8 or 16 edits
    for (int i = 0; i < stack; ++i) one_edit(d, other);
    if (d.size() > max_len_) d.resize(max_len_);
}

Bytes Mutator::splice(const Bytes& a, const Bytes& b) {
    if (a.size() < 2 || b.size() < 2) return a;
    size_t cut_a = 1 + (size_t)rng_.below(a.size() - 1), cut_b = (size_t)rng_.below(b.size());
    Bytes out(a.begin(), a.begin() + (std::ptrdiff_t)cut_a);
    out.insert(out.end(), b.begin() + (std::ptrdiff_t)cut_b, b.end());
    if (out.size() > max_len_) out.resize(max_len_);
    return out;
}

std::vector<Bytes> Mutator::repair(const Bytes& d, const std::vector<CmpPair>& cmps, size_t limit) {
    std::vector<Bytes> out;
    size_t looked = 0;
    for (auto& c : cmps) {
        if (out.size() >= limit || looked >= 32) break;
        if (c.is_const || c.size < 4) continue;
        ++looked;
        for (int be = 0; be < 2 && out.size() < limit; ++be) {
            for (int dir = 0; dir < 2 && out.size() < limit; ++dir) {
                Bytes from = int_bytes(dir ? c.b : c.a, c.size, be), to = int_bytes(dir ? c.a : c.b, c.size, be);
                // Only a value that occurs exactly once: otherwise we cannot tell which to fix.
                size_t at = SIZE_MAX;
                int found = 0;
                for (size_t i = 0; i + from.size() <= d.size() && found < 2; ++i)
                    if (std::memcmp(d.data() + i, from.data(), from.size()) == 0) {
                        at = i;
                        ++found;
                    }
                if (found != 1) continue;
                Bytes cand(d);
                std::copy(to.begin(), to.end(), cand.begin() + (std::ptrdiff_t)at);
                out.push_back(std::move(cand));
            }
        }
    }
    return out;
}

std::vector<Bytes> Mutator::input_to_state(const Bytes& d, const std::vector<CmpPair>& cmps, const std::vector<StrPair>& strs, size_t limit) {
    std::vector<Bytes> out;
    std::unordered_set<uint64_t> seen{hash64(d)};
    auto emit = [&](Bytes&& c) {
        if (out.size() >= limit || c.size() > max_len_) return;
        if (seen.insert(hash64(c)).second) out.push_back(std::move(c));
    };
    // Replaces every occurrence of `from` (at most 8) with `to`.
    auto replace_all = [&](const Bytes& from, const Bytes& to) {
        if (from.empty() || from.size() > d.size()) return;
        int found = 0;
        for (size_t i = 0; i + from.size() <= d.size() && found < 8; ++i) {
            if (std::memcmp(d.data() + i, from.data(), from.size()) != 0) continue;
            ++found;
            Bytes c(d);
            if (to.size() == from.size()) {
                std::copy(to.begin(), to.end(), c.begin() + (std::ptrdiff_t)i);
            } else {
                c.erase(c.begin() + (std::ptrdiff_t)i, c.begin() + (std::ptrdiff_t)(i + from.size()));
                c.insert(c.begin() + (std::ptrdiff_t)i, to.begin(), to.end());
            }
            emit(std::move(c));
        }
    };
    for (auto& c : cmps) {
        if (out.size() >= limit) break;
        for (int dir = 0; dir < 2; ++dir) {
            uint64_t from = dir ? c.b : c.a, to = dir ? c.a : c.b;
            for (int be = 0; be < 2; ++be) {
                if (c.size == 1 && be) continue;
                Bytes f = int_bytes(from, c.size, be);
                for (int64_t delta : {0, 1, -1}) replace_all(f, int_bytes(to + (uint64_t)delta, c.size, be));
            }
        }
    }
    for (auto& s : strs) {
        if (out.size() >= limit) break;
        // The input usually holds a prefix of the side it supplied; try the longest that occurs.
        for (int dir = 0; dir < 2; ++dir) {
            const Bytes& from = dir ? s.b : s.a;
            const Bytes& to = dir ? s.a : s.b;
            for (size_t len = from.size(); len >= 2; --len) {
                Bytes f(from.begin(), from.begin() + (std::ptrdiff_t)len);
                size_t before = out.size();
                replace_all(f, Bytes(to.begin(), to.begin() + (std::ptrdiff_t)std::min(len, to.size())));
                replace_all(f, to);
                if (out.size() != before) break;
            }
        }
    }
    return out;
}

}  // namespace sleuth
