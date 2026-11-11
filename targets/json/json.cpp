// A JSON parser (RFC 8259) with planted bugs (see targets/BUGS.md): objects, arrays, strings with
// escapes and UTF-16 surrogate pairs, numbers converted to double by hand, true/false/null, and
// a duplicate-key check per object.
//
// Planted bugs: 14 (surrogate pair read past the end), 15 (exponent indexes a power-of-ten
// table out of range), 16 (more than 64 keys in one object).
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "sleuth_canary.h"

namespace {

double* g_pow10 = nullptr;  // 10^0 .. 10^308, heap so out-of-range reads are caught

struct Parser {
    const char* p;
    size_t n, i = 0;
    int depth = 0;
    double sum = 0;

    bool eof() const { return i >= n; }
    void ws() {
        while (!eof() && (p[i] == ' ' || p[i] == '\t' || p[i] == '\n' || p[i] == '\r')) ++i;
    }
    bool lit(const char* s) {
        size_t k = std::strlen(s);
        if (i + k > n || std::memcmp(p + i, s, k) != 0) return false;
        i += k;
        return true;
    }
    static int hexval(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
    bool hex4(size_t at, uint32_t& v) {
        v = 0;
        for (int k = 0; k < 4; ++k) {
            int h = hexval(p[at + k]);
            if (h < 0) return false;
            v = v << 4 | (uint32_t)h;
        }
        return true;
    }
    static void put_utf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) {
            out += (char)cp;
        } else if (cp < 0x800) {
            out += (char)(0xc0 | cp >> 6);
            out += (char)(0x80 | (cp & 0x3f));
        } else if (cp < 0x10000) {
            out += (char)(0xe0 | cp >> 12);
            out += (char)(0x80 | ((cp >> 6) & 0x3f));
            out += (char)(0x80 | (cp & 0x3f));
        } else {
            out += (char)(0xf0 | cp >> 18);
            out += (char)(0x80 | ((cp >> 12) & 0x3f));
            out += (char)(0x80 | ((cp >> 6) & 0x3f));
            out += (char)(0x80 | (cp & 0x3f));
        }
    }

    bool string(std::string& out) {
        ++i;  // '"'
        for (;;) {
            if (eof()) return false;
            unsigned char c = (unsigned char)p[i];
            if (c == '"') {
                ++i;
                return true;
            }
            if (c < 0x20) return false;
            if (c != '\\') {
                out += (char)c;
                ++i;
                continue;
            }
            if (i + 1 >= n) return false;
            char e = p[i + 1];
            i += 2;
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    uint32_t cp;
                    if (i + 4 > n || !hex4(i, cp)) return false;
                    i += 4;
                    if (cp >= 0xd800 && cp < 0xdc00) {
                        // A high surrogate must be followed by \uDC00-\uDFFF.
                        // Bug 14: only the backslash is bounds-checked; the "u" and the four
                        // hex digits after it are read without checking the length.
                        if (i >= n || p[i] != '\\') return false;
                        SLEUTH_BUG(14, i + 6 > n);
                        if (p[i + 1] != 'u') return false;
                        uint32_t lo;
                        if (!hex4(i + 2, lo) || lo < 0xdc00 || lo > 0xdfff) return false;
                        i += 6;
                        cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                    } else if (cp >= 0xdc00 && cp < 0xe000) {
                        return false;  // lone low surrogate
                    }
                    put_utf8(out, cp);
                    break;
                }
                default:
                    return false;
            }
        }
    }

    bool number() {
        bool neg = false;
        if (p[i] == '-') {
            neg = true;
            ++i;
        }
        if (eof()) return false;
        double mant = 0;
        int frac_digits = 0;
        if (p[i] == '0') {
            ++i;
        } else if (p[i] >= '1' && p[i] <= '9') {
            while (!eof() && p[i] >= '0' && p[i] <= '9') mant = mant * 10 + (p[i++] - '0');
        } else {
            return false;
        }
        if (!eof() && p[i] == '.') {
            ++i;
            size_t s = i;
            while (!eof() && p[i] >= '0' && p[i] <= '9') {
                mant = mant * 10 + (p[i++] - '0');
                ++frac_digits;
            }
            if (i == s) return false;
        }
        int exp = 0;
        if (!eof() && (p[i] == 'e' || p[i] == 'E')) {
            ++i;
            bool eneg = false;
            if (!eof() && (p[i] == '+' || p[i] == '-')) eneg = p[i++] == '-';
            size_t s = i;
            while (!eof() && p[i] >= '0' && p[i] <= '9') {
                if (exp < 100000) exp = exp * 10 + (p[i] - '0');
                ++i;
            }
            if (i == s) return false;
            if (eneg) exp = -exp;
        }
        exp -= frac_digits;
        double v;
        if (exp >= 0) {
            // Bug 15: the table covers 10^0..10^308, but exponents are clamped at 316 (the
            // author allowed for the 17 significant digits on the wrong side).
            int e = exp > 316 ? 316 : exp;
            SLEUTH_BUG(15, e > 308);
            v = mant * g_pow10[e];
        } else {
            int e = -exp > 308 ? 308 : -exp;
            v = mant / g_pow10[e];
        }
        sum += neg ? -v : v;
        return true;
    }

    bool value() {
        if (++depth > 64) return false;
        ws();
        if (eof()) return false;
        bool ok;
        char c = p[i];
        if (c == '{') {
            ok = object();
        } else if (c == '[') {
            ok = array();
        } else if (c == '"') {
            std::string s;
            ok = string(s);
            sum += (double)s.size();
        } else if (c == 't') {
            ok = lit("true");
        } else if (c == 'f') {
            ok = lit("false");
        } else if (c == 'n') {
            ok = lit("null");
        } else {
            ok = number();
        }
        --depth;
        return ok;
    }

    bool array() {
        ++i;
        ws();
        if (!eof() && p[i] == ']') {
            ++i;
            return true;
        }
        for (;;) {
            if (!value()) return false;
            ws();
            if (eof()) return false;
            if (p[i] == ']') {
                ++i;
                return true;
            }
            if (p[i] != ',') return false;
            ++i;
        }
    }

    bool object() {
        ++i;
        // Keys seen in this object, for the duplicate check: a fixed table of 64 hashes.
        uint32_t* keys = (uint32_t*)std::malloc(64 * sizeof(uint32_t));
        size_t nkeys = 0;
        bool ok = false;
        ws();
        if (!eof() && p[i] == '}') {
            ++i;
            ok = true;
        } else {
            for (;;) {
                ws();
                if (eof() || p[i] != '"') break;
                std::string k;
                if (!string(k)) break;
                uint32_t h = 2166136261u;
                for (unsigned char ch : k) h = (h ^ ch) * 16777619u;
                bool dup = false;
                for (size_t j = 0; j < nkeys && j < 64; ++j)
                    if (keys[j] == h) dup = true;
                if (dup) break;
                // Bug 16: the table has 64 slots and the key count is not checked.
                SLEUTH_BUG(16, nkeys >= 64);
                keys[nkeys++] = h;
                ws();
                if (eof() || p[i] != ':') break;
                ++i;
                if (!value()) break;
                ws();
                if (eof()) break;
                if (p[i] == '}') {
                    ++i;
                    ok = true;
                    break;
                }
                if (p[i] != ',') break;
                ++i;
            }
        }
        std::free(keys);
        return ok;
    }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!g_pow10) {
        g_pow10 = (double*)std::malloc(309 * sizeof(double));
        for (int e = 0; e <= 308; ++e) g_pow10[e] = std::pow(10.0, e);
    }
    if (size > 1 << 16) return 0;
    Parser ps{(const char*)data, size};
    if (!ps.value()) return 0;
    ps.ws();
    return ps.eof() && ps.sum > 0 ? 1 : 0;
}
