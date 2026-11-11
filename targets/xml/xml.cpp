// A small XML parser with planted bugs (see targets/BUGS.md): the XML declaration, comments,
// CDATA sections, elements with attributes, text with entity and character references, and
// well-formedness checks for nesting.
//
// Planted bugs: 6 (character reference encoded past a 4-byte buffer), 7 (more than 16
// attributes), 8 (closing tag compared past the open tag's name), 9 (unterminated CDATA read
// past the end).
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "sleuth_canary.h"

namespace {

struct Attr {
    uint32_t name_hash;  // written first, by plain code: an overflow is caught by ASan even where
                         // std::string's members live in an uninstrumented library (libstdc++)
    std::string name, value;
};

struct Parser {
    const char* p;
    size_t n, i = 0;
    std::vector<char*> stack;  // open element names (heap copies of exactly their length)
    std::vector<size_t> stack_len;
    size_t text_bytes = 0, elements = 0;

    bool eof() const { return i >= n; }
    bool starts(const char* s) const {
        size_t k = std::strlen(s);
        return i + k <= n && std::memcmp(p + i, s, k) == 0;
    }
    static bool name_char(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ':' || c == '.'; }
    void spaces() {
        while (!eof() && (p[i] == ' ' || p[i] == '\t' || p[i] == '\n' || p[i] == '\r')) ++i;
    }
    bool name(std::string& out) {
        size_t s = i;
        while (!eof() && name_char(p[i])) ++i;
        if (i == s) return false;
        out.assign(p + s, i - s);
        return true;
    }

    // Encodes a code point as UTF-8 into buf (4 bytes) and returns its length.
    static size_t utf8(uint32_t cp, char* buf) {
        if (cp < 0x80) {
            buf[0] = (char)cp;
            return 1;
        }
        if (cp < 0x800) {
            buf[0] = (char)(0xc0 | cp >> 6);
            buf[1] = (char)(0x80 | (cp & 0x3f));
            return 2;
        }
        if (cp < 0x10000) {
            buf[0] = (char)(0xe0 | cp >> 12);
            buf[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
            buf[2] = (char)(0x80 | (cp & 0x3f));
            return 3;
        }
        if (cp < 0x200000) {
            buf[0] = (char)(0xf0 | cp >> 18);
            buf[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
            buf[2] = (char)(0x80 | ((cp >> 6) & 0x3f));
            buf[3] = (char)(0x80 | (cp & 0x3f));
            return 4;
        }
        // The obsolete 5- and 6-byte forms.
        if (cp < 0x4000000) {
            buf[0] = (char)(0xf8 | cp >> 24);
            buf[1] = (char)(0x80 | ((cp >> 18) & 0x3f));
            buf[2] = (char)(0x80 | ((cp >> 12) & 0x3f));
            buf[3] = (char)(0x80 | ((cp >> 6) & 0x3f));
            buf[4] = (char)(0x80 | (cp & 0x3f));
            return 5;
        }
        buf[0] = (char)(0xfc | cp >> 30);
        buf[1] = (char)(0x80 | ((cp >> 24) & 0x3f));
        buf[2] = (char)(0x80 | ((cp >> 18) & 0x3f));
        buf[3] = (char)(0x80 | ((cp >> 12) & 0x3f));
        buf[4] = (char)(0x80 | ((cp >> 6) & 0x3f));
        buf[5] = (char)(0x80 | (cp & 0x3f));
        return 6;
    }

    // Text or attribute value up to `stop`, with references decoded into out.
    bool chars(char stop, std::string& out) {
        while (!eof() && p[i] != stop) {
            if (p[i] == '<' && stop == '"') return false;
            if (p[i] != '&') {
                out += p[i++];
                continue;
            }
            ++i;
            if (!eof() && p[i] == '#') {
                ++i;
                bool hex = !eof() && p[i] == 'x';
                if (hex) ++i;
                uint32_t cp = 0;
                size_t digits = 0;
                while (!eof() && p[i] != ';') {
                    char c = p[i];
                    uint32_t d;
                    if (c >= '0' && c <= '9')
                        d = (uint32_t)(c - '0');
                    else if (hex && c >= 'a' && c <= 'f')
                        d = (uint32_t)(c - 'a' + 10);
                    else if (hex && c >= 'A' && c <= 'F')
                        d = (uint32_t)(c - 'A' + 10);
                    else
                        return false;
                    cp = cp * (hex ? 16 : 10) + d;
                    if (++digits > 8) return false;
                    ++i;
                }
                if (eof() || digits == 0 || cp == 0) return false;
                ++i;
                // Bug 6: code points above U+10FFFF are not rejected, and the encoder writes up
                // to 6 bytes into a 4-byte buffer.
                char* buf = (char*)std::malloc(4);
                SLEUTH_BUG(6, cp >= 0x200000);
                size_t k = utf8(cp, buf);
                out.append(buf, k);
                std::free(buf);
            } else {
                static const char* names[] = {"lt;", "gt;", "amp;", "quot;", "apos;"};
                static const char vals[] = "<>&\"'";
                bool ok = false;
                for (int k = 0; k < 5 && !ok; ++k)
                    if (starts(names[k])) {
                        out += vals[k];
                        i += std::strlen(names[k]);
                        ok = true;
                    }
                if (!ok) return false;
            }
        }
        return true;
    }

    bool element() {
        ++i;  // '<'
        std::string tag;
        if (!name(tag)) return false;
        Attr* attrs = new Attr[16];
        int nattr = 0;
        bool ok = true;
        for (;;) {
            spaces();
            if (eof()) {
                ok = false;
                break;
            }
            if (p[i] == '/' || p[i] == '>') break;
            std::string an, av;
            if (!name(an)) {
                ok = false;
                break;
            }
            spaces();
            if (eof() || p[i] != '=') {
                ok = false;
                break;
            }
            ++i;
            spaces();
            if (eof() || p[i] != '"') {
                ok = false;
                break;
            }
            ++i;
            if (!chars('"', av) || eof()) {
                ok = false;
                break;
            }
            ++i;
            for (int k = 0; k < nattr && k < 16; ++k)
                if (attrs[k].name == an) ok = false;  // duplicate attribute
            if (!ok) break;
            // Bug 7: the attribute array has 16 slots and the count is not checked.
            SLEUTH_BUG(7, nattr >= 16);
            uint32_t h = 2166136261u;
            for (char ch : an) h = (h ^ (uint8_t)ch) * 16777619u;
            attrs[nattr].name_hash = h;
            attrs[nattr].name = an;
            attrs[nattr].value = av;
            ++nattr;
        }
        delete[] attrs;
        if (!ok) return false;
        ++elements;
        if (p[i] == '/') {
            ++i;
            if (eof() || p[i] != '>') return false;
            ++i;
            return true;
        }
        ++i;  // '>'
        if (stack.size() >= 64) return false;
        char* copy = (char*)std::malloc(tag.size());
        std::memcpy(copy, tag.data(), tag.size());
        stack.push_back(copy);
        stack_len.push_back(tag.size());
        return true;
    }

    bool close() {
        i += 2;  // "</"
        std::string tag;
        if (!name(tag)) return false;
        spaces();
        if (eof() || p[i] != '>') return false;
        ++i;
        if (stack.empty()) return false;
        char* open = stack.back();
        size_t open_len = stack_len.back();
        // Bug 8: the names are compared over the closing tag's length, which may be longer
        // than the open tag's heap copy.
        SLEUTH_BUG(8, tag.size() > open_len);
        bool same = std::memcmp(open, tag.data(), tag.size()) == 0 && tag.size() == open_len;
        std::free(open);
        stack.pop_back();
        stack_len.pop_back();
        return same;
    }

    bool parse() {
        if (starts("<?xml")) {
            const char* e = (const char*)std::memchr(p + i, '>', n - i);
            if (!e || e[-1] != '?') return false;
            i = (size_t)(e - p) + 1;
        }
        bool root_done = false;
        while (!eof()) {
            if (starts("<!--")) {
                i += 4;
                bool found = false;
                for (; i + 2 < n; ++i)
                    if (p[i] == '-' && p[i + 1] == '-' && p[i + 2] == '>') {
                        i += 3;
                        found = true;
                        break;
                    }
                if (!found) return false;
            } else if (starts("<![CDATA[")) {
                if (stack.empty()) return false;
                i += 9;
                size_t start = i;
                bool found = false;
                // Bug 9: the terminator search reads two bytes past the end when the section is
                // not closed and the data ends with ']'.
                SLEUTH_BUG(9, n > start && p[n - 1] == ']' && std::string(p + start, n - start).find("]]>") == std::string::npos);
                for (; i < n; ++i)
                    if (p[i] == ']' && p[i + 1] == ']' && p[i + 2] == '>') {
                        text_bytes += i - start;
                        i += 3;
                        found = true;
                        break;
                    }
                if (!found) return false;
            } else if (starts("</")) {
                if (!close()) return false;
                if (stack.empty()) root_done = true;
            } else if (p[i] == '<') {
                if (root_done) return false;  // one root element
                if (!element()) return false;
                if (stack.empty()) root_done = true;
            } else {
                std::string text;
                if (!chars('<', text)) return false;
                if (stack.empty()) {
                    for (char c : text)
                        if (c != ' ' && c != '\n' && c != '\r' && c != '\t') return false;
                }
                text_bytes += text.size();
            }
        }
        return root_done && stack.empty();
    }

    ~Parser() {
        for (char* s : stack) std::free(s);
    }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 1 << 16) return 0;
    Parser ps{(const char*)data, size};
    return ps.parse() ? (int)(ps.elements + ps.text_bytes) % 2 : 0;
}
