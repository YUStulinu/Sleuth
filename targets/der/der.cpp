// A DER (ASN.1 Distinguished Encoding Rules) walker with planted bugs (see targets/BUGS.md). It
// parses tag-length-value elements recursively and decodes the primitive types an X.509
// certificate uses: INTEGER, BOOLEAN, NULL, OBJECT IDENTIFIER, BIT STRING, OCTET STRING, the
// string types and UTCTime / GeneralizedTime, descending into SEQUENCE, SET and context tags.
//
// Planted bugs: 10 (long-form length read into a signed int), 11 (OID with more than 16 arcs),
// 12 (BIT STRING unused-bits count above 7), 13 (UTCTime longer than 13 characters).
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "sleuth_canary.h"

namespace {

struct Walker {
    const uint8_t* base;
    size_t total;
    int depth = 0;
    uint64_t checksum = 0;

    // Reads a tag and a length at pos; returns false on malformed input.
    bool header(size_t& pos, size_t end, uint8_t& tag, size_t& len) {
        if (pos + 2 > end) return false;
        tag = base[pos++];
        if ((tag & 0x1f) == 0x1f) return false;  // high tag numbers are not used in DER certs
        uint8_t first = base[pos++];
        if (first < 0x80) {
            len = first;
        } else {
            int k = first & 0x7f;
            if (k == 0 || k > 4 || pos + (size_t)k > end) return false;
            // Bug 10: the length is accumulated in a signed int, so 0x80000000 and above turn
            // negative and the bounds check below passes; the caller then reads before base.
            int32_t v = 0;
            for (int j = 0; j < k; ++j) v = (int32_t)((uint32_t)v << 8 | base[pos++]);
            if (v < 0x80 && k == 1) return false;  // DER requires the short form here
            if (v > (int64_t)(end - pos)) return false;
            if (v <= 64) {
                // Short contents are hashed from a scratch copy; a "negative" length passes
                // the check above and reaches memcpy as an enormous size.
                SLEUTH_BUG(10, v < 0);
                uint8_t* scratch = (uint8_t*)std::malloc(64);
                std::memcpy(scratch, base + pos, (size_t)(int64_t)v);
                for (int32_t j = 0; j < v; ++j) checksum += scratch[j];
                std::free(scratch);
            }
            len = (size_t)v;
        }
        if (len > end - pos) return false;
        return true;
    }

    bool oid(const uint8_t* p, size_t n) {
        if (n == 0 || (p[n - 1] & 0x80)) return false;
        uint32_t* arcs = (uint32_t*)std::malloc(16 * sizeof(uint32_t));
        size_t count = 0;
        uint32_t v = 0;
        bool ok = true;
        for (size_t j = 0; j < n; ++j) {
            if (v > (1u << 25)) {
                ok = false;
                break;
            }
            v = v << 7 | (p[j] & 0x7f);
            if (!(p[j] & 0x80)) {
                if (count == 0) {
                    arcs[count++] = v < 80 ? v / 40 : 2;
                    // Bug 11: the arc count is not limited to the 16 slots.
                    SLEUTH_BUG(11, count >= 16);
                    arcs[count++] = v < 80 ? v % 40 : v - 80;
                } else {
                    SLEUTH_BUG(11, count >= 16);
                    arcs[count++] = v;
                }
                v = 0;
            }
        }
        for (size_t j = 0; ok && j < count; ++j) checksum += arcs[j];
        std::free(arcs);
        return ok;
    }

    bool bit_string(const uint8_t* p, size_t n) {
        if (n == 0) return false;
        uint8_t unused = p[0] & 0x1f;  // the top three bits are reserved and ignored
        if (p[0] & 0xe0) return false;
        if (n == 1) return unused == 0;
        // Bug 12: unused bits above 7 are not rejected; the mask table is indexed with them.
        static const uint8_t mask_table[8] = {0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80};
        uint8_t* masks = (uint8_t*)std::malloc(8);
        std::memcpy(masks, mask_table, 8);
        SLEUTH_BUG(12, unused > 7);
        uint8_t last = p[n - 1] & masks[unused];
        std::free(masks);
        checksum += last;
        return true;
    }

    bool time(const uint8_t* p, size_t n, bool utc) {
        // YYMMDDHHMMSSZ (13) or YYYYMMDDHHMMSSZ (15).
        if (n < 11 || p[n - 1] != 'Z') return false;
        for (size_t j = 0; j + 1 < n; ++j)
            if (p[j] < '0' || p[j] > '9') return false;
        if (utc) {
            // Bug 13: the copy assumes the 13-character form.
            char* buf = (char*)std::malloc(13);
            SLEUTH_BUG(13, n > 13);
            std::memcpy(buf, p, n);
            int year = (buf[0] - '0') * 10 + (buf[1] - '0');
            int month = (buf[2] - '0') * 10 + (buf[3] - '0');
            std::free(buf);
            if (month < 1 || month > 12) return false;
            checksum += (uint64_t)(year < 50 ? 2000 + year : 1900 + year);
        } else {
            if (n != 15) return false;
            int month = (p[4] - '0') * 10 + (p[5] - '0');
            if (month < 1 || month > 12) return false;
        }
        return true;
    }

    bool walk(size_t pos, size_t end) {
        if (++depth > 32) return false;
        while (pos < end) {
            uint8_t tag;
            size_t len;
            if (!header(pos, end, tag, len)) return false;
            const uint8_t* body = base + pos;
            bool constructed = tag & 0x20;
            if (constructed) {
                // SEQUENCE (0x30), SET (0x31), context-specific [n] (0xa0..).
                if (tag != 0x30 && tag != 0x31 && (tag & 0xc0) != 0x80) return false;
                if (!walk(pos, pos + len)) return false;
            } else if ((tag & 0xc0) == 0x80) {
                checksum += len;  // implicit primitive context tag
            } else {
                switch (tag) {
                    case 0x01:  // BOOLEAN
                        if (len != 1 || (body[0] != 0 && body[0] != 0xff)) return false;
                        break;
                    case 0x02:  // INTEGER
                        if (len == 0) return false;
                        if (len > 1 && ((body[0] == 0 && !(body[1] & 0x80)) || (body[0] == 0xff && (body[1] & 0x80)))) return false;
                        checksum += body[len - 1];
                        break;
                    case 0x03:
                        if (!bit_string(body, len)) return false;
                        break;
                    case 0x04:  // OCTET STRING
                        checksum += len;
                        break;
                    case 0x05:  // NULL
                        if (len != 0) return false;
                        break;
                    case 0x06:
                        if (!oid(body, len)) return false;
                        break;
                    case 0x0c:  // UTF8String
                    case 0x13:  // PrintableString
                    case 0x16:  // IA5String
                        for (size_t j = 0; j < len; ++j)
                            if (tag != 0x0c && body[j] >= 0x80) return false;
                        break;
                    case 0x17:
                        if (!time(body, len, true)) return false;
                        break;
                    case 0x18:
                        if (!time(body, len, false)) return false;
                        break;
                    default:
                        return false;
                }
            }
            pos += len;
        }
        --depth;
        return true;
    }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 1 << 16) return 0;
    Walker w{data, size};
    bool ok = w.walk(0, size);
    return ok ? (int)(w.checksum & 1) : 0;
}
