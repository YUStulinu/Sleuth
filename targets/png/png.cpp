// A small PNG decoder with planted bugs (see targets/BUGS.md): signature, chunks with CRC-32,
// IHDR, PLTE, tRNS, tEXt, IDAT through a zlib inflater (stored, fixed and dynamic Huffman blocks,
// Adler-32 check), and the five row filters.
//
// Planted bugs: 1 (PLTE overflow), 2 (tRNS overflow), 3 (tEXt keyword read past the chunk),
// 4 (Paeth filter on the first row reads before the image), 5 (size computation overflow).
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "sleuth_canary.h"

namespace {

uint32_t be32(const uint8_t* p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

uint32_t crc32(const uint8_t* p, size_t n) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xffffffffu;
    for (size_t i = 0; i < n; ++i) c = table[(c ^ p[i]) & 0xff] ^ (c >> 8);
    return c ^ 0xffffffffu;
}

// ------------------------------------------------------------- inflate (RFC 1950/1951)

struct Bits {
    const uint8_t* p;
    size_t n, pos = 0;
    uint32_t buf = 0;
    int cnt = 0;
    bool err = false;
    int bits(int need) {
        while (cnt < need) {
            if (pos >= n) {
                err = true;
                return 0;
            }
            buf |= (uint32_t)p[pos++] << cnt;
            cnt += 8;
        }
        int v = (int)(buf & ((1u << need) - 1));
        buf >>= need;
        cnt -= need;
        return v;
    }
};

struct Huffman {
    uint16_t count[16];
    uint16_t symbol[320];
};

bool build(Huffman& h, const uint8_t* lengths, int n) {
    std::memset(h.count, 0, sizeof h.count);
    for (int i = 0; i < n; ++i) h.count[lengths[i]]++;
    if (h.count[0] == n) return true;  // no codes: fine as long as none is used
    int left = 1;
    for (int len = 1; len < 16; ++len) {
        left <<= 1;
        left -= h.count[len];
        if (left < 0) return false;  // over-subscribed
    }
    uint16_t offs[16];
    offs[1] = 0;
    for (int len = 1; len < 15; ++len) offs[len + 1] = offs[len] + h.count[len];
    for (int i = 0; i < n; ++i)
        if (lengths[i]) h.symbol[offs[lengths[i]]++] = (uint16_t)i;
    return true;
}

int decode(Bits& b, const Huffman& h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len < 16; ++len) {
        code |= b.bits(1);
        if (b.err) return -1;
        int count = h.count[len];
        if (code - count < first) return h.symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

const uint16_t LBASE[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const uint16_t LEXT[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const uint16_t DBASE[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
const uint16_t DEXT[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

bool codes(Bits& b, std::vector<uint8_t>& out, const Huffman& lit, const Huffman& dist, size_t limit) {
    for (;;) {
        int sym = decode(b, lit);
        if (sym < 0) return false;
        if (sym < 256) {
            if (out.size() >= limit) return false;
            out.push_back((uint8_t)sym);
        } else if (sym == 256) {
            return true;
        } else {
            sym -= 257;
            if (sym >= 29) return false;
            int len = LBASE[sym] + b.bits(LEXT[sym]);
            int ds = decode(b, dist);
            if (ds < 0 || ds >= 30) return false;
            size_t d = DBASE[ds] + (size_t)b.bits(DEXT[ds]);
            if (b.err || d > out.size() || out.size() + len > limit) return false;
            for (int i = 0; i < len; ++i) out.push_back(out[out.size() - d]);
        }
    }
}

bool inflate(const uint8_t* p, size_t n, std::vector<uint8_t>& out, size_t limit) {
    if (n < 6) return false;
    // zlib header: CM 8, a valid FCHECK, no preset dictionary.
    if ((p[0] & 0x0f) != 8 || ((p[0] << 8) | p[1]) % 31 != 0 || (p[1] & 0x20)) return false;
    Bits b{p + 2, n - 2 - 4};
    int last;
    do {
        last = b.bits(1);
        int type = b.bits(2);
        if (b.err) return false;
        if (type == 0) {
            b.buf = 0;
            b.cnt = 0;
            if (b.pos + 4 > b.n) return false;
            uint16_t len = (uint16_t)(b.p[b.pos] | b.p[b.pos + 1] << 8);
            uint16_t nlen = (uint16_t)(b.p[b.pos + 2] | b.p[b.pos + 3] << 8);
            b.pos += 4;
            if (len != (uint16_t)~nlen || b.pos + len > b.n || out.size() + len > limit) return false;
            out.insert(out.end(), b.p + b.pos, b.p + b.pos + len);
            b.pos += len;
        } else if (type == 1) {
            static Huffman lit, dist;
            static bool init = false;
            if (!init) {
                uint8_t l[288];
                for (int i = 0; i < 144; ++i) l[i] = 8;
                for (int i = 144; i < 256; ++i) l[i] = 9;
                for (int i = 256; i < 280; ++i) l[i] = 7;
                for (int i = 280; i < 288; ++i) l[i] = 8;
                build(lit, l, 288);
                uint8_t d[30];
                std::memset(d, 5, 30);
                build(dist, d, 30);
                init = true;
            }
            if (!codes(b, out, lit, dist, limit)) return false;
        } else if (type == 2) {
            int nlen = b.bits(5) + 257, ndist = b.bits(5) + 1, ncode = b.bits(4) + 4;
            if (b.err || nlen > 286 || ndist > 30) return false;
            static const uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
            uint8_t lengths[320] = {0};
            for (int i = 0; i < ncode; ++i) lengths[order[i]] = (uint8_t)b.bits(3);
            Huffman lencode;
            if (b.err || !build(lencode, lengths, 19)) return false;
            int idx = 0;
            while (idx < nlen + ndist) {
                int sym = decode(b, lencode);
                if (sym < 0) return false;
                if (sym < 16) {
                    lengths[idx++] = (uint8_t)sym;
                } else {
                    int rep, val = 0;
                    if (sym == 16) {
                        if (idx == 0) return false;
                        val = lengths[idx - 1];
                        rep = 3 + b.bits(2);
                    } else if (sym == 17) {
                        rep = 3 + b.bits(3);
                    } else {
                        rep = 11 + b.bits(7);
                    }
                    if (b.err || idx + rep > nlen + ndist) return false;
                    while (rep--) lengths[idx++] = (uint8_t)val;
                }
            }
            Huffman lit, dist;
            if (!build(lit, lengths, nlen) || !build(dist, lengths + nlen, ndist)) return false;
            if (!codes(b, out, lit, dist, limit)) return false;
        } else {
            return false;
        }
    } while (!last);
    // Adler-32 of the output, stored big-endian after the deflate stream.
    uint32_t a = 1, s = 0;
    for (uint8_t c : out) {
        a = (a + c) % 65521;
        s = (s + a) % 65521;
    }
    return ((s << 16) | a) == be32(p + n - 4);
}

// ------------------------------------------------------------- PNG

struct Image {
    uint32_t width = 0, height = 0;
    uint8_t depth = 0, color = 0;
    // Separate heap buffers of exactly their size, so an overflow of one is caught at once
    // instead of spilling silently into a neighbouring field.
    std::vector<uint8_t> palette = std::vector<uint8_t>(256 * 3);
    int palette_entries = 0;
    std::vector<uint8_t> trns = std::vector<uint8_t>(256);
    std::vector<uint8_t> idat;
    bool have_ihdr = false;
};

int channels(uint8_t color) {
    switch (color) {
        case 0: return 1;
        case 2: return 3;
        case 3: return 1;
        case 4: return 2;
        case 6: return 4;
    }
    return 0;
}

uint8_t paeth(int a, int b, int c) {
    int p = a + b - c, pa = std::abs(p - a), pb = std::abs(p - b), pc = std::abs(p - c);
    return (uint8_t)(pa <= pb && pa <= pc ? a : pb <= pc ? b : c);
}

int decode_image(Image& img) {
    int bpp_bits = channels(img.color) * img.depth;
    uint32_t rowbytes = (uint32_t)(((uint64_t)img.width * bpp_bits + 7) / 8);
    // Bug 5: the image size is computed in 32 bits; a large width x height wraps around and the
    // buffer is too small for the rows written into it below.
    uint64_t real = (uint64_t)rowbytes * img.height;
    uint32_t size = rowbytes * img.height;
    SLEUTH_BUG(5, real != size);
    if (size == 0 || size > (16u << 20)) return 0;
    std::vector<uint8_t> raw;
    if (!inflate(img.idat.data(), img.idat.size(), raw, (size_t)(rowbytes + 1) * 4096)) return 0;
    uint8_t* pixels = (uint8_t*)std::malloc(size);
    int bpp = bpp_bits < 8 ? 1 : bpp_bits / 8;
    size_t pos = 0;
    int sum = 0;
    for (uint32_t y = 0; y < img.height && pos + 1 + rowbytes <= raw.size(); ++y) {
        uint8_t filter = raw[pos++];
        uint8_t* row = pixels + (size_t)y * rowbytes;
        // Bug 4: for the first row the "previous row" is taken as the bytes before the image
        // instead of zeros; only the Paeth filter reads it before checking.
        const uint8_t* prev = row - rowbytes;
        SLEUTH_BUG(4, filter == 4 && y == 0);
        for (uint32_t x = 0; x < rowbytes; ++x) {
            uint8_t v = raw[pos + x];
            int a = x >= (uint32_t)bpp ? row[x - bpp] : 0;
            switch (filter) {
                case 0: break;
                case 1: v = (uint8_t)(v + a); break;
                case 2: v = (uint8_t)(v + (y ? prev[x] : 0)); break;
                case 3: v = (uint8_t)(v + ((a + (y ? prev[x] : 0)) >> 1)); break;
                case 4: {
                    int b = prev[x];
                    int c = x >= (uint32_t)bpp ? prev[x - bpp] : 0;
                    v = (uint8_t)(v + paeth(a, b, c));
                    break;
                }
                default:
                    std::free(pixels);
                    return 0;
            }
            row[x] = v;
            sum += v;
        }
        pos += rowbytes;
    }
    std::free(pixels);
    return sum;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const uint8_t sig[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    if (size < 8 || std::memcmp(data, sig, 8) != 0) return 0;
    Image img;
    size_t pos = 8;
    while (pos + 12 <= size) {
        uint32_t len = be32(data + pos);
        if (len > size - pos - 12) return 0;
        const uint8_t* type = data + pos + 4;
        // The chunk body in its own buffer of exactly its size (as a decoder that copies
        // chunks would have it), so reads past it are caught.
        std::vector<uint8_t> body(data + pos + 8, data + pos + 8 + len);
        uint32_t crc = be32(data + pos + 8 + len);
        if (crc32(type, len + 4) != crc) return 0;  // bad CRC: stop, like libpng by default
        pos += 12 + len;
        if (std::memcmp(type, "IHDR", 4) == 0) {
            if (len != 13 || img.have_ihdr) return 0;
            img.width = be32(body.data());
            img.height = be32(body.data() + 4);
            img.depth = body[8];
            img.color = body[9];
            if (!img.width || !img.height || channels(img.color) == 0 || body[10] || body[11] || body[12]) return 0;
            if (img.depth != 1 && img.depth != 2 && img.depth != 4 && img.depth != 8 && img.depth != 16) return 0;
            img.have_ihdr = true;
        } else if (!img.have_ihdr) {
            return 0;
        } else if (std::memcmp(type, "PLTE", 4) == 0) {
            // Bug 1: the palette length is not checked against 256 entries.
            if (len % 3) return 0;
            SLEUTH_BUG(1, len > img.palette.size());
            std::memcpy(img.palette.data(), body.data(), len);
            img.palette_entries = (int)(len / 3);
        } else if (std::memcmp(type, "tRNS", 4) == 0) {
            if (img.color != 3) continue;
            // Bug 2: tRNS may hold one alpha value per palette entry, but its length is only
            // checked against the palette when there is a palette, and not at all otherwise.
            if (img.palette_entries && len > (uint32_t)img.palette_entries) return 0;
            SLEUTH_BUG(2, len > img.trns.size());
            std::memcpy(img.trns.data(), body.data(), len);
        } else if (std::memcmp(type, "tEXt", 4) == 0) {
            // Bug 3: the keyword is assumed to be NUL-terminated inside the chunk.
            SLEUTH_BUG(3, std::memchr(body.data(), 0, len) == nullptr);
            size_t klen = std::strlen((const char*)body.data());
            if (klen == 0 || klen > 79) return 0;
        } else if (std::memcmp(type, "IDAT", 4) == 0) {
            img.idat.insert(img.idat.end(), body.begin(), body.end());
        } else if (std::memcmp(type, "IEND", 4) == 0) {
            return img.idat.empty() ? 0 : decode_image(img);
        }
    }
    return 0;
}
