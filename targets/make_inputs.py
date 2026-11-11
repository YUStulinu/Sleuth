"""Writes the seed corpora and one proof-of-concept input per planted bug.

    python targets/make_inputs.py

    targets/<target>/seeds/*     small valid inputs that trigger no bug (the fuzzers start here)
    targets/<target>/pocs/bugN   an input that triggers bug N (used by the tests to check that
                                 every planted bug is reachable and that AddressSanitizer, or the
                                 CPU, detects it)
    targets/<target>/dict        tokens for the dictionary mutations (Sleuth and libFuzzer -dict)
"""
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def write(target, kind, name, data):
    d = os.path.join(HERE, target, kind)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def write_dict(target, tokens):
    with open(os.path.join(HERE, target, "dict"), "w", newline="\n") as f:
        for t in tokens:
            f.write('"' + "".join(c if 32 <= ord(c) < 127 and c not in '"\\' else f"\\x{ord(c):02x}" for c in t) + '"\n')


# ---------------------------------------------------------------- png

def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)


def png(width, height, depth, color, rows, extra=b"", before_idat=b""):
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, color, 0, 0, 0))
    idat = chunk(b"IDAT", zlib.compress(rows, 9))
    return sig + ihdr + before_idat + idat + extra + chunk(b"IEND", b"")


def pngs():
    gray = b"".join(b"\x00" + bytes((x * 16 + y) & 255 for x in range(8)) for y in range(8))
    write("png", "seeds", "gray8.png", png(8, 8, 8, 0, gray))
    rgb = b"".join(bytes([f]) + bytes((x * 3 + y + c) & 255 for x in range(4) for c in range(3)) for y, f in enumerate([0, 1, 2, 3]))
    write("png", "seeds", "rgb_filters.png", png(4, 4, 8, 2, rgb))
    pal = chunk(b"PLTE", bytes(range(12)))
    write("png", "seeds", "palette.png", png(4, 2, 8, 3, b"\x00\x00\x01\x02\x03\x00\x03\x02\x01\x00", before_idat=pal + chunk(b"tRNS", b"\xff\x80")))
    write("png", "seeds", "text.png", png(2, 2, 8, 0, b"\x00\x01\x02\x00\x03\x04", extra=chunk(b"tEXt", b"Title\x00hello")))
    write("png", "seeds", "rgba_paeth.png", png(2, 2, 8, 6, b"\x01" + bytes(8) + b"\x04" + bytes(range(8))))

    write("png", "pocs", "bug1", png(1, 1, 8, 3, b"\x00\x00", before_idat=chunk(b"PLTE", bytes(771))))
    write("png", "pocs", "bug2", png(1, 1, 8, 3, b"\x00\x00", before_idat=chunk(b"tRNS", bytes(300))))
    write("png", "pocs", "bug3", png(1, 1, 8, 0, b"\x00\x00", extra=chunk(b"tEXt", b"NoTerminator")))
    write("png", "pocs", "bug4", png(4, 2, 8, 0, b"\x04\x01\x02\x03\x04\x00\x05\x06\x07\x08"))
    w, h = 0x10000, 0x10001  # rowbytes * height = 2^32 + 2^16, which wraps to 65536
    write("png", "pocs", "bug5", png(w, h, 8, 0, bytes(2 * (w + 1))))
    write_dict("png", ["IHDR", "PLTE", "tRNS", "tEXt", "IDAT", "IEND", "\x89PNG\r\n\x1a\n"])


# ---------------------------------------------------------------- xml

def xmls():
    write("xml", "seeds", "simple.xml", b'<?xml version="1.0"?>\n<root a="1" b="x&amp;y">text &lt;here&gt; &#65;&#x42;</root>\n')
    write("xml", "seeds", "nested.xml", b"<a><b id=\"7\"><c/></b><!-- note --><d>t</d></a>")
    write("xml", "seeds", "cdata.xml", b"<doc><![CDATA[raw <data> & ]] stuff]]></doc>")
    write("xml", "pocs", "bug6", b"<a>&#x200000;</a>")
    write("xml", "pocs", "bug7", b"<a " + b" ".join(b'a%d="v"' % k for k in range(17)) + b"/>")
    write("xml", "pocs", "bug8", b"<ab></abcdefgh>")
    write("xml", "pocs", "bug9", b"<a><![CDATA[xyz]")
    write_dict("xml", ["<?xml", "?>", "<!--", "-->", "<![CDATA[", "]]>", "</", "/>", "&amp;", "&lt;", "&#x", "&#", "=\""])


# ---------------------------------------------------------------- der

def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    elif n < 0x100:
        head = b"\x81" + bytes([n])
    else:
        head = b"\x82" + struct.pack(">H", n)
    return bytes([tag]) + head + body


def oid(arcs):
    out = bytearray([arcs[0] * 40 + arcs[1]])
    for a in arcs[2:]:
        enc = [a & 0x7F]
        a >>= 7
        while a:
            enc.append(0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, bytes(out))


def ders():
    name = tlv(0x30, tlv(0x31, tlv(0x30, oid([2, 5, 4, 3]) + tlv(0x13, b"Sleuth Test"))))
    validity = tlv(0x30, tlv(0x17, b"240101000000Z") + tlv(0x18, b"20341231235959Z"))
    alg = tlv(0x30, oid([1, 2, 840, 113549, 1, 1, 11]) + tlv(0x05, b""))
    key = tlv(0x30, alg + tlv(0x03, b"\x00" + bytes(range(1, 33))))
    tbs = tlv(0x30, tlv(0xA0, tlv(0x02, b"\x02")) + tlv(0x02, b"\x01\x23") + alg + name + validity + name + key
              + tlv(0xA3, tlv(0x30, tlv(0x30, oid([2, 5, 29, 19]) + tlv(0x01, b"\xff") + tlv(0x04, tlv(0x30, b""))))))
    cert = tlv(0x30, tbs + alg + tlv(0x03, b"\x00" + bytes(64)))
    write("der", "seeds", "cert.der", cert)
    write("der", "seeds", "small.der", tlv(0x30, tlv(0x02, b"\x7f") + tlv(0x0C, "héllo".encode()) + tlv(0x03, b"\x03\xa8")))
    write("der", "pocs", "bug10", b"\x04\x84\x80\x00\x00\x00")
    write("der", "pocs", "bug11", oid([1, 2] + list(range(3, 20))))
    write("der", "pocs", "bug12", tlv(0x03, b"\x1c\xff"))
    write("der", "pocs", "bug13", tlv(0x17, b"240101000000000Z"))
    write_dict("der", ["\x30\x82", "\x06\x03\x55\x04\x03", "\x17\x0d", "\x18\x0f", "\x03\x01\x00", "\x05\x00", "\x84"])


# ---------------------------------------------------------------- json

def jsons():
    write("json", "seeds", "object.json", b'{"name": "sleuth", "n": [1, 2.5, -3e2, 0.125e+1], "ok": true, "x": null}')
    write("json", "seeds", "escapes.json", b'["a\\"b\\\\c\\n", "\\u00e9\\ud83d\\ude00", "\\/", 1E10]')
    write("json", "seeds", "nested.json", b'{"a": {"b": {"c": [[], {}, [false]]}}}')
    write("json", "pocs", "bug14", b'"\\ud800\\')
    write("json", "pocs", "bug15", b"[1e309]")
    write("json", "pocs", "bug16", b"{" + b",".join(b'"k%d":0' % k for k in range(65)) + b"}")
    write_dict("json", ["true", "false", "null", "\\u", "\\ud800", "\\udc00", "e+", "E-", "\":"])


# ---------------------------------------------------------------- vm

def prog(consts, code):
    return b"SVM1" + bytes([len(consts)]) + b"".join(struct.pack("<I", c & 0xFFFFFFFF) for c in consts) + bytes(code)


def vms():
    # r0 = 10, r1 = 0, r2 = 1; loop: r1 += r0; r0 -= r2; if r0 == 0 skip the jump; jump back to
    # the loop (from offset 22 to 9: -13); out r1; halt.
    loop = [0x02, 0, 10, 0x02, 1, 0, 0x02, 2, 1,
            0x03, 1, 1, 0, 0x04, 0, 0, 2, 0x09, 0, 2, 0x08, (-13) & 0xFF, 0x0F, 1, 0x00]
    write("vm", "seeds", "loop.svm", prog([], loop))
    # r1 = 7; r0 = const 0; call 12; out r0; halt;
    # 12: push r0; r0 *= r1; r0 /= r1; pop r3; r4 = r3; r5 = r4 % r1; ret
    calls = [0x02, 1, 7, 0x01, 0, 0, 0x0A, 12, 0, 0x0F, 0, 0x00,
             0x0C, 0, 0x05, 0, 0, 1, 0x06, 0, 0, 1, 0x0D, 3, 0x0E, 4, 3, 0x07, 5, 4, 1, 0x0B]
    write("vm", "seeds", "calls.svm", prog([1234, 7], calls))
    write("vm", "pocs", "bug17", prog([], [0x02, 0, 5, 0x02, 1, 0, 0x06, 2, 0, 1, 0x00]))
    write("vm", "pocs", "bug18", prog([], [0x02, 16, 1, 0x00]))
    write("vm", "pocs", "bug19", prog([], [0x0A, 0, 0]))  # calls itself until the 17th frame
    write("vm", "pocs", "bug20", prog([], [0x08, 0x80]))
    write_dict("vm", ["SVM1", "\x0a\x00\x00", "\x08\x80", "\x06", "\x10"])


if __name__ == "__main__":
    pngs()
    xmls()
    ders()
    jsons()
    vms()
    print("seeds, pocs and dictionaries written under", HERE)
