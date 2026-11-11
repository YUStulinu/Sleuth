# Planted bugs

Five small parsers, written for this project, with 20 documented bugs planted in them, in the
spirit of [Magma](https://hexhive.epfl.ch/magma/) (Hazimeh et al., 2020): every bug has a canary,
`SLEUTH_BUG(id, condition)`, placed just before the faulty code. The canary logs when the line is
**reached** and when the bug's condition is **triggered** (the faulty behaviour actually happens),
to the file named by `SLEUTH_BUG_LOG`, so any fuzzer running the target can be scored the same way.
A third level, **detected**, means a crash was reported and its input triggers the bug.

The bugs are modelled on real bug classes found in libpng, libxml2, ASN.1/X.509 parsers, JSON
libraries and interpreters, but the code is ours; no third-party source is used (see the README).

`targets/<target>/pocs/bugN` holds a proof-of-concept input for every bug, and the test suite checks
that each one triggers its canary and is detected by AddressSanitizer (or the CPU, for bug 17).

| # | Target | Class | Where | Condition | How it is detected |
|---|---|---|---|---|---|
| 1 | png | heap overflow (write) | `PLTE` chunk copied into a 768-byte palette | `len > 768` (and a multiple of 3) | ASan, memcpy |
| 2 | png | heap overflow (write) | `tRNS` with no palette yet, copied into 256 bytes | colour type 3, `len > 256` | ASan, memcpy |
| 3 | png | out-of-bounds read | `tEXt` keyword read with `strlen` | no NUL inside the chunk | ASan (or a null read for an empty chunk) |
| 4 | png | out-of-bounds read | Paeth filter on the first row reads the "previous row" before the image | filter 4 on row 0 | ASan |
| 5 | png | integer overflow → heap overflow | `rowbytes * height` computed in 32 bits | the product wraps | ASan, when enough image data follows |
| 6 | xml | heap overflow (write) | `&#x...;` encoded as UTF-8 into a 4-byte buffer | code point ≥ 0x200000 | ASan |
| 7 | xml | heap overflow (write) | attributes stored in a fixed array of 16 | a 17th distinct attribute | ASan |
| 8 | xml | out-of-bounds read | closing tag compared over its own length | `</abcd>` closes `<ab>` | ASan, memcmp |
| 9 | xml | out-of-bounds read | `]]>` search in an unterminated CDATA section | data ends with `]` | ASan |
| 10 | der | signed length → negative size | long-form length read into an `int32` | length ≥ 0x80000000 | ASan, negative-size-param |
| 11 | der | heap overflow (write) | OID arcs stored in a fixed array of 16 | more than 16 arcs | ASan |
| 12 | der | out-of-bounds read | BIT STRING mask table indexed by the unused-bits count | unused bits > 7 | ASan |
| 13 | der | heap overflow (write) | UTCTime copied into a 13-byte buffer | longer than 13 characters | ASan, memcpy |
| 14 | json | out-of-bounds read | `\uD800\u....` low surrogate read without a length check | input ends right after the backslash | ASan |
| 15 | json | out-of-bounds read | power-of-ten table (10^0..10^308) indexed by the exponent | exponent 309..316 | ASan |
| 16 | json | heap overflow (write) | object keys tracked in a fixed table of 64 | a 65th distinct key | ASan |
| 17 | vm | division by zero | `DIV`/`MOD` check only `INT_MIN / -1` | divisor 0 | CPU trap, reported by ASan |
| 18 | vm | heap overflow | register check `r <= 16` instead of `r < 16` | register 16 used | ASan |
| 19 | vm | heap overflow (write) | call depth check `> 16` instead of `>= 16` | a 17th nested call | ASan |
| 20 | vm | out-of-bounds read | backward jump not checked against the start of the code | jump target < 0 | ASan |

Notes:

- **Bug 5** can trigger without being detected: the size wraps, but nothing is written out of
  bounds unless the compressed data holds more rows than the small buffer. Magma has the same
  distinction between triggered and detected bugs.
- The targets are built with a minimum redzone of 128 bytes (`__asan_default_options` in
  `runtime/canary.cpp`, linked into both the Sleuth and the libFuzzer builds), so that the
  out-of-bounds accesses of bugs 4, 12, 15 and 20, which can land up to 128 bytes away from the
  buffer, are always caught rather than sometimes landing in a neighbouring allocation.
- Some bugs need structure that random edits rarely build: 17 attributes or 65 keys in one
  element or object (bugs 7 and 16), a palette of more than 256 entries with a valid CRC (bug 1),
  a UTCTime of the wrong length (bug 13). They are there on purpose, to tell the fuzzers apart.
