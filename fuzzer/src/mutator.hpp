// Input mutations.
//
//   havoc        a stack of 1-16 random edits: bit flips, "interesting" values (0, -1, INT_MAX,
//                powers of two...) in both byte orders, small additions, random bytes, block
//                delete / duplicate / copy / insert, dictionary and comparison-operand tokens
//   splice       the start of one input joined to the end of another, then havoc
//   input-to-state (RedQueen-lite): for every comparison the target made while running the
//                input, find one operand's bytes in the input and put the other operand there
//                (also +-1, both byte orders). This is what gets a fuzzer past magic numbers,
//                checksums and keywords that random edits almost never hit.
#pragma once
#include <string>
#include <vector>

#include "executor.hpp"
#include "util.hpp"

namespace sleuth {

// Reads an AFL / libFuzzer dictionary: one token per line, `"..."` or `name="..."`, with
// \xNN, \\ and \" escapes; '#' starts a comment.
std::vector<Bytes> parse_dictionary(const std::string& text);

class Mutator {
public:
    explicit Mutator(Rng& rng, size_t max_len) : rng_(rng), max_len_(max_len) {}

    void set_dictionary(std::vector<Bytes> d) { dict_ = std::move(d); }
    const std::vector<Bytes>& dictionary() const { return dict_; }
    // Remembers comparison operands as tokens for havoc (a bounded, recent-first pool).
    void learn(const std::vector<CmpPair>& cmps, const std::vector<StrPair>& strs);
    size_t learned() const { return auto_.size(); }

    // Applies a stack of random edits in place. `other` (may be null) is used by splicing ops.
    void havoc(Bytes& d, const Bytes* other);
    // Crossover: a prefix of a, a suffix of b.
    Bytes splice(const Bytes& a, const Bytes& b);
    // All input-to-state candidates for one input and the comparisons it made, deduplicated,
    // at most `limit`.
    std::vector<Bytes> input_to_state(const Bytes& d, const std::vector<CmpPair>& cmps, const std::vector<StrPair>& strs, size_t limit);

    // Checksum repair: for comparisons between two run-time values (a stored checksum against
    // a computed one, a length field against the real length) where one value occurs in the
    // input, candidates with the other value put in its place. At most `limit`.
    std::vector<Bytes> repair(const Bytes& d, const std::vector<CmpPair>& cmps, size_t limit);

    size_t max_len() const { return max_len_; }

private:
    void one_edit(Bytes& d, const Bytes* other);
    void put_token(Bytes& d, const Bytes& tok, bool insert);
    Rng& rng_;
    size_t max_len_;
    std::vector<Bytes> dict_;
    std::vector<Bytes> auto_;  // learned tokens, ring buffer
    size_t auto_next_ = 0;
};

}  // namespace sleuth
