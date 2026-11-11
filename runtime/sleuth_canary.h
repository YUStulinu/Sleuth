// Bug canaries, in the spirit of Magma (Hazimeh et al., 2020).
//
// Every planted bug in the targets is guarded by SLEUTH_BUG(id, condition), placed just before
// the faulty code: the canary records that bug `id` was REACHED (the line ran) and TRIGGERED (the
// condition that makes the bug happen was true). The events go to the file named by the
// SLEUTH_BUG_LOG environment variable, one line each ("R 3 1731350000123" / "T 3 ..."; the time
// is milliseconds since the Unix epoch), so any fuzzer running the target, Sleuth or libFuzzer,
// can be measured the same way. Without the variable the canaries do nothing.
//
// The canary does not change what the code does: a triggered bug still goes on to corrupt memory
// or crash, which is what the fuzzer must notice.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
void sleuth_bug(int id, int triggered);
#ifdef __cplusplus
}
#endif

#define SLEUTH_BUG(id, cond) sleuth_bug((id), (cond) ? 1 : 0)
