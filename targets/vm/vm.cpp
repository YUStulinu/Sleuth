// A tiny bytecode virtual machine with planted bugs (see targets/BUGS.md).
//
// Program format: "SVM1", u8 number of constants, constants (u32 little-endian each), then code.
// 16 registers of int32, a call stack, and these instructions (operands are bytes):
//   0x01 r k      LOADK  r = const[k]
//   0x02 r imm    LOADI  r = imm (sign-extended byte)
//   0x03 a b c    ADD    a = b + c          0x04 a b c  SUB
//   0x05 a b c    MUL                       0x06 a b c  DIV   a = b / c
//   0x07 a b c    MOD
//   0x08 off      JMP    pc += (int8)off    0x09 r off  JZ    if r == 0: pc += (int8)off
//   0x0a lo hi    CALL   absolute target    0x0b        RET
//   0x0c r        PUSH                      0x0d r      POP
//   0x0e a b      MOV    a = b              0x0f r      OUT   (adds r to the output checksum)
//   0x00          HALT
// Execution stops after 10000 steps.
//
// Planted bugs: 17 (division by zero), 18 (register index 16 accepted), 19 (call depth checked
// with > instead of >=), 20 (backward jump before the start of the code).
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "sleuth_canary.h"

namespace {

constexpr int NREGS = 16;
constexpr int MAX_DEPTH = 16;
constexpr int STACK = 64;

struct Vm {
    const uint8_t* code;
    size_t len;
    const uint32_t* consts;
    size_t nconsts;
    int32_t* regs;        // NREGS
    uint32_t* frames;     // MAX_DEPTH return addresses
    int32_t* stack;       // STACK values
    int depth = 0, sp = 0;
    int64_t out = 0;

    // Register operand check. Bug 18: off by one, register 16 is accepted.
    bool reg_ok(uint8_t r) {
        SLEUTH_BUG(18, r == NREGS);
        return r <= NREGS;
    }

    bool run() {
        int64_t pc = 0;  // signed so jumps can be relative
        for (int steps = 0; steps < 10000; ++steps) {
            if (pc >= (int64_t)len) return false;
            uint8_t op = code[pc];
            auto need = [&](int64_t k) { return pc + 1 + k <= (int64_t)len; };
            switch (op) {
                case 0x00:
                    return true;
                case 0x01: {
                    if (!need(2) || !reg_ok(code[pc + 1]) || code[pc + 2] >= nconsts) return false;
                    regs[code[pc + 1]] = (int32_t)consts[code[pc + 2]];
                    pc += 3;
                    break;
                }
                case 0x02: {
                    if (!need(2) || !reg_ok(code[pc + 1])) return false;
                    regs[code[pc + 1]] = (int8_t)code[pc + 2];
                    pc += 3;
                    break;
                }
                case 0x03: case 0x04: case 0x05: case 0x06: case 0x07: {
                    if (!need(3)) return false;
                    uint8_t a = code[pc + 1], b = code[pc + 2], c = code[pc + 3];
                    if (!reg_ok(a) || !reg_ok(b) || !reg_ok(c)) return false;
                    int32_t x = regs[b], y = regs[c];
                    int32_t r;
                    if (op == 0x03) {
                        r = (int32_t)((uint32_t)x + (uint32_t)y);
                    } else if (op == 0x04) {
                        r = (int32_t)((uint32_t)x - (uint32_t)y);
                    } else if (op == 0x05) {
                        r = (int32_t)((uint32_t)x * (uint32_t)y);
                    } else {
                        // Bug 17: the divisor is checked only for the INT_MIN / -1 overflow.
                        if (x == INT32_MIN && y == -1) return false;
                        SLEUTH_BUG(17, y == 0);
                        if (y == 0) {
                            // Integer division by zero traps on x86 but is undefined behaviour,
                            // which the optimizer may remove; make the fault explicit.
                            volatile int32_t zero = y;
                            r = op == 0x06 ? x / zero : x % zero;
                            if (zero == 0) std::abort();
                        } else {
                            r = op == 0x06 ? x / y : x % y;
                        }
                    }
                    regs[a] = r;
                    pc += 4;
                    break;
                }
                case 0x08: {
                    if (!need(1)) return false;
                    int8_t off = (int8_t)code[pc + 1];
                    pc += 2;
                    // Bug 20: a backward jump is not checked against the start of the code (the
                    // fetch only checks pc < len), so the next fetch reads before the buffer.
                    SLEUTH_BUG(20, pc + off < 0);
                    pc += off;
                    break;
                }
                case 0x09: {
                    if (!need(2) || !reg_ok(code[pc + 1])) return false;
                    int8_t off = (int8_t)code[pc + 2];
                    pc += 3;
                    if (regs[code[pc - 2]] == 0) {
                        if (pc + off < 0) return false;
                        pc += off;
                    }
                    break;
                }
                case 0x0a: {
                    if (!need(2)) return false;
                    int64_t target = (int64_t)code[pc + 1] | (int64_t)code[pc + 2] << 8;
                    if (target >= (int64_t)len) return false;
                    // Bug 19: the depth check uses > instead of >=, so a 17th frame is written.
                    if (depth > MAX_DEPTH) return false;
                    SLEUTH_BUG(19, depth == MAX_DEPTH);
                    frames[depth++] = (uint32_t)(pc + 3);
                    pc = target;
                    break;
                }
                case 0x0b: {
                    if (depth == 0) return false;
                    pc = frames[--depth];
                    break;
                }
                case 0x0c: {
                    if (!need(1) || !reg_ok(code[pc + 1]) || sp >= STACK) return false;
                    stack[sp++] = regs[code[pc + 1]];
                    pc += 2;
                    break;
                }
                case 0x0d: {
                    if (!need(1) || !reg_ok(code[pc + 1]) || sp == 0) return false;
                    regs[code[pc + 1]] = stack[--sp];
                    pc += 2;
                    break;
                }
                case 0x0e: {
                    if (!need(2) || !reg_ok(code[pc + 1]) || !reg_ok(code[pc + 2])) return false;
                    regs[code[pc + 1]] = regs[code[pc + 2]];
                    pc += 3;
                    break;
                }
                case 0x0f: {
                    if (!need(1) || !reg_ok(code[pc + 1])) return false;
                    out += regs[code[pc + 1]];
                    pc += 2;
                    break;
                }
                default:
                    return false;
            }
        }
        return false;
    }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 5 || size > 4096 || std::memcmp(data, "SVM1", 4) != 0) return 0;
    size_t nconsts = data[4];
    size_t code_at = 5 + 4 * nconsts;
    if (code_at > size) return 0;
    uint32_t* consts = (uint32_t*)std::malloc(nconsts * 4 + 1);
    std::memcpy(consts, data + 5, nconsts * 4);
    // The code gets its own exact-size heap copy, so reads before or after it are caught.
    size_t clen = size - code_at;
    uint8_t* code = (uint8_t*)std::malloc(clen + 1);
    std::memcpy(code, data + code_at, clen);
    Vm vm{code, clen, consts, nconsts};
    vm.regs = (int32_t*)std::calloc(NREGS, sizeof(int32_t));
    vm.frames = (uint32_t*)std::malloc(MAX_DEPTH * sizeof(uint32_t));
    vm.stack = (int32_t*)std::malloc(STACK * sizeof(int32_t));
    bool ok = vm.run();
    std::free(vm.stack);
    std::free(vm.frames);
    std::free(vm.regs);
    std::free(consts);
    std::free(code);
    return ok && vm.out != 0 ? 1 : 0;
}
