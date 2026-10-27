#!/usr/bin/env python3
"""Instruction-word corpora for the R5900 decode differential (little-endian 32-bit words).

  gen_corpus.py enum   <out.bin> [seed]      every opcode / function / format field combination
  gen_corpus.py random <out.bin> <n> [seed]  n uniformly random words

The enumeration walks every value of the fields that select an instruction (primary opcode, SPECIAL /
REGIMM / MMI function and sub-function, COP0/COP1/COP2 format and function, the VU macro dest / bc /
special opcode bits) and fills the remaining register and immediate fields with a few random values
plus the all-zero case, so the "zero register" aliases (move, li, clear, b ...) are covered too.
"""
import random
import struct
import sys


def regs(rng, n):
    """n random (rs, rt, rd, sa) tuples plus all-zero and all-ones."""
    out = [(0, 0, 0, 0), (31, 31, 31, 31)]
    for _ in range(n):
        out.append(tuple(rng.randrange(32) for _ in range(4)))
    return out


def rtype(op, rs, rt, rd, sa, fn):
    return (op << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | fn


def enum(rng):
    words = []
    # primary opcodes other than the sub-decoded ones: immediates random, registers varied
    for op in range(64):
        for _ in range(48):
            words.append((op << 26) | rng.getrandbits(26))
        for rs, rt, _, _ in regs(rng, 2):
            words.append((op << 26) | (rs << 21) | (rt << 16) | rng.getrandbits(16))
        words.append(op << 26)
    # SPECIAL: every function x every sa field, with register variations
    for fn in range(64):
        for sa in range(32):
            for rs, rt, rd, _ in regs(rng, 1):
                words.append(rtype(0, rs, rt, rd, sa, fn))
        for rs, rt, rd, sa in regs(rng, 6):
            words.append(rtype(0, rs, rt, rd, sa, fn))
            words.append(rtype(0, 0, rt, rd, sa, fn))
            words.append(rtype(0, rs, 0, rd, sa, fn))
            words.append(rtype(0, rs, rt, 0, sa, fn))
            words.append(rtype(0, rs, rt, 31, sa, fn))
    # one register field set, the others zero (the jr ra / move / neg ... aliases)
    for fn in range(64):
        for r in range(32):
            words += [rtype(0, r, 0, 0, 0, fn), rtype(0, 0, r, 0, 0, fn), rtype(0, 0, 0, r, 0, fn)]
    # REGIMM: every rt function
    for rt in range(32):
        for rs, _, _, _ in regs(rng, 6):
            words.append((1 << 26) | (rs << 21) | (rt << 16) | rng.getrandbits(16))
            words.append((1 << 26) | (rs << 21) | (rt << 16))
    # MMI: every function x every sub-function (sa field)
    for fn in range(64):
        for sub in range(32):
            for rs, rt, rd, _ in regs(rng, 3):
                words.append(rtype(28, rs, rt, rd, sub, fn))
                words.append(rtype(28, 0, rt, rd, sub, fn))
                words.append(rtype(28, rs, 0, rd, sub, fn))
                words.append(rtype(28, rs, rt, 0, sub, fn))
    # COP0 / COP1 / COP2: every rs format x every function, plus every rt for the branch formats
    for op in (16, 17, 18):
        for fmt in range(32):
            for fn in range(64):
                for rs, rt, rd, sa in regs(rng, 2):
                    words.append(rtype(op, fmt, rt, rd, sa, fn))
                words.append(rtype(op, fmt, rng.randrange(32), rng.randrange(32), 0, fn))
            for rt in range(32):
                words.append(rtype(op, fmt, rt, 0, 0, 0) | rng.getrandbits(16))
                words.append(rtype(op, fmt, rt, rng.randrange(32), 0, 0))
                words.append(rtype(op, fmt, rt, rng.randrange(32), 0, 1))
        # every register of the move-to/from forms with the low field clear
        for fmt in (0, 2, 4, 6):
            for rd in range(32):
                words.append(rtype(op, fmt, rng.randrange(32), rd, 0, 0))
        # COP0 move register / select combinations
        for rd in range(32):
            for low in range(64):
                words.append(rtype(op, 0, rng.randrange(32), rd, 0, low) if op == 16 else
                             rtype(op, 0, rng.randrange(32), rd, 0, 0))
                words.append(rtype(op, 4, rng.randrange(32), rd, 0, low) if op == 16 else
                             rtype(op, 4, rng.randrange(32), rd, 0, 0))
    # COP2 (VU0 macro mode), co=1: every dest x every 11-bit function (upper, special1 and special2)
    for dest in range(16):
        for low in range(2048):
            words.append((18 << 26) | (1 << 25) | (dest << 21) | (rng.randrange(32) << 16) |
                         (rng.randrange(32) << 11) | low)
    # COP2 transfers: every 11-bit low field for qmfc2 / qmtc2 / cfc2 / ctc2 (interlock bit, reserved bits)
    for fmt in (1, 2, 5, 6):
        for low in range(2048):
            words.append(rtype(18, fmt, rng.randrange(32), rng.randrange(32), 0, 0) | low)
    return words


def main():
    mode, out = sys.argv[1], sys.argv[2]
    if mode == 'enum':
        rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
        words = enum(rng)
    else:
        n = int(sys.argv[3])
        rng = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 7)
        words = [rng.getrandbits(32) for _ in range(n)]
    with open(out, 'wb') as f:
        f.write(b''.join(struct.pack('<I', w) for w in words))
    print(f'{out}: {len(words)} words')


if __name__ == '__main__':
    main()
