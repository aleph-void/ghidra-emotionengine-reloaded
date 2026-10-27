#!/usr/bin/env python3
"""Third encoding reference: the opcode tables of wasaylor/r5900-opcodes (MIT, transcribed from the EE
Core Instruction Set Manual). For every listed instruction, words are generated with all fixed bits set
as the table says and the free fields random; Ghidra must decode each as that instruction.

  table_check.py gen <tables-dir> <out.bin> <out.names>    generate the corpus
  table_check.py check <out.names> <ghidra.txt> <out.bin>  compare with DumpSlots output

Known transcription slips in the tables are corrected below (TYPOS) and listed in GHIDRA-RARE.md.
"""
import os
import random
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from explain import dealias  # noqa: E402

FILES = ('opcodes-cpu', 'opcodes-cop1', 'opcodes-ee-core-specific', 'opcodes-system-control-coprocessor')
FIELDS = {'rs': (25, 21), 'base': (25, 21), 'rt': (20, 16), 'rd': (15, 11), 'sa': (10, 6), 'fs': (15, 11),
          'ft': (20, 16), 'fd': (10, 6), 'immediate': (15, 0), 'offset': (15, 0), 'instr_index': (25, 0),
          'code20': (25, 6), 'code10': (15, 6), 'hint': (20, 16), 'op': (20, 16), 'stype': (10, 6),
          'reg': (5, 1), 'fmt': (10, 6), 'cond': (2, 1)}
# (table line as written) -> corrected line: slips in the transcription, checked against the other references
TYPOS = {
    'lui 31..26=0b001111 base rt immediate': 'lui 31..26=0b001111 25..21=0 rt immediate',
    'lhu 31..26=0b100111 base rt offset': 'lwu 31..26=0b100111 base rt offset',
    'mfhi 31..26=0 25..16=0 rd 10..6=0 5..0=0b010010': 'mflo 31..26=0 25..16=0 rd 10..6=0 5..0=0b010010',
    'msub.s 31..26=0b010001 25..21=0b10000 ft fs fd 5..0=0b01101': 'msub.s 31..26=0b010001 25..21=0b10000 ft fs fd 5..0=0b011101',
    'mtdab 31..26=16 25..21=0b00100 rt 15..11=0b11000 10..0=0': 'mtdab 31..26=16 25..21=0b00100 rt 15..11=0b11000 10..6=0 5..0=0b000100',
    'mtdabm 31..26=16 25..21=0b00100 rt 15..11=0b11000 10..0=0': 'mtdabm 31..26=16 25..21=0b00100 rt 15..11=0b11000 10..6=0 5..0=0b000101',
    'mtdvb 31..26=16 25..21=0b00100 rt 15..11=0b11000 10..0=0': 'mtdvb 31..26=16 25..21=0b00100 rt 15..11=0b11000 10..6=0 5..0=0b000110',
    # the manual's MFPS has reg = 0 only; GNU objdump accepts any register number (the module follows it)
    'mfps 31..26=16 25..21=0 rt 15..11=0b11001 10..6=0 reg=0 0=0': 'mfps 31..26=16 25..21=0 rt 15..11=0b11001 10..6=0 5..1=0 0=0',
    # PEXTU* are MMI1 (function 40) in GNU objdump, rabbitizer and the manual's MMI1 table
    'pextub 31..26=28 rs rt rd 10..6=0b11010 5..0=9': 'pextub 31..26=28 rs rt rd 10..6=0b11010 5..0=40',
    'pextuh 31..26=28 rs rt rd 10..6=0b10110 5..0=9': 'pextuh 31..26=28 rs rt rd 10..6=0b10110 5..0=40',
    'pextuw 31..26=28 rs rt rd 10..6=0b10010 5..0=9': 'pextuw 31..26=28 rs rt rd 10..6=0b10010 5..0=40',
    # generic fields the manual restricts: SYNC.stype 0 (SYNC.L) / 0x10 (SYNC.P); CFC1/CTC1 only FCR0 / FCR31
    'sync 31..26=0 25..11=0 stype 5..0=0b001111': 'sync 31..26=0 25..11=0 9..6=0 5..0=0b001111',
    'cfc1 31..26=0b010001 25..21=0b00010 rt fs 10..6=0 5..0=0': 'cfc1 31..26=0b010001 25..21=0b00010 rt 15..11=31 10..6=0 5..0=0',
    'ctc1 31..26=0b010001 25..21=0b00110 rt fs 10..6=0 5..0=0': 'ctc1 31..26=0b010001 25..21=0b00110 rt 15..11=31 10..6=0 5..0=0',
}
# the module's names for table entries that stand for a family (sub-format chosen by a field)
FAMILY = {'pmfhl': ['pmfhl.lw', 'pmfhl.uw', 'pmfhl.slw', 'pmfhl.lh', 'pmfhl.sh'], 'pmthl': ['pmthl.lw']}
FMT_RANGE = {'pmfhl': range(5), 'pmthl': range(1)}


def parse(tables):
    out = []
    for fn in FILES:
        for line in open(os.path.join(tables, fn)):
            line = line.split('#')[0].strip()
            if not line:
                continue
            line = ' '.join(line.split())
            line = TYPOS.get(line, line)
            name, *items = line.split()
            fixed, mask, free = 0, 0, []
            for it in items:
                m = re.fullmatch(r'(\d+)(?:\.\.(\d+))?=(\w+)', it)
                if m:
                    hi = int(m.group(1))
                    lo = int(m.group(2)) if m.group(2) else hi
                    v = int(m.group(3), 0)
                    width = hi - lo + 1
                    fixed |= (v & ((1 << width) - 1)) << lo
                    mask |= ((1 << width) - 1) << lo
                elif re.fullmatch(r'(\w+)=(\w+)', it):
                    f, v = it.split('=')
                    hi, lo = FIELDS[f]
                    fixed |= int(v, 0) << lo
                    mask |= ((1 << (hi - lo + 1)) - 1) << lo
                else:
                    free.append(it)
            out.append((name, fixed, mask, free))
    return out


def gen(tables, out_bin, out_names, n=24):
    rng = random.Random(5)
    words, names = [], []
    for name, fixed, mask, free in parse(tables):
        for k in range(n):
            w = fixed | (rng.getrandbits(32) & ~mask & 0xffffffff)
            if name in FMT_RANGE:
                w = (w & ~(0x1f << 6)) | (rng.choice(list(FMT_RANGE[name])) << 6)
            if k == 0:   # all free fields zero (aliases such as move / li / b / nop)
                w = fixed
            words.append(w)
            names.append(name)
    open(out_bin, 'wb').write(b''.join(struct.pack('<I', w) for w in words))
    open(out_names, 'w').write('\n'.join(names) + '\n')
    print(f'{out_bin}: {len(words)} words for {len(set(names))} instructions')


def check(names_file, gh_file, bin_file):
    names = open(names_file).read().split()
    data = open(bin_file, 'rb').read()
    gh = {}
    for line in open(gh_file):
        i, ln, text = line.rstrip('\n').split(' ', 2)
        gh[int(i)] = text if ln != '0' else 'BAD'
    bad = {}
    for i, name in enumerate(names):
        w = struct.unpack_from('<I', data, 4 * i)[0]
        text = gh[i]
        if text == 'BAD':
            mn = 'BAD'
        else:
            mn, toks = text.split()[0].lower(), [t for t in re.split(r'[,\s()]+', text.split(None, 1)[1] if ' ' in text else '') if t]
            mn, _ = dealias(mn, toks, w)
            if mn == 'nop':
                mn = 'sll'
            if mn == 'sync.p':
                mn = 'sync'
        ok = mn == name or mn in FAMILY.get(name, [])
        if not ok:
            bad.setdefault(name, []).append(f'{w:08x} {text}')
    print(f'   table check: {len(set(names)) - len(bad)}/{len(set(names))} instructions decode as listed '
          f'({len(names)} words)')
    for k, v in bad.items():
        print(f'   {k}: {len(v)} words differ, e.g. ' + '; '.join(v[:3]))
    return bad


if __name__ == '__main__':
    if sys.argv[1] == 'gen':
        gen(*sys.argv[2:5])
    else:
        sys.exit(1 if check(*sys.argv[2:5]) else 0)
