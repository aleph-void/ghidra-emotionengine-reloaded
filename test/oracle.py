#!/usr/bin/env python3
"""Run a reference disassembler over a raw little-endian word image; write "<index> <text>" per word.

  oracle.py objdump    <in.bin> <out.txt>   GNU objdump -m mips:5900 (OBJDUMP, default: binutils on PATH)
  oracle.py rabbitizer <in.bin> <out.txt>   rabbitizer (MIT, pip install rabbitizer), R5900 category

Both run as black boxes. An invalid word is written as "BAD".
"""
import os
import re
import shutil
import struct
import subprocess
import sys

OBJDUMP = os.environ.get('OBJDUMP') or os.path.expanduser(
    '~/.cache/ghidra-rare-scratch/tools/binutils-all/bin/objdump')
if not os.path.exists(OBJDUMP):
    OBJDUMP = shutil.which('objdump')
MACH = os.environ.get('OBJDUMP_MACH', 'mips:5900')


def objdump(src, dst):
    n = os.path.getsize(src) // 4
    res = ['BAD'] * n
    p = subprocess.Popen([OBJDUMP, '-b', 'binary', '-m', MACH, '-EL', '-D', '-z', '--no-show-raw-insn', src],
                         stdout=subprocess.PIPE, text=True, bufsize=1 << 20)
    line_re = re.compile(r'^\s*([0-9a-f]+):\s+(.*)$')
    for line in p.stdout:
        m = line_re.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        text = m.group(2).strip()
        if addr % 4 or addr // 4 >= n:
            continue
        if text.startswith('.word') or text.startswith('(bad)') or text.startswith('.short'):
            text = 'BAD'
        res[addr // 4] = text.replace('\t', ' ')
    p.wait()
    with open(dst, 'w') as f:
        for i, t in enumerate(res):
            f.write(f'{i} {t}\n')


def rabbitizer(src, dst, category=None):
    import rabbitizer as r
    r.config.toolchainTweaks_gnuMode = os.environ.get('RABBITIZER_GNU', '0') == '1'
    rel = re.compile(r'\. \+ 4 \+ \((-?0x[0-9A-Fa-f]+) << 2\)')
    cat = getattr(r.InstrCategory, category or os.environ.get('RABBITIZER_CATEGORY', 'R5900'))
    data = open(src, 'rb').read()
    with open(dst, 'w') as f:
        for i in range(len(data) // 4):
            w = struct.unpack_from('<I', data, i * 4)[0]
            ins = r.Instruction(w, i * 4, cat)
            if not ins.isValid():
                f.write(f'{i} BAD\n')
                continue
            text = ins.disassemble().split('#')[0]
            text = rel.sub(lambda m: hex((i * 4 + 4 + 4 * int(m.group(1), 16)) & 0xffffffff), text)
            text = re.sub(r'\bfunc_([0-9A-Fa-f]+)', lambda m: '0x' + m.group(1).lower(), text)
            f.write(f'{i} {" ".join(text.split())}\n')


if __name__ == '__main__':
    {'objdump': objdump, 'rabbitizer': rabbitizer}[sys.argv[1]](sys.argv[2], sys.argv[3])
