#!/usr/bin/env python3
"""Compare Ghidra's decode (DumpSlots.java output) with a reference disassembler (oracle.py output).

  compare.py <ghidra.txt> <oracle.txt> <corpus.bin> [--oracle objdump|rabbitizer] [--show N] [--dump-buckets]

Every word lands in one class:
  exact        same text after whitespace/'$' cleanup
  semantic     same instruction after normalisation (numbers compared by value, documented aliases)
  both-bad     neither decodes it
  explained:*  a difference class explained in explain() below (each with its reason)
  UNEXPLAINED  anything else; the exit status is 1 if there is any
"""
import os
import re
import struct
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict

sys.path.insert(0, __import__('os').path.dirname(__file__))
from explain import explain, normalise  # noqa: E402


def load(path):
    out = {}
    for line in open(path):
        parts = line.rstrip('\n').split(' ', 2)
        if len(parts) == 3 and parts[1].isdigit():   # DumpSlots: idx len text
            out[int(parts[0])] = parts[2] if parts[1] != '0' else 'BAD'
        else:
            out[int(parts[0])] = parts[1] if len(parts) > 1 else 'BAD'
            if len(parts) == 3:
                out[int(parts[0])] = parts[1] + ' ' + parts[2]
    return out


def run_oracle(oracle, words):
    """Run the reference on a list of words; returns their texts."""
    here = os.path.dirname(os.path.abspath(__file__))
    with tempfile.TemporaryDirectory() as d:
        b, t = os.path.join(d, 'c.bin'), os.path.join(d, 'c.txt')
        with open(b, 'wb') as f:
            f.write(b''.join(struct.pack('<I', w) for w in words))
        py = os.environ.get('RABBITIZER_PYTHON', sys.executable) if oracle == 'rabbitizer' else sys.executable
        subprocess.run([py, '-I', os.path.join(here, 'oracle.py'), oracle, b, t], check=True)
        res = load(t)
    return [res.get(i, 'BAD') for i in range(len(words))]


def main():
    gh, ref, corpus = load(sys.argv[1]), load(sys.argv[2]), open(sys.argv[3], 'rb').read()
    oracle = 'objdump'
    show = 5
    dump = False
    args = sys.argv[4:]
    while args:
        a = args.pop(0)
        if a == '--oracle':
            oracle = args.pop(0)
        elif a == '--show':
            show = int(args.pop(0))
        elif a == '--dump-buckets':
            dump = True
    counts = Counter()
    examples = defaultdict(list)
    pending = []   # (index, word, gh, ref, canonical word, reason, ignore_dest)
    n = len(corpus) // 4
    for i in range(n):
        w = struct.unpack_from('<I', corpus, i * 4)[0]
        g, r = gh.get(i, 'BAD'), ref.get(i, 'BAD')
        if g == 'BAD' and r == 'BAD':
            cls = 'both-bad'
        elif g != 'BAD' and r != 'BAD' and ' '.join(g.replace('$', '').split()) == ' '.join(r.replace('$', '').split()):
            cls = 'exact'
        elif g != 'BAD' and r != 'BAD' and normalise(g, oracle, w) == normalise(r, oracle, w):
            cls = 'semantic'
        else:
            why = explain(w, g, r, oracle)
            if isinstance(why, tuple):
                pending.append((i, w, g, r, why[1], why[2], why[3]))
                continue
            if why:
                cls = 'explained: ' + why
            else:
                gm = g.split()[0] if g != 'BAD' else 'BAD'
                rm = r.split()[0] if r != 'BAD' else 'BAD'
                cls = f'UNEXPLAINED {gm} / {rm}'
        counts[cls] += 1
        if len(examples[cls]) < show:
            examples[cls].append(f'{w:08x}  ghidra: {g:<40} {oracle}: {r}')
    if pending:
        canon_ref = run_oracle(oracle, [p[4] for p in pending])
        for (i, w, g, r, cw, reason, nodest), cr in zip(pending, canon_ref):
            a = normalise(g, oracle, w, strip=not nodest)
            b = normalise(cr, oracle, cw) if cr != 'BAD' else None
            if g.startswith('vcallmsr') and b is not None:
                b = (b[0], ('vi27',))
            if b is not None and nodest:
                a = (a[0].split('.')[0], a[1])
                b = (b[0].split('.')[0], b[1])
            cls = 'explained: ' + reason if a == b else f'UNEXPLAINED canonical {g.split()[0]} / {cr.split()[0]}'
            counts[cls] += 1
            if len(examples[cls]) < show:
                examples[cls].append(f'{w:08x}  ghidra: {g:<40} {oracle}: {r}   canonical {cw:08x}: {cr}')
    total = sum(counts.values())
    agree = counts['exact'] + counts['semantic']
    print(f'{oracle}: {total} words: exact {counts["exact"]}, semantic {counts["semantic"]}, '
          f'both-bad {counts["both-bad"]}, explained {sum(v for k, v in counts.items() if k.startswith("explained"))}, '
          f'unexplained {sum(v for k, v in counts.items() if k.startswith("UNEXPLAINED"))}')
    for k, v in sorted(counts.items(), key=lambda kv: (kv[0].startswith('UNEXPLAINED'), -kv[1])):
        if k in ('exact', 'semantic', 'both-bad'):
            continue
        print(f'  {v:7d}  {k}')
        if dump or k.startswith('UNEXPLAINED'):
            for e in examples[k]:
                print('             ' + e)
    sys.exit(1 if any(k.startswith('UNEXPLAINED') for k in counts) else 0)


if __name__ == '__main__':
    main()
