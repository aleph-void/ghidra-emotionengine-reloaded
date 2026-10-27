"""Normalisation and explained difference classes for the R5900 decode differential (used by compare.py).

normalise() maps both disassemblers' spellings onto one form (numbers by value, '$' dropped, GNU objdump's
register-suffix and alias spellings). explain() classifies a remaining difference; a class is only
accepted here with its reason, and some classes are checked further by compare.py (see CANON).
"""
import re

NUM = re.compile(r'^[-+]?(0x[0-9a-f]+|\d+)$')
VU_MN = re.compile(r'^v[a-z0-9]+')

# GNU objdump spellings of generic MIPS aliases that the module spells as the real instruction
OBJDUMP_ALIAS = {'ssnop': ('sll', ('zero', 'zero', '1')), 'ehb': ('sll', ('zero', 'zero', '3'))}


CACHE_OPS = ['ixltg', 'ixldt', 'bxlbt', 'op3', 'ixstg', 'ixsdt', 'bxsbt', 'ixin', 'bpr', 'op9', 'bhinbt', 'ihin',
             'bfh', 'op13', 'ifl', 'op15', 'dxltg', 'dxldt', 'dxstg', 'dxsdt', 'dxwbin', 'op21', 'dxin', 'op23',
             'dhwbin', 'op25', 'dhin', 'op27', 'dhwoin', 'op29', 'op30', 'op31']
COP0_NAMES = {'sr': 'status', 'errorepc': 'errorpc'}


def _num(tok):
    t = tok.lower()
    neg = t.startswith('-')
    t = t.lstrip('+-')
    v = int(t, 16) if t.startswith('0x') else int(t)
    return -v if neg else v


def dealias(mn, toks, word):
    """Rewrite the common MIPS aliases (both spellings) into the underlying instruction, using the word."""
    prime, fct = word >> 26, word & 0x3f
    if mn == 'move' and len(toks) == 2:
        base = {0x21: 'addu', 0x2d: 'daddu', 0x25: 'or'}.get(fct, 'move') if prime == 0 else 'move'
        return base, [toks[0], toks[1], 'zero']
    if mn == 'li' and len(toks) == 2:
        return {9: 'addiu', 13: 'ori'}.get(prime, 'li'), [toks[0], 'zero', toks[1]]
    if mn == 'b' and len(toks) == 1:
        return ('beq', ['zero', 'zero', toks[0]]) if prime == 4 else ('bgez', ['zero', toks[0]])
    if mn == 'bal' and len(toks) == 1:
        return 'bgezal', ['zero', toks[0]]
    if mn in ('beqz', 'bnez', 'beqzl', 'bnezl') and len(toks) == 2:
        return mn.replace('z', ''), [toks[0], 'zero', toks[1]]
    if mn in ('neg', 'negu', 'dneg', 'dnegu') and len(toks) == 2:
        return {'neg': 'sub', 'negu': 'subu', 'dneg': 'dsub', 'dnegu': 'dsubu'}[mn], [toks[0], 'zero', toks[1]]
    if mn == 'not' and len(toks) == 2:
        return 'nor', [toks[0], toks[1], 'zero']
    return mn, toks


def normalise(text, oracle, word, strip=True):
    """Text -> comparable tuple: mnemonic + operands, numbers by value, '$' dropped."""
    t = text.lower().replace('$', '').replace('\t', ' ')
    parts = t.split(None, 1)
    mn = parts[0]
    ops = parts[1] if len(parts) > 1 else ''
    toks = [x for x in re.split(r'[,\s()]+', ops) if x]
    if mn.endswith('.'):
        mn = mn[:-1]
    if mn in OBJDUMP_ALIAS:
        mn, toks = OBJDUMP_ALIAS[mn][0], list(OBJDUMP_ALIAS[mn][1])
    if oracle == 'rabbitizer' and mn.endswith('.ni'):
        mn = mn[:-3]
    dest = mn.split('.', 1)[1] if '.' in mn and mn.startswith('v') else ''
    if mn == 'break':
        if not toks:
            toks = ['0']
        elif len(toks) == 2:
            toks = [str((_num(toks[0]) << 10) | _num(toks[1]))]
        elif NUM.match(toks[0]) and ((word >> 6) & 0x3ff) == 0 and _num(toks[0]) == (word >> 16) & 0x3ff:
            # GNU / rabbitizer print only the upper ten bits of the code when the lower ten are zero
            toks = [str((word >> 6) & 0xfffff)]
    toks = ['s8' if x == 'fp' else x for x in toks]
    mn, toks = dealias(mn, toks, word)
    if mn in ('mult', 'multu', 'madd', 'maddu', 'mult1', 'multu1', 'madd1', 'maddu1') and len(toks) == 3 \
            and toks[0] == 'zero':
        toks = toks[1:]
    if mn in ('teq', 'tne', 'tge', 'tgeu', 'tlt', 'tltu') and len(toks) == 3 and toks[2] in ('0', '0x0'):
        toks = toks[:2]
    if oracle == 'rabbitizer' and mn in ('mfc0', 'mtc0', 'cfc1', 'ctc1') and len(toks) == 2:
        toks[1] = str((word >> 11) & 0x1f)     # register names differ by tool: compare the field
    if mn in ('syscall', 'sync') and not toks:
        toks = ['0']
    if mn == 'trunc.w.s':          # objdump's name for the R5900 CVT.W.S (which truncates)
        mn = 'cvt.w.s'
    if mn == 'ori' and len(toks) == 3 and toks[1] == 'zero':
        mn, toks = 'li', [toks[0], toks[2]]
    if mn == 'bgez' and len(toks) == 2 and toks[0] == 'zero':
        mn, toks = 'b', [toks[1]]
    if mn == 'cache' and toks and toks[0] in CACHE_OPS:
        toks[0] = str(CACHE_OPS.index(toks[0]))
    if mn in ('mfc0', 'mtc0') and len(toks) == 2:
        toks[1] = COP0_NAMES.get(re.sub(r'^c0_', '', toks[1]), re.sub(r'^c0_', '', toks[1]))
    if oracle == 'rabbitizer_gh' and mn in ('mfc0', 'mtc0', 'cfc1', 'ctc1') and len(toks) == 2:
        toks[1] = str((word >> 11) & 0x1f)
    # GNU objdump writes DIV/DIVU with rd = $zero as "div zero,rs,rt"
    if mn in ('div', 'divu', 'div1', 'divu1') and len(toks) == 3 and toks[0] == 'zero':
        toks = toks[1:]
    out = []
    for x in toks:
        m = re.fullmatch(r'(vf\d+|acc)([xyzw]+)', x)
        if m and dest and strip and m.group(2) == dest:
            x = m.group(1)
        x = re.sub(r'^c[01]_', '', x)                 # objdump c0_index / c1_fcsr
        x = re.sub(r'^cop0reg\.(\d+)$', r'\1', x)     # module name of an unnamed COP0 register
        if NUM.match(x):
            v = _num(x)
            out.append(str(v & 0xffffffff) if v < 0 else str(v))
        else:
            out.append(x)
    return (mn, tuple(out))


# VU macro instructions whose reserved fields the module ignores (upstream's deliberate choice, made
# after real compiler output with non-zero reserved fields failed to disassemble: upstream issue #38).
# compare.py clears / sets these fields and requires the reference to agree on the canonical word.
FT = 0x1f << 16
FS = 0x1f << 11
DEST = 0xf << 21
FSF = 3 << 21
FTF = 3 << 23


def canon(word, gh):
    """(canonical word, compare-without-dest) for a VU decode the reference rejects, else None."""
    mn = gh.split()[0].lower()
    base = mn.split('.')[0]
    if re.fullmatch(r'v(add|sub|mul|madd|msub|max|mini)a?[iq]', base):
        return word & ~FT, False
    if base in ('viadd', 'visub', 'viand', 'vior', 'viaddi'):
        return word & ~DEST, False
    if base in ('vwaitq', 'vnop'):
        return word & ~(DEST | FT | FS), False
    if base == 'vmtir':
        return word & ~FTF, False
    if base in ('vrnext', 'vrget'):
        return word & ~FS, False
    if base in ('vrinit', 'vrxor'):
        return word & ~(FT | FTF), False
    if base in ('vclipw', 'vopmula', 'vopmsub'):
        return (word & ~DEST) | (0xe << 21), True
    if base == 'vcallmsr':
        return word & ~(FT | FS | (0x1f << 6)), True
    return None


def explain(word, gh, ref, oracle):
    """Return a reason string, ('canon', word, reason, ignore_dest) or None."""
    g = gh.lower()
    r = ref.lower()
    gm = g.split()[0] if g != 'bad' else 'bad'
    rm = r.split()[0] if r != 'bad' else 'bad'
    if gm != 'bad' and VU_MN.match(gm) and (rm == 'bad' or rm == 'c2'):
        c = canon(word, gh)
        if c:
            return ('canon', c[0], 'VU reserved field ignored by the module (upstream issue #38); the reference '
                    'rejects it, and decodes the word with the field cleared the same way', c[1])
    if gm == 'vcallmsr' and rm == 'vcallmsr':
        return ('VCALLMSR always starts the microprogram at CMSAR0 (vi27); its fs field is reserved, '
                'objdump prints the register the field holds')
    if gm == 'vsqrt' and rm in ('bad', 'c2'):
        return ('VSQRT: GNU objdump has no VSQRT decode (it prints c2) and rabbitizer refuses it in GNU mode; '
                'encoding from rabbitizer\'s R5900 COP2 table, ee-objdump example in upstream issue #38')
    if oracle == 'rabbitizer':
        if gm in ('c0', 'c1', 'c2') and rm == 'bad':
            return 'generic coprocessor operation (CO bit set) that GNU objdump decodes as c0/c1/c2; rabbitizer has no such form'
        if gm == 'bad' and rm in ('ll', 'sc', 'lld', 'scd', 'ldc1', 'sdc1', 'lwc2', 'swc2', 'dmfc0', 'dmtc0', 'dmfc1',
                                  'dmtc1', 'cfc0', 'ctc0', 'ddiv', 'ddivu', 'dmult', 'dmultu', 'rfe', 'cache'):
            return ('MIPS III / R3000 instruction rabbitizer falls back to for R5900 words; absent from its own R5900 '
                    'opcode tables (and GNU objdump -m mips:5900 rejects it)')
        if gm in ('c0', 'bad') and rm == 'rfe':
            return 'RFE is the R3000 exception return; not an R5900 instruction (rabbitizer generic fallback)'
        if gm == 'bad' and rm in ('cfc1', 'ctc1'):
            return 'CFC1/CTC1 of an FPU control register other than FCR0/FCR31 (the only ones the R5900 FPU has)'
        if gm in ('mfpc', 'mfps', 'mtpc', 'mtps', 'mfbpc', 'mtbpc', 'mfiab', 'mtiab', 'mfiabm', 'mtiabm', 'mfdab',
                  'mtdab', 'mfdabm', 'mtdabm', 'mfdvb', 'mtdvb', 'mfdvbm', 'mtdvbm') and rm in ('bad', 'mfc0', 'mtc0'):
            return ('R5900 performance-counter / debug-register move (GNU objdump decodes it); rabbitizer only knows '
                    'plain MFC0/MTC0 of COP0 registers 24/25')
        if gm == 'syscall' and rm == 'bad':
            return 'SYSCALL with a non-zero code field: rabbitizer rejects it, GNU objdump decodes it (the code is ignored by the CPU)'
        if gm == 'bad' and rm in ('sync', 'sync.p'):
            return 'SYNC with a stype other than 0 (SYNC) / 0x10 (SYNC.P): rabbitizer ignores stype, GNU objdump rejects it'
        if gm == 'multu' and rm == 'bad':
            return ('three-operand MULTU (rd != 0): GNU objdump decodes it like the three-operand MULT; rabbitizer '
                    'only has the three-operand MULT')
        if gm in ('c1', 'bad') and re.fullmatch(r'(round|trunc|ceil|floor)\.[lw]\.[sd]|cvt\.[ld]\.[sdlw]|cvt\.s\.l|'
                                               r'c\.(un|ueq|olt|ult|ole|ule|sf|ngle|seq|ngl|nge|ngt)\.s|c\.(lt|le)\.s', rm):
            return ('MIPS FPU encoding rabbitizer falls back to; not in the R5900 COP1 function table (which has only '
                    'C.F/C.EQ/C.LT/C.LE at their R5900 function codes)')
        if gm == 'sqrt.s' and rm == 'c1':
            return 'SQRT.S: rabbitizer deliberately prints the raw c1 word (GNU and the R5900 disagree on the operand field)'
    if oracle == 'objdump':
        if gm == 'bad' and rm == 'jalx':
            return 'objdump decodes JALX (MIPS16/microMIPS jump); the R5900 has no JALX (primary opcode 29 is reserved)'
        if gm in ('bad', 'c0') and rm in ('wait', 'cfc0', 'ctc0'):
            return ('generic MIPS COP0 encodings (WAIT, CFC0/CTC0) that objdump also decodes for mips:5900; '
                    'they are not in the R5900 COP0 tables')
        if gm in ('bad', 'c1') and re.fullmatch(r'(round|trunc|ceil|floor)\.[lw]\.[sd]|cvt\.[ld]\.[sdlw]|cvt\.s\.l', rm):
            return ('MIPS III FPU conversions objdump decodes for mips:5900; the R5900 FPU (single precision only) '
                    'has none of them (R5900 COP1 function table)')
        if gm == 'bad' and rm in ('cfc1', 'ctc1'):
            return 'CFC1/CTC1 of an FPU control register other than FCR0/FCR31 (the only ones the R5900 FPU has)'
        if gm == 'sqrt.s' and rm == 'c1':
            return ('R5900 SQRT.S takes its operand from ft (fs reserved); GNU decodes only the MIPS form '
                    '(operand in fs, ft = 0), so the two disagree on which field is the source')
    return None
