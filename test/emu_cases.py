"""Hand-computed p-code test cases for the R5900 (EmotionEngine) module (assembled by emu_tests.py, run by
EmuCheck.java).

T(name, asm, init, expect): asm is a short sequence in GNU assembler syntax (.set noreorder: the
instruction after a branch is its delay slot); init / expect are comma-separated 'reg=hex' items
(Ghidra register names: v0 is the 64-bit view, v0_qw the 128-bit GPR, v0_w2 a word lane, vf1x a VU lane)
or 'm<size>:<addr>=hex' (little-endian memory), or TRAP=<pcodeop>. '@END@' is the address after the
sequence, '@Lname@' the address of a local label Lname.

Every expectation is worked out by hand from the instruction descriptions (EE Core Instruction Set
Manual semantics as summarised in GHIDRA-RARE.md), never copied from the module's output. Names starting
with XFAIL_ carry a deliberately wrong expectation that must be reported as a failure.
"""

CASES = []


def T(name, asm, init='', expect=''):
    CASES.append((name, asm, init, expect))


D = 0x10f000   # scratch data (inside the image: emu_tests.py pads the image past it)


def q(*w):
    """128-bit value from words w0 (lowest) .. w3."""
    v = 0
    for i, x in enumerate(w):
        v |= (x & 0xffffffff) << (32 * i)
    return f'{v:x}'


def h(*hw):
    """128-bit value from halfwords h0 (lowest) .. h7."""
    v = 0
    for i, x in enumerate(hw):
        v |= (x & 0xffff) << (16 * i)
    return f'{v:x}'


def b(*bs):
    v = 0
    for i, x in enumerate(bs):
        v |= (x & 0xff) << (8 * i)
    return f'{v:x}'


F1, F2, F3, F4, F05, F5, F6, F8, F10, FM1 = (0x3f800000, 0x40000000, 0x40400000, 0x40800000, 0x3f000000,
                                            0x40a00000, 0x40c00000, 0x41000000, 0x41200000, 0xbf800000)

# ---------------------------------------------------------------------------------------------------
# 1. integer ALU: 32-bit results are sign-extended to 64 bits; the upper 64 bits of the GPR are kept
# ---------------------------------------------------------------------------------------------------
T('addu_sign_extends', 'addu $2,$4,$5', 'a0=7fffffff,a1=1,v0_qw=' + q(0, 0, 0x11111111, 0x22222222),
  'v0_qw=' + q(0x80000000, 0xffffffff, 0x11111111, 0x22222222))
T('add_overflow_traps', 'add $2,$4,$5', 'a0=7fffffff,a1=1,v0=5', 'TRAP=integerOverflow,v0=5')
T('addi_no_overflow', 'addi $2,$4,-1', 'a0=80000001', 'v0=ffffffff80000000')
T('daddu_wraps_64', 'daddu $2,$4,$5', 'a0=ffffffffffffffff,a1=2', 'v0=1')
T('dsub_overflow_traps', 'dsub $2,$4,$5', 'a0=8000000000000000,a1=1', 'TRAP=integerOverflow')
T('dsrav_low6_bits', 'dsrav $2,$4,$5', 'a0=8000000000000000,a1=41', 'v0=c000000000000000')
T('dsll32', 'dsll32 $2,$4,4', 'a0=1', 'v0=1000000000')
T('srl_32bit_then_sext', 'srl $2,$4,0', 'a0=00000000ffffffff', 'v0=ffffffffffffffff')
T('slt_and_sltu', 'slt $2,$4,$5\nsltu $3,$4,$5', 'a0=ffffffffffffffff,a1=1', 'v0=1,v1=0')
T('sltiu_sign_extended_imm', 'sltiu $2,$4,-1', 'a0=fffffffffffffffe', 'v0=1')
T('lui_ori', 'lui $2,0x8001\nori $2,$2,0x2345', '', 'v0=ffffffff80012345')
T('nor_and_xori', 'nor $2,$4,$0\nxori $3,$4,0xffff', 'a0=0000ffff0000ff00', 'v0=ffff0000ffff00ff,v1=0000ffff000000ff')
T('movn_moves_when_nonzero', 'movn $2,$4,$5\nmovz $3,$4,$5', 'a0=1234,a1=1,v0=0,v1=99', 'v0=1234,v1=99')
T('zero_register_reads_zero', 'addiu $0,$0,5\naddu $2,$0,$0', 'v0=7', 'v0=0')
# ---------------------------------------------------------------------------------------------------
# 2. multiply / divide, pipeline 0 and 1
# ---------------------------------------------------------------------------------------------------
T('mult_three_operand', 'mult $2,$4,$5', 'a0=10000,a1=10000', 'lo=0,hi=1,v0=0')
T('multu_large', 'multu $4,$5', 'a0=ffffffff,a1=2', 'lo=fffffffffffffffe,hi=1')
T('div_signed', 'div $0,$4,$5', 'a0=fffffffffffffff9,a1=2', 'lo=fffffffffffffffd,hi=ffffffffffffffff')
T('divu_unsigned', 'divu $0,$4,$5', 'a0=ffffffffffffffff,a1=2', 'lo=7fffffff,hi=1')
T('madd_accumulates', 'madd $2,$4,$5', 'lo=5,hi=0,a0=3,a1=4', 'lo=11,hi=0,v0=11')
T('madd_carry_into_hi', 'maddu $4,$5', 'lo=ffffffff,hi=0,a0=1,a1=1', 'lo=0,hi=1')
T('mult1_uses_hi1_lo1', 'mult1 $2,$4,$5', 'a0=fffffffe,a1=3,lo=77,hi=88',
  'lo1=fffffffffffffffa,hi1=ffffffffffffffff,v0=fffffffffffffffa,lo=77,hi=88')
T('div1_pipeline1', 'div1 $0,$4,$5', 'a0=d,a1=4', 'lo1=3,hi1=1')
T('mthi1_mflo1', 'mthi1 $4\nmtlo1 $5\nmfhi1 $2\nmflo1 $3', 'a0=11,a1=22', 'v0=11,v1=22,hi1=11,lo1=22')
# ---------------------------------------------------------------------------------------------------
# 3. loads and stores (little-endian), LQ/SQ alignment, unaligned pairs
# ---------------------------------------------------------------------------------------------------
T('lb_lbu_lh_lhu', f'lb $2,0($4)\nlbu $3,0($4)\nlh $5,2($4)\nlhu $6,2($4)',
  f'a0={D:x},m4:{D:x}=8001ff80', 'v0=ffffffffffffff80,v1=80,a1=ffffffffffff8001,a2=8001')
T('lw_sign_extends_ld', f'lw $2,0($4)\nld $3,0($4)', f'a0={D:x},m8:{D:x}=1122334488776655',
  'v0=ffffffff88776655,v1=1122334488776655')
T('sw_sh_sb', f'sw $5,0($4)\nsh $5,4($4)\nsb $5,6($4)', f'a0={D:x},a1=aabbccdd,m8:{D:x}=0',
  f'm8:{D:x}=00ddccddaabbccdd')
T('negative_offset', f'lw $2,-4($4)', f'a0={D + 8:x},m4:{D + 4:x}=12345678', 'v0=12345678')
T('lwl_lwr_unaligned', f'lwl $2,3($4)\nlwr $2,0($4)', f'a0={D + 1:x},m8:{D:x}=6655443322110099',
  'v0=33221100')
T('swl_swr_unaligned', f'swl $5,3($4)\nswr $5,0($4)', f'a0={D + 1:x},a1=aabbccdd,m8:{D:x}=0',
  f'm8:{D:x}=000000aabbccdd00')
T('ldl_ldr_unaligned', f'ldl $2,7($4)\nldr $2,0($4)', f'a0={D + 2:x},m16:{D:x}=' + q(0x44332211, 0x88776655, 0xccbbaa99, 0),
  'v0=aa99887766554433')
T('lq_ignores_low_bits', f'lq $2,0($4)', f'a0={D + 8:x},m16:{D:x}=' + q(1, 2, 3, 4), 'v0_qw=' + q(1, 2, 3, 4))
T('sq_stores_128', f'sq $5,0($4)', f'a0={D + 4:x},a1_qw=' + q(5, 6, 7, 8) + f',m16:{D:x}=0',
  f'm16:{D:x}=' + q(5, 6, 7, 8))
# ---------------------------------------------------------------------------------------------------
# 4. control flow: delay slots, likely branches, calls and returns
# ---------------------------------------------------------------------------------------------------
T('beq_taken_runs_delay_slot', 'beq $4,$5,Lt\naddiu $2,$0,1\naddiu $2,$0,2\nLt:\naddiu $3,$0,3',
  'a0=5,a1=5', 'v0=1,v1=3')
T('bne_not_taken', 'bne $4,$5,Lt\naddiu $2,$0,1\naddiu $2,$2,2\nLt:', 'a0=5,a1=5', 'v0=3')
T('beql_not_taken_nullifies', 'beql $4,$5,Lt\naddiu $2,$0,1\naddiu $3,$0,2\nLt:', 'a0=5,a1=6,v0=0', 'v0=0,v1=2')
T('bgezal_links', 'bgezal $4,Lf\nnop\nLret:\nb Lend\nnop\nLf:\njr $31\naddiu $2,$0,7\nLend:', 'a0=0', 'v0=7,ra=@Lret@')
T('jal_jr_ra', 'jal Lf\naddiu $2,$0,1\nb Lend\nnop\nLf:\njr $31\naddiu $3,$0,2\nLend:', '', 'v0=1,v1=2')
T('bltz_negative', 'bltz $4,Lt\nnop\naddiu $2,$0,9\nLt:', 'a0=ffffffffffffffff,v0=0', 'v0=0')
T('teq_traps', 'teq $4,$5', 'a0=3,a1=3', 'TRAP=trap')
# ---------------------------------------------------------------------------------------------------
# 5. MMI (128-bit lanes)
# ---------------------------------------------------------------------------------------------------
T('paddw_lanes', 'paddw $2,$4,$5', 'a0_qw=' + q(1, 0xffffffff, 3, 0x7fffffff) + ',a1_qw=' + q(1, 1, 3, 1),
  'v0_qw=' + q(2, 0, 6, 0x80000000))
T('paddsw_saturates', 'paddsw $2,$4,$5', 'a0_qw=' + q(0x7fffffff, 0x80000000, 5, 0xfffffffe) +
  ',a1_qw=' + q(1, 0xffffffff, 2, 1), 'v0_qw=' + q(0x7fffffff, 0x80000000, 7, 0xffffffff))
T('paddub_saturates', 'paddub $2,$4,$5', 'a0_qw=' + b(0xff, 0x80, 1, 0, *[0] * 12) + ',a1_qw=' + b(1, 0x80, 2, 0, *[0] * 12),
  'v0_qw=' + b(0xff, 0xff, 3, 0, *[0] * 12))
T('psubuh_floors_at_zero', 'psubuh $2,$4,$5', 'a0_qw=' + h(5, 1, 0x8000, 0, 0, 0, 0, 9) + ',a1_qw=' + h(3, 2, 1, 0, 0, 0, 0, 10),
  'v0_qw=' + h(2, 0, 0x7fff, 0, 0, 0, 0, 0))
T('pcgtb_signed', 'pcgtb $2,$4,$5', 'a0_qw=' + b(1, 0x80, 0x7f, *[0] * 13) + ',a1_qw=' + b(0, 0x7f, 0x80, *[0] * 13),
  'v0_qw=' + b(0xff, 0, 0xff, *[0] * 13))
T('pceqh', 'pceqh $2,$4,$5', 'a0_qw=' + h(1, 2, 3, 4, 5, 6, 7, 8) + ',a1_qw=' + h(1, 0, 3, 0, 5, 0, 7, 0),
  'v0_qw=' + h(0xffff, 0, 0xffff, 0, 0xffff, 0, 0xffff, 0))
T('pmaxw_pminh', 'pmaxw $2,$4,$5\npminh $3,$4,$5', 'a0_qw=' + q(0xffffffff, 5, 0, 0) + ',a1_qw=' + q(1, 3, 0, 0),
  'v0_qw=' + q(1, 5, 0, 0) + ',v1_qw=' + h(0xffff, 0xffff, 3, 0, 0, 0, 0, 0))
T('pabsw_saturates', 'pabsw $2,$5', 'a1_qw=' + q(0x80000000, 0xfffffffb, 7, 0), 'v0_qw=' + q(0x7fffffff, 5, 7, 0))
T('pextlw_interleaves', 'pextlw $2,$4,$5', 'a0_qw=' + q(0xa0, 0xa1, 0xa2, 0xa3) + ',a1_qw=' + q(0xb0, 0xb1, 0xb2, 0xb3),
  'v0_qw=' + q(0xb0, 0xa0, 0xb1, 0xa1))
T('pextub_upper_bytes', 'pextub $2,$4,$5', 'a0_qw=' + b(*[0] * 8, *range(0xa0, 0xa8)) + ',a1_qw=' + b(*[0] * 8, *range(0xb0, 0xb8)),
  'v0_qw=' + b(0xb0, 0xa0, 0xb1, 0xa1, 0xb2, 0xa2, 0xb3, 0xa3, 0xb4, 0xa4, 0xb5, 0xa5, 0xb6, 0xa6, 0xb7, 0xa7))
T('ppacb_packs_even_bytes', 'ppacb $2,$4,$5', 'a0_qw=' + b(*range(0x10, 0x20)) + ',a1_qw=' + b(*range(0x30, 0x40)),
  'v0_qw=' + b(0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e))
T('pcpyld_pcpyud', 'pcpyld $2,$4,$5\npcpyud $3,$4,$5', 'a0_qw=' + q(1, 2, 3, 4) + ',a1_qw=' + q(5, 6, 7, 8),
  'v0_qw=' + q(5, 6, 1, 2) + ',v1_qw=' + q(3, 4, 7, 8))
T('pexew_prot3w', 'pexew $2,$5\nprot3w $3,$5', 'a1_qw=' + q(0, 1, 2, 3), 'v0_qw=' + q(2, 1, 0, 3) + ',v1_qw=' + q(1, 2, 0, 3))
T('prevh_pcpyh', 'prevh $2,$5\npcpyh $3,$5', 'a1_qw=' + h(0, 1, 2, 3, 4, 5, 6, 7),
  'v0_qw=' + h(3, 2, 1, 0, 7, 6, 5, 4) + ',v1_qw=' + h(0, 0, 0, 0, 4, 4, 4, 4))
T('pinth_interleave', 'pinth $2,$4,$5', 'a0_qw=' + h(*range(0xa0, 0xa8)) + ',a1_qw=' + h(*range(0xb0, 0xb8)),
  'v0_qw=' + h(0xb0, 0xa4, 0xb1, 0xa5, 0xb2, 0xa6, 0xb3, 0xa7))
T('psllh_uses_low4_bits', 'psllh $2,$5,17', 'a1_qw=' + h(1, 0x8001, 0, 0, 0, 0, 0, 0xffff),
  'v0_qw=' + h(2, 2, 0, 0, 0, 0, 0, 0xfffe))
T('psravw_sign_extends', 'psravw $2,$5,$4', 'a0_qw=' + q(4, 0, 1, 0) + ',a1_qw=' + q(0x80000000, 7, 0x10, 9),
  'v0_qw=' + q(0xf8000000, 0xffffffff, 8, 0))
T('plzcw_counts_sign_bits', 'plzcw $2,$4', 'a0=fffffffe00010000', 'v0=0000001e0000000e')
T('pext5_ppac5', 'pext5 $2,$5\nppac5 $3,$2', 'a1_qw=' + q(0x0000ffff, 0x00000421, 0, 0x8000),
  'v0_qw=' + q(0x80f8f8f8, 0x00080808, 0, 0x80000000) + ',v1_qw=' + q(0xffff, 0x421, 0, 0x8000))
T('pmultw_hi_lo', 'pmultw $2,$4,$5', 'a0_qw=' + q(0x10000, 9, 0xffffffff, 9) + ',a1_qw=' + q(0x10000, 9, 3, 9),
  'v0_qw=' + q(0, 1, 0xfffffffd, 0xffffffff) + ',lo=0,hi=1,lo1=fffffffffffffffd,hi1=ffffffffffffffff')
T('pmaddw_accumulates', 'pmaddw $2,$4,$5', 'lo=2,hi=0,lo1=ffffffff,hi1=0,a0_qw=' + q(3, 0, 1, 0) + ',a1_qw=' + q(4, 0, 1, 0),
  'lo=e,hi=0,lo1=0,hi1=1,v0_qw=' + q(14, 0, 0, 1))
T('pmulth_lane_placement', 'pmulth $2,$4,$5', 'a0_qw=' + h(1, 2, 3, 4, 5, 6, 7, 8) + ',a1_qw=' + h(2, 2, 2, 2, 2, 2, 2, 0xffff),
  'v0_qw=' + q(2, 6, 10, 14) + ',lo_qw=' + q(2, 4, 10, 12) + ',hi_qw=' + q(6, 8, 14, 0xfffffff8))
T('phmadh_pairs', 'phmadh $2,$4,$5', 'a0_qw=' + h(1, 2, 3, 4, 5, 6, 7, 8) + ',a1_qw=' + h(1, 1, 1, 1, 1, 1, 1, 1),
  'v0_qw=' + q(3, 7, 11, 15) + ',lo_w0=3,hi_w0=7,lo_w2=b,hi_w2=f')
T('pdivw_two_lanes', 'pdivw $4,$5', 'a0_qw=' + q(7, 0, 0xfffffff8, 0) + ',a1_qw=' + q(2, 0, 3, 0),
  'lo=3,hi=1,lo1=fffffffffffffffe,hi1=fffffffffffffffe')
T('pmfhl_lw', 'pmfhl.lw $2', 'lo_qw=' + q(1, 2, 3, 4) + ',hi_qw=' + q(5, 6, 7, 8), 'v0_qw=' + q(1, 5, 3, 7))
T('pmfhl_slw_saturates', 'pmfhl.slw $2', 'lo_qw=' + q(0, 0, 5, 0) + ',hi_qw=' + q(1, 0, 0, 0),
  'v0_qw=' + q(0x7fffffff, 0, 5, 0))
T('pmfhl_sh_saturates', 'pmfhl.sh $2', 'lo_qw=' + q(0x8000, 0xffff7fff, 1, 2) + ',hi_qw=' + q(3, 4, 5, 6),
  'v0_qw=' + h(0x7fff, 0x8000, 3, 4, 1, 2, 5, 6))
T('pmthl_lw', 'pmthl.lw $4', 'a0_qw=' + q(1, 2, 3, 4) + ',lo_qw=0,hi_qw=0', 'lo_qw=' + q(1, 0, 3, 0) + ',hi_qw=' + q(2, 0, 4, 0))
T('pmfhi_pmtlo', 'pmtlo $4\npmfhi $2', 'a0_qw=' + q(1, 2, 3, 4) + ',hi_qw=' + q(9, 8, 7, 6), 'lo_qw=' + q(1, 2, 3, 4) + ',v0_qw=' + q(9, 8, 7, 6))
T('mtsab_qfsrv_byte_shift', 'mtsab $6,0\nqfsrv $2,$4,$5', 'a2=4,a0_qw=' + q(0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc) +
  ',a1_qw=' + q(0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c),
  'sa=20,v0_qw=' + q(0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x33221100))
T('mtsah_mfsa', 'mtsah $4,3\nmfsa $2', 'a0=5', 'v0=60')
T('por_pnor', 'por $2,$4,$5\npnor $3,$4,$5', 'a0_qw=' + q(1, 0, 0, 0xf0000000) + ',a1_qw=' + q(2, 0, 0, 0x0f000000),
  'v0_qw=' + q(3, 0, 0, 0xff000000) + ',v1_qw=' + q(0xfffffffc, 0xffffffff, 0xffffffff, 0x00ffffff))
# ---------------------------------------------------------------------------------------------------
# 6. FPU (COP1)
# ---------------------------------------------------------------------------------------------------
T('mtc1_add_s_mfc1', 'mtc1 $4,$f1\nmtc1 $5,$f2\nadd.s $f3,$f1,$f2\nmfc1 $2,$f3', f'a0={F1:x},a1={F2:x}',
  f'f3={F3:x},v0={F3:x}')
T('mfc1_sign_extends', 'mfc1 $2,$f1', f'f1={FM1:x}', 'v0=ffffffffbf800000')
T('madd_s_uses_acc', 'mula.s $f1,$f2\nmadd.s $f3,$f1,$f2', f'f1={F2:x},f2={F3:x}', f'ACC={F6:x},f3=41400000')
T('cvt_w_s_truncates', 'cvt.w.s $f2,$f1', 'f1=40600000', 'f2=3')
T('cvt_w_s_saturates', 'cvt.w.s $f2,$f1', 'f1=7f000000', 'f2=7fffffff')
T('c_lt_s_bc1t', 'c.lt.s $f1,$f2\nbc1t Lt\nnop\naddiu $2,$0,1\nLt:', f'f1={F1:x},f2={F2:x},v0=0', 'v0=0,fcsr=800000')
T('c_le_s_false_bc1f', 'c.le.s $f2,$f1\nbc1f Lt\nnop\naddiu $2,$0,1\nLt:', f'f1={F1:x},f2={F2:x},v0=0,fcsr=800000', 'v0=0,fcsr=0')
T('rsqrt_s', 'rsqrt.s $f3,$f1,$f2', f'f1={F6:x},f2={F4:x}', f'f3={F3:x}')
T('max_s_min_s', 'max.s $f3,$f1,$f2\nmin.s $f4,$f1,$f2', f'f1={FM1:x},f2={F2:x}', f'f3={F2:x},f4={FM1:x}')
# FCR31 flags: O 15 / U 14 (last operation), I 17 / D 16 (last division / square root), sticky SO 4,
# SU 3, SI 6, SD 5. The register results of overflowing operations are not checked (IEEE p-code; the EE clamps)
T('fcr31_overflow', 'mul.s $f3,$f1,$f2', f'f1=7f000000,f2={F2:x},fcsr=0', 'fcsr=8010')
T('fcr31_o_cleared_so_kept', 'add.s $f3,$f1,$f2', f'f1={F1:x},f2={F2:x},fcsr=8010', f'fcsr=10,f3={F3:x}')
T('fcr31_underflow', 'mul.s $f3,$f1,$f2', f'f1=800000,f2={F05:x},fcsr=0', 'fcsr=4008')
T('fcr31_div_by_zero', 'div.s $f3,$f1,$f2', f'f1={F1:x},f2=0,fcsr=0', 'fcsr=10020')
T('fcr31_sqrt_negative', 'sqrt.s $f2,$f1', 'f1=c0800000,fcsr=0', f'fcsr=20040,f2={F2:x}')
T('lwc1_swc1', f'lwc1 $f1,0($4)\nswc1 $f1,4($4)', f'a0={D:x},m8:{D:x}={F5:x}', f'f1={F5:x},m8:{D:x}={F5:08x}{F5:08x}')
# ---------------------------------------------------------------------------------------------------
# 7. VU0 macro mode (COP2)
# ---------------------------------------------------------------------------------------------------
T('lqc2_sqc2', f'lqc2 $vf1,0($4)\nsqc2 $vf1,16($4)', f'a0={D:x},m16:{D:x}=' + q(F1, F2, F3, F4),
  f'vf1=' + q(F1, F2, F3, F4) + f',m16:{D + 16:x}=' + q(F1, F2, F3, F4))
T('vadd_dest_mask', 'vadd.xz $vf3,$vf1,$vf2', 'vf1=' + q(F1, F1, F1, F1) + ',vf2=' + q(F2, F2, F2, F2) + ',vf3=0',
  'vf3=' + q(F3, 0, F3, 0))
T('vmulx_broadcast', 'vmulx.xyzw $vf3,$vf1,$vf2x', 'vf1=' + q(F1, F2, F3, F4) + ',vf2=' + q(F2, 0, 0, 0),
  'vf3=' + q(F2, F4, F6, F8))
T('vf0_reads_0001', 'vadd.xyzw $vf3,$vf0,$vf0', 'vf3=' + q(1, 1, 1, 1), 'vf3=' + q(0, 0, 0, F2))
T('vf0_write_discarded', 'vadd.xyzw $vf0,$vf1,$vf1\nvadd.xyzw $vf2,$vf0,$vf0', 'vf1=' + q(F1, F1, F1, F1),
  'vf2=' + q(0, 0, 0, F2))
T('vmula_vmadd_acc', 'vmula.xyzw $ACC,$vf1,$vf2\nvmadd.xyzw $vf3,$vf1,$vf2', 'vf1=' + q(F1, F2, F3, F4) + ',vf2=' + q(F2, F2, F2, F2),
  'vf3=' + q(F4, F8, 0x41400000, 0x41800000))
T('vsub_operand_order', 'vsub.xyzw $vf3,$vf1,$vf2', 'vf1=' + q(F5, F5, F5, F5) + ',vf2=' + q(F1, F2, F3, F4),
  'vf3=' + q(F4, F3, F2, F1))
T('vdiv_vaddq', 'vdiv $Q,$vf1x,$vf2y\nvwaitq\nvaddq.x $vf3,$vf0,$Q', 'vf1=' + q(F6, 0, 0, 0) + ',vf2=' + q(0, F2, 0, 0),
  f'vi22={F3:x},vf3x={F3:x}')
T('vsqrt_q', 'vsqrt $Q,$vf1y', 'vf1=' + q(0, 0x41800000, 0, 0), f'vi22={F4:x}')
T('vclipw_flags', 'vclipw.xyz $vf1,$vf2w', 'vf1=' + q(F3, FM1, 0xc0400000, 0) + ',vf2=' + q(0, 0, 0, F2) + ',vi18=1',
  'vi18=61')
T('vitof4_vftoi4', 'vitof4.xyzw $vf2,$vf1\nvftoi4.xyzw $vf3,$vf2', 'vf1=' + q(16, 0xfffffff0, 8, 0),
  'vf2=' + q(F1, FM1, F05, 0) + ',vf3=' + q(16, 0xfffffff0, 8, 0))
T('vmr32_rotates', 'vmr32.xyzw $vf2,$vf1', 'vf1=' + q(F1, F2, F3, F4), 'vf2=' + q(F2, F3, F4, F1))
T('vopmula_vopmsub_cross', 'vopmula.xyz $ACC,$vf1,$vf2\nvopmsub.xyz $vf3,$vf2,$vf1',
  'vf1=' + q(F1, 0, 0, 0) + ',vf2=' + q(0, F1, 0, 0) + ',vf3=' + q(0, 0, 0, F5),
  'vf3=' + q(0, 0, F1, F5))
T('viaddi_vior', 'viaddi $vi1,$vi2,-3\nvior $vi3,$vi1,$vi2', 'vi2=5,vi1=0,vi3=0', 'vi1=2,vi3=7')
T('viadd_wraps_16bit', 'viadd $vi1,$vi2,$vi3', 'vi2=ffff,vi3=2', 'vi1=1')
T('vlqi_vu0_memory', 'vlqi.xyzw $vf1,($vi1++)', 'vi1=2,m16:11004020=' + q(F1, F2, F3, F4), 'vf1=' + q(F1, F2, F3, F4) + ',vi1=3')
T('vsqd_vu0_memory', 'vsqd.xw $vf1,(--$vi1)', 'vi1=1,vf1=' + q(F1, F2, F3, F4) + ',m16:11004000=0',
  'vi1=0,m16:11004000=' + q(F1, 0, 0, F4))
T('viswr_vilwr', 'viswr.y $vi2,($vi1)\nvilwr.y $vi3,($vi1)', 'vi1=1,vi2=1234,vi3=0,m16:11004010=0',
  'vi3=1234,m16:11004010=' + q(0, 0x1234, 0, 0))
T('qmtc2_qmfc2', 'qmtc2 $4,$vf1\nqmfc2 $2,$vf1', 'a0_qw=' + q(1, 2, 3, 4), 'vf1=' + q(1, 2, 3, 4) + ',v0_qw=' + q(1, 2, 3, 4))
T('ctc2_cfc2', 'ctc2 $4,$vi21\ncfc2 $2,$vi21', f'a0={F1:x}', f'vi21={F1:x},v0={F1:x}')
T('vaddi_uses_I', 'vaddi.xyzw $vf2,$vf1,$I', f'vi21={F2:x},vf1=' + q(F1, F2, F3, F4), 'vf2=' + q(F3, F4, F5, F6))
T('vmfir_sign_extends', 'vmfir.xy $vf1,$vi2', 'vi2=ffff,vf1=0', 'vf1=' + q(0xffffffff, 0xffffffff, 0, 0))
T('vmtir_low16', 'vmtir $vi1,$vf2y', 'vf2=' + q(0, 0x12345678, 0, 0), 'vi1=5678')
T('vrinit_vrget', 'vrinit $R,$vf1x\nvrget.x $vf2,$R', 'vf1=' + q(0xffffffff, 0, 0, 0), 'vi20=3fffffff,vf2x=3fffffff')
# MAC flags (vi17: Z 3..0, S 7..4, U 11..8, O 15..12, lane x highest) and Status (vi16: Z S U O in 0..3,
# I 4, D 5, sticky copies in 6..11)
T('vadd_mac_status', 'vadd.xyzw $vf3,$vf1,$vf2', 'vf1=' + q(F1, FM1, F1, F1) + ',vf2=' + q(FM1, FM1, F1, 0) + ',vi16=0',
  'vi17=48,vi16=c3')
T('vadd_mac_dest_masked', 'vadd.y $vf3,$vf1,$vf2', 'vf1=' + q(F1, FM1, F1, F1) + ',vf2=' + q(FM1, FM1, F1, 0) + ',vi16=1',
  'vi17=40,vi16=82')
T('vmula_sets_mac', 'vmula.w $ACC,$vf1,$vf2', 'vf1=' + q(0, 0, 0, F2) + ',vf2=' + q(0, 0, 0, 0x7f000000) + ',vi16=0',
  'vi17=1000,vi16=208')
T('vmax_keeps_mac', 'vmax.xyzw $vf3,$vf1,$vf2', 'vf1=' + q(F1, F1, F1, F1) + ',vf2=' + q(F2, F2, F2, F2) + ',vi17=1234',
  'vi17=1234')
T('vdiv_by_zero_flags', 'vdiv $Q,$vf1x,$vf2y', 'vf1=' + q(F1, 0, 0, 0) + ',vf2=' + q(0, 0, 0, 0) + ',vi16=0', 'vi16=820')
T('vsqrt_negative_flags', 'vsqrt $Q,$vf1y', 'vf1=' + q(0, 0xc0800000, 0, 0) + ',vi16=0', f'vi16=410,vi22={F2:x}')
T('vcallms_traps', 'vcallms 0x40', '', 'TRAP=vcallms,vi27=40')
# ---------------------------------------------------------------------------------------------------
# 8. COP0
# ---------------------------------------------------------------------------------------------------
T('ei_kernel_mode', 'ei', 'Status=0', 'Status=10000')
T('di_user_mode_without_edi', 'di', 'Status=10010', 'Status=10010')
T('di_user_mode_with_edi', 'di', 'Status=30010', 'Status=20010')
T('mtc0_mfc0_status', 'mtc0 $4,$12\nmfc0 $2,$12', 'a0=80000001', 'Status=80000001,v0=ffffffff80000001')
T('mfc0_count_is_hardware', 'mfc0 $2,$9', '', 'TRAP=readCount')
# ---------------------------------------------------------------------------------------------------
# the deliberately wrong expectation (must be reported)
# ---------------------------------------------------------------------------------------------------
T('XFAIL_addu_wrong_expectation', 'addu $2,$4,$5', 'a0=1,a1=2', 'v0=4')
