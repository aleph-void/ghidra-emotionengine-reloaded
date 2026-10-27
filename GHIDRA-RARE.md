# Ghidra-Rare notes: EmotionEngine (PS2 R5900)

This is the [Ghidra-Rare](https://github.com/aleph-void/Ghidra-Rare) fork of chaoticgd's
[Ghidra Emotion Engine: Reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded) (Apache-2.0),
verified to Ghidra-Rare's [verification bar](https://github.com/aleph-void/Ghidra-Rare/blob/main/docs/VERIFICATION.md).
Authors, upstream commit and the full list of changes: [CREDITS.md](CREDITS.md).

## What it covers

Language `r5900:LE:32:default` (processor `MIPS-R5900`, variant `PS2`): the EE core of the PlayStation 2 —
MIPS III integer instructions with 128-bit GPRs, the EE-specific instructions (LQ/SQ, the SA register,
pipeline-1 multiply/divide), the 107 multimedia (MMI) instructions, COP0 (including the debug and
performance-counter registers), the single-precision COP1 FPU and COP2 = VU0 in macro mode (upper,
special and integer instructions, VU0 data-memory transfers, QMFC2/QMTC2/CFC2/CTC2, VCALLMS). Plus
upstream's loader extensions (ELF section types, relocations), the constant-reference analyzer, the
STABS/`.mdebug` importer and the PCSX2 save-state importer, unchanged.

Not covered: VU0/VU1 **micro** mode (microprograms run on the vector units, a separate instruction set),
the IOP (an R3000A: Ghidra's own MIPS module), the GS.

## Semantics in this fork

Upstream deliberately kept the MMI and VU instructions as pcodeop stubs (`_paddb(...)`), after the old
lane-by-lane p-code of beardypig's version was found slow and unreadable (beardypig #45, #77). Ghidra-Rare's
bar requires p-code wherever p-code can express the behaviour, so `tools/gen_ee.py` generates the semantics
again, this time on *lane registers*: every 128-bit GPR, HI/LO, vf register and ACC is also defined as byte,
halfword, word and doubleword registers, and each lane of rs/rt/rd has its own operand subtable (register 0
reads as constant 0). The p-code stays small (no 128-bit masking), and the decompiler shows the arithmetic: a
VU0 4x4 matrix multiply from the PS2SDK samples decompiles to sixteen `a * b + c * d ...` float expressions.

Instruction semantics follow the EE Core Instruction Set Manual's descriptions:

- MMI: lane-wise add/sub (wrapping, signed- and unsigned-saturating), compares to all-ones masks, min/max,
  PABS (0x8000.. saturates), the pack/extend/interleave/exchange/reverse/rotate permutations, PEXT5/PPAC5,
  128-bit logic, shifts (halfword shifts use sa[3:0]; PSLLVW/PSRLVW/PSRAVW sign-extend the 32-bit result),
  PLZCW (leading sign bits - 1), QFSRV (funnel shift of {rs, rt} by SA bits), MTSAB/MTSAH (SA = byte / halfword
  count x 8 / x 16), PMULTW/PMULTUW/PMADDW/PMSUBW/PMADDUW (pipelines 0 and 1, HI/LO lanes sign-extended),
  PMULTH/PMADDH/PMSUBH/PHMADH/PHMSBH (HI/LO lane placement), PDIVW/PDIVUW/PDIVBW, PMFHL.{LW,UW,SLW,LH,SH}
  (with 16/32-bit saturation), PMTHL.LW, PMFHI/PMFLO/PMTHI/PMTLO, MULT1/MADD1/DIV1... on HI1/LO1.
- VU0 macro mode: per-lane float arithmetic with dest masks, broadcast (bc) and I/Q operands, ACC forms,
  OPMULA/OPMSUB (outer product, x/y/z), ITOF/FTOI with 0/4/12/15 fraction bits (FTOI saturates), ABS, MOVE,
  MR32, CLIPW (clipping flags shifted in vi18), DIV/SQRT/RSQRT into Q, integer ops on vi0-vi15 (16-bit),
  MTIR/MFIR, VU0 data memory at its EE address 0x11004000 (LQI/LQD/SQI/SQD, ILWR/ISWR with
  post-increment / pre-decrement), the random register R (RINIT/RGET/RXOR), QMFC2/QMTC2/CFC2/CTC2, LQC2/SQC2.
- Base ISA: 32-bit results sign-extended into the 64-bit view, the upper 64 bits of a GPR preserved;
  ADD/ADDI/SUB/DADD/DADDI/DSUB raise `integerOverflow` (the result is not written); traps call `trap`;
  LWL/LWR/LDL/LDR/SWL/SWR/SDL/SDR little-endian merging (and upstream's paired-load simplification);
  LQ/SQ/LQC2/SQC2 ignore address bits 3..0; EI/DI/ERET act on Status (EIE, EDI, EXL, ERL, KSU).
- Flags: FPU FCR31 O / U (FMAC operations) and I / D (DIV.S, SQRT.S, RSQRT.S) with their sticky bits; VU MAC
  flags (vi17: Z, S, U, O per lane, lanes outside dest cleared) and Status (vi16: Z S U O I D and sticky bits)
  for every FMAC operation and VDIV / VSQRT / VRSQRT. Overflow is detected as an infinite or NaN IEEE result and
  underflow as a non-zero denormal one, which is where the hardware clamps / flushes.
- Hardware state Ghidra cannot model is a pcodeop: COP0 Count / Random (`readCount`, `readRandom`, so the
  decompiler no longer folds polling loops, upstream #98), the performance counters, TLB operations, CACHE,
  SYNC, SYSCALL, BREAK, BC0x/BC2x conditions (external CPCOND inputs), VCALLMS (starts a microprogram on VU0),
  VRNEXT (see below).

## How to test

```
GHIDRA_INSTALL_DIR=<scratch copy of Ghidra 12.1.x> JAVA_HOME=<JDK with javac> \
RABBITIZER_PYTHON=<python with rabbitizer 1.16.2> test/run-tests.sh <workdir> [--real]
```

`test/run-tests.sh` symlinks the module into the given Ghidra, builds its Java classes into `lib/`, then:

1. `tools/gen_ee.py` reproduces the checked-in `lanefields.sinc`, `lanes.sinc`, `eecore.sinc`, `vu.sinc`;
2. `r5900.slaspec` compiles (`.sla` 162 KB);
3. decode differential (`gen_corpus.py`, `DumpSlots.java`, `oracle.py`, `compare.py`, `explain.py`) against
   GNU objdump 2.45 `-m mips:5900` and rabbitizer 1.16.2 (R5900 category, GNU mode off); 3b. every instruction
   of the [r5900-opcodes](https://github.com/wasaylor/r5900-opcodes) tables decodes as listed (`table_check.py`);
4. every SLEIGH constructor is reached (`Reach.java`, `reach_check.py`);
5. hand-computed emulator cases (`emu_cases.py`, assembled with the ps2dev GNU assembler by `emu_tests.py`,
   run by `EmuCheck.java`), including one wrong expectation that must be reported;
6. with `--real`: `real-binaries.sh` downloads the pinned ps2dev v2.0.0 toolchain release, builds eleven
   PS2SDK samples, imports each ELF without forcing the language, analyses it, decompiles every function,
   and compares every disassembled instruction with GNU objdump (`RealCheck.java`, `real_compare.py`).

## Results

Run on Ghidra 12.1.4 (`test/run-tests.sh <workdir> --real`); the module also compiles and builds on 12.1.3
and 12.2 (`tools/build-module.sh --standard --name EmotionEngine`).

| Area | Result |
|---|---|
| Build | `r5900.slaspec` compiles on 12.1.3, 12.1.4, 12.2 (`.sla` 162 KB); release zips built for all three |
| Decode vs GNU objdump 2.45 `-m mips:5900` | enumerated corpus (every opcode / function / format / VU field combination, 153,280 words): exact 31,358, semantic 27,636, both invalid 83,413, explained 10,873, **unexplained 0**; 100,000 random words: exact 7,222, semantic 61,986, both invalid 28,960, explained 1,832, **unexplained 0** |
| Decode vs rabbitizer 1.16.2 (R5900) | enumerated: exact 366, semantic 40,378, both invalid 82,523, explained 30,013, **unexplained 0**; random: exact 2, semantic 67,529, both invalid 18,192, explained 14,277, **unexplained 0** (rabbitizer spells registers and immediates differently, hence few exact matches) |
| Decode vs the r5900-opcodes tables | 275/275 listed instructions decode as listed (6,648 words with random free fields) |
| Every constructor reached | 667/667 (including upstream's paired LWL/LWR / LDL/LDR forms) |
| P-code, hand-computed | 122 emulator cases (ALU, 64-bit and 128-bit views, overflow traps, HI/LO and HI1/LO1, loads/stores incl. unaligned pairs and LQ/SQ, branches/likely branches/delay slots, MMI arithmetic/saturation/pack/shift/multiply/divide, FPU incl. FCR31 flags, VU0 macro mode incl. dest masks, vf0/vi0, ACC, Q, I, R, clipping, MAC and Status flags, VU0 memory, COP0 Status), plus 1 deliberately wrong expectation, which is detected |
| Real code | 11 PS2SDK samples built with the pinned ps2dev v2.0.0 toolchain: 380,075 instructions, 4,824 functions, all imported as `r5900:LE:32:default` by the opinion; 0 error bookmarks, 0 unexpected warnings, **0 decompile failures**; every disassembled instruction agrees with GNU objdump (exact or semantic), **0 unexplained** |

The only warning bookmarks on the samples are expected: "flow into non-existing memory at 00000000" (crt0
calls weak symbols that are not linked, e.g. `_init`), one "GP Global Register Set" per program, and DWARF
notes in the `-g` sample. The `mpeg` sample references 579 hardware registers (153 in `graph`).

Per sample (`test/real-binaries.sh`):

| Sample | Instructions | Functions | Errors | Decompile failures | vs objdump: exact / semantic / unexplained |
|---|---|---|---|---|---|
| graph | 31,017 | 408 | 0 | 0 | 12,008 / 19,009 / 0 |
| font | 41,435 | 463 | 0 | 0 | 16,138 / 25,297 / 0 |
| kernel/systemTime | 33,521 | 451 | 0 | 0 | 12,697 / 20,824 / 0 |
| kernel/timer_alarm | 29,915 | 446 | 0 | 0 | 11,622 / 18,293 / 0 |
| libcglue/regress | 39,978 | 542 | 0 | 0 | 15,174 / 24,804 / 0 |
| draw/teapot | 32,350 | 427 | 0 | 0 | 12,546 / 19,804 / 0 |
| draw/cube | 31,788 | 419 | 0 | 0 | 12,298 / 19,490 / 0 |
| libgs/draw | 32,584 | 387 | 0 | 0 | 12,170 / 20,414 / 0 |
| libgs/doublebuffer | 32,971 | 394 | 0 | 0 | 12,353 / 20,618 / 0 |
| mpeg | 40,915 | 433 | 0 | 0 | 15,550 / 25,365 / 0 |
| debug/callstacktest | 33,601 | 454 | 0 | 0 | 12,742 / 20,859 / 0 |

## Confirmed reference-tool bugs and disagreements

- **GNU objdump 2.45, `mips:5900`**: decodes JALX (primary opcode 29), WAIT, CFC0/CTC0 and the MIPS III FPU
  conversions (ROUND/TRUNC/CEIL/FLOOR .L/.W, CVT.L/CVT.D) for the R5900, none of which the R5900 has; has no
  VSQRT decode at all (prints `c2`; the ps2dev fork of binutils does decode it); decodes SQRT.S only in the
  MIPS form with the operand in fs (the R5900 reads ft, fs reserved: upstream, the r5900-opcodes table and
  the ps2dev assembler's encoding agree); rejects VU macro instructions whose reserved fields are non-zero,
  which real compiler output contains (upstream #38: `BD 03 25 4A` = `vsqrt Q,vf5x` from Sony's ee-objdump);
  accepts VCLIPW / VOPMULA / VOPMSUB only with dest .xyz.
- **rabbitizer 1.16.2**: falls back to its generic MIPS III / R3000 tables for R5900 words (LL/SC/LLD/SCD,
  LDC1/SDC1, LWC2/SWC2, DMFC0/DMTC0/DMFC1/DMTC1, DDIV/DMULT, RFE, the generic C.cond.S and conversions) although
  its own R5900 opcode tables list none of them; rejects SYSCALL with a non-zero code; has no
  performance-counter / debug-register forms (MFPC, MFPS, MFBPC...); accepts SYNC with any stype; knows the
  three-operand form only for MULT, not MULTU; prints SQRT.S as a raw `c1` word by design.
- **r5900-opcodes tables**: transcription slips corrected in `table_check.py` (LUI listed with a base field,
  LWU listed as a second LHU, MFLO as a second MFHI, MSUB.S function 0b01101, MTDAB/MTDABM/MTDVB without
  their function codes, PEXTUB/PEXTUH/PEXTUW under MMI2 instead of MMI1).

## Upstream known limitations and issues

Collected from the upstream README, the open and closed issues of chaoticgd/ghidra-emotionengine-reloaded and
of beardypig/ghidra-emotionengine (which it continues), and the TODO/FIXME comments.

| Issue | Status in this fork |
|---|---|
| Reloaded #127: ELF not detected as PS2 ELF | **Fixed**: the opinion also matches EF_MIPS_MACH = 0x92 with any ABI bits; the n32 ELFs of the current ps2dev GCC (e_flags 0x20920025) used to import as generic MIPS, now as `r5900:LE:32:default` (all eleven samples). |
| Reloaded #93: MMIO register references not found | **Fixed**: reproduced with the PS2SDK `mpeg` sample (138 hardware-register references with `mmio.sinc`, 579 without). The register names were SLEIGH symbols in the ram space; they are now `<default_symbols>` labels in `r5900.pspec` (all 173 kept; `ImportMMIORegisterLabels.java` updated), and the references are created. |
| Reloaded #98: COP0.Count assumed 0 | **Fixed**: MFC0 of Count and Random reads through `readCount` / `readRandom` pcodeops, so polling loops are no longer folded. |
| Reloaded #85: COP2 interlock bit always shown | Fixed upstream; checked by the differential (`.i` only with bit 0 set). |
| Reloaded #122 / beardypig #77: VU micro mode, VU decompilation unsound | **Remaining (separate processor)**: VU0/VU1 microprograms are a different instruction set running on the vector units; upstream removed the broken micro-mode support and `DvpOverlayTable` keeps it disabled (its TODOs). It would be a module of its own (`dvp-objdump` from the ps2dev toolchain is a usable reference). Macro mode, which runs on the EE, now has real semantics. Values a microprogram leaves in vf/vi registers are not visible to the EE-side decompilation (VCALLMS is a pcodeop). |
| beardypig #45: vector/matrix decompilation ergonomics; #77 | **Improved**: lane registers instead of 128-bit masking; matrix code decompiles to float expressions (see Semantics). |
| beardypig #76: wrong `ctc2` operand | **Fixed** (cfc2/ctc2 operands are vi0-vi31, as both references print). |
| beardypig #73: `callmsr` name | Fixed upstream (`vcallmsr`); it now always shows vi27 (the fs field is reserved). |
| beardypig #72: random-number instructions | **Fixed** for VRINIT / VRGET / VRXOR (p-code on R = vi20). **Remaining**: VRNEXT stays a pcodeop: the generator's feedback polynomial is not documented in any non-GPL source available to this project. |
| beardypig #58: `dsra32` special case | **Fixed**: removed (it hid the real instruction and had no p-code). |
| beardypig #54: ldl/ldr pairs decompile badly | Upstream's paired-load mechanism (`PAIR_INSTRUCTION_FLAG`, set by `MipsR5900PreAnalyzer`) is kept; both paired forms are reached by the every-entry test. Not separately re-verified on decompiler output. |
| beardypig #48: VU addressing hard-coded | **Fixed** for macro mode: VU0 data memory accesses address the EE's view at 0x11004000 with the quadword index wrapped to 4 KiB. |
| beardypig #38: invented `dmove`/`qmove`/`clear` | **Fixed**: the invented pseudo-instructions (`clear`, `moveq`) are removed; the aliases kept are GNU objdump's (`move`, `li`, `b`, `beqz`, `neg` ...). |
| beardypig #37: `&` instead of `&&` | **Fixed** (`MipsR5900AddressAnalyzer`). |
| beardypig #78, Reloaded #118, #124, #96: gp not recovered / incomplete analysis / analyzer stuck (Ghidra 10, 11.4) | **Not reproduced** on the eleven PS2SDK samples: the analyzer sets gp from `_gp` (one "GP Global Register Set" bookmark each) and references are created. The reports involve commercial games, a System 246 raw blob setting gp with `move`, and a BIOS dump, none of which can be used here: **unverified** for those inputs. |
| kotcrab/ghidra-allegrex #49: image base relocation broken with this extension installed | **Fixed**: `EE_ElfExtension` (priority 2) claimed every MIPS ELF; it now claims only R5900 / IRX / ERX ELFs and MIPS I / III files without a machine variant. PSP (Allegrex) ELFs are left to their own module. |
| Our own testing: FPU FCR31 and VU MAC / Status flags were never written | **Fixed**: FPU O/U/I/D (+ sticky) and VU MAC (Z, S, U, O per lane) and Status (Z S U O I D + sticky) flags are p-code now (emulator cases `fcr31_*`, `vadd_mac_*`, `vmula_sets_mac`, `vdiv_by_zero_flags`, `vsqrt_negative_flags`). |
| Reloaded #57: Japanese ELFs with overlays | **Remaining (loader feature)**: the code is in Metrowerks overlay files loaded at run time; supporting them is an importer feature outside the processor module. |
| Reloaded #114 / #115: identify static libraries / IRX libraries; beardypig #51 Function ID | **Remaining (outside the module)**: needs signature databases built from SDK libraries (the official ones are not redistributable). |
| Reloaded #99: DWARF 1 | **Remaining (outside the module)**: Ghidra's DWARF importer reads DWARF 2+; the module's `.dwarf` register mapping works for DWARF 2+ (the `libcglue/regress` sample imports its DWARF). |
| Reloaded #107: symbol tree fails to expand (Ghidra 12.0) | Fixed upstream (DvpOverlayTable disabled); no symbol-tree errors in headless runs. |
| Reloaded #52: lag filtering the symbol tree on macOS | **Unverified**: GUI on macOS, not testable here. |
| Reloaded #113: thunk P-code bleeds into caller | Ghidra decompiler behaviour for tail calls (upstream's answer), not a module issue. |
| beardypig #34: syscall signatures | `syscall` shows the v1 number (upstream); per-syscall signatures would need an OS model (outside the module). |
| beardypig #32: "Deleting integrated varnodes" | **Unverified**: reported on a commercial game; no decompiler failure in the samples (see Results). |
| README "Decompilation fails for some functions" | Not seen: every function of the samples decompiled with the default analyzers. |
| TODO/FIXME in `EE_ElfRelocationHandler`/`Context` (GP-relative, COPY, microMIPS, cross-mode jumps, multiple GPs) | Inherited verbatim from Ghidra's MIPS relocation handler; they concern dynamic linking, microMIPS and MIPS16, which PS2 executables do not use. Relocatable objects of the samples (`graph.o`) import without relocation errors. **Remaining** as in Ghidra. |
| TODO in `EE_ElfExtension` (IOPMOD sections) | **Remaining**: IOP modules are R3000A code for Ghidra's MIPS module; parsing their `.iopmod` section belongs to an IRX loader. |
| TODO in `MipsR5900PreAnalyzer` (delay-slot adjustment) | Inherited from Ghidra's MIPS pre-analyzer; behaviour unchanged. |

## Works / doesn't / unverified

| Area | State |
|---|---|
| Decode | 153,280 enumerated + 100,000 random words against GNU objdump 2.45 and rabbitizer 1.16.2: 0 unexplained differences (every difference class bucketed and explained, reference-tool bugs listed above); 275/275 r5900-opcodes table entries; 667/667 constructors reached |
| Semantics | Full p-code for the base ISA, MMI (107 instructions), COP0 Status/EPC handling, COP1 incl. FCR31 flags, VU0 macro mode incl. MAC/Status/clipping flags, Q, I, R and VU0 memory; 122/122 emulator cases, broken expectation detected |
| Real code | 11 PS2SDK samples (ps2dev v2.0.0): 380,075 instructions, 4,824 functions, 0 errors, 0 decompile failures, 100% agreement with objdump; auto-detected as `r5900:LE:32:default`; hardware-register references created (upstream #93) |
| Fixed here | MMI/VU0 macro semantics (were pcodeop stubs), FPU/VU flags, the base-MIPS/COP0/COP1 decode and semantic bugs listed in CREDITS.md, n32 ELF opinion (#127), MMIO references (#93), COP0.Count folding (#98), ELF extension claiming every MIPS ELF (Allegrex #49), `&`/`&&` (beardypig #37), invented aliases (#38, #58) |
| Doesn't work | The EE FPU and VUs are not IEEE 754 (no Inf/NaN/denormals: overflow clamps to ±max, underflow flushes to 0, rounding is toward zero): p-code float operations are IEEE round-to-nearest with no rounding-mode control, so reproducing this bit-exactly would mean integer emulation of every float operation and would turn every decompiled float expression into bit manipulation; results can differ in the last bit and at overflow/underflow (the flags are set as the hardware sets them). VRNEXT stays a pcodeop (the R register's feedback polynomial is not in any non-GPL source available here). VCALLMS / BC2x / COP0 Count, Random, TLB, cache and performance counters are pcodeops for hardware state outside the EE core (inherent). VU0/VU1 micro mode is a separate processor (not in this module). Overlays (#57), FID/library signatures (#114, #115), DWARF 1 (#99), IOP modules (R3000A) are outside the processor module |
| Unverified | Commercial games and BIOS images (not legally usable here): upstream reports of gp recovery / analysis stalls (#78, #118, #124, #96) and "Deleting integrated varnodes" (beardypig #32) could not be reproduced on the samples; macOS GUI lag (#52); hardware-exact flag behaviour at the clamping boundary |
