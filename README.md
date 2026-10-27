# Ghidra Emotion Engine: Reloaded [![run tests](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml)
An extension for Ghidra that adds support for the PlayStation 2.

This extension is based on the original [ghidra-emotionengine](https://github.com/beardypig/ghidra-emotionengine) project, with a number of changes.

> **Ghidra-Rare fork.** This is the [Ghidra-Rare](https://github.com/aleph-void/Ghidra-Rare) fork of
> chaoticgd's extension (branch `ghidra-rare`). It gives the MMI and VU0 macro-mode instructions real
> p-code semantics, fixes a number of decoding and semantic errors found by differential testing against
> GNU objdump and rabbitizer, and adds a test suite. See [GHIDRA-RARE.md](GHIDRA-RARE.md) for what was
> verified and how, and [CREDITS.md](CREDITS.md) for the authors and the list of changes. Prebuilt zips for
> the three newest Ghidra releases are on this fork's Releases page.

## Features

- Disassemble and decompile EE-specific instruction sets (MMI, VU0 macro mode, etc). In this fork the MMI
  and VU0 macro-mode instructions decompile to their lane-by-lane arithmetic instead of intrinsic calls.
- Recover data types, functions and global variables from ELF files with `.mdebug` sections with the included STABS Analyzer.
- Import PCSX2 save states.
- Fix references to global variables with the MIPS-R5900 Constant Reference Analyzer.

## Installation

Release builds of this fork (Ghidra 12.1.3, 12.1.4 and 12.2) are on this fork's Releases page. Upstream
release builds are available on the [releases](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases) page. Unstable builds, generated whenever there is a push to the main branch, are available [here](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases/tag/unstable). To install the package, follow the instructions in the [Ghidra documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md#extensions).

## Building

If you want to build the extension yourself, install `gradle` and run:
 
```
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

## Common Issues

### 7-Zip returned unsupported method

Modern versions of PCSX2 store save states using zstd compression by default, which Ghidra's zip implementation doesn't support. To work around this, if you are using PCSX2 v2.1.178 or higher you should make sure that `Tools -> Show Advanced Settings` is checked, then navigate to `File -> Settings -> Advanced -> Savestate Settings` and change the `Compression Method` option to `Deflate64`. If you are using an older version, you will have to change `SavestateZstdCompression` to `false` in the `EmuCore` section of your `PCSX2.ini` file.

### Decompilation fails for some functions

Try disabling the `Decompiler Parameter ID` analyzer. (In the Ghidra-Rare tests, every function of the
PS2SDK sample programs decompiled with the default analyzers; see GHIDRA-RARE.md.)

## Known limitations

Upstream's known issues and what the Ghidra-Rare fork did about them (details in GHIDRA-RARE.md):

- Fixed: PS2 ELFs with n32 flags (current ps2dev GCC) were imported as generic MIPS (#127).
- Fixed: polling loops on COP0.Count were folded away by the decompiler (#98).
- Fixed: `ctc2`/`cfc2` control-register operands, `vcallmsr` naming, random-number instructions,
  `dsra32` special case, invented pseudo-instructions (beardypig #76, #73, #72, #58, #38).
- Fixed: VU macro instructions were pcodeop stubs; they now have p-code semantics (beardypig #77, #45).
- Remaining: VU micro mode (VU0/VU1 microprograms) is not disassembled: it is a separate processor with its own
  instruction set (upstream removed the old, broken support; #122, beardypig #77).
- Fixed: the FPU (FCR31) and VU (MAC, Status) flags are updated.
- Remaining: the EE's FPU and VUs are not IEEE 754 (no infinities/NaNs, round toward zero); p-code float
  operations are IEEE single precision with round-to-nearest, so results can differ in the last bit and at
  overflow (modelling it exactly would replace every decompiled float expression by integer bit operations).
- Remaining: overlays loaded at run time (Metrowerks overlay files, #57), library identification (#114, #115),
  DWARF 1 (#99) and the macOS symbol-tree filter lag (#52) are outside the processor module.

### Symbols aren't being demangled

Enable the `Use Deprecated Demangler` option in the settings for the `Demangler GNU` analyzer.
