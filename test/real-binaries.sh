#!/usr/bin/env bash
# Real-code check: build the PS2SDK sample programs with the ps2dev toolchain (GCC 15, binutils, newlib,
# ps2sdk: GPL/LGPL tools, AFL-2.0 / BSD / newlib libraries; all freely licensed), import each ELF into
# Ghidra without forcing the language (the ELF opinion must pick r5900:LE:32:default), analyse, count
# functions / bookmarks / decompile failures, and compare every disassembled instruction with GNU objdump.
#
#   GHIDRA_INSTALL_DIR=... test/real-binaries.sh <workdir>
#
# Nothing downloaded here is committed. The toolchain release is pinned by URL and SHA-256; set
# PS2DEV_TARBALL to a local copy to skip the download.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "${1:?workdir}")
mkdir -p "$W"
URL=https://github.com/ps2dev/ps2dev/releases/download/v2.0.0/ps2dev-ubuntu-latest.tar.gz
SHA=c8e5dedccf62084d476894e88cd0451b57f1ed288e741eb3c1263010aaffc028
TAR=${PS2DEV_TARBALL:-$W/ps2dev-ubuntu-latest.tar.gz}
if [[ ! -f $TAR ]]; then curl -sSL -o "$TAR" "$URL"; fi
echo "$SHA  $TAR" | sha256sum -c --quiet
if [[ ! -d $W/ps2dev ]]; then tar -xzf "$TAR" -C "$W"; fi
export PS2DEV=$W/ps2dev PS2SDK=$W/ps2dev/ps2sdk GSKIT=$W/ps2dev/gsKit
export PATH=$PS2DEV/bin:$PS2DEV/ee/bin:$PS2DEV/iop/bin:$PS2DEV/dvp/bin:$PATH
rm -rf "$W/samples" && cp -r "$PS2SDK/samples" "$W/samples"
SAMPLES=(graph font kernel/systemTime kernel/timer_alarm libcglue/regress draw/teapot draw/cube libgs/draw
	libgs/doublebuffer mpeg debug/callstacktest)
fail=0
mkdir -p "$W/out"
printf '%-24s %8s %6s %6s %6s %6s %s\n' sample insns funcs errors warns decomp-fail objdump
for s in "${SAMPLES[@]}"; do
	(cd "$W/samples/$s" && make -s >/dev/null 2>&1) || { echo "build failed: $s"; fail=1; continue; }
	elf=$(ls "$W/samples/$s"/*.elf | head -1)
	n=$(echo "$s" | tr / _)
	"$HERE/ghidra-script.sh" auto - "$elf" RealCheck.java "$W/out/$n.sum" "$W/out/$n.lst" 100000
	grep -q '^language r5900:LE:32:default' "$W/out/$n.sum" || { echo "$s: wrong language"; fail=1; }
	cmp=$(python3 "$HERE/real_compare.py" "$W/out/$n.lst" "$elf" > "$W/out/$n.cmp" && head -1 "$W/out/$n.cmp" ||
		{ fail=1; head -1 "$W/out/$n.cmp"; })
	errs=$(grep -c '^Error/' "$W/out/$n.sum" || true)
	warns=$(grep '^Warning/' "$W/out/$n.sum" | grep -v -c -E 'non-existing memory at 00000000|GP Global Register|Warning/DWARF' || true)
	df=$(sed -n 's/^decompiled [0-9]* failed \([0-9]*\).*/\1/p' "$W/out/$n.sum")
	printf '%-24s %8s %6s %6s %6s %6s %s\n' "$s" "$(sed -n 's/^instructions //p' "$W/out/$n.sum")" \
		"$(sed -n 's/^functions //p' "$W/out/$n.sum")" "$errs" "$warns" "$df" "${cmp#*: }"
	if ((errs > 0 || df > 0)); then fail=1; fi
done
exit $fail
