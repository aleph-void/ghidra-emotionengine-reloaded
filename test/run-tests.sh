#!/usr/bin/env bash
# EmotionEngine (R5900) module test suite: everything that needs no downloaded inputs.
#
#   GHIDRA_INSTALL_DIR=<scratch Ghidra 12.1.x> test/run-tests.sh [workdir] [--real]
#
# 1. the generator reproduces the checked-in SLEIGH (lanefields / lanes / eecore / vu .sinc)
# 2. the spec compiles (.sla well under 16 MB) and the module is linked into the Ghidra install
# 3. decode differential against GNU objdump -m mips:5900 (binutils 2.45) and rabbitizer (MIT, R5900
#    category): every opcode / function / format / VU field combination and 100,000 random words;
#    compare.py classifies every difference and fails on any unexplained one
# 4. every SLEIGH constructor is reached (Reach.java), including the paired LWL/LWR... forms
# 5. p-code: hand-computed emulator tests (EmuCheck.java), one deliberately wrong expectation must be reported
# --real adds step 6: PS2SDK samples built with the ps2dev toolchain, auto-imported, analysed, decompiled
#    and compared with GNU objdump (test/real-binaries.sh; downloads the pinned toolchain release)
#
# Environment: GHIDRA_INSTALL_DIR (a scratch copy of Ghidra 12.1.x: the module is symlinked into its
# Ghidra/Processors/EmotionEngine and its Java classes are built into lib/), JAVA_HOME (a JDK with javac),
# OBJDUMP (GNU objdump with mips:5900), RABBITIZER_PYTHON (a python with `pip install rabbitizer==1.16.2`),
# EE_AS / EE_LD / EE_OBJCOPY / EE_NM (ps2dev mips64r5900el-ps2-elf-* tools, used to assemble the emulator cases).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a scratch Ghidra 12.1.x}"
REAL=0
ARGS=()
for a in "$@"; do if [[ $a == --real ]]; then REAL=1; else ARGS+=("$a"); fi; done
W=$(readlink -m "${ARGS[0]:-${TMPDIR:-/tmp}/ee-tests}")
mkdir -p "$W"
export GHIDRA_INSTALL_DIR
fail=0
LANGID=r5900:LE:32:default
L=$MOD/data/languages

echo "== 1. generator reproduces the checked-in SLEIGH"
for k in lanefields lanes eecore vu; do
	python3 "$MOD/tools/gen_ee.py" $k | cmp - "$L/$k.sinc" || { echo "   $k.sinc differs"; fail=1; }
done

echo "== 2. SLEIGH compiles; Java classes built"
"$GHIDRA_INSTALL_DIR/support/sleigh" "$L/r5900.slaspec" 2>&1 | grep -E "^ERROR|^Error" && exit 1 || true
sz=$(stat -c %s "$L/r5900.sla")
echo "   r5900.sla: $sz bytes"
((sz < 16 * 1024 * 1024))
if [[ ! -f $MOD/lib/EmotionEngine.jar || -n $(find "$MOD/src" -newer "$MOD/lib/EmotionEngine.jar" -name '*.java') ]]; then
	BT=$(mktemp -d "$W/build.XXXXXX")
	B=$BT/EmotionEngine   # the extension (and jar) name comes from the directory name
	mkdir -p "$B"
	GRADLE=gradle
	[[ -x "$GHIDRA_INSTALL_DIR/support/gradle/gradlew" ]] && GRADLE="$GHIDRA_INSTALL_DIR/support/gradle/gradlew"
	tar -C "$MOD" --exclude=.git --exclude=test --exclude=lib -cf - . | tar -C "$B" -xf -
	(cd "$B" && "$GRADLE" --no-daemon -q buildExtension >/dev/null)
	mkdir -p "$MOD/lib"
	unzip -o -q -j "$B"/dist/*.zip '*/lib/EmotionEngine.jar' -d "$MOD/lib"
	rm -rf "$BT"
fi
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/EmotionEngine"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then
	echo "warning: $P exists and is not this module" >&2; fi

echo "== 3. decode differential (GNU objdump, rabbitizer)"
python3 "$HERE/gen_corpus.py" enum "$W/enum.bin" 1
python3 "$HERE/gen_corpus.py" random "$W/rand.bin" 100000 7
RPY=${RABBITIZER_PYTHON:-python3}
for c in enum rand; do
	"$HERE/ghidra-script.sh" raw $LANGID "$W/$c.bin" DumpSlots.java "$W/$c.gh" 4
	python3 "$HERE/oracle.py" objdump "$W/$c.bin" "$W/$c.od"
	python3 "$HERE/compare.py" "$W/$c.gh" "$W/$c.od" "$W/$c.bin" --show 6 > "$W/$c.cmp-objdump" || fail=1
	head -1 "$W/$c.cmp-objdump"
	if "$RPY" -I -c 'import rabbitizer' 2>/dev/null; then
		"$RPY" -I "$HERE/oracle.py" rabbitizer "$W/$c.bin" "$W/$c.rz"
		RABBITIZER_PYTHON=$RPY python3 "$HERE/compare.py" "$W/$c.gh" "$W/$c.rz" "$W/$c.bin" --oracle rabbitizer \
			--show 6 > "$W/$c.cmp-rabbitizer" || fail=1
		head -1 "$W/$c.cmp-rabbitizer"
	else
		echo "   rabbitizer not installed: skipped (pip install rabbitizer==1.16.2; set RABBITIZER_PYTHON)"
	fi
done
echo "== 3b. opcode tables of wasaylor/r5900-opcodes (MIT; fetched, pinned by commit and SHA-256)"
T=$W/r5900-opcodes
mkdir -p "$T"
OK=1
while read -r sha f; do
	[[ -f $T/$f ]] || curl -sSfL -o "$T/$f" \
		"https://raw.githubusercontent.com/wasaylor/r5900-opcodes/d734aeac9b6cfbfb36d36b050e93a2f88d996afc/$f" || OK=0
	[[ -f $T/$f ]] && echo "$sha  $T/$f" | sha256sum -c --quiet || OK=0
done <<'TABLES'
0915290a5ba8b976fac10f29546127261fd21082f31585c9db843676e851a230 opcodes-cpu
79c874f0b7048d2c7ad3fe18cd00db042cbed3029f668182e475ac97300b474e opcodes-cop1
fa909a1bd4e75c9e0186f0d8efaba67d748767432bf8a2c7ebc543ef49225048 opcodes-ee-core-specific
c63f3696b842f7a51a00770309ef477045735a91e0b64774e5834023200059b5 opcodes-system-control-coprocessor
TABLES
if ((OK)); then
	python3 "$HERE/table_check.py" gen "$T" "$W/tab.bin" "$W/tab.names"
	"$HERE/ghidra-script.sh" raw $LANGID "$W/tab.bin" DumpSlots.java "$W/tab.gh" 4
	python3 "$HERE/table_check.py" check "$W/tab.names" "$W/tab.gh" "$W/tab.bin" || fail=1
else
	echo "   could not fetch the tables (offline?): skipped"
fi
for f in "$W"/*.cmp-*; do grep -q UNEXPLAINED "$f" && { echo "   unexplained differences in $f:"; grep -A6 UNEXPLAINED "$f" | head -40; fail=1; }; done

echo "== 4. every constructor is reached"
cat "$W/enum.bin" "$W/rand.bin" > "$W/reach.bin"
"$HERE/ghidra-script.sh" raw $LANGID "$W/reach.bin" Reach.java "$W/reach1.txt" 4
"$HERE/ghidra-script.sh" raw $LANGID "$W/enum.bin" Reach.java "$W/reach2.txt" 4 PAIR_INSTRUCTION_FLAG=1
cat "$W/reach1.txt" "$W/reach2.txt" > "$W/reach.txt"
python3 "$HERE/reach_check.py" "$L" "$W/reach.txt" || fail=1

echo "== 5. p-code: hand-computed emulator tests"
python3 "$HERE/emu_tests.py" "$W/emu"
BASE_ADDR=0x100000 "$HERE/ghidra-script.sh" raw $LANGID "$W/emu/emu.bin" EmuCheck.java "$W/emu/tests.txt" "$W/emu/result.txt"
grep -v '^PASS' "$W/emu/result.txt" | grep -v '^emulator tests' || true
tail -1 "$W/emu/result.txt"
grep -q ' 0 failed, 1 broken expectations detected' "$W/emu/result.txt" || fail=1

if ((REAL)); then
	echo "== 6. real code: PS2SDK samples (ps2dev toolchain)"
	"$HERE/real-binaries.sh" "$W/real" || fail=1
fi

if ((fail)); then echo "FAILED"; exit 1; fi
echo "all tests passed"
