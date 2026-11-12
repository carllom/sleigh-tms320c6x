#!/bin/bash
# Build lib/TMS320C6x.jar from src/main/java with the Ghidra install's jars.
# Run from WSL or adapt the JDK path; Ghidra must be restarted afterwards.
set -e
M="$(cd "$(dirname "$0")" && pwd)"
G="$(cd "$M/../../.." && pwd)/Ghidra"
JDK="${JDK:-/mnt/c/Users/clo/tools/jdk21.0.7_6}"
win() { if command -v wslpath >/dev/null; then wslpath -w "$1"; else echo "$1"; fi; }
SEP=";"; [ -x "$JDK/bin/javac" ] && SEP=":"
JAVAC="$JDK/bin/javac"; [ -x "$JAVAC" ] || JAVAC="$JDK/bin/javac.exe"
JAR="$JDK/bin/jar"; [ -x "$JAR" ] || JAR="$JDK/bin/jar.exe"
CP=""
for j in "$G"/Framework/*/lib/*.jar "$G"/Features/Base/lib/Base.jar; do CP="$CP$SEP$(win "$j")"; done
OUT="$M/build/classes"
rm -rf "$M/build"; mkdir -p "$OUT"
SRCS=()
while IFS= read -r f; do SRCS+=("$(win "$f")"); done < <(find "$M/src/main/java" -name '*.java')
"$JAVAC" --release 21 -nowarn -cp "${CP#$SEP}" -d "$(win "$OUT")" "${SRCS[@]}"
"$JAR" cf "$(win "$M/lib/TMS320C6x.jar")" -C "$(win "$OUT")" .
rm -rf "$M/build"
echo "built $M/lib/TMS320C6x.jar"
