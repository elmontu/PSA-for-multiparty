#!/bin/bash
# End-to-end probe: run vendored MPSO MPSICS with k parties in-process.
# Two phases:
#   1. Offline pregen (each party independently).
#   2. Online MPSICS.
# Party 0 prints PASS/FAIL comparing MPSICS output to cleartext ground truth.
set -euo pipefail

K=${K:-3}         # party count
NN=${NN:-6}       # log2(elements per set)
PROBE=./out/build/linux/tests/unit/mpso_mpsics_probe

# MPSICS writes/reads offline VOLE files under ./offline/ relative to CWD.
# Run from a clean workdir so leftover files don't pollute.
WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT
cp "$PROBE" "$WORKDIR/mpso_mpsics_probe"

cd "$WORKDIR"
mkdir -p offline

echo "=== Phase 1: offline pregen (k=$K, nn=$NN) ==="
PIDS=()
for i in $(seq 0 $((K-1))); do
    ./mpso_mpsics_probe -preGen -r $i -k $K -nn $NN > pregen_$i.log 2>&1 &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait $pid; done
echo "  pregen done"
ls offline/ | head -20 > /dev/null
echo "  offline files: $(ls offline/ 2>/dev/null | wc -l)"

echo "=== Phase 2: online MPSICS ==="
PIDS=()
for i in $(seq 0 $((K-1))); do
    ./mpso_mpsics_probe -r $i -k $K -nn $NN > online_$i.log 2>&1 &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait $pid; done

echo "=== Party 0 result ==="
if grep -q "^PASS" online_0.log; then
    grep "^PASS" online_0.log
    exit 0
fi
if grep -q "^FAIL" online_0.log; then
    grep "^FAIL" online_0.log
    echo "--- online_0.log ---"; tail -20 online_0.log
    exit 1
fi
echo "party 0 produced neither PASS nor FAIL. Dumping logs:"
for i in $(seq 0 $((K-1))); do
    echo "--- online_$i.log ---"
    tail -15 online_$i.log
done
exit 2
