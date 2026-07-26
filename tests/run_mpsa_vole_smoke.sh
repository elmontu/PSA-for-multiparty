#!/bin/bash
# End-to-end MPSA smoke with the Stage B VOLE-PSI backend.
# Same as run_mpsa_smoke.sh but passes -mpsi-backend vole to SP and every
# sender. Verifies the vendored ladnir/volepsi 2PC RsPsi cascade actually
# reaches the same intersection cardinality as the default Simple-Hash
# backend.
set -euo pipefail

N=3
BUILD=./out/build/linux/frontend/frontend
PORT=17510   # +10 offset from the default smoke to allow parallel runs

echo "Generating dataset..."
python3 tests/gen_mpsa_dataset.py --N "$N" --total 1000 --intersect 100 --outdir dataset

echo "Spawning SP (mpsi-backend vole)..."
"$BUILD" -mpsa -N "$N" -r 0 -port "$PORT" -out dataset/out_mpsa_vole.csv \
    -mpsi-backend vole &
SP_PID=$!
sleep 1

echo "Spawning $N senders (mpsi-backend vole)..."
SENDER_PIDS=()
for i in $(seq 0 $((N-1))); do
    "$BUILD" -mpsa -N "$N" -r 1 -i "$i" -port "$PORT" -host localhost \
        -in "dataset/sender_${i}.csv" -mpsi-backend vole &
    SENDER_PIDS+=($!)
done

wait "$SP_PID"
for pid in "${SENDER_PIDS[@]}"; do
    wait "$pid"
done

ACTUAL=$(wc -l < dataset/out_mpsa_vole.csv)
if [ "$ACTUAL" -ne 100 ]; then
    echo "FAIL: expected 100 rows, got $ACTUAL"
    exit 1
fi
echo "PASS: $ACTUAL intersection rows recovered (vole backend)"
