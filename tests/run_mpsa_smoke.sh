#!/bin/bash
# End-to-end MPSA smoke test. Requires the frontend binary already built.
# The HIGH-severity wiring TODOs were closed in subsequent commits; only
# OSN role/semantics verification and the real VOLE-PSI MPSI swap remain
# (see docs/DEFERRED_AUDITS.md). The smoke test may still fail if the
# OSN semantic assumption in MpShuffleDriver doesn't match the actual
# osn/OSNSender.cpp behavior.
set -euo pipefail

N=3
BUILD=./out/build/linux/frontend/frontend
PORT=17500

echo "Generating dataset..."
python3 tests/gen_mpsa_dataset.py --N "$N" --total 1000 --intersect 100 --outdir dataset

echo "Spawning SP..."
"$BUILD" -mpsa -N "$N" -r 0 -port "$PORT" -out dataset/out_mpsa.csv &
SP_PID=$!
sleep 1

echo "Spawning $N senders..."
SENDER_PIDS=()
for i in $(seq 0 $((N-1))); do
    "$BUILD" -mpsa -N "$N" -r 1 -i "$i" -port "$PORT" -host localhost -in "dataset/sender_${i}.csv" &
    SENDER_PIDS+=($!)
done

wait "$SP_PID"
for pid in "${SENDER_PIDS[@]}"; do
    wait "$pid"
done

ACTUAL=$(wc -l < dataset/out_mpsa.csv)
if [ "$ACTUAL" -ne 100 ]; then
    echo "FAIL: expected 100 rows, got $ACTUAL"
    exit 1
fi
echo "PASS: $ACTUAL intersection rows recovered"
