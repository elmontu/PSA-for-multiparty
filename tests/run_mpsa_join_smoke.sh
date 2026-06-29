#!/bin/bash
# R33 smoke test: end-to-end N-party table-valued private join wire
# protocol. Trusted-SP model (see docs/PRIVATE_JOIN_DESIGN.md).
set -euo pipefail

N=${N:-3}
M=${M:-2}
W=${W:-2}
INTERSECT=${INTERSECT:-5}
EXTRA=${EXTRA:-3}
BUILD=./out/build/linux/frontend/frontend
PORT=${PORT:-17900}
OUTDIR=${OUTDIR:-dataset_join}

if [ ! -x "$BUILD" ]; then
    echo "FAIL: frontend binary not found at $BUILD"; exit 1
fi

echo "Generating join dataset (N=$N, M=$M, W=$W, intersect=$INTERSECT, extra=$EXTRA)..."
python3 tests/gen_mpsa_join_dataset.py --N "$N" --M "$M" --W "$W" \
        --intersect "$INTERSECT" --extra "$EXTRA" \
        --outdir "$OUTDIR"

EXPECTED=$(cat "$OUTDIR/expected_rows.txt")
echo "Expected joined rows: $EXPECTED"

echo "Spawning SP..."
"$BUILD" -mpsa-join -N "$N" -r 0 -port "$PORT" -pw "$W" -M "$M" \
         -out "$OUTDIR/out_join.csv" &
SP_PID=$!
sleep 1

echo "Spawning $N senders..."
SENDER_PIDS=()
for i in $(seq 0 $((N-1))); do
    "$BUILD" -mpsa-join -N "$N" -r 1 -i "$i" -port "$PORT" -host localhost \
             -pw "$W" -M "$M" -in "$OUTDIR/sender_${i}.csv" &
    SENDER_PIDS+=($!)
done

wait "$SP_PID"
for pid in "${SENDER_PIDS[@]}"; do
    wait "$pid"
done

ACTUAL=$(wc -l < "$OUTDIR/out_join.csv")
if [ "$ACTUAL" -ne "$EXPECTED" ]; then
    echo "FAIL: expected $EXPECTED joined rows, got $ACTUAL"
    exit 1
fi

# Field-count check: each row should have N*W comma-separated hex blocks.
EXPECTED_FIELDS=$((N * W))
ACTUAL_FIELDS=$(head -n 1 "$OUTDIR/out_join.csv" | awk -F',' '{print NF}')
if [ "$ACTUAL_FIELDS" -ne "$EXPECTED_FIELDS" ]; then
    echo "FAIL: expected $EXPECTED_FIELDS blocks/row, got $ACTUAL_FIELDS"
    head -n 1 "$OUTDIR/out_join.csv"
    exit 1
fi

echo "PASS: $ACTUAL joined rows × $ACTUAL_FIELDS hex blocks (= N*W = $N*$W) per row"
