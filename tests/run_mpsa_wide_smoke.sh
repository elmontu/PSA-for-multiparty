#!/bin/bash
# R26b/step-5 smoke test: end-to-end MPSA with wide payload (W>1).
# Verifies that the cascade carries N*W single-block columns correctly
# and produces an output CSV with N*W comma-separated hex blocks per
# intersection row.
set -euo pipefail

N=3
W=${W:-4}
TOTAL=${TOTAL:-1000}
INTERSECT=${INTERSECT:-100}
BUILD=./out/build/linux/frontend/frontend
PORT=${PORT:-17600}    # different from baseline smoke (17500) to avoid collisions
OUTDIR=${OUTDIR:-dataset_wide}

if [ ! -x "$BUILD" ]; then
    echo "FAIL: frontend binary not found at $BUILD"
    exit 1
fi

echo "Generating wide dataset (N=$N, W=$W, total=$TOTAL, intersect=$INTERSECT)..."
python3 tests/gen_mpsa_dataset.py --N "$N" --total "$TOTAL" --intersect "$INTERSECT" \
        --outdir "$OUTDIR" --W "$W"

echo "Spawning SP (-pw $W)..."
"$BUILD" -mpsa -N "$N" -r 0 -port "$PORT" -pw "$W" -out "$OUTDIR/out_wide.csv" &
SP_PID=$!
sleep 1

echo "Spawning $N senders (each with -pw $W)..."
SENDER_PIDS=()
for i in $(seq 0 $((N-1))); do
    "$BUILD" -mpsa -N "$N" -r 1 -i "$i" -port "$PORT" -host localhost \
             -pw "$W" -in "$OUTDIR/sender_${i}.csv" &
    SENDER_PIDS+=($!)
done

wait "$SP_PID"
for pid in "${SENDER_PIDS[@]}"; do
    wait "$pid"
done

ACTUAL_ROWS=$(wc -l < "$OUTDIR/out_wide.csv")
if [ "$ACTUAL_ROWS" -ne "$INTERSECT" ]; then
    echo "FAIL: expected $INTERSECT rows, got $ACTUAL_ROWS"
    exit 1
fi

# Each row should have N*W comma-separated hex blocks. Each block prints
# as exactly 32 hex chars (the existing block::operator<< writes 32 chars
# with no padding). Sample first row.
FIRST=$(head -n 1 "$OUTDIR/out_wide.csv")
EXPECTED_FIELDS=$((N * W))
ACTUAL_FIELDS=$(echo "$FIRST" | awk -F',' '{print NF}')
if [ "$ACTUAL_FIELDS" -ne "$EXPECTED_FIELDS" ]; then
    echo "FAIL: expected $EXPECTED_FIELDS comma-separated blocks per row, got $ACTUAL_FIELDS"
    echo "  first row: $FIRST"
    exit 1
fi

echo "PASS: $ACTUAL_ROWS rows × $ACTUAL_FIELDS hex blocks (= N*W = $N*$W) per row"
