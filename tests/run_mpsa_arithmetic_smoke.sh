#!/bin/bash
# End-to-end MPSA test with numeric fixed-point payloads.
#
# Sender 0 contributes x_i, sender 1 contributes y_i, sender 2 contributes
# z_i for each intersection ID. After MPSA (MPSI + cascade shuffle +
# A-sum + A-mset-row integrity), SP outputs a shuffled table of (x, y, z)
# triples for the intersection IDs. The verifier reads each output row,
# extracts (x, y, z) as fixed-point uint64, and checks that:
#   1. Each observed (x, y, z) triple is a legitimate triple from ground
#      truth -- i.e., no cross-sender payload mixing.
#   2. Per-row (x + y) * scale / z matches the expected fixed-point ratio.
# Runs with both MPSI backends to prove the arithmetic works end-to-end
# regardless of which backend the operator chose.
set -euo pipefail

INTERSECT=${INTERSECT:-25}
SCALE=${SCALE:-1000000}
BUILD=./out/build/linux/frontend/frontend

run_backend() {
    local backend="$1"
    local outdir="dataset_arith_${backend}"
    local port="$2"
    local outcsv="${outdir}/out.csv"

    echo "=== backend=${backend} =============================================="
    echo "Generating dataset (intersect=${INTERSECT}, scale=${SCALE})..."
    python3 tests/gen_mpsa_arithmetic_dataset.py \
        --intersect "$INTERSECT" --scale "$SCALE" \
        --outdir "$outdir"

    echo "Spawning SP on port $port..."
    "$BUILD" -mpsa -N 3 -r 0 -port "$port" \
        -out "$outcsv" -mpsi-backend "$backend" &
    local SP_PID=$!
    sleep 0.4

    echo "Spawning 3 senders..."
    local PIDS=()
    for i in 0 1 2; do
        "$BUILD" -mpsa -N 3 -r 1 -i "$i" -port "$port" -host localhost \
            -in "${outdir}/sender_${i}.csv" -mpsi-backend "$backend" &
        PIDS+=($!)
    done

    wait "$SP_PID"
    for pid in "${PIDS[@]}"; do wait "$pid"; done

    echo "Verifying (x+y)/z against ground truth..."
    python3 tests/verify_mpsa_arithmetic.py \
        --out-csv "$outcsv" \
        --ground-truth "${outdir}/ground_truth.json"
    echo
}

# Run against both backends -- proves the arithmetic works whether SP uses
# simplehash (legacy) or vole (Stage B).
run_backend simplehash 17550
run_backend vole       17555

echo "ALL PASSED (both backends recovered correct (x+y)/z)."
