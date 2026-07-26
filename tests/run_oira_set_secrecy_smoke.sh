#!/bin/bash
# Set-secrecy adversarial probe orchestrator.
#
# Runs MPSICS twice with Bank A's submission set differing by one firm,
# and diffs MAS's output. Result classification:
#   IDENTICAL outputs across variants → output-tier set-secrecy HOLDS
#     for this specific perturbation. MAS cannot detect the swap from
#     (trueCard, trueAgg, noisyCard, noisyAgg).
#   DIFFERENT outputs → set-secrecy FAILS. MAS's observable output
#     reveals whether Bank A's set was variant A vs B.
#
# Bank A's variant B swaps firm 64 (which IS in the intersection under
# variant A) for firm 999 (which is in NO other party's set). Consequence:
# variant A intersection = {3..64}, |I|=62. Variant B intersection = {3..63},
# |I|=61. Aggregate also drops by exactly 100 * 64 = 6400.
#
# So we EXPECT the two runs to produce different outputs — this test
# DEMONSTRATES the output-tier leak channel and its magnitude, rather than
# proving secrecy. The measurement is the diff: how much do outputs differ?
set -euo pipefail

K=3
NN=6
PROBE=./out/build/linux/tests/unit/oira_set_secrecy_probe

echo "=== Set-secrecy probe: Bank A variants A vs B ==="

WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT
cp "$PROBE" "$WORKDIR/oira_set_secrecy_probe"
cd "$WORKDIR"
mkdir -p offline

# --- Phase 0: pregen (shared across both variants) ---
echo "Phase 0a: MPSIC pregen"
PIDS=()
for i in $(seq 0 $((K-1))); do
    ./oira_set_secrecy_probe -preGen-mpsic -r $i > pregen_mpsic_$i.log 2>&1 &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait $pid || { echo "MPSIC pregen party $pid FAIL"; cat pregen_mpsic_*.log; exit 1; }; done

echo "Phase 0b: MPSICS pregen"
PIDS=()
for i in $(seq 0 $((K-1))); do
    ./oira_set_secrecy_probe -preGen-mpsics -r $i > pregen_mpsics_$i.log 2>&1 &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait $pid || { echo "MPSICS pregen party $pid FAIL"; cat pregen_mpsics_*.log; exit 1; }; done

# --- Run variant A ---
run_variant() {
    # Prints progress to stderr; returns the SETSECRECY_RESULT line on stdout.
    local variant="$1"
    echo "--- variant $variant ---" >&2
    PIDS=()
    for i in $(seq 0 $((K-1))); do
        ./oira_set_secrecy_probe -r $i -bankA-set "$variant" \
            > "online_${variant}_p${i}.log" 2>&1 &
        PIDS+=($!)
    done
    for pid in "${PIDS[@]}"; do wait $pid || true; done
    local line
    line=$(grep '^SETSECRECY_RESULT' "online_${variant}_p0.log" || true)
    if [ -z "$line" ]; then
        echo "FAIL: no SETSECRECY_RESULT from variant $variant" >&2
        cat "online_${variant}_p0.log" >&2
        exit 1
    fi
    echo "  $line" >&2
    echo "$line"
}

RESULT_A=$(run_variant A)
# Wait for MPSO's hardcoded ports (1212 range) to drain
for _ in {1..30}; do
    open=$(ss -tan 2>/dev/null | awk '$4 ~ /:1[234][0-9][0-9]$/' | wc -l)
    [ "$open" -eq 0 ] && break
    sleep 2
done
RESULT_B=$(run_variant B)

# --- Diff analysis ---
echo ""
echo "=== SET-SECRECY OBSERVATION ==="
echo "Variant A: $RESULT_A"
echo "Variant B: $RESULT_B"
echo ""

# Extract fields
extract() {
    echo "$1" | tr ' ' '\n' | grep "^$2=" | cut -d= -f2
}
cardA=$(extract "$RESULT_A" trueCard)
cardB=$(extract "$RESULT_B" trueCard)
aggA=$(extract "$RESULT_A" trueAgg)
aggB=$(extract "$RESULT_B" trueAgg)

echo "trueCard: A=$cardA B=$cardB  Δ=$((cardA - cardB))"
echo "trueAgg:  A=$aggA B=$aggB  Δ=$((aggA - aggB))"

# Expected under the variant construction:
#   variant A intersection {3..64}, |I|=62, agg = 100 * Σ v ∈ [3,64] = 100*2077 = 207700
#   variant B intersection {3..63}, |I|=61, agg = 100 * Σ v ∈ [3,63] = 100*2013 = 201300
#   Δ card = 1  (firm 64 dropped)
#   Δ agg  = 6400  (value of firm 64 = 100*64)
EXPECTED_CARD_DIFF=1
EXPECTED_AGG_DIFF=6400

echo ""
echo "Expected Δcard = $EXPECTED_CARD_DIFF, Δagg = $EXPECTED_AGG_DIFF"

if [ "$((cardA - cardB))" = "$EXPECTED_CARD_DIFF" ] && [ "$((aggA - aggB))" = "$EXPECTED_AGG_DIFF" ]; then
    echo ""
    echo "OBSERVATION: Bank A's 1-firm swap is FULLY OBSERVABLE from MAS's output."
    echo "             MAS can detect the difference in both cardinality and aggregate."
    echo "             Set-secrecy at the OUTPUT tier: DOES NOT HOLD (as expected —"
    echo "             this is what DP + k-anon are designed to mitigate, currently disabled)."
    echo ""
    echo "PROBE COMPLETED SUCCESSFULLY (behavior matches theoretical prediction)"
    exit 0
else
    echo ""
    echo "UNEXPECTED: observed diffs (Δcard=$((cardA - cardB)), Δagg=$((aggA - aggB)))"
    echo "            do not match expected diffs. Either the aggregate formula is wrong"
    echo "            or MPSICS behavior differs from the model. Investigate."
    exit 1
fi
