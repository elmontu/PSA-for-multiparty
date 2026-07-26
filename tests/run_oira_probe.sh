#!/bin/bash
# End-to-end OIRA probe. Runs a single scenario per invocation to avoid
# TCP TIME_WAIT collisions on MPSO's hardcoded port 1212. Multiple
# scenarios can be run back-to-back by invoking this script multiple
# times with an env var override, or by waiting ~60s between calls.
#
# Scenarios (override with $SCENARIO env var):
#   pass              K=3, kAnon=20, |I|=61 -> expect PASS (default)
#   suppressed        K=3, kAnon=500, |I|=61 -> expect SUPPRESSED
#   n4                K=4, kAnon=20, |I|=60 -> expect PASS with 4 parties
#   values            K=3, useValues (aggregate = 100 * Σ id) -> expect PASS
#   budget_exhausted  DP-budget cap=0.5, per-query eps=1.0 -> expect REFUSAL
#                     on the very first call (0 + 1.0 > 0.5).
set -euo pipefail

SCENARIO=${SCENARIO:-pass}
PROBE=./out/build/linux/tests/unit/oira_probe

USE_VALUES_FLAG=""
BUDGET_FLAGS=""
case "$SCENARIO" in
    pass)       K=3; NN=6; K_ANON=20;  EXPECT=pass ;;
    suppressed) K=3; NN=6; K_ANON=500; EXPECT=suppressed ;;
    n4)         K=4; NN=6; K_ANON=20;  EXPECT=pass ;;
    values)     K=3; NN=6; K_ANON=20;  EXPECT=pass; USE_VALUES_FLAG="-useValues" ;;
    budget_exhausted)
        K=3; NN=6; K_ANON=20; EXPECT=budget
        BUDGET_FLAGS="-budgetFile oira_budget -budgetScope test_scope -budgetCap 0.5 -budgetQCap 100 -budgetReset"
        ;;
    *) echo "Unknown SCENARIO=$SCENARIO (want pass|suppressed|n4|values|budget_exhausted)"; exit 2 ;;
esac

echo "=== OIRA scenario: $SCENARIO (K=$K NN=$NN kAnon=$K_ANON expect=$EXPECT) ==="

WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT
cp "$PROBE" "$WORKDIR/oira_probe"
cd "$WORKDIR"
mkdir -p offline

echo "Phase 0a: MPSIC pregen (K=$K, NN=$NN)"
PIDS=()
for i in $(seq 0 $((K-1))); do
    ./oira_probe -preGen-mpsic -r $i -k $K -nn $NN > pregen_mpsic_$i.log 2>&1 &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait $pid || { echo "MPSIC PREGEN party $pid failed"; cat pregen_mpsic_*.log; exit 1; }; done

echo "Phase 0b: MPSICS pregen (K=$K, NN=$NN)"
PIDS=()
for i in $(seq 0 $((K-1))); do
    ./oira_probe -preGen-mpsics -r $i -k $K -nn $NN > pregen_mpsics_$i.log 2>&1 &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait $pid || { echo "MPSICS PREGEN party $pid failed"; cat pregen_mpsics_*.log; exit 1; }; done

echo "Phase 1: online OIRA"
PIDS=()
for i in $(seq 0 $((K-1))); do
    ./oira_probe -r $i -k $K -nn $NN -kAnon "$K_ANON" -eps 1.0 -delta 1024 $USE_VALUES_FLAG $BUDGET_FLAGS > online_$i.log 2>&1 &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait $pid || { echo "ONLINE party $pid failed"; }; done

echo "=== Party 0 result ==="
cat online_0.log

if [ "$EXPECT" = "pass" ] && grep -q "^PASS: OIRA" online_0.log; then
    exit 0
elif [ "$EXPECT" = "suppressed" ] && grep -q "^SUPPRESSED:" online_0.log; then
    exit 0
elif [ "$EXPECT" = "budget" ] && grep -q "^BUDGET_EXHAUSTED:" online_0.log; then
    exit 0
else
    echo "FAIL: expected=$EXPECT, party-0 output above"
    exit 1
fi
