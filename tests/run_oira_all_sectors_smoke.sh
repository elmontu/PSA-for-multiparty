#!/bin/bash
# End-to-end OIRA driver: run ONE OIRA per sector, collect the per-sector
# aggregates into a single output table. This is the operational shape
# MAS SupTech would use for output (a) of PROBLEM_STATEMENT.md.
#
# Design notes:
#   - MPSO opens hardcoded ports (1212 + i*100 + j) so each sector call
#     must complete + let TIME_WAIT drain before the next starts.
#   - Offline pregen is done ONCE (per K, NN) and shared across sectors.
#   - Each sector call uses -sectorFilter s -useValues; the probe zeros
#     values for items whose sector(id)=id%numSectors doesn't match s.
#   - DP-budget accountant is INTENTIONALLY NOT WIRED in this driver.
#     Focus is on the computation itself working across all sectors.
#     Budget composition is orthogonal and handled by MpOiraBudget when
#     a caller opts in; see tests/run_oira_probe.sh SCENARIO=budget_exhausted.
set -euo pipefail

K=${K:-3}                 # party count
NN=${NN:-6}               # log2(elements per party)
NUM_SECTORS=${NUM_SECTORS:-5}
K_ANON=${K_ANON:-3}       # per-sector; expected ~n/numSectors per sector
EPS=${EPS:-1.0}
DELTA=${DELTA:-1024}
PROBE=./out/build/linux/tests/unit/oira_probe

echo "=== OIRA all-sectors sweep ==="
echo "K=$K, NN=$NN, numSectors=$NUM_SECTORS, kAnon=$K_ANON, eps=$EPS"

WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT
cp "$PROBE" "$WORKDIR/oira_probe"
cd "$WORKDIR"
mkdir -p offline

# ---- Phase 0: pregen (shared across all sectors) ----
echo "Phase 0a: MPSIC pregen"
PIDS=()
for i in $(seq 0 $((K-1))); do
    ./oira_probe -preGen-mpsic -r $i -k $K -nn $NN > pregen_mpsic_$i.log 2>&1 &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait $pid || { echo "MPSIC pregen party $pid FAIL"; cat pregen_mpsic_*.log; exit 1; }; done

echo "Phase 0b: MPSICS pregen"
PIDS=()
for i in $(seq 0 $((K-1))); do
    ./oira_probe -preGen-mpsics -r $i -k $K -nn $NN > pregen_mpsics_$i.log 2>&1 &
    PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait $pid || { echo "MPSICS pregen party $pid FAIL"; cat pregen_mpsics_*.log; exit 1; }; done

# ---- Phase 1: online loop, one MPSICS per sector ----
echo "Phase 1: per-sector online sweep ($NUM_SECTORS sectors)"
declare -A SECTOR_RESULTS  # sector -> single-line summary

for s in $(seq 0 $((NUM_SECTORS-1))); do
    echo "-- sector $s --"
    # Wait for ports to drain from previous sector's teardown (skip on first).
    if [ "$s" -gt 0 ]; then
        for _ in {1..30}; do
            open=$(ss -tan 2>/dev/null | awk '$4 ~ /:1[234][0-9][0-9]$/' | wc -l)
            if [ "$open" -eq 0 ]; then break; fi
            sleep 2
        done
    fi

    PIDS=()
    for i in $(seq 0 $((K-1))); do
        ./oira_probe -r $i -k $K -nn $NN \
            -kAnon "$K_ANON" -eps "$EPS" -delta "$DELTA" \
            -useValues -numSectors "$NUM_SECTORS" -sectorFilter "$s" \
            > "online_s${s}_p${i}.log" 2>&1 &
        PIDS+=($!)
    done
    for pid in "${PIDS[@]}"; do wait $pid || true; done

    SUMMARY=$(grep '^SECTOR_RESULT' "online_s${s}_p0.log" || true)
    if [ -z "$SUMMARY" ]; then
        SUMMARY=$(grep -E '^(SUPPRESSED|BUDGET_EXHAUSTED):' "online_s${s}_p0.log" || echo "NO_OUTPUT")
        echo "  sector $s: NOT RELEASED — $SUMMARY"
    else
        echo "  $SUMMARY"
    fi
    SECTOR_RESULTS[$s]="$SUMMARY"
done

# ---- Phase 2: consolidated per-sector table ----
echo ""
echo "=== MAS SVS output (a): sector aggregate table ==="
printf "%-8s %-12s %-14s %-14s %-14s %s\n" \
       "sector" "released" "trueCardSec" "noisyCardTot" "trueAgg" "noisyAgg"
FAILURES=0
for s in $(seq 0 $((NUM_SECTORS-1))); do
    LINE="${SECTOR_RESULTS[$s]}"
    if [[ "$LINE" == SECTOR_RESULT* ]]; then
        eval $(echo "$LINE" | tr ' ' '\n' | grep '=' | sed 's/^/OIRA_/')
        printf "%-8s %-12s %-14s %-14s %-14s %s\n" \
               "$s" "yes" "$OIRA_trueCardSector" "$OIRA_noisyCardTotal" \
               "$OIRA_trueAgg" "$OIRA_noisyAgg"
        unset OIRA_sector OIRA_numSectors OIRA_trueCardTotal OIRA_trueCardSector \
              OIRA_noisyCardTotal OIRA_trueAgg OIRA_noisyAgg
    else
        printf "%-8s %-12s %s\n" "$s" "no" "$LINE"
        FAILURES=$((FAILURES+1))
    fi
done

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL SECTORS RELEASED SUCCESSFULLY"
    exit 0
else
    echo "FAIL: $FAILURES sector(s) did not release"
    exit 1
fi
