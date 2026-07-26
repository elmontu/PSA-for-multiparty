#pragma once

// DP-budget accountant for OIRA (Output-Inference-Resistant Aggregation).
//
// Defends against ADAPTIVE MULTI-SESSION attacks where a corrupt SP legitimately
// commits to different S_0 across sessions and subtracts aggregates to infer
// membership of specific companies. Standard DP composition: after q queries
// each spending ε, cumulative privacy loss is bounded by (basic) q·ε or
// (advanced) √(2q·ln(1/δ))·ε + q·ε(exp(ε)-1). This accountant tracks the
// basic-composition sum (conservative), refuses further queries once cap is hit.
//
// Deployment model
//
//   Each party runs its OWN accountant with its own local budget file. Before
//   agreeing to participate in a new OIRA session, party checks its budget for
//   the (scope_id) it's being asked to spend from. If exhausted, party refuses
//   participation. If ALL parties refuse — protocol aborts. If any subset of
//   honest parties refuses — protocol still can't run since MPSICS needs all N
//   parties online. Thus enforcement is COORDINATIVELY complete when at least
//   one honest party enforces.
//
//   For the reference implementation (single-process demo), we use one shared
//   budget file with flock-based locking. Production replaces with per-party
//   persistent files or a distributed ledger.
//
// Scope
//
//   scope_id identifies a query family for accounting purposes. Example:
//   "vuln-Q3-2026". Each scope has its own budget line. Different scopes are
//   accounted independently; caller chooses granularity.

#include <cstdint>
#include <string>

namespace volePSI {
namespace mpstar {

struct OIRABudgetConfig {
    std::string scopeId;         // logical grouping ("vuln-Q3-2026" etc.)
    std::string budgetFile;      // path to persistent state file
    double      epsilonCap = 10.0;  // max cumulative epsilon per scope
    uint32_t    queryCap   = 100;   // max queries per scope (belt+suspenders)
};

struct OIRABudgetCheckResult {
    bool        allowed = false;
    double      spentBefore  = 0.0;   // cumulative ε before this query
    uint32_t    countBefore  = 0;     // query count before this query
    double      spentAfter   = 0.0;   // reserved value after this query (if allowed)
    uint32_t    countAfter   = 0;     // reserved value after this query (if allowed)
    std::string reason;               // set if !allowed
};

// Atomically check + reserve one query. If the query would exceed either
// epsilonCap or queryCap, returns allowed=false and does NOT modify the
// budget file. Otherwise, increments the file's state and returns
// allowed=true with the new spent/count in *After fields.
//
// Uses flock(LOCK_EX) on the file for atomicity. File format:
//   <spent_epsilon> <query_count>
// One line per scope; scopes are keyed by scopeId (one file per scope in
// this reference impl -- filename = budgetFile + "." + scopeId).
OIRABudgetCheckResult oiraBudgetCheckAndReserve(
    const OIRABudgetConfig& cfg,
    double epsilonForThisQuery);

// Read-only inspection. Never modifies the file. Useful for tests and
// diagnostics.
OIRABudgetCheckResult oiraBudgetPeek(const OIRABudgetConfig& cfg);

// Reset the budget file for this scope. USE ONLY IN TESTS.
void oiraBudgetReset(const OIRABudgetConfig& cfg);

} // namespace mpstar
} // namespace volePSI
