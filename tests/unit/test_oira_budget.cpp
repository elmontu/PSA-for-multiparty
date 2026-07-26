// Unit test for the OIRA DP-budget accountant (MpOiraBudget).
// Pure API test, no network. Verifies:
//   1. Fresh scope allows queries up to epsilon cap.
//   2. Query that would exceed cap is refused; state unchanged.
//   3. Peek matches reserved state.
//   4. Reset clears the file.
//   5. Query cap enforced even when epsilon cap not hit.

#include "volePSI/MpOiraBudget.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>

namespace mp = volePSI::mpstar;

namespace {

std::string tempFile(const std::string& tag) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "/tmp/oira_budget_test_%s_%d.txt", tag.c_str(), ::getpid());
    return std::string(buf);
}

bool near(double a, double b, double eps = 1e-9) {
    return std::abs(a - b) < eps;
}

int failures = 0;
void check(bool ok, const std::string& msg) {
    std::cout << (ok ? "PASS" : "FAIL") << ": " << msg << "\n";
    if (!ok) ++failures;
}

} // namespace

int main() {
    // ---------- Scenario 1: fresh scope, one query within cap ----------
    {
        mp::OIRABudgetConfig cfg;
        cfg.scopeId    = "s1";
        cfg.budgetFile = tempFile("s1");
        cfg.epsilonCap = 3.0;
        cfg.queryCap   = 5;
        mp::oiraBudgetReset(cfg);

        auto r1 = mp::oiraBudgetCheckAndReserve(cfg, 1.0);
        check(r1.allowed, "fresh scope + one 1.0-ε query allowed");
        check(near(r1.spentAfter, 1.0), "spentAfter == 1.0");
        check(r1.countAfter == 1, "countAfter == 1");

        auto p = mp::oiraBudgetPeek(cfg);
        check(near(p.spentBefore, 1.0) && p.countBefore == 1,
              "peek after 1 reservation shows 1.0 / 1");
        mp::oiraBudgetReset(cfg);
    }

    // ---------- Scenario 2: exceed epsilon cap; state unchanged ----------
    {
        mp::OIRABudgetConfig cfg;
        cfg.scopeId    = "s2";
        cfg.budgetFile = tempFile("s2");
        cfg.epsilonCap = 1.5;
        cfg.queryCap   = 10;
        mp::oiraBudgetReset(cfg);

        auto r1 = mp::oiraBudgetCheckAndReserve(cfg, 1.0);
        check(r1.allowed, "first query 1.0-ε allowed under cap 1.5");

        auto r2 = mp::oiraBudgetCheckAndReserve(cfg, 1.0);
        check(!r2.allowed, "second query 1.0-ε refused (would push to 2.0 > 1.5)");
        check(r2.reason.find("budget_exhausted") != std::string::npos,
              "refusal reason contains budget_exhausted");

        auto p = mp::oiraBudgetPeek(cfg);
        check(near(p.spentBefore, 1.0) && p.countBefore == 1,
              "state after refused query still 1.0 / 1 (no rollback needed)");
        mp::oiraBudgetReset(cfg);
    }

    // ---------- Scenario 3: query cap enforced ----------
    {
        mp::OIRABudgetConfig cfg;
        cfg.scopeId    = "s3";
        cfg.budgetFile = tempFile("s3");
        cfg.epsilonCap = 100.0;   // plenty of ε budget
        cfg.queryCap   = 2;       // but only 2 queries
        mp::oiraBudgetReset(cfg);

        auto r1 = mp::oiraBudgetCheckAndReserve(cfg, 0.01);
        auto r2 = mp::oiraBudgetCheckAndReserve(cfg, 0.01);
        auto r3 = mp::oiraBudgetCheckAndReserve(cfg, 0.01);
        check(r1.allowed && r2.allowed && !r3.allowed,
              "3rd query refused when queryCap=2");
        check(r3.reason.find("budget_exhausted") != std::string::npos,
              "3rd refusal reason mentions budget_exhausted");
        mp::oiraBudgetReset(cfg);
    }

    // ---------- Scenario 4: empty scopeId means opt-out (always allowed) ----------
    {
        mp::OIRABudgetConfig cfg;
        cfg.scopeId    = "";
        cfg.budgetFile = tempFile("s4");
        cfg.epsilonCap = 0.0;   // even zero cap
        auto r = mp::oiraBudgetCheckAndReserve(cfg, 100.0);
        check(r.allowed, "empty scopeId opts out — allowed regardless of cap");
    }

    // ---------- Scenario 5: reset clears state ----------
    {
        mp::OIRABudgetConfig cfg;
        cfg.scopeId    = "s5";
        cfg.budgetFile = tempFile("s5");
        cfg.epsilonCap = 5.0;
        cfg.queryCap   = 10;

        mp::oiraBudgetReset(cfg);
        auto r1 = mp::oiraBudgetCheckAndReserve(cfg, 3.0);
        check(r1.allowed && near(r1.spentAfter, 3.0), "reserved 3.0");
        mp::oiraBudgetReset(cfg);
        auto p = mp::oiraBudgetPeek(cfg);
        check(near(p.spentBefore, 0.0) && p.countBefore == 0,
              "after reset, state is fresh");
    }

    if (failures == 0) {
        std::cout << "ALL PASSED\n";
        return 0;
    }
    std::cerr << "FAIL: " << failures << " checks failed\n";
    return 1;
}
