// Tool 4 — Coset factorization: knowledge-state closure (C++ port).

#include <cstdio>
#include <set>
#include <string>
#include <vector>
#include <algorithm>

namespace {

using State = std::set<std::string>;
const std::vector<std::string> FACTORS = {"pi", "rho1", "rho2", "s"};

// Derivation rules: {prereq set} -> derived factor
struct Rule { std::set<std::string> prereq; std::string out; };
const std::vector<Rule> RULES = {
    {{"pi", "rho1"}, "rho2"},
    {{"pi", "rho2"}, "rho1"},
    {{"rho1", "rho2"}, "pi"},
    {{"s"}, "rho1"},
};

State closure(State known) {
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& r : RULES) {
            if (std::includes(known.begin(), known.end(),
                              r.prereq.begin(), r.prereq.end())
                && known.find(r.out) == known.end()) {
                known.insert(r.out);
                changed = true;
            }
        }
    }
    return known;
}

std::string classify(const State& s0) {
    auto c = closure(s0);
    if (c.count("pi")) return "full_leak";
    if (c.count("rho2") && !c.count("rho1") && !c.count("s")) return "gamma_D";
    if ((c.count("rho1") || c.count("s")) && !c.count("rho2")) return "perfect";
    return "trivial";
}

std::string set_str(const State& s) {
    std::string r = "{";
    bool first = true;
    for (const auto& e : s) { if (!first) r += ","; r += e; first = false; }
    return r + "}";
}

void enumerate_all_states() {
    std::printf("%-28s %-38s %s\n", "state", "closure", "class");
    std::printf("%s\n", std::string(90, '-').c_str());
    int n = FACTORS.size();
    for (int mask = 0; mask < (1 << n); ++mask) {
        State s;
        for (int i = 0; i < n; ++i) if ((mask >> i) & 1) s.insert(FACTORS[i]);
        std::printf("%-28s %-38s %s\n",
                    set_str(s).c_str(), set_str(closure(s)).c_str(),
                    classify(s).c_str());
    }
}

const std::vector<std::pair<std::string, State>> ROLES = {
    {"Router",     {"s"}},
    {"Matcher",    {"pi", "rho2"}},
    {"Party P_i",  {"rho2"}},
};

}  // namespace

int main() {
    std::puts("=== Tool 4 — Coset factorization: knowledge closure (C++) ===\n");
    enumerate_all_states();

    std::puts("\n--- Per-role hiding classification (Theorem 4.2) ---");
    for (const auto& [role, s] : ROLES) {
        std::printf("  %-15s initial=%s  closure=%s  -> %s\n",
                    role.c_str(), set_str(s).c_str(),
                    set_str(closure(s)).c_str(), classify(s).c_str());
    }

    std::puts("\n--- Coalition matrix (Corollary 4.3) ---");
    for (size_t i = 0; i < ROLES.size(); ++i) {
        for (size_t j = i; j < ROLES.size(); ++j) {
            State joined = ROLES[i].second;
            for (const auto& x : ROLES[j].second) joined.insert(x);
            std::printf("  %s + %s: joined=%s -> %s\n",
                        ROLES[i].first.c_str(), ROLES[j].first.c_str(),
                        set_str(joined).c_str(), classify(joined).c_str());
        }
    }
    return 0;
}
