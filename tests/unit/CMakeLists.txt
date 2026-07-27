# Offline unit tests for the MPSA additions. Link against the volePSI lib
# (which already pulls cryptoTools/libsodium transitively).
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(test_mpstar_crypto test_mpstar_crypto.cpp)
target_link_libraries(test_mpstar_crypto PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpstar_crypto PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

add_executable(test_kdf test_kdf.cpp)
target_link_libraries(test_kdf PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_kdf PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# OSN semantics test — requires an in-process coproto socket pair; the
# helper at the top of test_osn_semantics.cpp is currently a stub that
# returns "skipped" (exit 77) until the build-time coproto API is wired in.
add_executable(test_osn_semantics test_osn_semantics.cpp)
target_link_libraries(test_osn_semantics PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_osn_semantics PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MAC primitives test for malicious-secure cascade (R25 / T1 production).
add_executable(test_mac test_mac.cpp)
target_link_libraries(test_mac PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mac PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# In-memory simulation of the MAC-propagating cascade (R25).
add_executable(test_auth_cascade test_auth_cascade.cpp)
target_link_libraries(test_auth_cascade PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_auth_cascade PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# CGP secret-shared shuffle simulation (R26).
add_executable(test_cgp_shuffle test_cgp_shuffle.cpp)
target_link_libraries(test_cgp_shuffle PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_cgp_shuffle PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Oblivious bitonic sort (R29: foundation for private-join Phase 3).
add_executable(test_oblivious_sort test_oblivious_sort.cpp)
target_link_libraries(test_oblivious_sort PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_oblivious_sort PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Join expander phases 4+5 (R30: window detect + cross-product expansion).
add_executable(test_join_expander test_join_expander.cpp)
target_link_libraries(test_join_expander PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_join_expander PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Join filter phase 6 (R31: oblivious is_intersection filter + truncate).
add_executable(test_join_filter test_join_filter.cpp)
target_link_libraries(test_join_filter PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_join_filter PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# End-to-end private join (R32: composes phases 1-6 in-memory).
add_executable(test_join_e2e test_join_e2e.cpp)
target_link_libraries(test_join_e2e PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_join_e2e PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPC foundation primitives (R34a-c: secret shares + Beaver triples +
# secure multiply for the SP-blind private-join variant).
add_executable(test_secret_share test_secret_share.cpp)
target_link_libraries(test_secret_share PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_secret_share PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Secure 64-bit compare on XOR-shared bits (R34d).
add_executable(test_secure_compare test_secure_compare.cpp)
target_link_libraries(test_secure_compare PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_secure_compare PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPC bitonic sort (R34e + R34f) — full SP-blind sort.
add_executable(test_mpc_sort test_mpc_sort.cpp)
target_link_libraries(test_mpc_sort PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpc_sort PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# End-to-end SP-blind MPC private join (R34g + R34h + R34i + R34j).
add_executable(test_mpc_join test_mpc_join.cpp)
target_link_libraries(test_mpc_join PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpc_join PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Ristretto255 + Pedersen + Bayer-Groth-inspired shuffle NIZK (R27).
add_executable(test_shuffle_nizk test_shuffle_nizk.cpp)
target_link_libraries(test_shuffle_nizk PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_shuffle_nizk PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# R34k: OLE-based Beaver triple gen via libOTe SilentOtTriple (closes
# the trusted-dealer gap for 2-party MPC).
add_executable(test_ole_triple test_ole_triple.cpp)
target_link_libraries(test_ole_triple PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_ole_triple PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# R34k-remain: 2-party wire MPC primitives (secureAnd/OR/LT/Equal over wire).
add_executable(test_mpc_wire test_mpc_wire.cpp)
target_link_libraries(test_mpc_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpc_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# R28: OLE-based α-sharing for malicious cascade.
add_executable(test_ole_alpha test_ole_alpha.cpp)
target_link_libraries(test_ole_alpha PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_ole_alpha PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# R27b: Bayer-Groth multiplicative shuffle NIZK.
add_executable(test_shuffle_nizk_bg test_shuffle_nizk_bg.cpp)
target_link_libraries(test_shuffle_nizk_bg PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_shuffle_nizk_bg PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# R36b: wire MPC composition (conditional swap + bitonic sort).
add_executable(test_mpc_wire_ops test_mpc_wire_ops.cpp)
target_link_libraries(test_mpc_wire_ops PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpc_wire_ops PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# R36c: end-to-end wire MPC join driver.
add_executable(test_mpc_wire_driver test_mpc_wire_driver.cpp)
target_link_libraries(test_mpc_wire_driver PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpc_wire_driver PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# R26b/step2: OT-based CGP shuffle preprocessing wire protocol.
add_executable(test_cgp_preprocess test_cgp_preprocess.cpp)
target_link_libraries(test_cgp_preprocess PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_cgp_preprocess PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# R27c: Pedersen vector commit + audit-mode shuffle NIZK.
add_executable(test_pedersen_vector test_pedersen_vector.cpp)
target_link_libraries(test_pedersen_vector PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_pedersen_vector PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# A1 fix (R37): SP cannot reconstruct the cascade permutation — offline check
# of OSNSender::permuteBlocks (bijection + local-seed privacy).
add_executable(test_shuffle_seed_privacy test_shuffle_seed_privacy.cpp)
target_link_libraries(test_shuffle_seed_privacy PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_shuffle_seed_privacy PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# A1 fix (R37): input->output demonstration that a semi-honest SP cannot
# reconstruct the cascade permutation, plus a regression-catch branch that
# reproduces the pre-fix behavior to prove the test would catch a revert.
add_executable(test_shuffle_leak_demo test_shuffle_leak_demo.cpp)
target_link_libraries(test_shuffle_leak_demo PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_shuffle_leak_demo PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# C4 fix (R37): OSN internals no longer use hardcoded PRNG seeds. Offline
# check that init_wj -- which used to produce identical dest[] across calls --
# now yields distinct permutations. Wire-mask + OT-base freshness are covered
# by test_osn_semantics.cpp (real OSN over an in-process socket pair).
add_executable(test_osn_seed_freshness test_osn_seed_freshness.cpp)
target_link_libraries(test_osn_seed_freshness PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_osn_seed_freshness PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Stage A-sum shuffle-integrity check: MpsaShuffleIntegrity module regression.
# Eight scenarios: honest, drop, substitute, sum-preserving swap (documented
# gap), replay opening, serialization round-trips, W=0 edge case.
add_executable(test_shuffle_integrity_sum test_shuffle_integrity_sum.cpp)
target_link_libraries(test_shuffle_integrity_sum PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_shuffle_integrity_sum PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Stage A-mset-row: catches cross-column tampering that A-sum accepts.
add_executable(test_shuffle_integrity_row test_shuffle_integrity_row.cpp)
target_link_libraries(test_shuffle_integrity_row PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_shuffle_integrity_row PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Vuln-score foundation (session 1): bit-shared add/sub primitives, to be
# extended in session 2 with secureDivideU64Bin. See docs/DESIGN_VULN_SCORE.md.
add_executable(test_mpc_arithmetic test_mpc_arithmetic.cpp)
target_link_libraries(test_mpc_arithmetic PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpc_arithmetic PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Vuln-score V2 building block: secure integer division on bit-shared u64.
# See docs/DESIGN_VULN_SCORE_V2.md.
add_executable(test_mpc_divide test_mpc_divide.cpp)
target_link_libraries(test_mpc_divide PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpc_divide PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Vuln-score session 2: probe the vendored MPSO MPSICS end-to-end.
# Multi-process protocol; invoked by tests/run_mpso_mpsics_probe.sh.
add_executable(mpso_mpsics_probe mpso_mpsics_probe.cpp)
target_link_libraries(mpso_mpsics_probe PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(mpso_mpsics_probe PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# OIRA (Output-Inference-Resistant Aggregation) end-to-end probe.
# Runs full construction: MPSIC cardinality + k-anon gate + MPSICS
# aggregate + Laplace DP noise. See docs/OIRA_CONSTRUCTION.md.
add_executable(oira_probe oira_probe.cpp)
target_link_libraries(oira_probe PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(oira_probe PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)


# OIRA DP-budget accountant unit test (pure API, no network).
add_executable(test_oira_budget test_oira_budget.cpp)
target_link_libraries(test_oira_budget PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_oira_budget PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Set-secrecy adversarial probe: two-variant MPSICS run to check if MAS
# can distinguish Bank A's submission set from output-tier alone.
# Driven by tests/run_oira_set_secrecy_smoke.sh.
add_executable(oira_set_secrecy_probe oira_set_secrecy_probe.cpp)
target_link_libraries(oira_set_secrecy_probe PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(oira_set_secrecy_probe PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# Math validation — Tool 1 (Prop 1.2 i) against the deployed Beneš network.
# Anchors the Python math-tool tests (tests/math/tool1_column_hom.py) to
# the actual production code in volePSI/osn/benes.cpp.
add_executable(test_math_tool1_switching test_math_tool1_switching.cpp)
target_link_libraries(test_math_tool1_switching PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_math_tool1_switching PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 1 — Local prep + payload schema acceptance-criteria tests.
# Per docs/DEPLOYMENT_FULL_MPC.md Phase 1 (spec §6, §8, §12 partial).
add_executable(test_mpsvs_local_prep test_mpsvs_local_prep.cpp)
target_link_libraries(test_mpsvs_local_prep PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_local_prep PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 2 — Server-aided blind DH-OPRF acceptance-criteria tests.
# Per docs/DEPLOYMENT_FULL_MPC.md Phase 2 + Protocol §2 (DKG) + §3 (OPRF).
add_executable(test_mpsvs_oprf test_mpsvs_oprf.cpp)
target_link_libraries(test_mpsvs_oprf PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_oprf PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 3 — Two-domain topology / session / Beaver / transcript.
# Per docs/DEPLOYMENT_FULL_MPC.md Phase 3.
add_executable(test_mpsvs_topology test_mpsvs_topology.cpp)
target_link_libraries(test_mpsvs_topology PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_topology PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 4 — F_PSA binned oblivious alignment (semantic reference).
# Per docs/DEPLOYMENT_FULL_MPC.md Phase 4 + Protocol §5.
add_executable(test_mpsvs_alignment test_mpsvs_alignment.cpp)
target_link_libraries(test_mpsvs_alignment PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_alignment PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 5 — Inclusion bits + entity-level ratio prep.
# Per docs/DEPLOYMENT_FULL_MPC.md Phase 5 + Protocol §7.
add_executable(test_mpsvs_inclusion test_mpsvs_inclusion.cpp)
target_link_libraries(test_mpsvs_inclusion PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_inclusion PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 6 — BucketIndex + Goldschmidt reciprocal.
# Per docs/DEPLOYMENT_FULL_MPC.md Phase 6 + Protocol §8.1 (bucket index)
# + §8.1.1 (Goldschmidt convergence).
add_executable(test_mpsvs_ratio_bucket test_mpsvs_ratio_bucket.cpp)
target_link_libraries(test_mpsvs_ratio_bucket PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_ratio_bucket PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 8 — RankViaHistogram + slim-sort (§8.2 + §8.2.1).
add_executable(test_mpsvs_rank test_mpsvs_rank.cpp)
target_link_libraries(test_mpsvs_rank PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_rank PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 9 — TwoScore composite vuln score (§13).
add_executable(test_mpsvs_composite test_mpsvs_composite.cpp)
target_link_libraries(test_mpsvs_composite PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_composite PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 10 — GroupPercentiles + CDF inversion (§11).
add_executable(test_mpsvs_percentiles test_mpsvs_percentiles.cpp)
target_link_libraries(test_mpsvs_percentiles PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_percentiles PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 11 — Sector aggregation (§10).
add_executable(test_mpsvs_sector_agg test_mpsvs_sector_agg.cpp)
target_link_libraries(test_mpsvs_sector_agg PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_sector_agg PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 12 — DP noise + R26 CDF clamp + zCDP tracker (§12).
add_executable(test_mpsvs_dp test_mpsvs_dp.cpp)
target_link_libraries(test_mpsvs_dp PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_dp PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 12.1 — Output opening protocol to GovTech.
add_executable(test_mpsvs_open test_mpsvs_open.cpp)
target_link_libraries(test_mpsvs_open PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_open PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 13-17 — end-to-end pipeline audit + malicious-upgrade register.
add_executable(test_mpsvs_e2e test_mpsvs_e2e.cpp)
target_link_libraries(test_mpsvs_e2e PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_e2e PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 5 MPC-wire — real Beaver-triple AND + secureLessThan.
add_executable(test_mpsvs_inclusion_wire test_mpsvs_inclusion_wire.cpp)
target_link_libraries(test_mpsvs_inclusion_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_inclusion_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 11 MPC-wire — additive-share aggregation.
add_executable(test_mpsvs_sector_agg_wire test_mpsvs_sector_agg_wire.cpp)
target_link_libraries(test_mpsvs_sector_agg_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_sector_agg_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 12.1 MPC-wire — output opening from shares.
add_executable(test_mpsvs_open_wire test_mpsvs_open_wire.cpp)
target_link_libraries(test_mpsvs_open_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_open_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 6 MPC-wire — bucketIndex on shares.
add_executable(test_mpsvs_ratio_bucket_wire test_mpsvs_ratio_bucket_wire.cpp)
target_link_libraries(test_mpsvs_ratio_bucket_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_ratio_bucket_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 12 MPC-wire — DP joint noise via commit-then-reveal.
add_executable(test_mpsvs_dp_wire test_mpsvs_dp_wire.cpp)
target_link_libraries(test_mpsvs_dp_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_dp_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 8 MPC-wire — rank via bitonic sort on shares + segmented scan.
add_executable(test_mpsvs_rank_wire test_mpsvs_rank_wire.cpp)
target_link_libraries(test_mpsvs_rank_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_rank_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 6 MPC-wire — Goldschmidt reciprocal on shares (128-bit fp).
add_executable(test_mpsvs_goldschmidt_wire test_mpsvs_goldschmidt_wire.cpp)
target_link_libraries(test_mpsvs_goldschmidt_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_goldschmidt_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 9 MPC-wire — composite vuln score (STRICT variant).
add_executable(test_mpsvs_composite_wire test_mpsvs_composite_wire.cpp)
target_link_libraries(test_mpsvs_composite_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_composite_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 10 MPC-wire — shared percentile query.
add_executable(test_mpsvs_percentiles_wire test_mpsvs_percentiles_wire.cpp)
target_link_libraries(test_mpsvs_percentiles_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_percentiles_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 4 MPC-wire — F_PSA alignment (sort + windowed merge on shares).
add_executable(test_mpsvs_alignment_wire test_mpsvs_alignment_wire.cpp)
target_link_libraries(test_mpsvs_alignment_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_alignment_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS E2E MPC-wire — full pipeline (Phase 5 → 11 → 12.1) on 2-party shares.
add_executable(test_mpsvs_e2e_wire test_mpsvs_e2e_wire.cpp)
target_link_libraries(test_mpsvs_e2e_wire PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_e2e_wire PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Privacy-Leakage Trace — instruments full pipeline and reports per-
# party view + entity-level leakage classification vs Rev 7 threat model.
add_executable(test_mpsvs_privacy_trace test_mpsvs_privacy_trace.cpp)
target_link_libraries(test_mpsvs_privacy_trace PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_privacy_trace PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Membership-Leakage Trace — focused on set-membership leakage:
# entity presence per source, intersection cardinality, avail_core, bucket
# occupancy, cell-existence metadata, adversarial residual inference.
add_executable(test_mpsvs_membership_trace test_mpsvs_membership_trace.cpp)
target_link_libraries(test_mpsvs_membership_trace PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_membership_trace PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Membership-Hiding via sensitivity-calibrated DP — demonstrates
# that σ = C_max / √(2ρ) closes the Q7 residual attack.
add_executable(test_mpsvs_membership_hiding test_mpsvs_membership_hiding.cpp)
target_link_libraries(test_mpsvs_membership_hiding PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_membership_hiding PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS MAS-Membership Hiding Analysis — enumerates leak channels for
# "is firm F in MAS's loan-holder list?" and proposes additional protection.
add_executable(test_mpsvs_mas_membership test_mpsvs_mas_membership.cpp)
target_link_libraries(test_mpsvs_mas_membership PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_mas_membership PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Cover-Firm Injection — demonstrates additional MAS-membership
# protection via jointly-sampled shared cover count K ∈ [K_min, K_max].
add_executable(test_mpsvs_cover_firms test_mpsvs_cover_firms.cpp)
target_link_libraries(test_mpsvs_cover_firms PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_cover_firms PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Prediction-Rate — empirically measures attacker's accuracy on
# the membership-inference question "is firm X in MAS?"
add_executable(test_mpsvs_prediction_rate test_mpsvs_prediction_rate.cpp)
target_link_libraries(test_mpsvs_prediction_rate PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_prediction_rate PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS k-Anonymity Gate — fully oblivious membership hiding via shared
# secureLessThan + secureMultiply MUX. Combined with covers → indistinguishable.
add_executable(test_mpsvs_kanon_gate test_mpsvs_kanon_gate.cpp)
target_link_libraries(test_mpsvs_kanon_gate PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_kanon_gate PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Formal-Hiding Proof — statistical validation of the 4 membership-
# hiding claims: distributional indistinguishability, attack accuracy = 50%,
# DP composition bound, mutual information ≈ 0.
add_executable(test_mpsvs_hiding_proof test_mpsvs_hiding_proof.cpp)
target_link_libraries(test_mpsvs_hiding_proof PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_hiding_proof PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS MIA proof — targeted membership-inference attack test with
# ablation across protection layers.
add_executable(test_mpsvs_mia_proof test_mpsvs_mia_proof.cpp)
target_link_libraries(test_mpsvs_mia_proof PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_mia_proof PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS ε sweep — parameter Pareto frontier for how low ε can go.
add_executable(test_mpsvs_epsilon_sweep test_mpsvs_epsilon_sweep.cpp)
target_link_libraries(test_mpsvs_epsilon_sweep PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_epsilon_sweep PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS No-DP membership hiding — pure crypto via cover firms + k-anon.
add_executable(test_mpsvs_no_dp_hiding test_mpsvs_no_dp_hiding.cpp)
target_link_libraries(test_mpsvs_no_dp_hiding PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_no_dp_hiding PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Pure-Crypto Proof — formal proof (lemmas + theorem + corollaries)
# of membership hiding via cover firms, without any DP noise.
add_executable(test_mpsvs_pure_crypto_proof test_mpsvs_pure_crypto_proof.cpp)
target_link_libraries(test_mpsvs_pure_crypto_proof PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_pure_crypto_proof PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS MOM attack — concrete example of MOM trying to identify which
# of its firms are in MAS, at each protection level.
add_executable(test_mpsvs_mom_attack test_mpsvs_mom_attack.cpp)
target_link_libraries(test_mpsvs_mom_attack PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_mom_attack PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS MOM simulation-based proof — MOM as protocol party (with S1 collusion).
add_executable(test_mpsvs_mom_sim_proof test_mpsvs_mom_sim_proof.cpp)
target_link_libraries(test_mpsvs_mom_sim_proof PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_mom_sim_proof PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS MOM data-flow trace — architectural doc showing MOM as input-only party.
add_executable(test_mpsvs_mom_flow test_mpsvs_mom_flow.cpp)
target_link_libraries(test_mpsvs_mom_flow PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_mom_flow PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 17.1 — MAC-authenticated shares (SPDZ-style malicious detection).
add_executable(test_mpsvs_auth_share test_mpsvs_auth_share.cpp)
target_link_libraries(test_mpsvs_auth_share PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_auth_share PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 17.1-ext — SPDZ sacrifice check + batched MAC verification.
add_executable(test_mpsvs_sacrifice test_mpsvs_sacrifice.cpp)
target_link_libraries(test_mpsvs_sacrifice PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_sacrifice PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 17.7 — comprehensive malicious adversary catalog.
add_executable(test_mpsvs_adversary_catalog test_mpsvs_adversary_catalog.cpp)
target_link_libraries(test_mpsvs_adversary_catalog PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_adversary_catalog PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 17.6 — reciprocal consistency check (Goldschmidt output verify).
add_executable(test_mpsvs_reciprocal_verify test_mpsvs_reciprocal_verify.cpp)
target_link_libraries(test_mpsvs_reciprocal_verify PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_reciprocal_verify PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 17.4 — Bayer-Groth shuffle NIZK for CGP shuffle.
add_executable(test_mpsvs_shuffle_nizk test_mpsvs_shuffle_nizk.cpp)
target_link_libraries(test_mpsvs_shuffle_nizk PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_shuffle_nizk PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 17.5 — bit membership proof (Chaum-Pedersen OR).
add_executable(test_mpsvs_bit_proof test_mpsvs_bit_proof.cpp)
target_link_libraries(test_mpsvs_bit_proof PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_bit_proof PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 17.2 — OLE-based Beaver triple generation over sockets.
add_executable(test_mpsvs_ole_integration test_mpsvs_ole_integration.cpp)
target_link_libraries(test_mpsvs_ole_integration PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_ole_integration PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Phase 17 CAPSTONE — malicious-secure E2E demo.
add_executable(test_mpsvs_malicious_e2e test_mpsvs_malicious_e2e.cpp)
target_link_libraries(test_mpsvs_malicious_e2e PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_malicious_e2e PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Production Hygiene — CSPRNG + memzero + structured abort.
add_executable(test_mpsvs_prod_hygiene test_mpsvs_prod_hygiene.cpp)
target_link_libraries(test_mpsvs_prod_hygiene PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_prod_hygiene PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Prod-Retrofit — hardened AuthShare (SecureAlpha + Result + audit log).
add_executable(test_mpsvs_auth_share_prod test_mpsvs_auth_share_prod.cpp)
target_link_libraries(test_mpsvs_auth_share_prod PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_auth_share_prod PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS DP Prod-Retrofit — CSPRNG-backed Gaussian + audit-log integration.
add_executable(test_mpsvs_dp_prod test_mpsvs_dp_prod.cpp)
target_link_libraries(test_mpsvs_dp_prod PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_dp_prod PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Audit persistence + Prometheus metrics.
add_executable(test_mpsvs_audit_metrics test_mpsvs_audit_metrics.cpp)
target_link_libraries(test_mpsvs_audit_metrics PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_audit_metrics PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Config — parameter config with validation + change control.
add_executable(test_mpsvs_config test_mpsvs_config.cpp)
target_link_libraries(test_mpsvs_config PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_config PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS Constant-time primitives.
add_executable(test_mpsvs_const_time test_mpsvs_const_time.cpp)
target_link_libraries(test_mpsvs_const_time PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_const_time PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS KeyStore (encrypted-at-rest + HSM stub).
add_executable(test_mpsvs_key_store test_mpsvs_key_store.cpp)
target_link_libraries(test_mpsvs_key_store PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_key_store PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS SecureChannel (libsodium authenticated encrypted channel).
add_executable(test_mpsvs_secure_channel test_mpsvs_secure_channel.cpp)
target_link_libraries(test_mpsvs_secure_channel PRIVATE volePSI ${SODIUM_LIBRARIES} pthread)
target_include_directories(test_mpsvs_secure_channel PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS shared-α DPSZ MAC-check (α never reconstructed).
add_executable(test_mpsvs_auth_share_dpsz test_mpsvs_auth_share_dpsz.cpp)
target_link_libraries(test_mpsvs_auth_share_dpsz PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_auth_share_dpsz PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS shared-α end-to-end (Beaver mult + sacrifice + reciprocal verify).
add_executable(test_mpsvs_shared_alpha_e2e test_mpsvs_shared_alpha_e2e.cpp)
target_link_libraries(test_mpsvs_shared_alpha_e2e PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_shared_alpha_e2e PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS CryptoParams (security-proof-derived parameters + cross-tool bounds).
add_executable(test_mpsvs_crypto_params test_mpsvs_crypto_params.cpp)
target_link_libraries(test_mpsvs_crypto_params PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_crypto_params PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

# MPSVS scale test — 1M firms × 20 sectors × MAS=10%. Semantic-reference
# Phase 5+11+12 to demonstrate end-to-end release feasibility.
add_executable(test_mpsvs_scale_1M test_mpsvs_scale_1M.cpp)
target_link_libraries(test_mpsvs_scale_1M PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(test_mpsvs_scale_1M PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)
