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
