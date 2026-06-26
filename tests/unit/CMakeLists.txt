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
