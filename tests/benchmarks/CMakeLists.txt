# R35 benchmark binaries. Built only when VOLE_PSI_BUILD_TESTS is ON.
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(bench_mpc_join bench_mpc_join.cpp)
target_link_libraries(bench_mpc_join PRIVATE volePSI ${SODIUM_LIBRARIES})
target_include_directories(bench_mpc_join PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)
