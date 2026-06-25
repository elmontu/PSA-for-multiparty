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
