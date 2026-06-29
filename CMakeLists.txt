cmake_minimum_required (VERSION 3.15)

project(volePSI VERSION 0.1.2)

set(VOLEPSI_BUILD ON)

# sets some variables
include(cmake/preamble.cmake)

# sets build option
include(cmake/buildOptions.cmake)

# find all the dependancies.
include(cmake/findDependancies.cmake)

# build volePSI
add_subdirectory(volePSI)

# link the executable.
add_subdirectory(frontend)

# offline unit tests (opt-in via -DVOLE_PSI_BUILD_TESTS=ON)
option(VOLE_PSI_BUILD_TESTS "Build offline unit tests for MPSA additions" OFF)
if(VOLE_PSI_BUILD_TESTS)
    add_subdirectory(tests/unit)
    add_subdirectory(tests/benchmarks)
endif()

# setup the install
include(cmake/install.cmake)