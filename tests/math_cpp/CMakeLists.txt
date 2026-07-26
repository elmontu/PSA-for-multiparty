# Math validation suite (C++ port of tests/math/*.py).
# Each executable is a standalone port of the corresponding Python file.
# Opt-in via -DVOLE_PSI_BUILD_TESTS=ON (see root CMakeLists.txt).

# Eigen is needed for tool3_friedrichs (SVD).
find_path(EIGEN3_INCLUDE_DIR NAMES Eigen/Dense
    PATHS /usr/include/eigen3 /usr/local/include/eigen3
    REQUIRED)
message(STATUS "Math suite: Eigen found at ${EIGEN3_INCLUDE_DIR}")

set(MATH_TOOLS
    composite_bound
    tool1_column_hom
    tool2_min_entropy
    tool2_conjecture_2_6
    tool3_mixing
    tool3_friedrichs
    tool4_coset
    tool4_simulator
    tool4_both_blind
    tool4_rho2_protocol
    tool5_moebius
    rev7_r27_break_even
)

foreach(tool ${MATH_TOOLS})
    add_executable(math_${tool} ${tool}.cpp)
    target_include_directories(math_${tool} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${EIGEN3_INCLUDE_DIR}
    )
    target_compile_features(math_${tool} PRIVATE cxx_std_17)
endforeach()
