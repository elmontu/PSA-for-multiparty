#pragma once

// Hand-rolled config.h for the vendored ladnir/volepsi subset.
// Upstream generates this file from config.h.in via CMake. See
// volePSI/upstream/README.md for provenance and integration status.

// GMW is vendored (needed by MPSO). Enable.
#define VOLE_PSI_ENABLE_GMW 1

// Circuit-PSI: not vendored (MPSO doesn't need it).
/* #undef VOLE_PSI_ENABLE_CPSI */

// OPPRF: not vendored (MPSO doesn't need it).
/* #undef VOLE_PSI_ENABLE_OPPRF */
