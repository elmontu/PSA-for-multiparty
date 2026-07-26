// volePSI/MpsaShuffleIntegrity.cpp
//
// See MpsaShuffleIntegrity.h for the protocol + threat model.

#include "MpsaShuffleIntegrity.h"
#include "MpPedersen.h"   // pedersenCommit, pedersenVerify
#include "MpRistretto.h"  // R255Scalar, hashToScalar, scalarAdd

#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace volePSI {
namespace mpstar {

// ---------- sender side --------------------------------------------------

SenderColumnWitness makeSenderWitness(
    const std::vector<std::vector<oc::block>>& columns)
{
    // W=0 is a valid input (no payload columns) -- return an empty witness
    // rather than throwing. Callers can freely pass empty column sets.
    const size_t W = columns.size();
    SenderColumnWitness witness;
    witness.commits.resize(W);
    witness.claimedSums.resize(W);
    witness.openings.resize(W);

    for (size_t w = 0; w < W; ++w) {
        const auto& col = columns[w];
        // claimedSum = Σ_j hashToScalar(block_bytes)
        R255Scalar sum = R255Scalar::zero();
        for (const auto& blk : col) {
            std::vector<uint8_t> tmp(16);
            std::memcpy(tmp.data(), &blk, 16);
            R255Scalar h = hashToScalar(tmp);
            sum = scalarAdd(sum, h);
        }

        R255Scalar r = R255Scalar::random();
        PedersenCommitment com = pedersenCommit(sum, r);

        witness.commits[w]     = com;
        witness.claimedSums[w] = sum;
        witness.openings[w]    = r;
    }
    return witness;
}

// ---------- serialization helpers ----------------------------------------

std::vector<uint8_t> serializeCommits(
    const std::vector<PedersenCommitment>& commits)
{
    const size_t W = commits.size();
    std::vector<uint8_t> out(W * 32);
    for (size_t i = 0; i < W; ++i) {
        std::memcpy(out.data() + i * 32, commits[i].c.bytes.data(), 32);
    }
    return out;
}

std::vector<PedersenCommitment> deserializeCommits(
    const std::vector<uint8_t>& data, size_t W)
{
    if (data.size() != W * 32) {
        throw std::runtime_error("deserializeCommits: data size mismatch");
    }
    std::vector<PedersenCommitment> commits(W);
    for (size_t i = 0; i < W; ++i) {
        std::memcpy(commits[i].c.bytes.data(), data.data() + i * 32, 32);
    }
    return commits;
}

std::vector<uint8_t> serializeOpenings(
    const std::vector<R255Scalar>& claimedSums,
    const std::vector<R255Scalar>& openings)
{
    if (claimedSums.size() != openings.size()) {
        throw std::runtime_error("serializeOpenings: size mismatch");
    }
    const size_t W = claimedSums.size();
    std::vector<uint8_t> out(2 * W * 32);
    // W claimedSums, then W openings.
    for (size_t i = 0; i < W; ++i) {
        std::memcpy(out.data() + i * 32, claimedSums[i].bytes.data(), 32);
    }
    for (size_t i = 0; i < W; ++i) {
        std::memcpy(out.data() + (W + i) * 32, openings[i].bytes.data(), 32);
    }
    return out;
}

void deserializeOpenings(
    const std::vector<uint8_t>& data, size_t W,
    std::vector<R255Scalar>& claimedSums,
    std::vector<R255Scalar>& openings)
{
    if (data.size() != 2 * W * 32) {
        throw std::runtime_error("deserializeOpenings: data size mismatch");
    }
    claimedSums.resize(W);
    openings.resize(W);
    for (size_t i = 0; i < W; ++i) {
        std::memcpy(claimedSums[i].bytes.data(), data.data() + i * 32, 32);
    }
    for (size_t i = 0; i < W; ++i) {
        std::memcpy(openings[i].bytes.data(), data.data() + (W + i) * 32, 32);
    }
}

// ---------- SP verification ------------------------------------------------

bool verifySenderIntegrity(
    const std::vector<PedersenCommitment>& commits,
    const std::vector<R255Scalar>&         claimedSums,
    const std::vector<R255Scalar>&         openings,
    const std::vector<std::vector<oc::block>>& shuffledColumns)
{
    const size_t W = commits.size();
    if (claimedSums.size() != W || openings.size() != W ||
        shuffledColumns.size() != W) {
        return false;
    }

    for (size_t w = 0; w < W; ++w) {
        // 1. Commitment binding.
        if (!pedersenVerify(commits[w], claimedSums[w], openings[w])) {
            return false;
        }

        // 2. Sum of shuffled column == claimedSum (cascade preserved sum).
        R255Scalar actual = R255Scalar::zero();
        for (const auto& blk : shuffledColumns[w]) {
            std::vector<uint8_t> tmp(16);
            std::memcpy(tmp.data(), &blk, 16);
            R255Scalar h = hashToScalar(tmp);
            actual = scalarAdd(actual, h);
        }
        if (!(actual == claimedSums[w])) {
            return false;
        }
    }
    return true;
}

// ------------- A-mset-row: cross-column row-integrity check ---------------

namespace {

// Hash the concatenated bytes of a sender's row (W blocks -> 16*W bytes)
// to a Ristretto scalar. The concatenation is what makes this a *row* hash
// (not a per-column hash) -- if any column of any row is swapped for a
// different column's value, the concatenation changes and the hash changes.
R255Scalar hashRowConcat(const std::vector<oc::block>& row) {
    std::vector<uint8_t> concat(16 * row.size());
    for (size_t w = 0; w < row.size(); ++w) {
        std::memcpy(concat.data() + w * 16, &row[w], 16);
    }
    return hashToScalar(concat);
}

// Reconstruct the sender's row j from its W parallel columns.
std::vector<oc::block> reconstructRow(
    const std::vector<std::vector<oc::block>>& columns, size_t j) {
    std::vector<oc::block> row(columns.size());
    for (size_t w = 0; w < columns.size(); ++w) {
        row[w] = columns[w][j];
    }
    return row;
}

} // anonymous namespace

SenderRowWitness makeSenderRowWitness(
    const std::vector<std::vector<oc::block>>& rows)
{
    SenderRowWitness witness;
    if (rows.empty()) {
        // No rows -> nothing to commit to. Return a canonical empty
        // witness (all zeros). verifySenderRowIntegrity handles this shape
        // without invoking Pedersen (which errors on zero scalars).
        witness.claimedSum = R255Scalar::zero();
        witness.opening    = R255Scalar::zero();
        // commit stays default-constructed (all zeros); never used.
        return witness;
    }
    R255Scalar sum = R255Scalar::zero();
    for (const auto& row : rows) {
        R255Scalar h = hashRowConcat(row);
        sum = scalarAdd(sum, h);
    }
    R255Scalar r = R255Scalar::random();
    witness.commit     = pedersenCommit(sum, r);
    witness.claimedSum = sum;
    witness.opening    = r;
    return witness;
}

std::vector<uint8_t> serializeRowCommit(const PedersenCommitment& c) {
    std::vector<uint8_t> out(32);
    std::memcpy(out.data(), c.c.bytes.data(), 32);
    return out;
}

PedersenCommitment deserializeRowCommit(const std::vector<uint8_t>& data) {
    if (data.size() != 32) {
        throw std::runtime_error("deserializeRowCommit: expected 32 bytes");
    }
    PedersenCommitment c;
    std::memcpy(c.c.bytes.data(), data.data(), 32);
    return c;
}

std::vector<uint8_t> serializeRowOpening(
    const R255Scalar& claimedSum, const R255Scalar& opening)
{
    std::vector<uint8_t> out(64);
    std::memcpy(out.data(),      claimedSum.bytes.data(), 32);
    std::memcpy(out.data() + 32, opening.bytes.data(),    32);
    return out;
}

void deserializeRowOpening(
    const std::vector<uint8_t>& data,
    R255Scalar& claimedSum, R255Scalar& opening)
{
    if (data.size() != 64) {
        throw std::runtime_error("deserializeRowOpening: expected 64 bytes");
    }
    std::memcpy(claimedSum.bytes.data(), data.data(),      32);
    std::memcpy(opening.bytes.data(),    data.data() + 32, 32);
}

bool verifySenderRowIntegrity(
    const PedersenCommitment& commit,
    const R255Scalar&         claimedSum,
    const R255Scalar&         opening,
    const std::vector<std::vector<oc::block>>& shuffledColumns)
{
    // Empty-input edge case: makeSenderRowWitness returned a canonical
    // all-zero witness without invoking Pedersen. Accept iff the shuffled
    // side is also empty and the witness matches the canonical form.
    // Empty here means 0 columns (W=0), matching what the sender produced.
    if (shuffledColumns.empty()) {
        return claimedSum == R255Scalar::zero()
            && opening    == R255Scalar::zero();
    }

    // 1. Binding.
    if (!pedersenVerify(commit, claimedSum, opening)) return false;

    // 2. Row-hash sum matches claim. Column vectors must all have the same C.
    const size_t C = shuffledColumns[0].size();
    for (const auto& col : shuffledColumns) {
        if (col.size() != C) return false;
    }
    R255Scalar actual = R255Scalar::zero();
    for (size_t j = 0; j < C; ++j) {
        auto row = reconstructRow(shuffledColumns, j);
        actual = scalarAdd(actual, hashRowConcat(row));
    }
    return actual == claimedSum;
}

} // namespace mpstar
} // namespace volePSI
