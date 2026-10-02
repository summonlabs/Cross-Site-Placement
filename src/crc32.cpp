// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// CRC-32 (IEEE 802.3): reflected, polynomial 0xEDB88320, initial value 0xFFFFFFFF,
// final xor 0xFFFFFFFF.
//
// The reflected state is kept across chunks rather than the finalised value, so a
// caller can hand the checksum of a prefix back in and get the checksum of the
// concatenation. The table is built on first use; the initialisation of a function-local
// static is thread-safe by the language rules, so no caller needs to arrange it.

#include "crc32.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace csp::detail {
namespace {

constexpr std::uint32_t kPolynomial = 0xEDB88320u;
constexpr std::uint32_t kInitialState = 0xFFFFFFFFu;
constexpr std::uint32_t kFinalXor = 0xFFFFFFFFu;
constexpr std::size_t kTableSize = 256;
constexpr std::uint32_t kByteMask = 0xFFu;

using CrcTable = std::array<std::uint32_t, kTableSize>;

CrcTable build_table() noexcept {
  CrcTable table{};
  for (std::size_t index = 0; index < kTableSize; ++index) {
    std::uint32_t value = static_cast<std::uint32_t>(index);
    for (int bit = 0; bit < 8; ++bit) {
      if ((value & 1u) != 0u) {
        value = (value >> 1u) ^ kPolynomial;
      } else {
        value >>= 1u;
      }
    }
    table[index] = value;
  }
  return table;
}

const CrcTable& table() noexcept {
  static const CrcTable instance = build_table();
  return instance;
}

/// Advances the reflected state over every byte.
std::uint32_t step(std::uint32_t state, std::string_view bytes) noexcept {
  const CrcTable& lookup = table();
  for (const char ch : bytes) {
    const auto byte = static_cast<std::uint8_t>(ch);
    const std::uint32_t index = (state ^ byte) & kByteMask;
    state = lookup[index] ^ (state >> 8u);
  }
  return state;
}

}  // namespace

std::uint32_t crc32(std::string_view bytes) noexcept {
  return step(kInitialState, bytes) ^ kFinalXor;
}

std::uint32_t crc32_extend(std::uint32_t seed, std::string_view bytes) noexcept {
  return step(seed ^ kFinalXor, bytes) ^ kFinalXor;
}

}  // namespace csp::detail
