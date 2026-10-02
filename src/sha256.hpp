// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// FIPS 180-4 SHA-256, first-party, streaming, no allocation on the update path.
//
// The plan digest, the store's record digests, and the evidence digests a caller may
// compare against upstream are all SHA-256. A weaker checksum would be cheaper and
// would also make it practical to construct two different plans with the same digest,
// which would quietly break the contract that equivalent inputs produce an identical
// plan.

#ifndef CSP_SRC_SHA256_HPP
#define CSP_SRC_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "cross_site_placement/error.hpp"

namespace csp::detail {

class Sha256 {
 public:
  Sha256() noexcept;

  void update(std::string_view bytes) noexcept;
  void update(const void* data, std::size_t size) noexcept;

  /// Finalises and returns the 32 raw digest bytes. The object is left finalised;
  /// update() after finish() is a programming defect and is ignored rather than
  /// producing a digest of silently truncated input.
  [[nodiscard]] std::string finish() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_;
  std::array<std::uint8_t, 64> buffer_;
  std::size_t buffered_;
  std::uint64_t total_bytes_;
  bool finished_;
};

/// Lowercase hexadecimal of an arbitrary byte string.
[[nodiscard]] std::string to_hex(std::string_view bytes);

/// Decodes lowercase or uppercase hexadecimal. Rejects an odd length, a non-hex
/// character, and an empty string.
[[nodiscard]] Result<std::string> from_hex(std::string_view hex);

}  // namespace csp::detail

#endif  // CSP_SRC_SHA256_HPP
