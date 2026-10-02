// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320, initial value 0xFFFFFFFF,
// final xor 0xFFFFFFFF).
//
// This checksum frames persisted records so that a torn write is detected cheaply.
// It is explicitly not a security primitive and is never the only integrity check on
// authoritative state: a record also carries a SHA-256 digest of its payload.

#ifndef CSP_SRC_CRC32_HPP
#define CSP_SRC_CRC32_HPP

#include <cstdint>
#include <string_view>

namespace csp::detail {

/// The CRC of the empty input is 0x00000000.
[[nodiscard]] std::uint32_t crc32(std::string_view bytes) noexcept;

/// Continues a checksum over a further chunk, so a record can be checked while
/// streaming without ever holding the whole payload twice.
[[nodiscard]] std::uint32_t crc32_extend(std::uint32_t seed, std::string_view bytes) noexcept;

}  // namespace csp::detail

#endif  // CSP_SRC_CRC32_HPP
