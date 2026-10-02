// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Checked integer arithmetic.
//
// Every capacity, duration, count, sequence number, and externally supplied size in
// this boundary is an exact integer, and every operation on one goes through these
// helpers. A wrapped capacity total is a fabricated capacity total: it would let the
// planner report that a site can hold something it cannot, which is precisely the
// failure this boundary exists to prevent. Overflow is therefore reported, never
// absorbed.

#ifndef CSP_SRC_CHECKED_HPP
#define CSP_SRC_CHECKED_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace csp::detail {

[[nodiscard]] bool add_overflow(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept;
[[nodiscard]] bool sub_overflow(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept;
[[nodiscard]] bool mul_overflow(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept;

[[nodiscard]] bool add_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept;
[[nodiscard]] bool sub_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept;
[[nodiscard]] bool mul_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept;

/// std::nullopt on overflow; the exact sum otherwise.
[[nodiscard]] std::optional<std::int64_t> checked_add(std::int64_t a, std::int64_t b) noexcept;
[[nodiscard]] std::optional<std::int64_t> checked_sub(std::int64_t a, std::int64_t b) noexcept;
[[nodiscard]] std::optional<std::int64_t> checked_mul(std::int64_t a, std::int64_t b) noexcept;
[[nodiscard]] std::optional<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b) noexcept;
[[nodiscard]] std::optional<std::uint64_t> checked_sub(std::uint64_t a, std::uint64_t b) noexcept;
[[nodiscard]] std::optional<std::uint64_t> checked_mul(std::uint64_t a, std::uint64_t b) noexcept;

/// Exact sum over a range of quantities, or std::nullopt if any step overflows.
/// Consumes the half-open range [first, last) exactly once.
[[nodiscard]] std::optional<std::uint64_t> checked_sum_u64(const std::uint64_t* first,
                                                           const std::uint64_t* last) noexcept;
[[nodiscard]] std::optional<std::int64_t> checked_sum_i64(const std::int64_t* first,
                                                          const std::int64_t* last) noexcept;

/// Converts a size_t count that came from outside this process into an exact
/// integer, reporting a count larger than int64 can hold rather than wrapping it.
[[nodiscard]] std::optional<std::int64_t> checked_from_size(std::size_t value) noexcept;

/// Strict decimal parsers. Leading whitespace, a leading plus sign, underscores, a
/// leading zero before further digits, and the string "-0" are all rejected; an
/// empty string is rejected; a value that does not fit the destination is rejected.
/// These run on untrusted text, so they never fall back to a lenient reading.
[[nodiscard]] bool parse_u64(std::string_view text, std::uint64_t& out) noexcept;
[[nodiscard]] bool parse_i64(std::string_view text, std::int64_t& out) noexcept;

}  // namespace csp::detail

#endif  // CSP_SRC_CHECKED_HPP
