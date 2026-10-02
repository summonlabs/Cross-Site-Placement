// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Checked integer arithmetic and the strict decimal parsers.
//
// Two implementations of the overflow primitives are provided. On GCC and Clang the
// compiler builtins compute the exact result and say whether it fits. On MSVC the same
// six operations are written out so that every intermediate value is computed either in
// unsigned arithmetic, where wraparound is defined, or inside a range that has already
// been proven to fit, so no expression in this file can overflow a signed type. Both
// paths report overflow; neither absorbs it.

#include "checked.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

namespace csp::detail {
namespace {

constexpr std::uint64_t kMaxU64 = (std::numeric_limits<std::uint64_t>::max)();
constexpr std::uint64_t kMaxI64 = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
/// The magnitude of INT64_MIN, which is one larger than kMaxI64.
constexpr std::uint64_t kMinI64Magnitude = kMaxI64 + 1u;

constexpr bool is_digit(char ch) noexcept { return ch >= '0' && ch <= '9'; }

/// Folds one decimal digit into a magnitude that may not exceed limit, reporting the
/// overflow instead of wrapping. The caller guarantees that ch is a decimal digit and
/// that limit is at least nine.
bool fold_digit(std::uint64_t& magnitude, std::uint64_t limit, char ch) noexcept {
  const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
  if (magnitude > (limit - digit) / 10u) {
    return false;
  }
  magnitude = magnitude * 10u + digit;
  return true;
}

}  // namespace

#if defined(_MSC_VER)

// ---------------------------------------------------------------------------------
// MSVC: no builtins are assumed. Unsigned wraparound is defined behaviour, so each
// signed operation is evaluated in the unsigned domain and the sign of that result is
// then compared against the sign the exact result would have carried.
// ---------------------------------------------------------------------------------

bool add_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  out = a + b;
  return out < a;
}

bool sub_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  out = a - b;
  return a < b;
}

bool mul_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  if (a != 0u && b > kMaxU64 / a) {
    out = a * b;
    return true;
  }
  out = a * b;
  return false;
}

bool add_overflow(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept {
  const std::int64_t sum =
      static_cast<std::int64_t>(static_cast<std::uint64_t>(a) + static_cast<std::uint64_t>(b));
  if ((a >= 0) == (b >= 0) && (sum >= 0) != (a >= 0)) {
    return true;
  }
  out = sum;
  return false;
}

bool sub_overflow(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept {
  const std::int64_t difference =
      static_cast<std::int64_t>(static_cast<std::uint64_t>(a) - static_cast<std::uint64_t>(b));
  if ((a >= 0) != (b >= 0) && (difference >= 0) != (a >= 0)) {
    return true;
  }
  out = difference;
  return false;
}

bool mul_overflow(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept {
  const bool negative = (a < 0) != (b < 0);
  const std::uint64_t magnitude_a =
      (a < 0) ? (std::uint64_t{0} - static_cast<std::uint64_t>(a)) : static_cast<std::uint64_t>(a);
  const std::uint64_t magnitude_b =
      (b < 0) ? (std::uint64_t{0} - static_cast<std::uint64_t>(b)) : static_cast<std::uint64_t>(b);
  const std::uint64_t limit = negative ? kMinI64Magnitude : kMaxI64;
  if (magnitude_b != 0u && magnitude_a > limit / magnitude_b) {
    return true;
  }
  const std::uint64_t product = magnitude_a * magnitude_b;
  out = negative ? static_cast<std::int64_t>(std::uint64_t{0} - product)
                 : static_cast<std::int64_t>(product);
  return false;
}

#else

// ---------------------------------------------------------------------------------
// GCC and Clang: the builtins evaluate the operation in an infinite-precision domain
// and report whether the result is representable.
// ---------------------------------------------------------------------------------

bool add_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  return __builtin_add_overflow(a, b, &out);
}

bool sub_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  return __builtin_sub_overflow(a, b, &out);
}

bool mul_overflow(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
  return __builtin_mul_overflow(a, b, &out);
}

bool add_overflow(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept {
  return __builtin_add_overflow(a, b, &out);
}

bool sub_overflow(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept {
  return __builtin_sub_overflow(a, b, &out);
}

bool mul_overflow(std::int64_t a, std::int64_t b, std::int64_t& out) noexcept {
  return __builtin_mul_overflow(a, b, &out);
}

#endif

std::optional<std::int64_t> checked_add(std::int64_t a, std::int64_t b) noexcept {
  std::int64_t result = 0;
  if (add_overflow(a, b, result)) {
    return std::nullopt;
  }
  return result;
}

std::optional<std::int64_t> checked_sub(std::int64_t a, std::int64_t b) noexcept {
  std::int64_t result = 0;
  if (sub_overflow(a, b, result)) {
    return std::nullopt;
  }
  return result;
}

std::optional<std::int64_t> checked_mul(std::int64_t a, std::int64_t b) noexcept {
  std::int64_t result = 0;
  if (mul_overflow(a, b, result)) {
    return std::nullopt;
  }
  return result;
}

std::optional<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b) noexcept {
  std::uint64_t result = 0;
  if (add_overflow(a, b, result)) {
    return std::nullopt;
  }
  return result;
}

std::optional<std::uint64_t> checked_sub(std::uint64_t a, std::uint64_t b) noexcept {
  std::uint64_t result = 0;
  if (sub_overflow(a, b, result)) {
    return std::nullopt;
  }
  return result;
}

std::optional<std::uint64_t> checked_mul(std::uint64_t a, std::uint64_t b) noexcept {
  std::uint64_t result = 0;
  if (mul_overflow(a, b, result)) {
    return std::nullopt;
  }
  return result;
}

std::optional<std::uint64_t> checked_sum_u64(const std::uint64_t* first,
                                             const std::uint64_t* last) noexcept {
  std::uint64_t total = 0;
  while (first != last) {
    std::uint64_t next = 0;
    if (add_overflow(total, *first, next)) {
      return std::nullopt;
    }
    total = next;
    ++first;
  }
  return total;
}

std::optional<std::int64_t> checked_sum_i64(const std::int64_t* first,
                                            const std::int64_t* last) noexcept {
  std::int64_t total = 0;
  while (first != last) {
    std::int64_t next = 0;
    if (add_overflow(total, *first, next)) {
      return std::nullopt;
    }
    total = next;
    ++first;
  }
  return total;
}

std::optional<std::int64_t> checked_from_size(std::size_t value) noexcept {
  const std::uint64_t wide = static_cast<std::uint64_t>(value);
  if (wide > kMaxI64) {
    return std::nullopt;
  }
  return static_cast<std::int64_t>(wide);
}

bool parse_u64(std::string_view text, std::uint64_t& out) noexcept {
  if (text.empty()) {
    return false;
  }
  // A leading zero is legal only when the whole literal is that zero.
  if (text.size() > 1 && text.front() == '0') {
    return false;
  }
  std::uint64_t magnitude = 0;
  for (const char ch : text) {
    if (!is_digit(ch)) {
      return false;
    }
    if (!fold_digit(magnitude, kMaxU64, ch)) {
      return false;
    }
  }
  out = magnitude;
  return true;
}

bool parse_i64(std::string_view text, std::int64_t& out) noexcept {
  if (text.empty()) {
    return false;
  }
  bool negative = false;
  std::size_t first_digit = 0;
  if (text.front() == '-') {
    negative = true;
    first_digit = 1;
    // The sign must be followed immediately by a digit: "-" and "-x" are both refused.
    if (text.size() == 1 || !is_digit(text[1])) {
      return false;
    }
  }
  const std::string_view digits = text.substr(first_digit);
  if (digits.size() > 1 && digits.front() == '0') {
    return false;
  }
  if (negative && digits.front() == '0') {
    return false;  // "-0"
  }
  const std::uint64_t limit = negative ? kMinI64Magnitude : kMaxI64;
  std::uint64_t magnitude = 0;
  for (const char ch : digits) {
    if (!is_digit(ch)) {
      return false;
    }
    if (!fold_digit(magnitude, limit, ch)) {
      return false;
    }
  }
  out = negative ? static_cast<std::int64_t>(std::uint64_t{0} - magnitude)
                 : static_cast<std::int64_t>(magnitude);
  return true;
}

}  // namespace csp::detail
