// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "cross_site_placement/strong_types.hpp"

#include <string>

#include "checked.hpp"
#include "sha256.hpp"

namespace csp {
namespace {

// The identity alphabet is deliberately narrow and, more importantly, path-safe.
// An identity ends up as a file name in the durable store, in a URL-shaped reference,
// and in a trace line, so a separator, a drive letter, a dot at either end, or a
// control character in one would be a defect waiting for the right input. Identities
// outside the alphabet are refused by the authority that owns them, not silently
// rewritten here.
constexpr bool is_alpha_numeric(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

constexpr bool is_allowed_punctuation(char c) noexcept {
  return c == '-' || c == '_' || c == '.' || c == ':' || c == '@' || c == '+' || c == '#';
}

constexpr bool is_hex_digit(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

}  // namespace

namespace detail {

Result<std::string> identifier_validate(std::string_view text, std::string_view what) {
  std::string prefix(what);

  if (text.empty()) {
    return fail(ErrorCategory::Invalid, "csp.identifier.empty", prefix + " identity is empty");
  }
  if (text.size() > kMaxIdentifierBytes) {
    return fail(ErrorCategory::OutOfRange, "csp.identifier.too_long",
                prefix + " identity is " + std::to_string(text.size()) + " bytes, above the " +
                    std::to_string(kMaxIdentifierBytes) + " byte bound");
  }
  if (!is_alpha_numeric(text.front())) {
    return fail(ErrorCategory::Invalid, "csp.identifier.first_byte",
                prefix + " identity must start with an alphanumeric character");
  }
  if (!is_alpha_numeric(text.back())) {
    return fail(ErrorCategory::Invalid, "csp.identifier.last_byte",
                prefix + " identity must end with an alphanumeric character");
  }
  for (std::size_t index = 0; index < text.size(); ++index) {
    const char c = text[index];
    if (!is_alpha_numeric(c) && !is_allowed_punctuation(c)) {
      static constexpr char kHex[] = "0123456789abcdef";
      std::string message = prefix;
      message += " identity contains a byte outside the documented alphabet at offset ";
      message += std::to_string(index);
      message += " (0x";
      const auto byte = static_cast<unsigned int>(static_cast<unsigned char>(c));
      message += kHex[(byte >> 4) & 0x0FU];
      message += kHex[byte & 0x0FU];
      message += ")";
      return fail(ErrorCategory::Invalid, "csp.identifier.alphabet", std::move(message));
    }
  }
  return std::string(text);
}

}  // namespace detail

Result<Duration> Duration::from_millis(std::int64_t millis) {
  const std::optional<std::int64_t> nanos = detail::checked_mul(millis, 1000000);
  if (!nanos.has_value()) {
    return fail(ErrorCategory::OutOfRange, "csp.duration.overflow",
                "milliseconds do not fit a nanosecond interval");
  }
  return Duration::from_nanos(*nanos);
}

Result<Duration> Duration::from_seconds(std::int64_t seconds) {
  const std::optional<std::int64_t> nanos = detail::checked_mul(seconds, 1000000000);
  if (!nanos.has_value()) {
    return fail(ErrorCategory::OutOfRange, "csp.duration.overflow",
                "seconds do not fit a nanosecond interval");
  }
  return Duration::from_nanos(*nanos);
}

Result<Duration> Duration::checked_add(Duration other) const {
  const std::optional<std::int64_t> sum = detail::checked_add(nanos_, other.nanos_);
  if (!sum.has_value()) {
    return fail(ErrorCategory::OutOfRange, "csp.duration.overflow", "adding two intervals overflowed");
  }
  return Duration::from_nanos(*sum);
}

Result<Duration> Duration::checked_sub(Duration other) const {
  const std::optional<std::int64_t> difference = detail::checked_sub(nanos_, other.nanos_);
  if (!difference.has_value()) {
    return fail(ErrorCategory::OutOfRange, "csp.duration.overflow", "subtracting two intervals overflowed");
  }
  return Duration::from_nanos(*difference);
}

Result<Duration> elapsed(Instant earlier, Instant later) {
  if (later.nanos() < earlier.nanos()) {
    return fail(ErrorCategory::OutOfRange, "csp.time.negative_interval",
                "the later instant precedes the earlier one, so the interval would be negative");
  }
  const std::optional<std::int64_t> difference = detail::checked_sub(later.nanos(), earlier.nanos());
  if (!difference.has_value()) {
    return fail(ErrorCategory::OutOfRange, "csp.time.overflow", "the interval between two instants overflowed");
  }
  return Duration::from_nanos(*difference);
}

Result<Quantity> Quantity::parse(std::string_view text) {
  std::int64_t parsed = 0;
  if (!detail::parse_i64(text, parsed)) {
    return fail(ErrorCategory::Invalid, "csp.quantity.parse",
                "quantity is not a canonical decimal integer");
  }
  return Quantity::from_units(parsed);
}

Result<Quantity> Quantity::checked_add(Quantity other) const {
  const std::optional<std::int64_t> sum = detail::checked_add(units_, other.units_);
  if (!sum.has_value()) {
    return fail(ErrorCategory::OutOfRange, "csp.quantity.overflow", "adding two quantities overflowed");
  }
  return Quantity::from_units(*sum);
}

Result<Quantity> Quantity::checked_sub(Quantity other) const {
  const std::optional<std::int64_t> difference = detail::checked_sub(units_, other.units_);
  if (!difference.has_value()) {
    return fail(ErrorCategory::OutOfRange, "csp.quantity.overflow", "subtracting two quantities overflowed");
  }
  return Quantity::from_units(*difference);
}

Result<Quantity> Quantity::checked_mul(std::int64_t factor) const {
  const std::optional<std::int64_t> product = detail::checked_mul(units_, factor);
  if (!product.has_value()) {
    return fail(ErrorCategory::OutOfRange, "csp.quantity.overflow", "scaling a quantity overflowed");
  }
  return Quantity::from_units(*product);
}

Result<Generation> Generation::next() const {
  std::uint64_t next_value = 0;
  if (detail::add_overflow(value_, std::uint64_t{1}, next_value)) {
    return fail(ErrorCategory::OutOfRange, "csp.generation.exhausted",
                "the generation counter is exhausted; it would wrap to a value that reads as older");
  }
  return Generation::from_value(next_value);
}

Result<Digest> Digest::parse_hex(std::string_view hex) {
  if (hex.size() != 64) {
    return fail(ErrorCategory::Invalid, "csp.digest.length",
                "a SHA-256 digest is 64 hexadecimal characters; this one is " + std::to_string(hex.size()));
  }
  for (const char c : hex) {
    if (!is_hex_digit(c)) {
      return fail(ErrorCategory::Invalid, "csp.digest.alphabet",
                  "a digest may contain only hexadecimal characters");
    }
  }
  Result<std::string> raw = detail::from_hex(hex);
  if (!raw) {
    return raw.error();
  }
  Digest digest;
  const std::string& bytes = raw.value();
  for (std::size_t index = 0; index < digest.bytes_.size(); ++index) {
    digest.bytes_[index] = static_cast<std::uint8_t>(static_cast<unsigned char>(bytes[index]));
  }
  return digest;
}

Digest Digest::of(std::string_view bytes) {
  detail::Sha256 hasher;
  hasher.update(bytes);
  const std::string raw = hasher.finish();
  Digest digest;
  for (std::size_t index = 0; index < digest.bytes_.size() && index < raw.size(); ++index) {
    digest.bytes_[index] = static_cast<std::uint8_t>(static_cast<unsigned char>(raw[index]));
  }
  return digest;
}

bool Digest::is_zero() const noexcept {
  for (const std::uint8_t byte : bytes_) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

std::string Digest::to_hex() const {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes_.size() * 2);
  for (const std::uint8_t byte : bytes_) {
    out.push_back(kHex[(byte >> 4) & 0x0FU]);
    out.push_back(kHex[byte & 0x0FU]);
  }
  return out;
}

}  // namespace csp
