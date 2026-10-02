// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The document model shared by the CLI, the durable store, and the plan digest.
//
// Two properties matter more than convenience here.
//
//   * There is no floating-point type in the model at all. Every number in this
//     boundary is an exact integer, so the decoder never has to decide how to round
//     a measurement and the encoder never has to choose a float format. A document
//     containing a fractional or exponent number is rejected as malformed rather
//     than silently truncated into a different value.
//
//   * Object members are stored sorted by key in byte order and keys are unique, so
//     the canonical encoding of a value is a pure function of that value. Nothing in
//     the digest path depends on insertion order.
//
// The decoder is a trust boundary. It never throws, never reads past the declared
// input length, never allocates an array or object before the declared count has been
// checked against both the configured limits and the bytes that remain, and reports a
// structured error rather than a partially decoded value.

#ifndef CSP_SRC_JSON_HPP
#define CSP_SRC_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cross_site_placement/error.hpp"

namespace csp::detail {

class JsonValue {
 public:
  enum class Kind : std::uint8_t { Null, Bool, Int, Uint, String, Array, Object };

  JsonValue() noexcept;

  static JsonValue make_null();
  static JsonValue make_bool(bool value);
  static JsonValue make_int(std::int64_t value);
  static JsonValue make_uint(std::uint64_t value);
  static JsonValue make_string(std::string value);
  static JsonValue make_array(std::vector<JsonValue> values);
  static JsonValue make_object();

  Kind kind() const noexcept { return kind_; }
  bool is_null() const noexcept { return kind_ == Kind::Null; }
  bool is_bool() const noexcept { return kind_ == Kind::Bool; }
  bool is_number() const noexcept { return kind_ == Kind::Int || kind_ == Kind::Uint; }
  bool is_string() const noexcept { return kind_ == Kind::String; }
  bool is_array() const noexcept { return kind_ == Kind::Array; }
  bool is_object() const noexcept { return kind_ == Kind::Object; }

  /// Typed access. The require_* accessors distinguish "absent" (NotFound) from
  /// "present with the wrong type" (Invalid), because a caller acting on a document
  /// has to tell those apart to report anything useful.
  Result<bool> require_bool() const;
  Result<std::int64_t> require_int() const;
  Result<std::uint64_t> require_uint() const;
  Result<std::string_view> require_string() const;

  /// Preconditions: the matching is_* predicate holds. These do not throw and do not
  /// check; they exist for the writer and for code that has already dispatched on
  /// kind(). A wrong precondition is a defect in this library, not in caller input.
  bool as_bool() const noexcept;
  std::int64_t as_int() const noexcept;
  std::uint64_t as_uint() const noexcept;
  const std::string& as_string() const noexcept;
  const std::vector<JsonValue>& items() const noexcept;
  const std::vector<std::pair<std::string, JsonValue>>& members() const noexcept;

  /// Binary search over the sorted members; nullptr when absent.
  const JsonValue* find(std::string_view key) const noexcept;

  /// Inserts or replaces, keeping members sorted by key.
  void set(std::string key, JsonValue value);

  /// Appends to an array. A no-op on any other kind, so a caller that has already
  /// checked is_object() cannot corrupt the value by accident.
  void push_back(JsonValue value);

 private:
  Kind kind_;
  bool bool_{};
  std::int64_t int_{};
  std::uint64_t uint_{};
  std::string string_;
  std::vector<JsonValue> items_;
  std::vector<std::pair<std::string, JsonValue>> members_;
};

struct JsonLimits {
  std::size_t max_bytes = 16u * 1024u * 1024u;
  std::size_t max_depth = 48;
  std::size_t max_string_bytes = 1u * 1024u * 1024u;
  std::size_t max_array_items = 4u * 1024u * 1024u;
  std::size_t max_object_members = 1u * 1024u * 1024u;
  std::size_t max_key_bytes = 4096;
};

/// Strict decoder with the restrictions described at the top of this file. The whole
/// input must be consumed: trailing bytes are malformed, not ignored.
[[nodiscard]] Result<JsonValue> json_parse(std::string_view text, const JsonLimits& limits);

/// Compact canonical encoding, ASCII only. Every byte outside printable ASCII is
/// emitted as a \uXXXX escape, with surrogate pairs where required, so the encoding
/// is stable across platforms and locales and cannot be perturbed by how a terminal or
/// a source file happens to represent text.
[[nodiscard]] std::string json_write_canonical(const JsonValue& value);

/// The same key order, indented for a human, ending with a newline.
[[nodiscard]] std::string json_write_pretty(const JsonValue& value, std::size_t indent = 2);

/// True when the byte string is well-formed UTF-8: no truncated sequence, no overlong
/// encoding, no surrogate code point, nothing above U+10FFFF.
[[nodiscard]] bool utf8_is_valid(std::string_view text) noexcept;

/// Decodes at most one code point at the given byte offset. Returns the code point
/// and the number of bytes consumed, or std::nullopt when the bytes there are not
/// exactly one valid encoded scalar value.
[[nodiscard]] std::optional<std::pair<std::uint32_t, std::size_t>> utf8_decode(std::string_view text,
                                                                               std::size_t offset) noexcept;

}  // namespace csp::detail

#endif  // CSP_SRC_JSON_HPP
