// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The document model: value storage, strict UTF-8, the strict decoder, and the two
// encoders.
//
// Key order. Object members are kept sorted by std::string_view::compare, which the
// standard defines in terms of std::char_traits<char>::compare. For the standard char
// traits that comparison has memcmp semantics, so the bytes are compared as unsigned
// char: the order is unsigned byte order on every supported platform and does not depend
// on whether plain char is signed. find(), set(), and the decoder's duplicate check all
// compare through compare_keys, so the ordering exists in exactly one place here.
//
// Escaping. Both encoders are ASCII-only: every byte at or above 0x7F is decoded and
// written as a \uXXXX escape, with a surrogate pair above U+FFFF. A byte that is not
// part of a valid UTF-8 sequence is written as \uFFFD, one replacement character per
// invalid byte, so the output of the writer is always well-formed ASCII regardless of
// what a caller stored in a string value.

#include "json.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cross_site_placement/error.hpp"

namespace csp::detail {
namespace {

constexpr std::uint64_t kMaxU64 = (std::numeric_limits<std::uint64_t>::max)();
constexpr std::uint64_t kMaxI64 = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
/// The magnitude of INT64_MIN, which is one larger than kMaxI64.
constexpr std::uint64_t kMinI64Magnitude = kMaxI64 + 1u;

constexpr bool is_digit(char ch) noexcept { return ch >= '0' && ch <= '9'; }

constexpr int hex_digit(char ch) noexcept {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  }
  if (ch >= 'A' && ch <= 'F') {
    return ch - 'A' + 10;
  }
  return -1;
}

constexpr bool is_continuation(std::uint8_t byte) noexcept { return (byte & 0xC0u) == 0x80u; }

/// The one ordering used for object keys: unsigned byte comparison.
int compare_keys(std::string_view lhs, std::string_view rhs) noexcept { return lhs.compare(rhs); }

constexpr std::string_view kind_name(JsonValue::Kind kind) noexcept {
  switch (kind) {
    case JsonValue::Kind::Null:
      return "null";
    case JsonValue::Kind::Bool:
      return "bool";
    case JsonValue::Kind::Int:
      return "int";
    case JsonValue::Kind::Uint:
      return "uint";
    case JsonValue::Kind::String:
      return "string";
    case JsonValue::Kind::Array:
      return "array";
    case JsonValue::Kind::Object:
      return "object";
  }
  return "unknown";
}

/// Builds an error whose message ends with the byte offset the problem was found at.
Error json_error(ErrorCategory category, std::string_view code, std::size_t offset,
                 std::string_view detail) {
  std::string message(detail);
  message += " at byte offset ";
  message += std::to_string(offset);
  return fail(category, std::string(code), std::move(message));
}

Error type_error(std::string_view expected, JsonValue::Kind actual) {
  std::string message = "expected ";
  message += expected;
  message += " but found ";
  message += kind_name(actual);
  return fail(ErrorCategory::Invalid, "csp.json.type", std::move(message));
}

/// Appends the UTF-8 encoding of one scalar value. The decoder only calls this with a
/// value it has already proven is a scalar, so no surrogate or range check is repeated.
void append_utf8(std::string& out, std::uint32_t code_point) {
  if (code_point <= 0x7Fu) {
    out.push_back(static_cast<char>(code_point));
  } else if (code_point <= 0x7FFu) {
    out.push_back(static_cast<char>(0xC0u | (code_point >> 6u)));
    out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  } else if (code_point <= 0xFFFFu) {
    out.push_back(static_cast<char>(0xE0u | (code_point >> 12u)));
    out.push_back(static_cast<char>(0x80u | ((code_point >> 6u) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  } else {
    out.push_back(static_cast<char>(0xF0u | (code_point >> 18u)));
    out.push_back(static_cast<char>(0x80u | ((code_point >> 12u) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | ((code_point >> 6u) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  }
}

void append_indent(std::string& out, std::size_t indent, std::size_t depth) {
  out.append(indent * depth, ' ');
}

}  // namespace

std::optional<std::pair<std::uint32_t, std::size_t>> utf8_decode(std::string_view text,
                                                                 std::size_t offset) noexcept {
  if (offset >= text.size()) {
    return std::nullopt;
  }
  const auto first = static_cast<std::uint8_t>(text[offset]);
  if (first < 0x80u) {
    return std::make_pair(static_cast<std::uint32_t>(first), std::size_t{1});
  }
  const std::size_t remaining = text.size() - offset;
  // 0xC0 and 0xC1 would encode a code point below U+0080 (an overlong form); 0x80..0xBF
  // is a stray continuation byte; 0xF5..0xFF can never appear.
  if (first >= 0xC2u && first <= 0xDFu) {
    if (remaining < 2) {
      return std::nullopt;
    }
    const auto second = static_cast<std::uint8_t>(text[offset + 1]);
    if (!is_continuation(second)) {
      return std::nullopt;
    }
    const std::uint32_t code_point =
        (static_cast<std::uint32_t>(first & 0x1Fu) << 6u) | static_cast<std::uint32_t>(second & 0x3Fu);
    return std::make_pair(code_point, std::size_t{2});
  }
  if (first >= 0xE0u && first <= 0xEFu) {
    if (remaining < 3) {
      return std::nullopt;
    }
    const auto second = static_cast<std::uint8_t>(text[offset + 1]);
    const auto third = static_cast<std::uint8_t>(text[offset + 2]);
    if (!is_continuation(second) || !is_continuation(third)) {
      return std::nullopt;
    }
    // 0xE0 0x80..0x9F is overlong, and 0xED 0xA0..0xBF encodes a surrogate.
    if (first == 0xE0u && second < 0xA0u) {
      return std::nullopt;
    }
    if (first == 0xEDu && second > 0x9Fu) {
      return std::nullopt;
    }
    const std::uint32_t code_point = (static_cast<std::uint32_t>(first & 0x0Fu) << 12u) |
                                     (static_cast<std::uint32_t>(second & 0x3Fu) << 6u) |
                                     static_cast<std::uint32_t>(third & 0x3Fu);
    return std::make_pair(code_point, std::size_t{3});
  }
  if (first >= 0xF0u && first <= 0xF4u) {
    if (remaining < 4) {
      return std::nullopt;
    }
    const auto second = static_cast<std::uint8_t>(text[offset + 1]);
    const auto third = static_cast<std::uint8_t>(text[offset + 2]);
    const auto fourth = static_cast<std::uint8_t>(text[offset + 3]);
    if (!is_continuation(second) || !is_continuation(third) || !is_continuation(fourth)) {
      return std::nullopt;
    }
    // 0xF0 0x80..0x8F is overlong, and 0xF4 0x90..0xBF is above U+10FFFF.
    if (first == 0xF0u && second < 0x90u) {
      return std::nullopt;
    }
    if (first == 0xF4u && second > 0x8Fu) {
      return std::nullopt;
    }
    const std::uint32_t code_point = (static_cast<std::uint32_t>(first & 0x07u) << 18u) |
                                     (static_cast<std::uint32_t>(second & 0x3Fu) << 12u) |
                                     (static_cast<std::uint32_t>(third & 0x3Fu) << 6u) |
                                     static_cast<std::uint32_t>(fourth & 0x3Fu);
    return std::make_pair(code_point, std::size_t{4});
  }
  return std::nullopt;
}

bool utf8_is_valid(std::string_view text) noexcept {
  std::size_t offset = 0;
  while (offset < text.size()) {
    const auto decoded = utf8_decode(text, offset);
    if (!decoded.has_value()) {
      return false;
    }
    offset += decoded->second;
  }
  return true;
}

// ===================================================================================
// JsonValue
// ===================================================================================

JsonValue::JsonValue() noexcept : kind_(Kind::Null) {}

JsonValue JsonValue::make_null() { return JsonValue(); }

JsonValue JsonValue::make_bool(bool value) {
  JsonValue out;
  out.kind_ = Kind::Bool;
  out.bool_ = value;
  return out;
}

JsonValue JsonValue::make_int(std::int64_t value) {
  JsonValue out;
  out.kind_ = Kind::Int;
  out.int_ = value;
  return out;
}

JsonValue JsonValue::make_uint(std::uint64_t value) {
  JsonValue out;
  out.kind_ = Kind::Uint;
  out.uint_ = value;
  return out;
}

JsonValue JsonValue::make_string(std::string value) {
  JsonValue out;
  out.kind_ = Kind::String;
  out.string_ = std::move(value);
  return out;
}

JsonValue JsonValue::make_array(std::vector<JsonValue> values) {
  JsonValue out;
  out.kind_ = Kind::Array;
  out.items_ = std::move(values);
  return out;
}

JsonValue JsonValue::make_object() {
  JsonValue out;
  out.kind_ = Kind::Object;
  return out;
}

Result<bool> JsonValue::require_bool() const {
  if (kind_ != Kind::Bool) {
    return type_error("bool", kind_);
  }
  return bool_;
}

Result<std::int64_t> JsonValue::require_int() const {
  if (kind_ != Kind::Int) {
    return type_error("int", kind_);
  }
  return int_;
}

Result<std::uint64_t> JsonValue::require_uint() const {
  if (kind_ == Kind::Uint) {
    return uint_;
  }
  if (kind_ == Kind::Int && int_ >= 0) {
    return static_cast<std::uint64_t>(int_);
  }
  return type_error("uint", kind_);
}

Result<std::string_view> JsonValue::require_string() const {
  if (kind_ != Kind::String) {
    return type_error("string", kind_);
  }
  return std::string_view(string_);
}

bool JsonValue::as_bool() const noexcept { return bool_; }

std::int64_t JsonValue::as_int() const noexcept { return int_; }

std::uint64_t JsonValue::as_uint() const noexcept {
  // Mirrors require_uint: the widening from Int is part of the accessor's contract.
  return (kind_ == Kind::Uint) ? uint_ : static_cast<std::uint64_t>(int_);
}

const std::string& JsonValue::as_string() const noexcept { return string_; }

const std::vector<JsonValue>& JsonValue::items() const noexcept { return items_; }

const std::vector<std::pair<std::string, JsonValue>>& JsonValue::members() const noexcept {
  return members_;
}

const JsonValue* JsonValue::find(std::string_view key) const noexcept {
  std::size_t low = 0;
  std::size_t high = members_.size();
  while (low < high) {
    const std::size_t middle = low + (high - low) / 2;
    const int order = compare_keys(members_[middle].first, key);
    if (order == 0) {
      return &members_[middle].second;
    }
    if (order < 0) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  return nullptr;
}

void JsonValue::set(std::string key, JsonValue value) {
  if (kind_ != Kind::Object) {
    // A value has one kind. Setting a member on a value that is not an object makes it
    // an object rather than silently discarding the member: the alternative would be an
    // operation that reports nothing and does nothing.
    kind_ = Kind::Object;
    bool_ = false;
    int_ = 0;
    uint_ = 0;
    string_.clear();
    items_.clear();
    members_.clear();
  }
  std::size_t low = 0;
  std::size_t high = members_.size();
  while (low < high) {
    const std::size_t middle = low + (high - low) / 2;
    const int order = compare_keys(members_[middle].first, key);
    if (order == 0) {
      members_[middle].second = std::move(value);
      return;
    }
    if (order < 0) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  members_.emplace(members_.begin() + static_cast<std::ptrdiff_t>(low), std::move(key),
                   std::move(value));
}

void JsonValue::push_back(JsonValue value) {
  if (kind_ != Kind::Array) {
    return;
  }
  items_.push_back(std::move(value));
}

// ===================================================================================
// Encoders
// ===================================================================================

namespace {

constexpr char kHexDigits[] = "0123456789ABCDEF";

void append_hex4(std::string& out, std::uint32_t value) {
  out += "\\u";
  out.push_back(kHexDigits[(value >> 12u) & 0xFu]);
  out.push_back(kHexDigits[(value >> 8u) & 0xFu]);
  out.push_back(kHexDigits[(value >> 4u) & 0xFu]);
  out.push_back(kHexDigits[value & 0xFu]);
}

void append_code_point(std::string& out, std::uint32_t code_point) {
  if (code_point <= 0xFFFFu) {
    append_hex4(out, code_point);
    return;
  }
  const std::uint32_t adjusted = code_point - 0x10000u;
  append_hex4(out, 0xD800u + (adjusted >> 10u));
  append_hex4(out, 0xDC00u + (adjusted & 0x3FFu));
}

void append_escaped_string(std::string& out, std::string_view text) {
  out.push_back('"');
  std::size_t offset = 0;
  while (offset < text.size()) {
    const auto byte = static_cast<std::uint8_t>(text[offset]);
    if (byte < 0x80u) {
      switch (byte) {
        case '"':
          out += "\\\"";
          break;
        case '\\':
          out += "\\\\";
          break;
        case '\b':
          out += "\\b";
          break;
        case '\f':
          out += "\\f";
          break;
        case '\n':
          out += "\\n";
          break;
        case '\r':
          out += "\\r";
          break;
        case '\t':
          out += "\\t";
          break;
        default:
          if (byte < 0x20u || byte == 0x7Fu) {
            append_hex4(out, byte);
          } else {
            out.push_back(static_cast<char>(byte));
          }
          break;
      }
      ++offset;
      continue;
    }
    const auto decoded = utf8_decode(text, offset);
    if (!decoded.has_value()) {
      // One replacement character per invalid byte, so the output stays valid ASCII.
      append_hex4(out, 0xFFFDu);
      ++offset;
      continue;
    }
    append_code_point(out, decoded->first);
    offset += decoded->second;
  }
  out.push_back('"');
}

void write_canonical_into(std::string& out, const JsonValue& value) {
  switch (value.kind()) {
    case JsonValue::Kind::Null:
      out += "null";
      return;
    case JsonValue::Kind::Bool:
      out += value.as_bool() ? "true" : "false";
      return;
    case JsonValue::Kind::Int:
      out += std::to_string(value.as_int());
      return;
    case JsonValue::Kind::Uint:
      out += std::to_string(value.as_uint());
      return;
    case JsonValue::Kind::String:
      append_escaped_string(out, value.as_string());
      return;
    case JsonValue::Kind::Array: {
      out.push_back('[');
      const std::vector<JsonValue>& items = value.items();
      for (std::size_t index = 0; index < items.size(); ++index) {
        if (index != 0) {
          out.push_back(',');
        }
        write_canonical_into(out, items[index]);
      }
      out.push_back(']');
      return;
    }
    case JsonValue::Kind::Object: {
      out.push_back('{');
      const std::vector<std::pair<std::string, JsonValue>>& members = value.members();
      for (std::size_t index = 0; index < members.size(); ++index) {
        if (index != 0) {
          out.push_back(',');
        }
        append_escaped_string(out, members[index].first);
        out.push_back(':');
        write_canonical_into(out, members[index].second);
      }
      out.push_back('}');
      return;
    }
  }
}

void write_pretty_into(std::string& out, const JsonValue& value, std::size_t indent,
                       std::size_t depth) {
  switch (value.kind()) {
    case JsonValue::Kind::Null:
      out += "null";
      return;
    case JsonValue::Kind::Bool:
      out += value.as_bool() ? "true" : "false";
      return;
    case JsonValue::Kind::Int:
      out += std::to_string(value.as_int());
      return;
    case JsonValue::Kind::Uint:
      out += std::to_string(value.as_uint());
      return;
    case JsonValue::Kind::String:
      append_escaped_string(out, value.as_string());
      return;
    case JsonValue::Kind::Array: {
      const std::vector<JsonValue>& items = value.items();
      if (items.empty()) {
        out += "[]";
        return;
      }
      out += "[\n";
      for (std::size_t index = 0; index < items.size(); ++index) {
        append_indent(out, indent, depth + 1);
        write_pretty_into(out, items[index], indent, depth + 1);
        if (index + 1 == items.size()) {
          out.push_back('\n');
        } else {
          out += ",\n";
        }
      }
      append_indent(out, indent, depth);
      out.push_back(']');
      return;
    }
    case JsonValue::Kind::Object: {
      const std::vector<std::pair<std::string, JsonValue>>& members = value.members();
      if (members.empty()) {
        out += "{}";
        return;
      }
      out += "{\n";
      for (std::size_t index = 0; index < members.size(); ++index) {
        append_indent(out, indent, depth + 1);
        append_escaped_string(out, members[index].first);
        out += ": ";
        write_pretty_into(out, members[index].second, indent, depth + 1);
        if (index + 1 == members.size()) {
          out.push_back('\n');
        } else {
          out += ",\n";
        }
      }
      append_indent(out, indent, depth);
      out.push_back('}');
      return;
    }
  }
}

}  // namespace

std::string json_write_canonical(const JsonValue& value) {
  std::string out;
  write_canonical_into(out, value);
  return out;
}

std::string json_write_pretty(const JsonValue& value, std::size_t indent) {
  std::string out;
  write_pretty_into(out, value, indent, 0);
  out.push_back('\n');
  return out;
}

// ===================================================================================
// Decoder
// ===================================================================================

namespace {

class Parser {
 public:
  Parser(std::string_view text, const JsonLimits& limits) noexcept : text_(text), limits_(limits) {}

  [[nodiscard]] std::size_t position() const noexcept { return pos_; }
  [[nodiscard]] bool at_end() const noexcept { return pos_ >= text_.size(); }

  /// JSON whitespace only: space, tab, line feed, carriage return. A vertical tab or a
  /// form feed is not whitespace here, so it is rejected as trailing content.
  void skip_whitespace() noexcept {
    while (pos_ < text_.size()) {
      const char ch = text_[pos_];
      if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') {
        return;
      }
      ++pos_;
    }
  }

  /// Parses one value. The depth argument counts the containers already open around
  /// this value. A container whose members would sit at max_depth + 1 is refused before
  /// it recurses, so the recursion is one frame per nesting level and never exceeds
  /// limits.max_depth frames.
  Result<JsonValue> parse_value(std::size_t depth) {
    skip_whitespace();
    if (at_end()) {
      return malformed("csp.json.unexpected_end", pos_,
                       "unexpected end of input where a value was expected");
    }
    const char ch = text_[pos_];
    if (ch == '{') {
      const std::size_t member_depth = depth + 1;
      if (member_depth > limits_.max_depth) {
        return bound("csp.json.bound_depth", pos_, "object nesting exceeds max_depth");
      }
      ++pos_;
      JsonValue object = JsonValue::make_object();
      skip_whitespace();
      if (at_end()) {
        return malformed("csp.json.unexpected_end", pos_, "unexpected end of input inside an object");
      }
      if (text_[pos_] == '}') {
        ++pos_;
        return object;
      }
      for (;;) {
        skip_whitespace();
        if (at_end()) {
          return malformed("csp.json.unexpected_end", pos_,
                           "unexpected end of input where an object member name was expected");
        }
        if (text_[pos_] != '"') {
          return malformed("csp.json.expected_key", pos_, "expected a quoted object member name");
        }
        if (object.members().size() >= limits_.max_object_members) {
          return bound("csp.json.bound_object_members", pos_,
                       "object has more members than max_object_members allows");
        }
        const std::size_t key_position = pos_;
        auto key =
            parse_string(limits_.max_key_bytes, "csp.json.bound_key_bytes", "object member name");
        if (!key) {
          return key.error();
        }
        skip_whitespace();
        if (at_end()) {
          return malformed("csp.json.unexpected_end", pos_,
                           "unexpected end of input where ':' was expected");
        }
        if (text_[pos_] != ':') {
          return malformed("csp.json.expected_colon", pos_, "expected ':' after an object member name");
        }
        ++pos_;
        auto member = parse_value(member_depth);
        if (!member) {
          return member.error();
        }
        if (object.find(key.value()) != nullptr) {
          std::string detail = "duplicate object member name \"";
          detail += key.value();
          detail += "\"";
          return json_error(ErrorCategory::Conflict, "csp.json.duplicate_key", key_position, detail);
        }
        object.set(std::move(key).value(), std::move(member).value());
        skip_whitespace();
        if (at_end()) {
          return malformed("csp.json.unexpected_end", pos_, "unexpected end of input inside an object");
        }
        const char separator = text_[pos_];
        if (separator == ',') {
          ++pos_;
          skip_whitespace();
          if (at_end()) {
            return malformed("csp.json.unexpected_end", pos_, "unexpected end of input after ','");
          }
          if (text_[pos_] == '}') {
            return malformed("csp.json.trailing_comma", pos_,
                             "object member list ends with a trailing ','");
          }
          continue;
        }
        if (separator == '}') {
          ++pos_;
          return object;
        }
        return malformed("csp.json.expected_separator", pos_, "expected ',' or '}' inside an object");
      }
    }
    if (ch == '[') {
      const std::size_t element_depth = depth + 1;
      if (element_depth > limits_.max_depth) {
        return bound("csp.json.bound_depth", pos_, "array nesting exceeds max_depth");
      }
      ++pos_;
      std::vector<JsonValue> items;
      skip_whitespace();
      if (at_end()) {
        return malformed("csp.json.unexpected_end", pos_, "unexpected end of input inside an array");
      }
      if (text_[pos_] == ']') {
        ++pos_;
        return JsonValue::make_array(std::move(items));
      }
      for (;;) {
        if (items.size() >= limits_.max_array_items) {
          return bound("csp.json.bound_array_items", pos_,
                       "array has more items than max_array_items allows");
        }
        auto element = parse_value(element_depth);
        if (!element) {
          return element.error();
        }
        items.push_back(std::move(element).value());
        skip_whitespace();
        if (at_end()) {
          return malformed("csp.json.unexpected_end", pos_, "unexpected end of input inside an array");
        }
        const char separator = text_[pos_];
        if (separator == ',') {
          ++pos_;
          skip_whitespace();
          if (at_end()) {
            return malformed("csp.json.unexpected_end", pos_, "unexpected end of input after ','");
          }
          if (text_[pos_] == ']') {
            return malformed("csp.json.trailing_comma", pos_,
                             "array element list ends with a trailing ','");
          }
          continue;
        }
        if (separator == ']') {
          ++pos_;
          return JsonValue::make_array(std::move(items));
        }
        return malformed("csp.json.expected_separator", pos_, "expected ',' or ']' inside an array");
      }
    }
    if (ch == '"') {
      auto text = parse_string(limits_.max_string_bytes, "csp.json.bound_string_bytes", "string value");
      if (!text) {
        return text.error();
      }
      return JsonValue::make_string(std::move(text).value());
    }
    if (ch == 't') {
      const Status status = consume_literal("true");
      if (!status) {
        return status.error();
      }
      return JsonValue::make_bool(true);
    }
    if (ch == 'f') {
      const Status status = consume_literal("false");
      if (!status) {
        return status.error();
      }
      return JsonValue::make_bool(false);
    }
    if (ch == 'n') {
      const Status status = consume_literal("null");
      if (!status) {
        return status.error();
      }
      return JsonValue::make_null();
    }
    if (ch == '-' || is_digit(ch)) {
      return parse_number();
    }
    std::string detail = "byte '";
    detail += ch;
    detail += "' cannot start a value";
    return malformed("csp.json.unexpected_byte", pos_, detail);
  }

 private:
  Error malformed(std::string_view code, std::size_t offset, std::string_view detail) const {
    return json_error(ErrorCategory::Malformed, code, offset, detail);
  }

  Error bound(std::string_view code, std::size_t offset, std::string_view detail) const {
    return json_error(ErrorCategory::BoundExceeded, code, offset, detail);
  }

  /// Consumes a quoted string starting at the current position. The max_bytes argument
  /// bounds the decoded size, so an escape cannot be used to smuggle more bytes past a
  /// configured limit.
  Result<std::string> parse_string(std::size_t max_bytes, std::string_view bound_code,
                                   std::string_view what) {
    ++pos_;  // the opening quote
    std::string out;
    for (;;) {
      if (at_end()) {
        return malformed("csp.json.unexpected_end", pos_, "unexpected end of input inside a string");
      }
      const char raw = text_[pos_];
      const auto byte = static_cast<std::uint8_t>(raw);
      if (raw == '"') {
        ++pos_;
        return out;
      }
      if (raw == '\\') {
        const Status status = parse_escape(out);
        if (!status) {
          return status.error();
        }
      } else if (byte < 0x20u) {
        return malformed("csp.json.string_control", pos_, "unescaped control byte inside a string");
      } else if (byte < 0x80u) {
        out.push_back(raw);
        ++pos_;
      } else {
        const auto decoded = utf8_decode(text_, pos_);
        if (!decoded.has_value()) {
          return malformed("csp.json.string_utf8", pos_, "invalid UTF-8 sequence inside a string");
        }
        out.append(text_.substr(pos_, decoded->second));
        pos_ += decoded->second;
      }
      if (out.size() > max_bytes) {
        std::string detail(what);
        detail += " is longer than the configured limit of ";
        detail += std::to_string(max_bytes);
        detail += " bytes";
        return json_error(ErrorCategory::BoundExceeded, bound_code, pos_, detail);
      }
    }
  }

  /// Consumes one escape sequence, appending its decoded scalar value to out.
  Status parse_escape(std::string& out) {
    const std::size_t escape_position = pos_;
    ++pos_;  // the backslash
    if (at_end()) {
      return malformed("csp.json.unexpected_end", pos_, "unexpected end of input after a backslash");
    }
    const char code = text_[pos_];
    switch (code) {
      case '"':
        out.push_back('"');
        break;
      case '\\':
        out.push_back('\\');
        break;
      case '/':
        out.push_back('/');
        break;
      case 'b':
        out.push_back('\b');
        break;
      case 'f':
        out.push_back('\f');
        break;
      case 'n':
        out.push_back('\n');
        break;
      case 'r':
        out.push_back('\r');
        break;
      case 't':
        out.push_back('\t');
        break;
      case 'u':
        break;
      default:
        return malformed("csp.json.string_escape", escape_position,
                         "unknown escape sequence inside a string");
    }
    if (code != 'u') {
      ++pos_;
      return success();
    }
    ++pos_;  // the 'u'
    std::uint32_t code_point = 0;
    Status status = read_hex4(code_point);
    if (!status) {
      return status.error();
    }
    if (code_point >= 0xD800u && code_point <= 0xDBFFu) {
      const std::size_t pair_position = pos_;
      if (pos_ + 2 > text_.size() || text_[pos_] != '\\' || text_[pos_ + 1] != 'u') {
        return malformed("csp.json.surrogate", pair_position,
                         "a high surrogate is not followed by a low surrogate");
      }
      pos_ += 2;
      std::uint32_t low = 0;
      status = read_hex4(low);
      if (!status) {
        return status.error();
      }
      if (low < 0xDC00u || low > 0xDFFFu) {
        return malformed("csp.json.surrogate", pair_position,
                         "a high surrogate is not followed by a low surrogate");
      }
      code_point = 0x10000u + ((code_point - 0xD800u) << 10u) + (low - 0xDC00u);
    } else if (code_point >= 0xDC00u && code_point <= 0xDFFFu) {
      return malformed("csp.json.surrogate", escape_position,
                       "a lone low surrogate is not a scalar value");
    }
    append_utf8(out, code_point);
    return success();
  }

  /// Consumes exactly four hexadecimal digits. A byte that is not a hexadecimal digit
  /// is reported at its own offset, so a short escape is diagnosed where it actually
  /// goes wrong rather than only as a truncated input.
  Status read_hex4(std::uint32_t& code_point) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
      if (pos_ + index >= text_.size()) {
        return malformed("csp.json.unexpected_end", text_.size(),
                         "unexpected end of input inside a \\u escape");
      }
      const int digit = hex_digit(text_[pos_ + index]);
      if (digit < 0) {
        return malformed("csp.json.string_escape", pos_ + index,
                         "a \\u escape requires four hexadecimal digits");
      }
      value = (value << 4u) | static_cast<std::uint32_t>(digit);
    }
    pos_ += 4;
    code_point = value;
    return success();
  }

  Status consume_literal(std::string_view literal) {
    if (pos_ + literal.size() > text_.size() || text_.substr(pos_, literal.size()) != literal) {
      std::string detail = "expected the literal '";
      detail += literal;
      detail += "'";
      return malformed("csp.json.literal", pos_, detail);
    }
    pos_ += literal.size();
    return success();
  }

  /// The literal is an optional '-' followed by digits, nothing else. A fractional part
  /// or an exponent is refused rather than rounded, because the model has no float type.
  Result<JsonValue> parse_number() {
    const std::size_t start = pos_;
    bool negative = false;
    if (text_[pos_] == '-') {
      negative = true;
      ++pos_;
      if (at_end() || !is_digit(text_[pos_])) {
        return malformed("csp.json.number", pos_, "expected a digit after '-'");
      }
    }
    const std::size_t digits_start = pos_;
    if (text_[pos_] == '0') {
      ++pos_;
      if (!at_end() && is_digit(text_[pos_])) {
        return malformed("csp.json.number_leading_zero", start,
                         "a number may not carry a leading zero");
      }
    } else {
      while (!at_end() && is_digit(text_[pos_])) {
        ++pos_;
      }
    }
    if (!at_end() && (text_[pos_] == '.' || text_[pos_] == 'e' || text_[pos_] == 'E')) {
      return malformed("csp.json.number_fraction", pos_,
                       "a fractional or exponent number is not part of this model");
    }
    if (negative && pos_ - digits_start == 1 && text_[digits_start] == '0') {
      return malformed("csp.json.number_negative_zero", start, "'-0' is not an accepted number");
    }
    const std::uint64_t limit = negative ? kMinI64Magnitude : kMaxU64;
    std::uint64_t magnitude = 0;
    for (std::size_t index = digits_start; index < pos_; ++index) {
      const std::uint64_t digit = static_cast<std::uint64_t>(text_[index] - '0');
      if (magnitude > (limit - digit) / 10u) {
        return json_error(ErrorCategory::OutOfRange, "csp.json.number_out_of_range", start,
                          "number does not fit in 64 bits");
      }
      magnitude = magnitude * 10u + digit;
    }
    if (negative) {
      return JsonValue::make_int(static_cast<std::int64_t>(std::uint64_t{0} - magnitude));
    }
    if (magnitude <= kMaxI64) {
      return JsonValue::make_int(static_cast<std::int64_t>(magnitude));
    }
    return JsonValue::make_uint(magnitude);
  }

  std::string_view text_;
  const JsonLimits& limits_;
  std::size_t pos_ = 0;
};

}  // namespace

Result<JsonValue> json_parse(std::string_view text, const JsonLimits& limits) {
  if (text.size() > limits.max_bytes) {
    std::string detail = "input is longer than the configured max_bytes of ";
    detail += std::to_string(limits.max_bytes);
    detail += " bytes";
    return json_error(ErrorCategory::BoundExceeded, "csp.json.bound_bytes", limits.max_bytes, detail);
  }
  Parser parser(text, limits);
  auto value = parser.parse_value(0);
  if (!value) {
    return value.error();
  }
  parser.skip_whitespace();
  if (!parser.at_end()) {
    return json_error(ErrorCategory::Malformed, "csp.json.trailing_content", parser.position(),
                      "trailing content after the top-level value");
  }
  return std::move(value).value();
}

}  // namespace csp::detail
