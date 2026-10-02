// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The error model of this boundary.
//
// Every refusal this library can produce is one of a small, closed set of
// categories. The categories exist because collapsing them would lose meaning the
// caller needs: "stale" is not "invalid", "indeterminate" is not "violated", and
// "bound exceeded" is a statement about the planner's budget rather than about the
// world. A caller that cannot tell those apart cannot act correctly on a refusal.

#ifndef CROSS_SITE_PLACEMENT_ERROR_HPP
#define CROSS_SITE_PLACEMENT_ERROR_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace csp {

enum class ErrorCategory : std::uint8_t {
  /// The value is well-formed but violates a structural rule of the boundary.
  Invalid,
  /// The bytes could not be decoded as the declared format at all.
  Malformed,
  /// The value decoded, but lies outside its declared domain.
  OutOfRange,
  /// A configured bound stopped the operation. This is a statement about the
  /// planner's budget, never a claim that the underlying question has an answer.
  BoundExceeded,
  /// A referenced identity is not present in the supplied evidence.
  NotFound,
  /// Two pieces of evidence claim incompatible things about one identity. This is
  /// never resolved by preferring one of them.
  Conflict,
  /// The evidence is older than the caller's freshness envelope, or carries no
  /// usable observation time. Stale evidence is refused, not merged.
  Stale,
  /// The request asks for something this boundary deliberately does not own.
  Unsupported,
  /// A required authority or capability was absent from the supplied evidence.
  Unavailable,
  /// The planner could not decide. Indeterminate is a third outcome beside
  /// satisfied and violated, and it is never reported as either of them.
  Indeterminate,
  /// An operating-system operation failed.
  Io,
  /// Persisted bytes failed verification.
  Integrity,
  /// Another holder owns an exclusive resource. The wait was bounded and lost.
  Locked,
  /// The caller cancelled the work. Cancelled work never reports success.
  Cancelled,
  /// An invariant internal to this library was violated. Reaching this category is
  /// a defect in the library, not in the caller's input.
  Internal,
};

/// Stable lowercase token for an error category. The token is part of the textual
/// output format and does not change between releases.
const char* to_string(ErrorCategory category) noexcept;

/// Parses a category token produced by to_string. Returns std::nullopt for an
/// unknown token rather than guessing a category.
std::optional<ErrorCategory> error_category_from_string(std::string_view token) noexcept;

/// An error value. The code is a stable machine-readable token of the form
/// "csp.<area>.<condition>"; the message is for a human and may change.
class Error {
 public:
  Error() = default;
  Error(ErrorCategory category, std::string code, std::string message);

  ErrorCategory category() const noexcept { return category_; }
  const std::string& code() const noexcept { return code_; }
  const std::string& message() const noexcept { return message_; }

  /// "category: code: message", with an empty tail omitted.
  std::string render() const;

 private:
  ErrorCategory category_ = ErrorCategory::Internal;
  std::string code_;
  std::string message_;
};

bool operator==(const Error& lhs, const Error& rhs) noexcept;
bool operator!=(const Error& lhs, const Error& rhs) noexcept;

/// Constructs an error. Returning this from a function declared to return Status or
/// Result<T> is the intended use.
Error fail(ErrorCategory category, std::string code, std::string message);

/// An empty value type, so that "no value" successes share one Result template
/// rather than needing a second, subtly different one.
struct Unit {};

/// A success value or an error. Result is deliberately not std::expected: this
/// project is C++20, and inventing a half-compatible substitute later would be a
/// worse outcome than owning a small, fully tested one now.
template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)), error_() {}          // NOLINT(google-explicit-constructor)
  Result(Error error) : value_(), error_(std::move(error)) {}      // NOLINT(google-explicit-constructor)

  bool has_value() const noexcept { return value_.has_value(); }
  explicit operator bool() const noexcept { return has_value(); }

  /// Precondition: has_value(). Calling value() on an error is a programming
  /// defect; the library does not throw to report it.
  const T& value() const& noexcept { return *value_; }
  T& value() & noexcept { return *value_; }
  T&& value() && noexcept { return std::move(*value_); }
  const T& operator*() const& noexcept { return *value_; }
  T& operator*() & noexcept { return *value_; }
  const T* operator->() const noexcept { return &*value_; }
  T* operator->() noexcept { return &*value_; }

  const Error& error() const noexcept { return error_; }

  template <class U>
  T value_or(U&& fallback) const {
    return value_.has_value() ? *value_ : static_cast<T>(std::forward<U>(fallback));
  }

 private:
  std::optional<T> value_;
  Error error_;
};

using Status = Result<Unit>;

inline Status success() { return Status(Unit{}); }

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_ERROR_HPP
