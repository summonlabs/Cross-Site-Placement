// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "cross_site_placement/error.hpp"

#include <array>

namespace csp {
namespace {

struct CategoryName {
  ErrorCategory category;
  const char* token;
};

// The order of this table is the order of the enumeration; a static assertion below
// keeps the two in step so a new category cannot be added without a token.
constexpr std::array<CategoryName, 15> kCategoryNames{{
    {ErrorCategory::Invalid, "invalid"},
    {ErrorCategory::Malformed, "malformed"},
    {ErrorCategory::OutOfRange, "out_of_range"},
    {ErrorCategory::BoundExceeded, "bound_exceeded"},
    {ErrorCategory::NotFound, "not_found"},
    {ErrorCategory::Conflict, "conflict"},
    {ErrorCategory::Stale, "stale"},
    {ErrorCategory::Unsupported, "unsupported"},
    {ErrorCategory::Unavailable, "unavailable"},
    {ErrorCategory::Indeterminate, "indeterminate"},
    {ErrorCategory::Io, "io"},
    {ErrorCategory::Integrity, "integrity"},
    {ErrorCategory::Locked, "locked"},
    {ErrorCategory::Cancelled, "cancelled"},
    {ErrorCategory::Internal, "internal"},
}};

}  // namespace

static_assert(static_cast<std::size_t>(ErrorCategory::Internal) + 1 == kCategoryNames.size(),
              "every ErrorCategory needs exactly one stable token");

const char* to_string(ErrorCategory category) noexcept {
  const auto index = static_cast<std::size_t>(category);
  if (index >= kCategoryNames.size()) {
    return "internal";
  }
  return kCategoryNames[index].token;
}

std::optional<ErrorCategory> error_category_from_string(std::string_view token) noexcept {
  for (const auto& entry : kCategoryNames) {
    if (token == entry.token) {
      return entry.category;
    }
  }
  return std::nullopt;
}

Error::Error(ErrorCategory category, std::string code, std::string message)
    : category_(category), code_(std::move(code)), message_(std::move(message)) {}

std::string Error::render() const {
  std::string out;
  out.reserve(code_.size() + message_.size() + 24);
  out += to_string(category_);
  if (!code_.empty()) {
    out += ": ";
    out += code_;
  }
  if (!message_.empty()) {
    out += ": ";
    out += message_;
  }
  return out;
}

bool operator==(const Error& lhs, const Error& rhs) noexcept {
  return lhs.category() == rhs.category() && lhs.code() == rhs.code() && lhs.message() == rhs.message();
}

bool operator!=(const Error& lhs, const Error& rhs) noexcept { return !(lhs == rhs); }

Error fail(ErrorCategory category, std::string code, std::string message) {
  return Error(category, std::move(code), std::move(message));
}

}  // namespace csp
