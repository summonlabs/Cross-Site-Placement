// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Stable identities, exact quantities, and digests.
//
// Identities in this boundary come from the authorities that own them: a site identity
// belongs to the site registry, a failure-domain identity to the failure-domain
// registry, and so on. This boundary never mints, renames, normalises, or folds an
// identity it was given. Two identities that differ in any byte are two identities,
// including when they differ only in case, because silently merging them would let a
// plan satisfy a failure-independence rule using one site counted twice.
//
// The typed identity template exists so that a SiteId cannot be passed where a
// FailureDomainId is expected. One implementation, thirteen distinct types.

#ifndef CROSS_SITE_PLACEMENT_STRONG_TYPES_HPP
#define CROSS_SITE_PLACEMENT_STRONG_TYPES_HPP

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "cross_site_placement/error.hpp"

namespace csp {

/// Longest accepted identity, in bytes. The bound exists because identities arrive
/// from outside the process and are copied into plans and trace records.
inline constexpr std::size_t kMaxIdentifierBytes = 128;

/// Longest free-text field this boundary stores in a plan: a refusal detail or a rule
/// description. Free text is bounded separately from identities because it is the only
/// place where a large value would be accepted without a structural reason.
inline constexpr std::size_t kMaxDetailBytes = 512;

namespace detail {

/// Internal. One implementation of the identity alphabet, shared by every typed
/// identity instead of being repeated thirteen times with thirteen chances to drift.
/// Declared here because the template below is instantiated by callers.
[[nodiscard]] Result<std::string> identifier_validate(std::string_view text, std::string_view what);

}  // namespace detail

/// A stable identity of the given kind. The empty identity is not a valid identity:
/// valid() is false for a default-constructed value, so an unset field cannot be
/// mistaken for an identity that an authority issued.
template <class Tag>
class Id {
 public:
  Id() = default;

  /// Parses an identity from untrusted text. Rejects an empty string, a value longer
  /// than kMaxIdentifierBytes, any byte outside the documented alphabet, and any
  /// leading or trailing whitespace.
  static Result<Id> parse(std::string_view text) {
    Result<std::string> validated = detail::identifier_validate(text, name());
    if (!validated) {
      return validated.error();
    }
    Id id;
    id.value_ = std::move(validated).value();
    return id;
  }

  bool valid() const noexcept { return !value_.empty(); }
  const std::string& value() const noexcept { return value_; }
  std::string_view view() const noexcept { return value_; }

  friend bool operator==(const Id& lhs, const Id& rhs) noexcept { return lhs.value_ == rhs.value_; }
  friend bool operator!=(const Id& lhs, const Id& rhs) noexcept { return !(lhs == rhs); }
  friend bool operator<(const Id& lhs, const Id& rhs) noexcept { return lhs.value_ < rhs.value_; }
  friend bool operator>(const Id& lhs, const Id& rhs) noexcept { return rhs < lhs; }
  friend bool operator<=(const Id& lhs, const Id& rhs) noexcept { return !(rhs < lhs); }
  friend bool operator>=(const Id& lhs, const Id& rhs) noexcept { return !(lhs < rhs); }

  /// Only for diagnostics: the identity kind, not the identity.
  static constexpr const char* name() noexcept { return Tag::kName; }

 private:
  std::string value_;
};

// Each tag carries the name used in diagnostics. The name is a property of the tag
// rather than of the identity template, so a new identity kind cannot be introduced
// without deciding what to call it in a message.
struct SiteIdTag {
  static constexpr const char* kName = "site";
};
struct FailureDomainIdTag {
  static constexpr const char* kName = "failure-domain";
};
struct ObligationIdTag {
  static constexpr const char* kName = "obligation";
};
struct ServiceClassIdTag {
  static constexpr const char* kName = "service-class";
};
struct PolicyIdTag {
  static constexpr const char* kName = "policy";
};
struct CapacityRefIdTag {
  static constexpr const char* kName = "capacity-reference";
};
struct DependencyIdTag {
  static constexpr const char* kName = "dependency";
};
struct JurisdictionIdTag {
  static constexpr const char* kName = "jurisdiction";
};
struct RequestIdTag {
  static constexpr const char* kName = "request";
};
struct PlanIdTag {
  static constexpr const char* kName = "plan";
};
struct EvidenceIdTag {
  static constexpr const char* kName = "evidence";
};
struct AuthorityIdTag {
  static constexpr const char* kName = "authority";
};
struct RecoveryRefIdTag {
  static constexpr const char* kName = "recovery-reference";
};

using SiteId = Id<SiteIdTag>;
using FailureDomainId = Id<FailureDomainIdTag>;
using ObligationId = Id<ObligationIdTag>;
using ServiceClassId = Id<ServiceClassIdTag>;
using PolicyId = Id<PolicyIdTag>;
/// Identity of a capacity offer or commitment in the authority that owns it. This
/// boundary reads the reference and records it; it never creates, extends, or consumes
/// one.
using CapacityRefId = Id<CapacityRefIdTag>;
using DependencyId = Id<DependencyIdTag>;
using JurisdictionId = Id<JurisdictionIdTag>;
using RequestId = Id<RequestIdTag>;
using PlanId = Id<PlanIdTag>;
using EvidenceId = Id<EvidenceIdTag>;
using AuthorityId = Id<AuthorityIdTag>;
using RecoveryRefId = Id<RecoveryRefIdTag>;

/// A point in time, in nanoseconds since the Unix epoch.
///
/// The planner never reads a clock. Every instant it uses is supplied by the caller,
/// because two runs of the same logical request have to agree byte for byte and a
/// clock reading cannot be made to agree with itself twice.
class Instant {
 public:
  constexpr Instant() noexcept = default;
  static constexpr Instant from_nanos(std::int64_t nanos) noexcept { return Instant(nanos); }

  constexpr std::int64_t nanos() const noexcept { return nanos_; }
  constexpr bool is_zero() const noexcept { return nanos_ == 0; }

  friend constexpr bool operator==(const Instant& lhs, const Instant& rhs) noexcept { return lhs.nanos_ == rhs.nanos_; }
  friend constexpr bool operator!=(const Instant& lhs, const Instant& rhs) noexcept { return !(lhs == rhs); }
  friend constexpr bool operator<(const Instant& lhs, const Instant& rhs) noexcept { return lhs.nanos_ < rhs.nanos_; }
  friend constexpr bool operator>(const Instant& lhs, const Instant& rhs) noexcept { return rhs < lhs; }
  friend constexpr bool operator<=(const Instant& lhs, const Instant& rhs) noexcept { return !(rhs < lhs); }
  friend constexpr bool operator>=(const Instant& lhs, const Instant& rhs) noexcept { return !(lhs < rhs); }

 private:
  constexpr explicit Instant(std::int64_t nanos) noexcept : nanos_(nanos) {}
  std::int64_t nanos_ = 0;
};

/// A signed interval in nanoseconds. Durations that must not be negative (validity
/// windows, evidence ages, recovery objectives) are checked at the point where the
/// requirement is validated, not here, so that one type covers both a difference of
/// two instants and a configured window.
class Duration {
 public:
  constexpr Duration() noexcept = default;
  static constexpr Duration from_nanos(std::int64_t nanos) noexcept { return Duration(nanos); }
  static Result<Duration> from_millis(std::int64_t millis);
  static Result<Duration> from_seconds(std::int64_t seconds);

  constexpr std::int64_t nanos() const noexcept { return nanos_; }
  constexpr bool is_negative() const noexcept { return nanos_ < 0; }
  constexpr bool is_zero() const noexcept { return nanos_ == 0; }

  Result<Duration> checked_add(Duration other) const;
  Result<Duration> checked_sub(Duration other) const;

  friend constexpr bool operator==(const Duration& lhs, const Duration& rhs) noexcept { return lhs.nanos_ == rhs.nanos_; }
  friend constexpr bool operator!=(const Duration& lhs, const Duration& rhs) noexcept { return !(lhs == rhs); }
  friend constexpr bool operator<(const Duration& lhs, const Duration& rhs) noexcept { return lhs.nanos_ < rhs.nanos_; }
  friend constexpr bool operator>(const Duration& lhs, const Duration& rhs) noexcept { return rhs < lhs; }
  friend constexpr bool operator<=(const Duration& lhs, const Duration& rhs) noexcept { return !(rhs < lhs); }
  friend constexpr bool operator>=(const Duration& lhs, const Duration& rhs) noexcept { return !(lhs < rhs); }

 private:
  constexpr explicit Duration(std::int64_t nanos) noexcept : nanos_(nanos) {}
  std::int64_t nanos_ = 0;
};

/// The exact time from earlier to later, or an error when the two instants are in the
/// wrong order. Used for evidence age, where a negative age would silently read as
/// perfectly fresh.
[[nodiscard]] Result<Duration> elapsed(Instant earlier, Instant later);

/// A whole number of resource units. Capacity here is a count of whatever unit the
/// owning authority reports; this boundary never converts between units, because a
/// conversion factor it invented would be exactly the fabrication it refuses to make.
class Quantity {
 public:
  constexpr Quantity() noexcept = default;
  static constexpr Quantity from_units(std::int64_t units) noexcept { return Quantity(units); }
  static Result<Quantity> parse(std::string_view text);

  constexpr std::int64_t units() const noexcept { return units_; }
  constexpr bool is_negative() const noexcept { return units_ < 0; }
  constexpr bool is_zero() const noexcept { return units_ == 0; }

  Result<Quantity> checked_add(Quantity other) const;
  Result<Quantity> checked_sub(Quantity other) const;
  Result<Quantity> checked_mul(std::int64_t factor) const;

  friend constexpr bool operator==(const Quantity& lhs, const Quantity& rhs) noexcept { return lhs.units_ == rhs.units_; }
  friend constexpr bool operator!=(const Quantity& lhs, const Quantity& rhs) noexcept { return !(lhs == rhs); }
  friend constexpr bool operator<(const Quantity& lhs, const Quantity& rhs) noexcept { return lhs.units_ < rhs.units_; }
  friend constexpr bool operator>(const Quantity& lhs, const Quantity& rhs) noexcept { return rhs < lhs; }
  friend constexpr bool operator<=(const Quantity& lhs, const Quantity& rhs) noexcept { return !(rhs < lhs); }
  friend constexpr bool operator>=(const Quantity& lhs, const Quantity& rhs) noexcept { return !(lhs < rhs); }

 private:
  constexpr explicit Quantity(std::int64_t units) noexcept : units_(units) {}
  std::int64_t units_ = 0;
};

/// A monotonic version of some authority's state. Zero means "no generation asserted",
/// which is never treated as a valid generation to compare against.
class Generation {
 public:
  constexpr Generation() noexcept = default;
  static constexpr Generation from_value(std::uint64_t value) noexcept { return Generation(value); }

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool is_set() const noexcept { return value_ != 0; }

  /// The next generation, or an error when the counter would wrap. A wrapped
  /// generation would make a newer state compare as older, which is the one failure a
  /// generation exists to prevent.
  Result<Generation> next() const;

  friend constexpr bool operator==(const Generation& lhs, const Generation& rhs) noexcept { return lhs.value_ == rhs.value_; }
  friend constexpr bool operator!=(const Generation& lhs, const Generation& rhs) noexcept { return !(lhs == rhs); }
  friend constexpr bool operator<(const Generation& lhs, const Generation& rhs) noexcept { return lhs.value_ < rhs.value_; }
  friend constexpr bool operator>(const Generation& lhs, const Generation& rhs) noexcept { return rhs < lhs; }
  friend constexpr bool operator<=(const Generation& lhs, const Generation& rhs) noexcept { return !(rhs < lhs); }
  friend constexpr bool operator>=(const Generation& lhs, const Generation& rhs) noexcept { return !(lhs < rhs); }

 private:
  constexpr explicit Generation(std::uint64_t value) noexcept : value_(value) {}
  std::uint64_t value_ = 0;
};

/// A SHA-256 digest. The all-zero digest means "no digest supplied", which is distinct
/// from a digest that happens to be absent, so a comparison against an unsupplied
/// digest is never reported as a match.
class Digest {
 public:
  Digest() = default;
  static Result<Digest> parse_hex(std::string_view hex);
  static Digest of(std::string_view bytes);

  bool is_zero() const noexcept;
  std::string to_hex() const;

  friend bool operator==(const Digest& lhs, const Digest& rhs) noexcept { return lhs.bytes_ == rhs.bytes_; }
  friend bool operator!=(const Digest& lhs, const Digest& rhs) noexcept { return !(lhs == rhs); }
  friend bool operator<(const Digest& lhs, const Digest& rhs) noexcept { return lhs.bytes_ < rhs.bytes_; }

 private:
  std::array<std::uint8_t, 32> bytes_{};
};

/// Shortest hexadecimal prefix of a digest that is still long enough to be an
/// identity rather than a coincidence. Used to derive a plan identity from a plan
/// digest, so that two identical plans have equal identities.
inline constexpr std::size_t kPlanIdentityHexChars = 32;

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_STRONG_TYPES_HPP
