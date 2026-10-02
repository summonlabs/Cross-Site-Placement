// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Values: identities, digests, generations, exact quantities, three-valued logic,
// error categories, limits, and the textual encoders.
//
// Every case here pins a property of the value layer rather than an incidental
// constant: the alphabet is closed, the arithmetic refuses instead of wrapping, and
// the encoders round trip byte for byte.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"
#include "test_harness.hpp"

using namespace csp;

namespace {

constexpr std::int64_t kInt64Max = (std::numeric_limits<std::int64_t>::max)();
constexpr std::int64_t kInt64Min = (std::numeric_limits<std::int64_t>::min)();
constexpr std::uint64_t kUint64Max = (std::numeric_limits<std::uint64_t>::max)();

std::string repeated(char value, std::size_t count) { return std::string(count, value); }

/// One refusal of the identity alphabet, with the category and code it must carry.
struct IdentityRefusal {
  const char* label;
  std::string text;
  ErrorCategory category;
  const char* code;
};

void expect_identity_refusal(const IdentityRefusal& refusal) {
  const Result<SiteId> parsed = SiteId::parse(refusal.text);
  const std::string label = std::string("identity ") + refusal.label;
  CSP_EXPECT_MSG(!parsed.has_value(), label + " was accepted");
  if (parsed.has_value()) {
    return;
  }
  CSP_EXPECT_MSG(parsed.error().category() == refusal.category,
                 label + " failed with the wrong category: " + parsed.error().render());
  CSP_EXPECT_MSG(parsed.error().code() == refusal.code,
                 label + " failed with the wrong code: " + parsed.error().render());
}

void expect_identity_accepted(std::string_view text, const char* label) {
  const Result<SiteId> parsed = SiteId::parse(text);
  CSP_EXPECT_MSG(parsed.has_value(), std::string(label) + " was refused");
}

/// Asserts that an expression failed, with the category and (when given) the code.
///
/// The harness's CSP_EXPECT_CATEGORY macro substitutes its second parameter into the
/// member call `error().category()`, so a category constant cannot be passed through it.
/// This helper asserts exactly the property that macro documents, and the code as well.
template <class T>
void expect_failure(const Result<T>& result, ErrorCategory wanted, const char* code, const char* expression,
                    const char* file, int line) {
  const bool failed = !result.has_value();
  (void)csp_test::check(failed, expression, file, line,
                        failed ? std::string() : std::string("it succeeded"));
  if (!failed) {
    return;
  }
  (void)csp_test::check(result.error().category() == wanted, expression, file, line,
                        result.error().render());
  if (code != nullptr) {
    (void)csp_test::check(result.error().code() == code, expression, file, line, result.error().render());
  }
}

#define EXPECT_FAILURE(expression, wanted_category, wanted_code) \
  expect_failure((expression), (wanted_category), (wanted_code), #expression, __FILE__, __LINE__)

/// Every category, in the order the enumeration declares them.
const std::vector<ErrorCategory>& all_categories() {
  static const std::vector<ErrorCategory> kCategories{
      ErrorCategory::Invalid,       ErrorCategory::Malformed,   ErrorCategory::OutOfRange,
      ErrorCategory::BoundExceeded, ErrorCategory::NotFound,    ErrorCategory::Conflict,
      ErrorCategory::Stale,         ErrorCategory::Unsupported, ErrorCategory::Unavailable,
      ErrorCategory::Indeterminate, ErrorCategory::Io,          ErrorCategory::Integrity,
      ErrorCategory::Locked,        ErrorCategory::Cancelled,   ErrorCategory::Internal,
  };
  return kCategories;
}

/// A request that carries every optional field the encoder can write.
PlacementRequest request_with_every_optional_field() {
  PlacementRequest request;
  const Result<RequestId> request_id = RequestId::parse("req-full");
  const Result<PolicyId> policy_id = PolicyId::parse("policy-full");
  if (request_id) {
    request.request = request_id.value();
  }
  if (policy_id) {
    request.policy.policy = policy_id.value();
  }
  request.generation = Generation::from_value(7);
  request.policy.generation = Generation::from_value(4);

  const Result<SiteId> site_a = SiteId::parse("site-a");
  const Result<SiteId> site_b = SiteId::parse("site-b");
  const Result<SiteId> site_c = SiteId::parse("site-c");
  const Result<JurisdictionId> jurisdiction = JurisdictionId::parse("region-eu");
  const Result<JurisdictionId> jurisdiction_two = JurisdictionId::parse("region-us");
  const Result<ServiceClassId> service = ServiceClassId::parse("payments");
  const Result<ObligationId> obligation_id = ObligationId::parse("obligation-1");
  const Result<ObligationId> peer_id = ObligationId::parse("obligation-2");
  const Result<FailureDomainId> domain = FailureDomainId::parse("feed-1");

  if (site_a) {
    request.allowed_sites.push_back(site_a.value());
  }
  if (site_b) {
    request.forbidden_sites.push_back(site_b.value());
  }
  request.preferences.objectives.push_back(Preferences::Objective::MinimiseCost);
  request.preferences.objectives.push_back(Preferences::Objective::MaximiseDomainSpread);
  request.freshness.max_evidence_age_nanos = 60000000000LL;
  request.freshness.require_observation_time = false;
  request.validity.validity_nanos = 300000000000LL;

  Obligation obligation;
  if (obligation_id) {
    obligation.obligation = obligation_id.value();
  }
  if (service) {
    obligation.service_class = service.value();
  }
  obligation.required_capacity = Quantity::from_units(4);
  obligation.primary_placements = 2;
  obligation.recovery_placements = 1;
  obligation.required_rto = Duration::from_nanos(5000000);
  obligation.required_rpo = Duration::from_nanos(1000000);
  if (jurisdiction) {
    obligation.allowed_jurisdictions.push_back(jurisdiction.value());
  }
  if (jurisdiction_two) {
    obligation.allowed_jurisdictions.push_back(jurisdiction_two.value());
  }
  if (site_a) {
    obligation.allowed_sites.push_back(site_a.value());
  }
  if (site_c) {
    obligation.forbidden_sites.push_back(site_c.value());
  }
  obligation.allow_colocation = true;

  SeparationRequirement separation;
  separation.group = SeparationGroup::AcrossRoles;
  separation.separated_kinds.push_back(DomainKind::Power);
  separation.separated_kinds.push_back(DomainKind::Network);
  if (domain) {
    separation.forbidden_shared_domains.push_back(domain.value());
  }
  obligation.separations.push_back(separation);

  LatencyRequirement latency;
  latency.peer.kind = DependencyEndpoint::Kind::Obligation;
  if (peer_id) {
    latency.peer.obligation = peer_id.value();
  }
  latency.direction = LatencyDirection::ToPlacement;
  latency.statistic = LatencyStatistic::P99;
  latency.max_latency = Duration::from_nanos(25000000);
  latency.applies_to = PlacementRole::Recovery;
  obligation.latency_requirements.push_back(latency);

  request.obligations.push_back(obligation);
  return request;
}

/// A request that leaves every optional field absent.
PlacementRequest request_without_optional_fields() {
  PlacementRequest request;
  const Result<RequestId> request_id = RequestId::parse("req-bare");
  const Result<PolicyId> policy_id = PolicyId::parse("policy-bare");
  const Result<ServiceClassId> service = ServiceClassId::parse("storage");
  const Result<ObligationId> obligation_id = ObligationId::parse("obligation-bare");
  if (request_id) {
    request.request = request_id.value();
  }
  if (policy_id) {
    request.policy.policy = policy_id.value();
  }
  request.generation = Generation::from_value(1);
  request.policy.generation = Generation::from_value(1);

  Obligation obligation;
  if (obligation_id) {
    obligation.obligation = obligation_id.value();
  }
  if (service) {
    obligation.service_class = service.value();
  }
  obligation.required_capacity = Quantity::from_units(1);
  request.obligations.push_back(obligation);
  return request;
}

}  // namespace

// ---------------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------------

CSP_TEST(values, identity_parse_accepts_the_documented_alphabet) {
  const char* kAccepted[] = {"a", "Z", "0", "site-01", "A.b_c:d@e+f#g", "x-9", "a.b.c", "r1", "a#b"};
  for (const char* text : kAccepted) {
    expect_identity_accepted(text, text);
  }
  const std::string punctuation = "-_.:@+#";
  for (const char byte : punctuation) {
    std::string text = "a";
    text.push_back(byte);
    text += "b";
    expect_identity_accepted(text, "an identity with interior punctuation");
  }
  // The bound itself is accepted; one byte more is not.
  expect_identity_accepted(repeated('a', kMaxIdentifierBytes), "an identity of exactly the maximum length");
  const Result<SiteId> longest = SiteId::parse(repeated('a', kMaxIdentifierBytes));
  CSP_REQUIRE(longest.has_value());
  CSP_EXPECT_EQ(longest.value().value().size(), kMaxIdentifierBytes);
}

CSP_TEST(values, identity_parse_refuses_what_the_alphabet_excludes) {
  const std::vector<IdentityRefusal> kRefusals{
      {"(empty)", "", ErrorCategory::Invalid, "csp.identifier.empty"},
      {"of 129 bytes", repeated('a', kMaxIdentifierBytes + 1), ErrorCategory::OutOfRange,
       "csp.identifier.too_long"},
      {"with a leading dash", "-abc", ErrorCategory::Invalid, "csp.identifier.first_byte"},
      {"with a leading dot", ".abc", ErrorCategory::Invalid, "csp.identifier.first_byte"},
      {"with a trailing dot", "abc.", ErrorCategory::Invalid, "csp.identifier.last_byte"},
      {"with a trailing underscore", "abc_", ErrorCategory::Invalid, "csp.identifier.last_byte"},
      {"that is punctuation only", "-_-", ErrorCategory::Invalid, "csp.identifier.first_byte"},
      {"with a forward slash", "a/b", ErrorCategory::Invalid, "csp.identifier.alphabet"},
      {"with a backslash", "a\\b", ErrorCategory::Invalid, "csp.identifier.alphabet"},
      {"with a tab", std::string("a\tb"), ErrorCategory::Invalid, "csp.identifier.alphabet"},
      {"with a newline", std::string("a\nb"), ErrorCategory::Invalid, "csp.identifier.alphabet"},
      {"with a space", "a b", ErrorCategory::Invalid, "csp.identifier.alphabet"},
      {"with a leading space", " abc", ErrorCategory::Invalid, "csp.identifier.first_byte"},
      {"with a trailing space", "abc ", ErrorCategory::Invalid, "csp.identifier.last_byte"},
      {"ending with a non-ASCII byte", std::string("caf\xC3\xA9"), ErrorCategory::Invalid,
       "csp.identifier.last_byte"},
      {"with a non-ASCII byte inside", std::string("ca\xC3\xA9") + "f", ErrorCategory::Invalid,
       "csp.identifier.alphabet"},
      {"with a NUL byte", std::string("a\0b", 3), ErrorCategory::Invalid, "csp.identifier.alphabet"},
      {"with a semicolon", "a;b", ErrorCategory::Invalid, "csp.identifier.alphabet"},
      {"with a percent sign", "a%b", ErrorCategory::Invalid, "csp.identifier.alphabet"},
  };
  for (const IdentityRefusal& refusal : kRefusals) {
    expect_identity_refusal(refusal);
  }
}

CSP_TEST(values, identity_case_is_part_of_the_identity) {
  const Result<SiteId> lower = SiteId::parse("region-a");
  const Result<SiteId> upper = SiteId::parse("Region-A");
  CSP_REQUIRE(lower.has_value());
  CSP_REQUIRE(upper.has_value());
  CSP_EXPECT(lower.value() != upper.value());
  CSP_EXPECT(!(lower.value() == upper.value()));
  // Ordering is byte order, so the upper-case identity sorts first.
  CSP_EXPECT(upper.value() < lower.value());
  CSP_EXPECT(!(lower.value() < upper.value()));
  // The bytes are preserved exactly; nothing normalises them.
  CSP_EXPECT_EQ(lower.value().value(), std::string("region-a"));
  CSP_EXPECT_EQ(upper.value().value(), std::string("Region-A"));
  // A default-constructed identity is not a valid identity.
  const SiteId unset;
  CSP_EXPECT(!unset.valid());
  CSP_EXPECT_EQ(SiteId::name(), std::string_view("site"));
  CSP_EXPECT_EQ(FailureDomainId::name(), std::string_view("failure-domain"));
}

// ---------------------------------------------------------------------------------
// Digests and generations
// ---------------------------------------------------------------------------------

CSP_TEST(values, digest_hex_round_trips_and_bounds_the_length) {
  const Digest real = Digest::of("cross-site-placement");
  const std::string hex = real.to_hex();
  CSP_EXPECT_EQ(hex.size(), std::size_t{64});
  for (const char digit : hex) {
    CSP_EXPECT(!(digit >= 'A' && digit <= 'F'));
  }
  const Result<Digest> parsed = Digest::parse_hex(hex);
  CSP_REQUIRE(parsed.has_value());
  CSP_EXPECT(parsed.value() == real);
  CSP_EXPECT_EQ(parsed.value().to_hex(), hex);

  // Upper case hexadecimal is the same digest.
  std::string upper = hex;
  for (char& digit : upper) {
    if (digit >= 'a' && digit <= 'f') {
      digit = static_cast<char>(digit - 'a' + 'A');
    }
  }
  const Result<Digest> parsed_upper = Digest::parse_hex(upper);
  CSP_REQUIRE(parsed_upper.has_value());
  CSP_EXPECT(parsed_upper.value() == real);
  CSP_EXPECT_EQ(parsed_upper.value().to_hex(), hex);

  const std::size_t kWrongLengths[] = {0, 63, 65};
  for (const std::size_t length : kWrongLengths) {
    const std::string text = repeated('a', length);
    const Result<Digest> refused = Digest::parse_hex(text);
    CSP_EXPECT_MSG(!refused.has_value(),
                   "a digest of " + std::to_string(length) + " characters was accepted");
    if (!refused.has_value()) {
      CSP_EXPECT(refused.error().category() == ErrorCategory::Invalid);
      CSP_EXPECT_EQ(refused.error().code(), std::string("csp.digest.length"));
    }
  }
  const Result<Digest> not_hex = Digest::parse_hex(repeated('z', 64));
  CSP_EXPECT(!not_hex.has_value());
  if (!not_hex.has_value()) {
    CSP_EXPECT(not_hex.error().category() == ErrorCategory::Invalid);
    CSP_EXPECT_EQ(not_hex.error().code(), std::string("csp.digest.alphabet"));
  }
}

CSP_TEST(values, digest_zero_is_distinguishable_from_a_real_digest) {
  const Digest zero;
  const Digest real = Digest::of("cross-site-placement");
  CSP_EXPECT(zero.is_zero());
  CSP_EXPECT(!real.is_zero());
  CSP_EXPECT(zero != real);
  CSP_EXPECT(!(zero == real));
  const Result<Digest> parsed_zero = Digest::parse_hex(repeated('0', 64));
  CSP_REQUIRE(parsed_zero.has_value());
  CSP_EXPECT(parsed_zero.value().is_zero());
  // The all-zero digest is the "no digest supplied" value, so it equals a default one.
  CSP_EXPECT(parsed_zero.value() == zero);
  CSP_EXPECT(parsed_zero.value() != real);
  // Different content yields a different digest, and hashing is a pure function.
  CSP_EXPECT(Digest::of("a") != Digest::of("b"));
  CSP_EXPECT(Digest::of("a") == Digest::of("a"));
  CSP_EXPECT(Digest::of("") == Digest::of(std::string_view{}));
}

CSP_TEST(values, generation_next_refuses_to_wrap) {
  const Result<Generation> wrapped = Generation::from_value(kUint64Max).next();
  CSP_EXPECT_MSG(!wrapped.has_value(), "the generation counter did not report exhaustion");
  if (!wrapped.has_value()) {
    CSP_EXPECT(wrapped.error().category() == ErrorCategory::OutOfRange);
    CSP_EXPECT_EQ(wrapped.error().code(), std::string("csp.generation.exhausted"));
  }
  const Result<Generation> next = Generation::from_value(41).next();
  CSP_REQUIRE(next.has_value());
  CSP_EXPECT_EQ(next.value().value(), std::uint64_t{42});
  CSP_EXPECT(!Generation::from_value(0).is_set());
  CSP_EXPECT(Generation::from_value(1).is_set());
  const Result<Generation> from_zero = Generation::from_value(0).next();
  CSP_REQUIRE(from_zero.has_value());
  CSP_EXPECT_EQ(from_zero.value().value(), std::uint64_t{1});
}

// ---------------------------------------------------------------------------------
// Exact arithmetic
// ---------------------------------------------------------------------------------

CSP_TEST(values, duration_checked_arithmetic_reports_overflow) {
  const Result<Duration> add = Duration::from_nanos(kInt64Max).checked_add(Duration::from_nanos(1));
  CSP_EXPECT(!add.has_value());
  if (!add.has_value()) {
    CSP_EXPECT(add.error().category() == ErrorCategory::OutOfRange);
    CSP_EXPECT_EQ(add.error().code(), std::string("csp.duration.overflow"));
  }
  EXPECT_FAILURE(Duration::from_nanos(kInt64Min).checked_sub(Duration::from_nanos(1)),
                 ErrorCategory::OutOfRange, "csp.duration.overflow");
  EXPECT_FAILURE(Duration::from_millis(kInt64Max), ErrorCategory::OutOfRange, "csp.duration.overflow");
  EXPECT_FAILURE(Duration::from_seconds(kInt64Max), ErrorCategory::OutOfRange, "csp.duration.overflow");
  EXPECT_FAILURE(Duration::from_seconds(kInt64Min), ErrorCategory::OutOfRange, "csp.duration.overflow");

  // The operations that do fit are exact, and a negative interval survives.
  const Result<Duration> sum = Duration::from_nanos(5).checked_add(Duration::from_nanos(-7));
  CSP_REQUIRE(sum.has_value());
  CSP_EXPECT_EQ(sum.value().nanos(), std::int64_t{-2});
  const Result<Duration> difference = Duration::from_nanos(5).checked_sub(Duration::from_nanos(7));
  CSP_REQUIRE(difference.has_value());
  CSP_EXPECT_EQ(difference.value().nanos(), std::int64_t{-2});
  CSP_EXPECT(Duration::from_nanos(5).is_negative() == false);
  CSP_EXPECT(Duration::from_nanos(-5).is_negative());
  CSP_EXPECT(Duration{}.is_zero());
  const Result<Duration> millis = Duration::from_millis(3);
  CSP_REQUIRE(millis.has_value());
  CSP_EXPECT_EQ(millis.value().nanos(), std::int64_t{3000000});
  const Result<Duration> seconds = Duration::from_seconds(-2);
  CSP_REQUIRE(seconds.has_value());
  CSP_EXPECT_EQ(seconds.value().nanos(), std::int64_t{-2000000000});
}

CSP_TEST(values, quantity_checked_arithmetic_reports_overflow) {
  const Result<Quantity> add = Quantity::from_units(kInt64Max).checked_add(Quantity::from_units(1));
  CSP_EXPECT(!add.has_value());
  if (!add.has_value()) {
    CSP_EXPECT(add.error().category() == ErrorCategory::OutOfRange);
    CSP_EXPECT_EQ(add.error().code(), std::string("csp.quantity.overflow"));
  }
  EXPECT_FAILURE(Quantity::from_units(kInt64Max).checked_mul(2), ErrorCategory::OutOfRange,
                 "csp.quantity.overflow");
  EXPECT_FAILURE(Quantity::from_units(kInt64Min).checked_sub(Quantity::from_units(1)),
                 ErrorCategory::OutOfRange, "csp.quantity.overflow");
  EXPECT_FAILURE(Quantity::from_units(kInt64Min).checked_mul(-1), ErrorCategory::OutOfRange,
                 "csp.quantity.overflow");
  const Result<Quantity> exact = Quantity::from_units(21).checked_mul(2);
  CSP_REQUIRE(exact.has_value());
  CSP_EXPECT_EQ(exact.value().units(), std::int64_t{42});
  const Result<Quantity> difference = Quantity::from_units(3).checked_sub(Quantity::from_units(10));
  CSP_REQUIRE(difference.has_value());
  CSP_EXPECT_EQ(difference.value().units(), std::int64_t{-7});
  CSP_EXPECT(Quantity{}.is_zero());
  CSP_EXPECT(Quantity::from_units(-1).is_negative());
}

CSP_TEST(values, quantity_parse_refuses_text_that_is_not_canonical) {
  const auto expect_parsed = [](std::string_view text, std::int64_t units) {
    const Result<Quantity> parsed = Quantity::parse(text);
    CSP_EXPECT_MSG(parsed.has_value(), "quantity \"" + std::string(text) + "\" was refused");
    if (parsed.has_value()) {
      CSP_EXPECT_MSG(parsed.value().units() == units,
                     "quantity \"" + std::string(text) + "\" decoded to the wrong value");
    }
  };
  expect_parsed("0", 0);
  expect_parsed("42", 42);
  expect_parsed("-7", -7);
  expect_parsed("9223372036854775807", kInt64Max);
  expect_parsed("-9223372036854775808", kInt64Min);

  const char* kRefused[] = {"",
                            "01",
                            "00",
                            "+1",
                            "-0",
                            " 1",
                            "1 ",
                            "1.0",
                            "1e3",
                            "0x10",
                            "abc",
                            "-",
                            "--1",
                            "1-",
                            "9223372036854775808",
                            "-9223372036854775809",
                            "1\n"};
  for (const char* text : kRefused) {
    const Result<Quantity> parsed = Quantity::parse(text);
    CSP_EXPECT_MSG(!parsed.has_value(), std::string("quantity \"") + text + "\" was accepted");
    if (!parsed.has_value()) {
      CSP_EXPECT(parsed.error().category() == ErrorCategory::Invalid);
      CSP_EXPECT_EQ(parsed.error().code(), std::string("csp.quantity.parse"));
    }
  }
}

CSP_TEST(values, elapsed_refuses_a_reversed_pair) {
  const Instant earlier = Instant::from_nanos(100);
  const Instant later = Instant::from_nanos(250);
  const Result<Duration> forward = elapsed(earlier, later);
  CSP_REQUIRE(forward.has_value());
  CSP_EXPECT_EQ(forward.value().nanos(), std::int64_t{150});
  const Result<Duration> same = elapsed(later, later);
  CSP_REQUIRE(same.has_value());
  CSP_EXPECT(same.value().is_zero());
  const Result<Duration> backward = elapsed(later, earlier);
  CSP_EXPECT(!backward.has_value());
  if (!backward.has_value()) {
    CSP_EXPECT(backward.error().category() == ErrorCategory::OutOfRange);
    CSP_EXPECT_EQ(backward.error().code(), std::string("csp.time.negative_interval"));
  }
  // An interval that does not fit is refused rather than wrapped.
  EXPECT_FAILURE(elapsed(Instant::from_nanos(kInt64Min), Instant::from_nanos(kInt64Max)),
                 ErrorCategory::OutOfRange, "csp.time.overflow");
  CSP_EXPECT(Instant{}.is_zero());
  CSP_EXPECT(Instant::from_nanos(700) > earlier);
}

// ---------------------------------------------------------------------------------
// Measurements and three-valued logic
// ---------------------------------------------------------------------------------

CSP_TEST(values, measurement_default_is_unknown_and_usability_is_three_valued) {
  const Measurement<std::int64_t> unset;
  CSP_EXPECT(unset.state() == MeasurementState::Unknown);
  CSP_EXPECT(unset.is_unknown());
  CSP_EXPECT(!unset.is_known());
  CSP_EXPECT(!unset.is_unsupported());
  CSP_EXPECT(!unset.is_unavailable());
  CSP_EXPECT(unset.usability() == Tri::Indeterminate);

  const Measurement<std::int64_t> known = Measurement<std::int64_t>::known(0);
  CSP_EXPECT(known.is_known());
  CSP_EXPECT(known.usability() == Tri::Satisfied);
  CSP_EXPECT_EQ(known.value(), std::int64_t{0});
  CSP_EXPECT(Measurement<std::int64_t>::unknown().usability() == Tri::Indeterminate);
  CSP_EXPECT(Measurement<std::int64_t>::unsupported().usability() == Tri::Violated);
  CSP_EXPECT(Measurement<std::int64_t>::unavailable().usability() == Tri::Violated);

  // A measurement without a value never compares equal to one with a value.
  CSP_EXPECT(Measurement<std::int64_t>::unknown() != Measurement<std::int64_t>::known(0));
  CSP_EXPECT(Measurement<std::int64_t>::unsupported() != Measurement<std::int64_t>::known(0));
  CSP_EXPECT(Measurement<std::int64_t>::unavailable() != Measurement<std::int64_t>::known(0));
  CSP_EXPECT(Measurement<std::int64_t>::unknown() != Measurement<std::int64_t>::unsupported());
  CSP_EXPECT(Measurement<std::int64_t>::known(0) == Measurement<std::int64_t>::known(0));
  CSP_EXPECT(Measurement<std::int64_t>::known(0) != Measurement<std::int64_t>::known(1));
  // The default measurement of a state-valued measurement is Unknown too.
  const Measurement<MaintenanceState> state;
  CSP_EXPECT(state.is_unknown());
  CSP_EXPECT(state != Measurement<MaintenanceState>::known(MaintenanceState::Offline));
}

CSP_TEST(values, tri_conjunction_is_minimum_and_disjunction_is_maximum) {
  const Tri kValues[] = {Tri::Violated, Tri::Indeterminate, Tri::Satisfied};
  // Written as explicit numbers so the case checks the lattice, not the implementation.
  const int kConjunction[3][3] = {{0, 0, 0}, {0, 1, 1}, {0, 1, 2}};
  const int kDisjunction[3][3] = {{0, 1, 2}, {1, 1, 2}, {2, 2, 2}};
  for (std::size_t left = 0; left < 3; ++left) {
    for (std::size_t right = 0; right < 3; ++right) {
      const Tri conjunction = tri_conjunction(kValues[left], kValues[right]);
      const Tri disjunction = tri_disjunction(kValues[left], kValues[right]);
      CSP_EXPECT_MSG(static_cast<int>(conjunction) == kConjunction[left][right],
                     "conjunction is not the minimum");
      CSP_EXPECT_MSG(static_cast<int>(disjunction) == kDisjunction[left][right],
                     "disjunction is not the maximum");
      // Commutativity, idempotence, and absorption.
      CSP_EXPECT(tri_conjunction(kValues[right], kValues[left]) == conjunction);
      CSP_EXPECT(tri_disjunction(kValues[right], kValues[left]) == disjunction);
      CSP_EXPECT(tri_conjunction(kValues[left], kValues[left]) == kValues[left]);
      CSP_EXPECT(tri_disjunction(kValues[left], kValues[left]) == kValues[left]);
      CSP_EXPECT(tri_conjunction(kValues[left], tri_disjunction(kValues[left], kValues[right])) ==
                 kValues[left]);
      CSP_EXPECT(tri_disjunction(kValues[left], tri_conjunction(kValues[left], kValues[right])) ==
                 kValues[left]);
    }
  }
}

CSP_TEST(values, tri_negation_and_de_morgan) {
  const Tri kValues[] = {Tri::Violated, Tri::Indeterminate, Tri::Satisfied};
  CSP_EXPECT(tri_negation(Tri::Satisfied) == Tri::Violated);
  CSP_EXPECT(tri_negation(Tri::Violated) == Tri::Satisfied);
  CSP_EXPECT(tri_negation(Tri::Indeterminate) == Tri::Indeterminate);
  CSP_EXPECT(!tri_is_definite(Tri::Indeterminate));
  CSP_EXPECT(tri_is_definite(Tri::Satisfied));
  CSP_EXPECT(tri_is_definite(Tri::Violated));
  for (const Tri left : kValues) {
    for (const Tri right : kValues) {
      // Negation is an involution and De Morgan holds over all nine pairs.
      CSP_EXPECT(tri_negation(tri_negation(left)) == left);
      CSP_EXPECT(tri_negation(tri_conjunction(left, right)) ==
                 tri_disjunction(tri_negation(left), tri_negation(right)));
      CSP_EXPECT(tri_negation(tri_disjunction(left, right)) ==
                 tri_conjunction(tri_negation(left), tri_negation(right)));
    }
  }
  // The textual tokens round trip.
  for (const Tri value : kValues) {
    const std::optional<Tri> parsed = tri_from_string(to_string(value));
    CSP_EXPECT(parsed.has_value());
    if (parsed.has_value()) {
      CSP_EXPECT(parsed.value() == value);
    }
  }
  CSP_EXPECT(!tri_from_string("maybe").has_value());
  CSP_EXPECT(!tri_from_string("").has_value());
}

// ---------------------------------------------------------------------------------
// Error categories and limits
// ---------------------------------------------------------------------------------

CSP_TEST(values, error_category_tokens_round_trip_one_per_enumerator) {
  const std::vector<ErrorCategory>& categories = all_categories();
  std::vector<std::string> tokens;
  tokens.reserve(categories.size());
  for (const ErrorCategory category : categories) {
    const char* token = to_string(category);
    CSP_REQUIRE(token != nullptr);
    const std::string text(token);
    CSP_EXPECT_MSG(!text.empty(), "a category has an empty token");
    const std::optional<ErrorCategory> parsed = error_category_from_string(text);
    CSP_EXPECT_MSG(parsed.has_value(), "token \"" + text + "\" does not decode");
    if (parsed.has_value()) {
      CSP_EXPECT_MSG(parsed.value() == category, "token \"" + text + "\" decodes to another category");
    }
    // A category whose token fell through to the fallback would collide with Internal.
    if (category != ErrorCategory::Internal) {
      CSP_EXPECT_MSG(text != "internal", "a category fell through to the fallback token");
    }
    tokens.push_back(text);
  }
  // One entry per enumerator: as many distinct tokens as enumerators.
  std::sort(tokens.begin(), tokens.end());
  CSP_EXPECT_EQ(tokens.size(), categories.size());
  CSP_EXPECT(std::adjacent_find(tokens.begin(), tokens.end()) == tokens.end());
  CSP_EXPECT_EQ(tokens.size(), std::size_t{15});

  CSP_EXPECT(!error_category_from_string("").has_value());
  CSP_EXPECT(!error_category_from_string("bogus").has_value());
  CSP_EXPECT(!error_category_from_string("Invalid").has_value());
  CSP_EXPECT_EQ(to_string(ErrorCategory::BoundExceeded), std::string_view("bound_exceeded"));

  const Error error(ErrorCategory::Conflict, "csp.example.code", "something disagreed");
  CSP_EXPECT(error.category() == ErrorCategory::Conflict);
  CSP_EXPECT_EQ(error.render(), std::string("conflict: csp.example.code: something disagreed"));
  const Error bare(ErrorCategory::Io, "", "");
  CSP_EXPECT_EQ(bare.render(), std::string("io"));
  const Error code_only(ErrorCategory::Stale, "csp.stale", "");
  CSP_EXPECT_EQ(code_only.render(), std::string("stale: csp.stale"));
  CSP_EXPECT(Error(ErrorCategory::Io, "a", "b") == Error(ErrorCategory::Io, "a", "b"));
  CSP_EXPECT(Error(ErrorCategory::Io, "a", "b") != Error(ErrorCategory::Io, "a", "c"));
  CSP_EXPECT(Error(ErrorCategory::Io, "a", "b") != Error(ErrorCategory::Locked, "a", "b"));
}

CSP_TEST(values, limits_validate_refuses_zero_bounds_and_an_excess_thread_count) {
  const Limits defaults;
  CSP_EXPECT_OK(limits_validate(defaults));
  CSP_EXPECT_EQ(defaults.worker_threads, std::size_t{0});

  const std::pair<const char*, std::size_t Limits::*> kZeroedBounds[] = {
      {"max_document_bytes", &Limits::max_document_bytes},
      {"max_obligations", &Limits::max_obligations},
      {"max_sites", &Limits::max_sites},
      {"max_latency_evidence", &Limits::max_latency_evidence},
      {"max_trace_entries", &Limits::max_trace_entries},
      {"max_search_nodes", &Limits::max_search_nodes},
      {"max_derived_hops", &Limits::max_derived_hops},
  };
  for (const auto& entry : kZeroedBounds) {
    Limits lowered;
    lowered.*(entry.second) = 0;
    const Status status = limits_validate(lowered);
    CSP_EXPECT_MSG(!status.has_value(), std::string(entry.first) + " accepted a zero bound");
    if (!status.has_value()) {
      CSP_EXPECT(status.error().category() == ErrorCategory::Invalid);
      CSP_EXPECT_MSG(status.error().code() == "csp.limits.zero",
                     std::string(entry.first) + " failed with " + status.error().render());
    }
  }

  Limits at_ceiling;
  at_ceiling.worker_threads = 1024;
  CSP_EXPECT_OK(limits_validate(at_ceiling));
  Limits above_ceiling;
  above_ceiling.worker_threads = 1025;
  const Status threads = limits_validate(above_ceiling);
  CSP_EXPECT(!threads.has_value());
  if (!threads.has_value()) {
    CSP_EXPECT(threads.error().category() == ErrorCategory::Invalid);
    CSP_EXPECT_EQ(threads.error().code(), std::string("csp.limits.worker_threads"));
  }

  Limits kind_bound;
  kind_bound.max_separated_kinds = 8;
  EXPECT_FAILURE(limits_validate(kind_bound), ErrorCategory::Invalid, "csp.limits.separated_kinds");
  Limits shallow;
  shallow.max_document_depth = 1;
  EXPECT_FAILURE(limits_validate(shallow), ErrorCategory::Invalid, "csp.limits.document_depth");
  Limits retry;
  retry.store_lock_retry_ms = retry.store_lock_wait_ms + 1;
  EXPECT_FAILURE(limits_validate(retry), ErrorCategory::Invalid, "csp.limits.lock_retry");
  Limits negative_age;
  negative_age.max_evidence_age_nanos = -1;
  EXPECT_FAILURE(limits_validate(negative_age), ErrorCategory::Invalid, "csp.limits.evidence_age");
  Limits negative_validity;
  negative_validity.max_plan_validity_nanos = -1;
  EXPECT_FAILURE(limits_validate(negative_validity), ErrorCategory::Invalid, "csp.limits.negative");
}

// ---------------------------------------------------------------------------------
// Text encoders
// ---------------------------------------------------------------------------------

CSP_TEST(values, request_document_round_trips_every_optional_field) {
  const Limits limits;
  const PlacementRequest full = request_with_every_optional_field();
  const Result<std::string> canonical = request_to_document(full, false);
  CSP_REQUIRE(canonical.has_value());
  const Result<std::string> canonical_again = request_to_document(full, false);
  CSP_REQUIRE(canonical_again.has_value());
  CSP_EXPECT_EQ(canonical.value(), canonical_again.value());

  const Result<PlacementRequest> decoded = request_from_document(canonical.value(), limits);
  CSP_REQUIRE(decoded.has_value());
  const Result<std::string> re_encoded = request_to_document(decoded.value(), false);
  CSP_REQUIRE(re_encoded.has_value());
  CSP_EXPECT_EQ(re_encoded.value(), canonical.value());

  // The optional fields came back.
  const PlacementRequest& back = decoded.value();
  CSP_REQUIRE(back.obligations.size() == 1);
  const Obligation& obligation = back.obligations.front();
  CSP_EXPECT(obligation.required_rto.has_value());
  CSP_EXPECT(obligation.required_rpo.has_value());
  if (obligation.required_rto.has_value()) {
    CSP_EXPECT_EQ(obligation.required_rto->nanos(), std::int64_t{5000000});
  }
  if (obligation.required_rpo.has_value()) {
    CSP_EXPECT_EQ(obligation.required_rpo->nanos(), std::int64_t{1000000});
  }
  CSP_EXPECT_EQ(obligation.allowed_jurisdictions.size(), std::size_t{2});
  CSP_EXPECT_EQ(obligation.allowed_sites.size(), std::size_t{1});
  CSP_EXPECT_EQ(obligation.forbidden_sites.size(), std::size_t{1});
  CSP_EXPECT(obligation.allow_colocation);
  CSP_EXPECT_EQ(obligation.required_capacity.units(), std::int64_t{4});
  CSP_EXPECT_EQ(obligation.primary_placements, std::uint32_t{2});
  CSP_EXPECT_EQ(obligation.recovery_placements, std::uint32_t{1});
  CSP_REQUIRE(obligation.separations.size() == 1);
  CSP_EXPECT(obligation.separations.front().group == SeparationGroup::AcrossRoles);
  CSP_EXPECT_EQ(obligation.separations.front().separated_kinds.size(), std::size_t{2});
  CSP_EXPECT_EQ(obligation.separations.front().forbidden_shared_domains.size(), std::size_t{1});
  CSP_REQUIRE(obligation.latency_requirements.size() == 1);
  CSP_EXPECT(obligation.latency_requirements.front().peer.kind == DependencyEndpoint::Kind::Obligation);
  CSP_EXPECT(obligation.latency_requirements.front().direction == LatencyDirection::ToPlacement);
  CSP_EXPECT(obligation.latency_requirements.front().statistic == LatencyStatistic::P99);
  CSP_EXPECT(obligation.latency_requirements.front().applies_to == PlacementRole::Recovery);
  CSP_EXPECT_EQ(obligation.latency_requirements.front().max_latency.nanos(), std::int64_t{25000000});
  CSP_EXPECT_EQ(back.allowed_sites.size(), std::size_t{1});
  CSP_EXPECT_EQ(back.forbidden_sites.size(), std::size_t{1});
  CSP_EXPECT_EQ(back.preferences.objectives.size(), std::size_t{2});
  CSP_EXPECT(back.preferences.objectives.front() == Preferences::Objective::MinimiseCost);
  CSP_EXPECT_EQ(back.generation.value(), std::uint64_t{7});
  CSP_EXPECT_EQ(back.policy.generation.value(), std::uint64_t{4});
  CSP_EXPECT_EQ(back.freshness.max_evidence_age_nanos, std::int64_t{60000000000LL});
  CSP_EXPECT(!back.freshness.require_observation_time);
  CSP_EXPECT_EQ(back.validity.validity_nanos, std::int64_t{300000000000LL});

  // The same request with every optional field absent.
  const PlacementRequest bare = request_without_optional_fields();
  const Result<std::string> bare_canonical = request_to_document(bare, false);
  CSP_REQUIRE(bare_canonical.has_value());
  const Result<PlacementRequest> bare_decoded = request_from_document(bare_canonical.value(), limits);
  CSP_REQUIRE(bare_decoded.has_value());
  const Result<std::string> bare_again = request_to_document(bare_decoded.value(), false);
  CSP_REQUIRE(bare_again.has_value());
  CSP_EXPECT_EQ(bare_again.value(), bare_canonical.value());
  CSP_REQUIRE(bare_decoded.value().obligations.size() == 1);
  const Obligation& bare_obligation = bare_decoded.value().obligations.front();
  CSP_EXPECT(!bare_obligation.required_rto.has_value());
  CSP_EXPECT(!bare_obligation.required_rpo.has_value());
  CSP_EXPECT(bare_obligation.allowed_jurisdictions.empty());
  CSP_EXPECT(bare_obligation.separations.empty());
  CSP_EXPECT(bare_obligation.latency_requirements.empty());
  CSP_EXPECT(!bare_obligation.allow_colocation);
  CSP_EXPECT(bare_decoded.value().preferences.objectives.empty());
  CSP_EXPECT(bare_decoded.value().freshness.require_observation_time);
}

CSP_TEST(values, request_document_pretty_form_decodes_to_the_same_value) {
  const Limits limits;
  const PlacementRequest full = request_with_every_optional_field();
  const Result<std::string> canonical = request_to_document(full, false);
  CSP_REQUIRE(canonical.has_value());
  const Result<std::string> pretty = request_to_document(full, true);
  CSP_REQUIRE(pretty.has_value());
  CSP_EXPECT(pretty.value() != canonical.value());
  const Result<PlacementRequest> from_pretty = request_from_document(pretty.value(), limits);
  CSP_REQUIRE(from_pretty.has_value());
  const Result<std::string> re_encoded = request_to_document(from_pretty.value(), false);
  CSP_REQUIRE(re_encoded.has_value());
  CSP_EXPECT_EQ(re_encoded.value(), canonical.value());
}

CSP_TEST(values, policy_document_round_trips_every_flag) {
  const Limits limits;
  PlacementPolicy policy;
  const Result<PolicyId> policy_id = PolicyId::parse("policy-round-trip");
  CSP_REQUIRE(policy_id.has_value());
  policy.policy = policy_id.value();
  policy.generation = Generation::from_value(23);
  policy.allow_degraded_sites = true;
  policy.allow_unknown_maintenance_state = true;
  policy.allow_unknown_jurisdiction = true;
  policy.allow_offer_capacity = false;
  policy.require_commitment_capacity = true;
  policy.allow_derived_latency_bounds = false;
  policy.max_derived_hops = 3;
  policy.allow_recovery_on_primary_site = true;

  const Result<std::string> canonical = policy_to_document(policy, false);
  CSP_REQUIRE(canonical.has_value());
  const Result<std::string> canonical_again = policy_to_document(policy, false);
  CSP_REQUIRE(canonical_again.has_value());
  CSP_EXPECT_EQ(canonical.value(), canonical_again.value());

  const Result<PlacementPolicy> decoded = policy_from_document(canonical.value(), limits);
  CSP_REQUIRE(decoded.has_value());
  const PlacementPolicy& back = decoded.value();
  CSP_EXPECT(back.policy == policy.policy);
  CSP_EXPECT_EQ(back.generation.value(), std::uint64_t{23});
  CSP_EXPECT(back.allow_degraded_sites);
  CSP_EXPECT(back.allow_unknown_maintenance_state);
  CSP_EXPECT(back.allow_unknown_jurisdiction);
  CSP_EXPECT(!back.allow_offer_capacity);
  CSP_EXPECT(back.require_commitment_capacity);
  CSP_EXPECT(!back.allow_derived_latency_bounds);
  CSP_EXPECT_EQ(back.max_derived_hops, std::size_t{3});
  CSP_EXPECT(back.allow_recovery_on_primary_site);
  const Result<std::string> re_encoded = policy_to_document(back, false);
  CSP_REQUIRE(re_encoded.has_value());
  CSP_EXPECT_EQ(re_encoded.value(), canonical.value());

  // A policy with default flags and no derived hops round trips too.
  PlacementPolicy defaults;
  defaults.policy = policy_id.value();
  const Result<std::string> default_document = policy_to_document(defaults, false);
  CSP_REQUIRE(default_document.has_value());
  const Result<PlacementPolicy> default_decoded = policy_from_document(default_document.value(), limits);
  CSP_REQUIRE(default_decoded.has_value());
  // An unset policy identity is not an identity, so a document carrying one is refused.
  const PlacementPolicy unset;
  const Result<std::string> unset_document = policy_to_document(unset, false);
  CSP_REQUIRE(unset_document.has_value());
  const Result<PlacementPolicy> unset_decoded = policy_from_document(unset_document.value(), limits);
  EXPECT_FAILURE(unset_decoded, ErrorCategory::Invalid, "csp.identifier.empty");
  CSP_EXPECT(!default_decoded.value().allow_degraded_sites);
  CSP_EXPECT(default_decoded.value().allow_offer_capacity);
  CSP_EXPECT(default_decoded.value().allow_derived_latency_bounds);
  CSP_EXPECT_EQ(default_decoded.value().max_derived_hops, std::size_t{0});
  const Result<std::string> pretty = policy_to_document(policy, true);
  CSP_REQUIRE(pretty.has_value());
  const Result<PlacementPolicy> from_pretty = policy_from_document(pretty.value(), limits);
  CSP_REQUIRE(from_pretty.has_value());
  const Result<std::string> from_pretty_canonical = policy_to_document(from_pretty.value(), false);
  CSP_REQUIRE(from_pretty_canonical.has_value());
  CSP_EXPECT_EQ(from_pretty_canonical.value(), canonical.value());
}
