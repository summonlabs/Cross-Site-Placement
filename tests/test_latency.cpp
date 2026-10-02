// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Latency: direct measurements, statistic coverage, direction, and derived chains.
//
// A latency requirement is decided from records the fabric authority published. Every
// case below states the records, the bound, and the answer the bound has to produce;
// where the answer is "nobody knows", the plan is indeterminate rather than placed.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"
#include "test_harness.hpp"

using namespace csp;

namespace {

constexpr std::int64_t kObserved = 1700000000000000000LL;
constexpr std::int64_t kEvaluated = kObserved + 1000000000LL;
constexpr std::int64_t kInt64Max = (std::numeric_limits<std::int64_t>::max)();
constexpr std::int64_t kMillis = 1000000LL;

template <class T>
void expect_failure(const Result<T>& result, ErrorCategory wanted, const char* code, const char* expression,
                    const char* file, int line) {
  const bool failed = !result.has_value();
  (void)csp_test::check(failed, expression, file, line, failed ? std::string() : std::string("it succeeded"));
  if (!failed) {
    return;
  }
  (void)csp_test::check(result.error().category() == wanted, expression, file, line, result.error().render());
  if (code != nullptr) {
    (void)csp_test::check(result.error().code() == code, expression, file, line, result.error().render());
  }
}

#define EXPECT_FAILURE(expression, wanted_category, wanted_code) \
  expect_failure((expression), (wanted_category), (wanted_code), #expression, __FILE__, __LINE__)

template <class IdType>
IdType id_of(std::string_view text) {
  const Result<IdType> parsed = IdType::parse(text);
  CSP_REQUIRE(parsed.has_value());
  return parsed.value();
}

struct Fleet {
  SiteEvidenceSnapshot snapshot;
  PlacementRequest request;
  PlacementPolicy policy;
  PlanningContext context;
  int counter = 0;

  Fleet() {
    snapshot.generation = Generation::from_value(11);
    snapshot.captured_at = Instant::from_nanos(kEvaluated);
    context.evaluation_instant = Instant::from_nanos(kEvaluated);
    request.request = id_of<RequestId>("req-latency");
    request.generation = Generation::from_value(3);
    request.policy.policy = id_of<PolicyId>("policy-1");
    request.policy.generation = Generation::from_value(5);
    policy.policy = id_of<PolicyId>("policy-1");
    policy.generation = Generation::from_value(5);
  }

  Result<PlacementPlan> plan() const { return Planner().plan(request, snapshot, policy, context); }
  Result<PlacementPlan> plan_with(const Limits& limits) const {
    return Planner(limits).plan(request, snapshot, policy, context);
  }

  std::string fresh(std::string_view prefix) {
    return std::string(prefix) + "-" + std::to_string(++counter);
  }

  Provenance provenance(std::string_view prefix) {
    Provenance record;
    record.source_record = id_of<EvidenceId>(fresh(prefix));
    record.authority = id_of<AuthorityId>("fabric-authority");
    record.authority_generation = Generation::from_value(9);
    record.observed_at = Instant::from_nanos(kObserved);
    return record;
  }

  void add_site(std::string_view site) {
    SiteRecord record;
    record.site = id_of<SiteId>(site);
    record.maintenance = Measurement<MaintenanceState>::known(MaintenanceState::Operational);
    record.provenance = provenance("site");
    snapshot.sites.push_back(std::move(record));
  }

  /// A capacity reference and a compatibility record for the one candidate site.
  void add_host(std::string_view site, std::string_view service_class) {
    CapacityRecord capacity;
    capacity.reference = id_of<CapacityRefId>(fresh("capacity"));
    capacity.site = id_of<SiteId>(site);
    capacity.service_class = id_of<ServiceClassId>(service_class);
    capacity.kind = CapacityKind::Commitment;
    capacity.available = Measurement<Quantity>::known(Quantity::from_units(10));
    capacity.provenance = provenance("capacity-record");
    snapshot.capacity.push_back(std::move(capacity));

    CompatibilityRecord compatibility;
    compatibility.reference = id_of<EvidenceId>(fresh("compatibility"));
    compatibility.site = id_of<SiteId>(site);
    compatibility.service_class = id_of<ServiceClassId>(service_class);
    compatibility.compatible = Measurement<bool>::known(true);
    compatibility.provenance = provenance("compatibility-record");
    snapshot.compatibility.push_back(std::move(compatibility));
  }

  void add_latency_measured(std::string_view from, std::string_view to, LatencyStatistic statistic,
                            Measurement<Duration> measured) {
    LatencyRecord record;
    record.reference = id_of<DependencyId>(fresh("latency"));
    record.from_site = id_of<SiteId>(from);
    record.to_site = id_of<SiteId>(to);
    record.statistic = statistic;
    record.latency = measured;
    record.provenance = provenance("latency-record");
    snapshot.latency.push_back(std::move(record));
  }

  void add_latency(std::string_view from, std::string_view to, LatencyStatistic statistic, std::int64_t nanos) {
    add_latency_measured(from, to, statistic, Measurement<Duration>::known(Duration::from_nanos(nanos)));
  }

  /// One obligation needing one primary placement, allowed on one site only, with a
  /// latency requirement against a service that already runs at the peer site.
  Obligation& add_obligation(std::string_view obligation, std::string_view service_class,
                             std::string_view allowed_site, std::string_view peer_site,
                             LatencyStatistic statistic, LatencyDirection direction, std::int64_t bound_nanos) {
    Obligation record;
    record.obligation = id_of<ObligationId>(obligation);
    record.service_class = id_of<ServiceClassId>(service_class);
    record.required_capacity = Quantity::from_units(4);
    record.primary_placements = 1;
    record.allowed_sites.push_back(id_of<SiteId>(allowed_site));
    LatencyRequirement requirement;
    requirement.peer.kind = DependencyEndpoint::Kind::SiteService;
    requirement.peer.site = id_of<SiteId>(peer_site);
    requirement.peer.service_class = id_of<ServiceClassId>(service_class);
    requirement.direction = direction;
    requirement.statistic = statistic;
    requirement.max_latency = Duration::from_nanos(bound_nanos);
    requirement.applies_to = PlacementRole::Primary;
    record.latency_requirements.push_back(requirement);
    request.obligations.push_back(std::move(record));
    return request.obligations.back();
  }

  Obligation& obligation() { return request.obligations.front(); }
};

const ObligationPlacement& sole_obligation(const PlacementPlan& plan) {
  CSP_REQUIRE(plan.obligations.size() == 1);
  return plan.obligations.front();
}

const LatencyResolution& sole_resolution(const PlacementPlan& plan) {
  const ObligationPlacement& obligation = sole_obligation(plan);
  CSP_REQUIRE(obligation.latency.size() == 1);
  return obligation.latency.front();
}

void expect_planned(const PlacementPlan& plan) {
  CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Planned,
                 std::string("the plan was not planned: ") + to_string(plan.outcome));
  CSP_EXPECT(plan_is_applicable(plan));
  const ObligationPlacement& obligation = sole_obligation(plan);
  CSP_EXPECT(obligation.outcome == Tri::Satisfied);
  CSP_EXPECT_EQ(obligation.placements.size(), std::size_t{1});
  CSP_EXPECT(obligation.placements.front().site == id_of<SiteId>("site-a"));
}

void expect_refused(const PlacementPlan& plan, const char* detail) {
  CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Refused,
                 std::string("the plan was not refused: ") + to_string(plan.outcome));
  CSP_EXPECT(!plan_is_applicable(plan));
  CSP_REQUIRE(plan.refusal.has_value());
  CSP_EXPECT_MSG(plan.refusal->code == "csp.rule.latency-bound",
                 "the refusal code was " + plan.refusal->code);
  const ObligationPlacement& obligation = sole_obligation(plan);
  CSP_EXPECT(obligation.outcome == Tri::Violated);
  CSP_EXPECT(obligation.placements.empty());
  CSP_EXPECT_MSG(obligation.detail == detail, "the refusal detail was: " + obligation.detail);
}

void expect_indeterminate(const PlacementPlan& plan, const char* detail) {
  CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Indeterminate,
                 std::string("the plan was not indeterminate: ") + to_string(plan.outcome));
  CSP_EXPECT(!plan_is_applicable(plan));
  CSP_REQUIRE(plan.refusal.has_value());
  CSP_EXPECT_MSG(plan.refusal->code == "csp.rule.latency-bound",
                 "the refusal code was " + plan.refusal->code);
  const ObligationPlacement& obligation = sole_obligation(plan);
  CSP_EXPECT(obligation.outcome == Tri::Indeterminate);
  CSP_EXPECT(obligation.placements.empty());
  CSP_EXPECT_MSG(obligation.detail == detail, "the refusal detail was: " + obligation.detail);
}

const char* kNoPairDetail = "no measurement of this pair exists in the supplied evidence, so the bound is unknown";
const char* kUnusableDetail = "measurements exist for this pair but none of them is usable evidence for this bound";

/// Sites a, b and c. Only site-a can host the obligation, so the plan is a placement at
/// site-a and the other two exist as peers and intermediate hops.
Fleet three_sites() {
  Fleet fleet;
  fleet.add_site("site-a");
  fleet.add_site("site-b");
  fleet.add_site("site-c");
  fleet.add_host("site-a", "payments");
  return fleet;
}

}  // namespace

// ---------------------------------------------------------------------------------
// Direct measurements
// ---------------------------------------------------------------------------------

CSP_TEST(latency, a_direct_measurement_decides_the_bound) {
  Fleet fleet = three_sites();
  fleet.add_latency("site-a", "site-c", LatencyStatistic::Max, 1 * kMillis);
  fleet.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                       LatencyDirection::FromPlacement, 5 * kMillis);

  const Result<PlacementPlan> within = fleet.plan();
  CSP_REQUIRE(within.has_value());
  expect_planned(within.value());
  const LatencyResolution& resolution = sole_resolution(within.value());
  CSP_EXPECT(!resolution.derived);
  CSP_EXPECT(resolution.direction == LatencyDirection::FromPlacement);
  CSP_EXPECT(resolution.statistic == LatencyStatistic::Max);
  CSP_EXPECT_EQ(resolution.measured.nanos(), 1 * kMillis);
  CSP_EXPECT_EQ(resolution.chain.size(), std::size_t{1});
  CSP_EXPECT_EQ(resolution.peer, std::string("site-a to site-c"));

  // Exactly at the bound is within it.
  Fleet exact = three_sites();
  exact.add_latency("site-a", "site-c", LatencyStatistic::Max, 5 * kMillis);
  exact.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                       LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> at_bound = exact.plan();
  CSP_REQUIRE(at_bound.has_value());
  expect_planned(at_bound.value());
  CSP_EXPECT_EQ(sole_resolution(at_bound.value()).measured.nanos(), 5 * kMillis);

  // One nanosecond beyond the bound is a refusal that names the latency rule.
  Fleet beyond = three_sites();
  beyond.add_latency("site-a", "site-c", LatencyStatistic::Max, 5 * kMillis + 1);
  beyond.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                        LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> refused = beyond.plan();
  CSP_REQUIRE(refused.has_value());
  expect_refused(refused.value(), "a direct measurement exceeds the bound");

  // The tightest usable record decides, not the first one read.
  Fleet several = three_sites();
  several.add_latency("site-a", "site-c", LatencyStatistic::Max, 9 * kMillis);
  several.add_latency("site-a", "site-c", LatencyStatistic::Max, 2 * kMillis);
  several.add_latency("site-a", "site-c", LatencyStatistic::Max, 7 * kMillis);
  several.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                         LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> best = several.plan();
  CSP_REQUIRE(best.has_value());
  expect_planned(best.value());
  CSP_EXPECT_EQ(sole_resolution(best.value()).measured.nanos(), 2 * kMillis);
}

CSP_TEST(latency, an_unknown_latency_stays_unknown) {
  // No record at all.
  Fleet absent = three_sites();
  absent.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                        LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> unknown = absent.plan();
  CSP_REQUIRE(unknown.has_value());
  expect_indeterminate(unknown.value(), kNoPairDetail);

  // A record that carries no value is not a fast path.
  Fleet unmeasured = three_sites();
  unmeasured.add_latency_measured("site-a", "site-c", LatencyStatistic::Max,
                                  Measurement<Duration>::unknown());
  unmeasured.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                            LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> no_value = unmeasured.plan();
  CSP_REQUIRE(no_value.has_value());
  expect_indeterminate(no_value.value(), kUnusableDetail);

  // A record for another pair is not a record for this pair.
  Fleet other_pair = three_sites();
  other_pair.add_latency("site-b", "site-c", LatencyStatistic::Max, 1 * kMillis);
  other_pair.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                            LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> elsewhere = other_pair.plan();
  CSP_REQUIRE(elsewhere.has_value());
  expect_indeterminate(elsewhere.value(), kNoPairDetail);
}

// ---------------------------------------------------------------------------------
// Statistic coverage and direction
// ---------------------------------------------------------------------------------

CSP_TEST(latency, statistic_coverage_is_one_directional) {
  // A bound over P99 is satisfied by a maximum measurement: a peak is stricter.
  Fleet peak = three_sites();
  peak.add_latency("site-a", "site-c", LatencyStatistic::Max, 1 * kMillis);
  peak.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::P99,
                      LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> by_peak = peak.plan();
  CSP_REQUIRE(by_peak.has_value());
  expect_planned(by_peak.value());
  const LatencyResolution& peak_resolution = sole_resolution(by_peak.value());
  CSP_EXPECT(!peak_resolution.derived);
  CSP_EXPECT(peak_resolution.statistic == LatencyStatistic::P99);
  CSP_EXPECT_EQ(peak_resolution.measured.nanos(), 1 * kMillis);

  // A bound over the maximum is not satisfied by a tail measurement: a p99 says nothing
  // about the peak.
  Fleet tail = three_sites();
  tail.add_latency("site-a", "site-c", LatencyStatistic::P99, 1 * kMillis);
  tail.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                      LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> by_tail = tail.plan();
  CSP_REQUIRE(by_tail.has_value());
  expect_indeterminate(by_tail.value(), kUnusableDetail);

  // The same coverage rule orders the other pairs of statistics.
  Fleet p95_requirement = three_sites();
  p95_requirement.add_latency("site-a", "site-c", LatencyStatistic::P99, 1 * kMillis);
  p95_requirement.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::P95,
                                 LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> covered = p95_requirement.plan();
  CSP_REQUIRE(covered.has_value());
  expect_planned(covered.value());

  Fleet p99_requirement = three_sites();
  p99_requirement.add_latency("site-a", "site-c", LatencyStatistic::P95, 1 * kMillis);
  p99_requirement.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::P99,
                                 LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> uncovered = p99_requirement.plan();
  CSP_REQUIRE(uncovered.has_value());
  expect_indeterminate(uncovered.value(), kUnusableDetail);
}

CSP_TEST(latency, a_path_is_directed) {
  // The requirement runs from the placement to the peer, and only the opposite pair is
  // on record.
  Fleet reversed = three_sites();
  reversed.add_latency("site-c", "site-a", LatencyStatistic::Max, 1 * kMillis);
  reversed.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                          LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> forward_missing = reversed.plan();
  CSP_REQUIRE(forward_missing.has_value());
  expect_indeterminate(forward_missing.value(), kNoPairDetail);

  // The same record satisfies the requirement that reads in its direction.
  Fleet reverse_requirement = three_sites();
  reverse_requirement.add_latency("site-c", "site-a", LatencyStatistic::Max, 1 * kMillis);
  reverse_requirement.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                                     LatencyDirection::ToPlacement, 5 * kMillis);
  const Result<PlacementPlan> backward_ok = reverse_requirement.plan();
  CSP_REQUIRE(backward_ok.has_value());
  expect_planned(backward_ok.value());
  const LatencyResolution& resolution = sole_resolution(backward_ok.value());
  CSP_EXPECT(resolution.direction == LatencyDirection::ToPlacement);
  CSP_EXPECT_EQ(resolution.peer, std::string("site-c to site-a"));

  // A requirement measured to the placement is not satisfied by a record the other way.
  Fleet forward_only = three_sites();
  forward_only.add_latency("site-a", "site-c", LatencyStatistic::Max, 1 * kMillis);
  forward_only.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                              LatencyDirection::ToPlacement, 5 * kMillis);
  const Result<PlacementPlan> reversed_missing = forward_only.plan();
  CSP_REQUIRE(reversed_missing.has_value());
  expect_indeterminate(reversed_missing.value(), kNoPairDetail);

  // Both directions on record: each requirement reads its own.
  Fleet both = three_sites();
  both.add_latency("site-a", "site-c", LatencyStatistic::Max, 1 * kMillis);
  both.add_latency("site-c", "site-a", LatencyStatistic::Max, 9 * kMillis);
  both.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                      LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> measured = both.plan();
  CSP_REQUIRE(measured.has_value());
  expect_planned(measured.value());
  CSP_EXPECT_EQ(sole_resolution(measured.value()).measured.nanos(), 1 * kMillis);
}

// ---------------------------------------------------------------------------------
// Derived bounds
// ---------------------------------------------------------------------------------

CSP_TEST(latency, a_chain_of_maxima_bounds_the_path) {
  // Two hops and no direct record.
  Fleet fleet = three_sites();
  fleet.add_latency("site-a", "site-b", LatencyStatistic::Max, 2 * kMillis);
  fleet.add_latency("site-b", "site-c", LatencyStatistic::Max, 3 * kMillis);
  fleet.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                       LatencyDirection::FromPlacement, 5 * kMillis);
  const Limits limits;
  CSP_EXPECT_EQ(limits.max_derived_hops, std::size_t{4});

  const Result<PlacementPlan> derived = fleet.plan();
  CSP_REQUIRE(derived.has_value());
  expect_planned(derived.value());
  const LatencyResolution& resolution = sole_resolution(derived.value());
  CSP_EXPECT(resolution.derived);
  CSP_EXPECT_EQ(resolution.measured.nanos(), 5 * kMillis);
  // The whole chain is recorded, in path order: the first hop, then the second.
  CSP_REQUIRE(fleet.snapshot.latency.size() == 2);
  CSP_REQUIRE(resolution.chain.size() == 2);
  CSP_EXPECT(resolution.chain[0] == fleet.snapshot.latency[0].reference);
  CSP_EXPECT(resolution.chain[1] == fleet.snapshot.latency[1].reference);

  // The same chain beyond the bound is a refusal that names the chain.
  Fleet too_slow = three_sites();
  too_slow.add_latency("site-a", "site-b", LatencyStatistic::Max, 2 * kMillis);
  too_slow.add_latency("site-b", "site-c", LatencyStatistic::Max, 4 * kMillis);
  too_slow.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                          LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> refused = too_slow.plan();
  CSP_REQUIRE(refused.has_value());
  expect_refused(refused.value(), "a chain of maximum-statistic measurements exceeds the requirement");

  // A direct record is preferred to a shorter derived path.
  Fleet direct = three_sites();
  direct.add_latency("site-a", "site-c", LatencyStatistic::Max, 4 * kMillis);
  direct.add_latency("site-a", "site-b", LatencyStatistic::Max, 1 * kMillis);
  direct.add_latency("site-b", "site-c", LatencyStatistic::Max, 1 * kMillis);
  direct.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                        LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> measured = direct.plan();
  CSP_REQUIRE(measured.has_value());
  expect_planned(measured.value());
  const LatencyResolution& direct_resolution = sole_resolution(measured.value());
  CSP_EXPECT(!direct_resolution.derived);
  CSP_EXPECT_EQ(direct_resolution.measured.nanos(), 4 * kMillis);
  CSP_EXPECT_EQ(direct_resolution.chain.size(), std::size_t{1});
}

CSP_TEST(latency, a_chain_is_not_composed_from_percentiles) {
  // Only percentile hops exist: a chain of tails is not a bound.
  Fleet fleet = three_sites();
  fleet.add_latency("site-a", "site-b", LatencyStatistic::P99, 2 * kMillis);
  fleet.add_latency("site-b", "site-c", LatencyStatistic::P99, 3 * kMillis);
  fleet.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                       LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> refused_to_compose = fleet.plan();
  CSP_REQUIRE(refused_to_compose.has_value());
  expect_indeterminate(refused_to_compose.value(), kNoPairDetail);

  // The same two hops as maxima do compose, which is the control.
  Fleet maxima = three_sites();
  maxima.add_latency("site-a", "site-b", LatencyStatistic::Max, 2 * kMillis);
  maxima.add_latency("site-b", "site-c", LatencyStatistic::Max, 3 * kMillis);
  maxima.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                        LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> composed = maxima.plan();
  CSP_REQUIRE(composed.has_value());
  expect_planned(composed.value());
  CSP_EXPECT(sole_resolution(composed.value()).derived);

  // One percentile hop in an otherwise maximal chain is enough to stop the derivation.
  Fleet mixed = three_sites();
  mixed.add_latency("site-a", "site-b", LatencyStatistic::Max, 2 * kMillis);
  mixed.add_latency("site-b", "site-c", LatencyStatistic::P99, 3 * kMillis);
  mixed.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                       LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> incomplete = mixed.plan();
  CSP_REQUIRE(incomplete.has_value());
  expect_indeterminate(incomplete.value(), kNoPairDetail);

  // The derived chain follows the same coverage rule as a single record: a chain of
  // maxima bounds every statistic, so it covers a requirement expressed over a
  // percentile, exactly as a Max measurement does.
  Fleet peak_chain = three_sites();
  peak_chain.add_latency("site-a", "site-b", LatencyStatistic::Max, 2 * kMillis);
  peak_chain.add_latency("site-b", "site-c", LatencyStatistic::Max, 3 * kMillis);
  peak_chain.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::P99,
                            LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> tail_bound = peak_chain.plan();
  CSP_REQUIRE(tail_bound.has_value());
  expect_planned(tail_bound.value());
  CSP_EXPECT(sole_resolution(tail_bound.value()).derived);
  CSP_EXPECT_EQ(sole_resolution(tail_bound.value()).measured.nanos(), 5 * kMillis);
}

CSP_TEST(latency, deriving_a_bound_needs_a_policy_that_allows_it) {
  Fleet fleet = three_sites();
  fleet.add_latency("site-a", "site-b", LatencyStatistic::Max, 2 * kMillis);
  fleet.add_latency("site-b", "site-c", LatencyStatistic::Max, 3 * kMillis);
  fleet.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                       LatencyDirection::FromPlacement, 5 * kMillis);

  fleet.policy.allow_derived_latency_bounds = false;
  const Result<PlacementPlan> refused_to_derive = fleet.plan();
  CSP_REQUIRE(refused_to_derive.has_value());
  expect_indeterminate(refused_to_derive.value(), kNoPairDetail);

  // A direct record still decides when derivation is off.
  Fleet direct = three_sites();
  direct.add_latency("site-a", "site-c", LatencyStatistic::Max, 1 * kMillis);
  direct.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                        LatencyDirection::FromPlacement, 5 * kMillis);
  direct.policy.allow_derived_latency_bounds = false;
  const Result<PlacementPlan> measured = direct.plan();
  CSP_REQUIRE(measured.has_value());
  expect_planned(measured.value());
  CSP_EXPECT(!sole_resolution(measured.value()).derived);
}

CSP_TEST(latency, a_path_longer_than_the_hop_bound_is_indeterminate) {
  // Three hops: a to b to c to d.
  Fleet fleet;
  fleet.add_site("site-a");
  fleet.add_site("site-b");
  fleet.add_site("site-c");
  fleet.add_site("site-d");
  fleet.add_host("site-a", "payments");
  fleet.add_latency("site-a", "site-b", LatencyStatistic::Max, 1 * kMillis);
  fleet.add_latency("site-b", "site-c", LatencyStatistic::Max, 1 * kMillis);
  fleet.add_latency("site-c", "site-d", LatencyStatistic::Max, 1 * kMillis);
  fleet.add_obligation("obligation-1", "payments", "site-a", "site-d", LatencyStatistic::Max,
                       LatencyDirection::FromPlacement, 5 * kMillis);

  Limits two_hops;
  two_hops.max_derived_hops = 2;
  const Result<PlacementPlan> bounded = fleet.plan_with(two_hops);
  CSP_REQUIRE(bounded.has_value());
  expect_indeterminate(bounded.value(), kNoPairDetail);

  // The hop count may also be narrowed by the policy, and is then the one that applies.
  fleet.policy.max_derived_hops = 2;
  const Result<PlacementPlan> narrowed = fleet.plan();
  CSP_REQUIRE(narrowed.has_value());
  expect_indeterminate(narrowed.value(), kNoPairDetail);

  // With room for three hops the same evidence decides the bound.
  fleet.policy.max_derived_hops = 0;
  Limits three_hops;
  three_hops.max_derived_hops = 3;
  const Result<PlacementPlan> allowed = fleet.plan_with(three_hops);
  CSP_REQUIRE(allowed.has_value());
  expect_planned(allowed.value());
  const LatencyResolution& resolution = sole_resolution(allowed.value());
  CSP_EXPECT(resolution.derived);
  CSP_EXPECT_EQ(resolution.measured.nanos(), 3 * kMillis);
  CSP_EXPECT_EQ(resolution.chain.size(), std::size_t{3});
}

// ---------------------------------------------------------------------------------
// Cycles and overflow
// ---------------------------------------------------------------------------------

CSP_TEST(latency, a_cycle_does_not_change_the_answer) {
  // The acyclic reading.
  Fleet acyclic = three_sites();
  acyclic.add_latency("site-a", "site-b", LatencyStatistic::Max, 2 * kMillis);
  acyclic.add_latency("site-b", "site-c", LatencyStatistic::Max, 3 * kMillis);
  acyclic.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                         LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> plain = acyclic.plan();
  CSP_REQUIRE(plain.has_value());
  expect_planned(plain.value());
  CSP_EXPECT(sole_resolution(plain.value()).derived);

  // The same reading with every edge also recorded in the opposite direction.
  Fleet cyclic = three_sites();
  cyclic.add_latency("site-a", "site-b", LatencyStatistic::Max, 2 * kMillis);
  cyclic.add_latency("site-b", "site-a", LatencyStatistic::Max, 1 * kMillis);
  cyclic.add_latency("site-b", "site-c", LatencyStatistic::Max, 3 * kMillis);
  cyclic.add_latency("site-c", "site-b", LatencyStatistic::Max, 1 * kMillis);
  cyclic.add_latency("site-a", "site-a", LatencyStatistic::Max, 0);
  cyclic.add_latency("site-c", "site-a", LatencyStatistic::Max, 1 * kMillis);
  cyclic.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                        LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> with_cycle = cyclic.plan();
  CSP_REQUIRE(with_cycle.has_value());
  expect_planned(with_cycle.value());
  const LatencyResolution& cyclic_resolution = sole_resolution(with_cycle.value());
  CSP_EXPECT(cyclic_resolution.derived);
  CSP_EXPECT_EQ(cyclic_resolution.measured.nanos(), 5 * kMillis);
  CSP_EXPECT_EQ(cyclic_resolution.chain.size(), std::size_t{2});
  // The answer is the same answer as the acyclic reading. The canonical bytes are not
  // compared: the plan reports how many nodes the search explored, which is a statement
  // about the work the evidence caused rather than about the arrangement it produced.
  CSP_EXPECT(with_cycle.value().outcome == plain.value().outcome);
  const ObligationPlacement& cyclic_obligation = sole_obligation(with_cycle.value());
  const ObligationPlacement& plain_obligation = sole_obligation(plain.value());
  CSP_EXPECT_EQ(cyclic_obligation.placements.front().site.value(),
                plain_obligation.placements.front().site.value());
  CSP_REQUIRE(cyclic.snapshot.latency.size() == 6);
  CSP_REQUIRE(cyclic_resolution.chain.size() == 2);
  // The path is the acyclic reading's two hops, named by this snapshot's own records:
  // a to b, then b to c. The extra records of the cycle are not part of the answer.
  CSP_EXPECT(cyclic_resolution.chain[0] == cyclic.snapshot.latency[0].reference);
  CSP_EXPECT(cyclic_resolution.chain[1] == cyclic.snapshot.latency[2].reference);
  CSP_EXPECT(!(cyclic_resolution.chain[1] == cyclic.snapshot.latency[3].reference));
  CSP_EXPECT(sole_resolution(plain.value()).chain[0] == acyclic.snapshot.latency[0].reference);
  CSP_EXPECT(sole_resolution(plain.value()).chain[1] == acyclic.snapshot.latency[1].reference);

  // A direct record still wins over a shorter cycle through the intermediate site.
  Fleet direct_with_cycle = three_sites();
  direct_with_cycle.add_latency("site-a", "site-c", LatencyStatistic::Max, 4 * kMillis);
  direct_with_cycle.add_latency("site-a", "site-b", LatencyStatistic::Max, 1 * kMillis);
  direct_with_cycle.add_latency("site-b", "site-a", LatencyStatistic::Max, 1 * kMillis);
  direct_with_cycle.add_latency("site-b", "site-c", LatencyStatistic::Max, 1 * kMillis);
  direct_with_cycle.add_latency("site-c", "site-b", LatencyStatistic::Max, 1 * kMillis);
  direct_with_cycle.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                                   LatencyDirection::FromPlacement, 5 * kMillis);
  const Result<PlacementPlan> direct = direct_with_cycle.plan();
  CSP_REQUIRE(direct.has_value());
  expect_planned(direct.value());
  CSP_EXPECT(!sole_resolution(direct.value()).derived);
  CSP_EXPECT_EQ(sole_resolution(direct.value()).measured.nanos(), 4 * kMillis);
}

CSP_TEST(latency, an_interval_that_would_overflow_is_not_adopted) {
  // The first hop is the largest interval a duration can hold. Summing it with the
  // second hop does not fit, so the chain is not adopted and the bound stays unknown.
  Fleet fleet = three_sites();
  fleet.add_latency("site-a", "site-b", LatencyStatistic::Max, kInt64Max);
  fleet.add_latency("site-b", "site-c", LatencyStatistic::Max, 1 * kMillis);
  fleet.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                       LatencyDirection::FromPlacement, kInt64Max);
  const Result<PlacementPlan> overflowed = fleet.plan();
  CSP_REQUIRE(overflowed.has_value());
  expect_indeterminate(overflowed.value(), kNoPairDetail);

  // The control: the same first hop alone, against a bound that can hold it, is a
  // direct measurement and is adopted exactly.
  Fleet direct = three_sites();
  direct.add_latency("site-a", "site-c", LatencyStatistic::Max, kInt64Max);
  direct.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                        LatencyDirection::FromPlacement, kInt64Max);
  const Result<PlacementPlan> measured = direct.plan();
  CSP_REQUIRE(measured.has_value());
  expect_planned(measured.value());
  CSP_EXPECT_EQ(sole_resolution(measured.value()).measured.nanos(), kInt64Max);

  // Two hops that do fit are still summed exactly.
  Fleet fits = three_sites();
  fits.add_latency("site-a", "site-b", LatencyStatistic::Max, kInt64Max / 2);
  fits.add_latency("site-b", "site-c", LatencyStatistic::Max, kInt64Max / 4);
  fits.add_obligation("obligation-1", "payments", "site-a", "site-c", LatencyStatistic::Max,
                      LatencyDirection::FromPlacement, kInt64Max);
  const Result<PlacementPlan> summed = fits.plan();
  CSP_REQUIRE(summed.has_value());
  expect_planned(summed.value());
  CSP_EXPECT_EQ(sole_resolution(summed.value()).measured.nanos(), kInt64Max / 2 + kInt64Max / 4);
}
