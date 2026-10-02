// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Placement: the planner as a whole, over a small hand-built fleet.
//
// Each case builds the least evidence that isolates one rule, states the outcome the
// rule is supposed to produce, and names the rule detail when the site is refused.
// Where a case is randomized it names its seed in the failure detail.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
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
constexpr std::int64_t kNanosPerSecond = 1000000000LL;

/// The harness's CSP_EXPECT_CATEGORY substitutes its second parameter into the member
/// call `error().category()`, so a category constant cannot be passed through it.
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

/// A request, a snapshot, and a policy that agree with each other, plus the instant the
/// caller asserts. Everything a case needs is added through the methods below, so a
/// case reads as the difference between one fleet and another.
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
    request.request = id_of<RequestId>("req-1");
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
    record.authority = id_of<AuthorityId>("authority-1");
    record.authority_generation = Generation::from_value(9);
    record.observed_at = Instant::from_nanos(kObserved);
    return record;
  }

  SiteRecord& add_site(std::string_view site) {
    return add_site_measured(site, Measurement<MaintenanceState>::known(MaintenanceState::Operational),
                             std::string_view{});
  }

  SiteRecord& add_site_measured(std::string_view site, Measurement<MaintenanceState> maintenance,
                                std::string_view jurisdiction) {
    SiteRecord record;
    record.site = id_of<SiteId>(site);
    if (!jurisdiction.empty()) {
      record.jurisdiction = id_of<JurisdictionId>(jurisdiction);
    }
    record.maintenance = maintenance;
    record.provenance = provenance("site");
    snapshot.sites.push_back(std::move(record));
    return snapshot.sites.back();
  }

  void add_capacity_measured(std::string_view site, std::string_view service_class,
                             Measurement<Quantity> available,
                             CapacityKind kind = CapacityKind::Commitment) {
    CapacityRecord record;
    record.reference = id_of<CapacityRefId>(fresh("capacity"));
    record.site = id_of<SiteId>(site);
    record.service_class = id_of<ServiceClassId>(service_class);
    record.kind = kind;
    record.available = available;
    record.provenance = provenance("capacity-record");
    snapshot.capacity.push_back(std::move(record));
  }

  void add_capacity(std::string_view site, std::string_view service_class, std::int64_t units,
                    CapacityKind kind = CapacityKind::Commitment) {
    add_capacity_measured(site, service_class, Measurement<Quantity>::known(Quantity::from_units(units)), kind);
  }

  void add_compatibility_measured(std::string_view site, std::string_view service_class,
                                  Measurement<bool> compatible) {
    CompatibilityRecord record;
    record.reference = id_of<EvidenceId>(fresh("compatibility"));
    record.site = id_of<SiteId>(site);
    record.service_class = id_of<ServiceClassId>(service_class);
    record.compatible = compatible;
    record.provenance = provenance("compatibility-record");
    snapshot.compatibility.push_back(std::move(record));
  }

  void add_compatibility(std::string_view site, std::string_view service_class, bool compatible) {
    add_compatibility_measured(site, service_class, Measurement<bool>::known(compatible));
  }

  void add_cost_risk(std::string_view site, std::string_view service_class, Measurement<Quantity> cost,
                     Measurement<std::int64_t> risk) {
    CostRiskRecord record;
    record.reference = id_of<EvidenceId>(fresh("cost"));
    record.site = id_of<SiteId>(site);
    if (!service_class.empty()) {
      record.service_class = id_of<ServiceClassId>(service_class);
    }
    record.cost_per_unit = cost;
    record.risk_per_mille = risk;
    record.provenance = provenance("cost-record");
    snapshot.cost_risk.push_back(std::move(record));
  }

  void add_cost(std::string_view site, std::string_view service_class, std::int64_t cost) {
    add_cost_risk(site, service_class, Measurement<Quantity>::known(Quantity::from_units(cost)),
                  Measurement<std::int64_t>::known(500));
  }

  void add_recovery_measured(std::string_view site, std::string_view service_class, Measurement<bool> can_host,
                             Measurement<Duration> rto) {
    RecoveryRecord record;
    record.reference = id_of<RecoveryRefId>(fresh("recovery"));
    record.site = id_of<SiteId>(site);
    record.service_class = id_of<ServiceClassId>(service_class);
    record.can_host_recovery = can_host;
    record.achievable_rto = rto;
    record.provenance = provenance("recovery-record");
    snapshot.recovery.push_back(std::move(record));
  }

  void add_domain(std::string_view domain, DomainKind kind, std::string_view parent = {}) {
    FailureDomainRecord record;
    record.domain = id_of<FailureDomainId>(domain);
    record.kind = kind;
    if (!parent.empty()) {
      record.parent = id_of<FailureDomainId>(parent);
    }
    record.provenance = provenance("domain");
    snapshot.failure_domains.push_back(std::move(record));
  }

  void add_assignment(std::string_view site, std::string_view domain) {
    DomainAssignment record;
    record.site = id_of<SiteId>(site);
    record.domain = id_of<FailureDomainId>(domain);
    record.provenance = provenance("assignment");
    snapshot.domain_assignments.push_back(std::move(record));
  }

  void add_alias(std::string_view domain, std::string_view alias_of) {
    DomainAliasRecord record;
    record.domain = id_of<FailureDomainId>(domain);
    record.alias_of = id_of<FailureDomainId>(alias_of);
    record.provenance = provenance("alias");
    snapshot.domain_aliases.push_back(std::move(record));
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

  void add_latency(std::string_view from, std::string_view to, LatencyStatistic statistic,
                   std::int64_t nanos) {
    add_latency_measured(from, to, statistic, Measurement<Duration>::known(Duration::from_nanos(nanos)));
  }

  Obligation& add_obligation(std::string_view obligation, std::string_view service_class, std::int64_t capacity,
                             std::uint32_t primary = 1, std::uint32_t recovery = 0) {
    Obligation record;
    record.obligation = id_of<ObligationId>(obligation);
    record.service_class = id_of<ServiceClassId>(service_class);
    record.required_capacity = Quantity::from_units(capacity);
    record.primary_placements = primary;
    record.recovery_placements = recovery;
    request.obligations.push_back(std::move(record));
    return request.obligations.back();
  }

  Obligation& obligation() { return request.obligations.front(); }
};

/// One site that can host one unit of one service class, with one obligation asking for
/// it: the smallest fleet that produces a plan.
Fleet one_site_fleet() {
  Fleet fleet;
  fleet.add_site("site-a");
  fleet.add_capacity("site-a", "payments", 10);
  fleet.add_compatibility("site-a", "payments", true);
  fleet.add_obligation("obligation-1", "payments", 4);
  return fleet;
}

/// Three sites, four evidence collections, one separation requirement and one latency
/// requirement: enough moving parts that an order-dependent planner would differ.
Fleet rich_fleet() {
  Fleet fleet;
  fleet.add_site_measured("site-a", Measurement<MaintenanceState>::known(MaintenanceState::Operational),
                          "region-eu");
  fleet.add_site("site-b");
  fleet.add_site("site-c");

  fleet.add_domain("feed-1", DomainKind::Power);
  fleet.add_domain("feed-2", DomainKind::Power);
  fleet.add_domain("region-1", DomainKind::Geography);
  fleet.add_assignment("site-a", "feed-1");
  fleet.add_assignment("site-b", "feed-2");
  fleet.add_assignment("site-c", "region-1");
  fleet.add_alias("feed-one", "feed-1");

  const char* kSites[] = {"site-a", "site-b", "site-c"};
  for (const char* site : kSites) {
    fleet.add_capacity(site, "payments", 10);
    fleet.add_capacity(site, "payments", 2, CapacityKind::Offer);
    fleet.add_compatibility(site, "payments", true);
  }
  fleet.add_cost("site-a", "payments", 30);
  fleet.add_cost("site-b", "payments", 10);
  fleet.add_cost("site-c", "payments", 20);

  fleet.add_latency("site-a", "site-c", LatencyStatistic::Max, 1000000);
  fleet.add_latency("site-b", "site-c", LatencyStatistic::Max, 1000000);
  fleet.add_latency("site-c", "site-a", LatencyStatistic::Max, 1000000);
  fleet.add_latency("site-a", "site-c", LatencyStatistic::P99, 999999);

  Obligation& obligation = fleet.add_obligation("obligation-1", "payments", 4);
  fleet.request.preferences.objectives.push_back(Preferences::Objective::MinimiseCost);
  SeparationRequirement separation;
  separation.group = SeparationGroup::All;
  separation.separated_kinds.push_back(DomainKind::Power);
  obligation.separations.push_back(separation);
  LatencyRequirement latency;
  latency.peer.kind = DependencyEndpoint::Kind::SiteService;
  latency.peer.site = id_of<SiteId>("site-c");
  latency.peer.service_class = id_of<ServiceClassId>("payments");
  latency.direction = LatencyDirection::FromPlacement;
  latency.statistic = LatencyStatistic::Max;
  latency.max_latency = Duration::from_nanos(5000000);
  latency.applies_to = PlacementRole::Primary;
  obligation.latency_requirements.push_back(latency);
  return fleet;
}

template <class T>
void shuffle_with(std::vector<T>& values, csp_test::SeededRandom& random) {
  for (std::size_t size = values.size(); size > 1; --size) {
    const std::size_t other = static_cast<std::size_t>(random.below(size));
    std::swap(values[size - 1], values[other]);
  }
}

void shuffle_evidence(Fleet& fleet, csp_test::SeededRandom& random) {
  shuffle_with(fleet.snapshot.sites, random);
  shuffle_with(fleet.snapshot.failure_domains, random);
  shuffle_with(fleet.snapshot.domain_assignments, random);
  shuffle_with(fleet.snapshot.domain_aliases, random);
  shuffle_with(fleet.snapshot.capacity, random);
  shuffle_with(fleet.snapshot.latency, random);
  shuffle_with(fleet.snapshot.recovery, random);
  shuffle_with(fleet.snapshot.compatibility, random);
  shuffle_with(fleet.snapshot.cost_risk, random);
}

std::string canonical_of(const PlacementPlan& plan) {
  const Result<std::string> bytes = plan_canonical_bytes(plan);
  return bytes.has_value() ? bytes.value() : std::string();
}

std::string render_refusal(const PlacementPlan& plan) {
  if (!plan.refusal.has_value()) {
    return "no refusal";
  }
  return plan.refusal->code + ": " + plan.refusal->detail;
}

const ObligationPlacement& sole_obligation(const PlacementPlan& plan) {
  CSP_REQUIRE(plan.obligations.size() == 1);
  return plan.obligations.front();
}

/// The published rule list is the contract a reader of a trace relies on, so a case that
/// names a rule checks that the rule is published as well as that its detail appeared.
bool rule_is_published(std::string_view rule) {
  const std::vector<std::string>& tokens = Planner::rule_tokens();
  return std::find(tokens.begin(), tokens.end(), rule) != tokens.end();
}

/// The plan named a site for every placement it promised.
void expect_planned(const PlacementPlan& plan, std::size_t placements) {
  CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Planned, "the plan was not planned: " + render_refusal(plan));
  CSP_EXPECT(plan_is_applicable(plan));
  CSP_EXPECT(!plan.refusal.has_value());
  const ObligationPlacement& obligation = sole_obligation(plan);
  CSP_EXPECT_MSG(obligation.outcome == Tri::Satisfied,
                 "the obligation was not satisfied: " + obligation.detail);
  CSP_EXPECT_MSG(obligation.placements.size() == placements,
                 "the plan selected " + std::to_string(obligation.placements.size()) + " placements, not " +
                     std::to_string(placements));
  CSP_EXPECT(obligation.refusal_code.empty());
}

/// The planner proved that no arrangement satisfies the request as stated, named the
/// rule that decided it, and published that rule.
void expect_refused(const PlacementPlan& plan, const char* rule, const char* detail) {
  CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Refused,
                 std::string("the plan was not refused: ") + to_string(plan.outcome));
  CSP_EXPECT_MSG(rule_is_published(rule), std::string("the rule ") + rule + " is not published");
  CSP_EXPECT(!plan_is_applicable(plan));
  CSP_REQUIRE(plan.refusal.has_value());
  CSP_EXPECT_MSG(plan.refusal->code == rule, "the refusal code was " + plan.refusal->code);
  CSP_EXPECT(plan.refusal->category == ErrorCategory::Unavailable);
  const ObligationPlacement& obligation = sole_obligation(plan);
  CSP_EXPECT(obligation.outcome == Tri::Violated);
  CSP_EXPECT(obligation.placements.empty());
  CSP_EXPECT_MSG(obligation.refusal_code == rule,
                 "the obligation refusal code was " + obligation.refusal_code);
  CSP_EXPECT_MSG(obligation.detail == detail, "the refusal detail was: " + obligation.detail);
}

/// The planner could not decide, which is not the same answer as a refusal.
void expect_indeterminate(const PlacementPlan& plan, const char* rule, const char* detail) {
  CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Indeterminate,
                 std::string("the plan was not indeterminate: ") + to_string(plan.outcome));
  CSP_EXPECT_MSG(rule_is_published(rule), std::string("the rule ") + rule + " is not published");
  CSP_EXPECT(!plan_is_applicable(plan));
  CSP_REQUIRE(plan.refusal.has_value());
  CSP_EXPECT_MSG(plan.refusal->code == rule, "the refusal code was " + plan.refusal->code);
  CSP_EXPECT(plan.refusal->category == ErrorCategory::Indeterminate);
  const ObligationPlacement& obligation = sole_obligation(plan);
  CSP_EXPECT(obligation.outcome == Tri::Indeterminate);
  CSP_EXPECT(obligation.placements.empty());
  CSP_EXPECT_MSG(obligation.refusal_code == rule,
                 "the obligation refusal code was " + obligation.refusal_code);
  CSP_EXPECT_MSG(obligation.detail == detail, "the refusal detail was: " + obligation.detail);
}

}  // namespace

// ---------------------------------------------------------------------------------
// The minimal fleet
// ---------------------------------------------------------------------------------

CSP_TEST(placement, minimal_fleet_places_one_obligation) {
  Fleet fleet;
  fleet.add_site("site-a");
  fleet.add_capacity("site-a", "payments", 10);
  fleet.add_compatibility("site-a", "payments", true);
  fleet.add_obligation("obligation-1", "payments", 4);

  const Result<PlacementPlan> first = fleet.plan();
  CSP_REQUIRE(first.has_value());
  const PlacementPlan& plan = first.value();
  CSP_EXPECT(plan.outcome == PlanOutcome::Planned);
  CSP_EXPECT(plan_is_applicable(plan));
  CSP_EXPECT(!plan.digest.is_zero());
  CSP_EXPECT(plan.digest == plan_compute_digest(plan));
  CSP_EXPECT(!plan.plan.value().empty());
  CSP_EXPECT(!plan.refusal.has_value());
  CSP_EXPECT(plan.nodes_explored > 0);
  CSP_EXPECT(!plan.search_exhausted);
  expect_planned(plan, 1);

  const SitePlacement& placement = sole_obligation(plan).placements.front();
  CSP_EXPECT(placement.site == id_of<SiteId>("site-a"));
  CSP_EXPECT(placement.role == PlacementRole::Primary);
  CSP_EXPECT_EQ(placement.index, std::uint32_t{0});
  CSP_EXPECT_EQ(placement.capacity_required.units(), std::int64_t{4});
  CSP_EXPECT_EQ(placement.capacity.references.size(), std::size_t{1});
  CSP_EXPECT_EQ(placement.capacity.evidenced_total.units(), std::int64_t{10});
  CSP_EXPECT(!placement.capacity.includes_offers);
  CSP_EXPECT(placement.domains.empty());
  CSP_EXPECT(!placement.jurisdiction.valid());

  // The envelope records what the caller asserted and nothing it did not.
  CSP_EXPECT_EQ(plan.envelope.evaluated_at.nanos(), kEvaluated);
  CSP_EXPECT_EQ(plan.envelope.oldest_evidence_observed_at.nanos(), kObserved);
  CSP_EXPECT_EQ(plan.envelope.request_generation.value(), std::uint64_t{3});
  CSP_EXPECT_EQ(plan.envelope.policy_generation.value(), std::uint64_t{5});
  CSP_EXPECT_EQ(plan.envelope.evidence_generation.value(), std::uint64_t{11});
  CSP_EXPECT(plan.envelope.valid_until.nanos() > kEvaluated);
  CSP_EXPECT(!plan.envelope.revalidate_when.empty());

  // The same inputs twice produce the same identity and the same canonical bytes, and a
  // different Planner object agrees.
  const Result<PlacementPlan> second = fleet.plan();
  CSP_REQUIRE(second.has_value());
  CSP_EXPECT(second.value().plan == plan.plan);
  CSP_EXPECT(second.value().digest == plan.digest);
  CSP_EXPECT_EQ(canonical_of(second.value()), canonical_of(plan));
  const Planner other;
  const Result<PlacementPlan> third = other.plan(fleet.request, fleet.snapshot, fleet.policy, fleet.context);
  CSP_REQUIRE(third.has_value());
  CSP_EXPECT(third.value().plan == plan.plan);
  CSP_EXPECT_EQ(canonical_of(third.value()), canonical_of(plan));
}

CSP_TEST(placement, ingestion_order_does_not_change_the_plan) {
  const Fleet fleet = rich_fleet();
  const Result<PlacementPlan> reference = fleet.plan();
  CSP_REQUIRE(reference.has_value());
  CSP_REQUIRE(reference.value().outcome == PlanOutcome::Planned);
  const std::string reference_bytes = canonical_of(reference.value());
  CSP_EXPECT(!reference_bytes.empty());

  csp_test::SeededRandom random(0x5EED0001ULL);
  for (int round = 0; round < 12; ++round) {
    Fleet shuffled = fleet;
    shuffle_evidence(shuffled, random);
    const Result<PlacementPlan> outcome = shuffled.plan();
    const std::string detail = "seed " + std::to_string(random.seed()) + ", round " +
                               std::to_string(round) + ": the canonical plan changed with ingestion order";
    CSP_REQUIRE(outcome.has_value());
    CSP_EXPECT_MSG(canonical_of(outcome.value()) == reference_bytes, detail);
    CSP_EXPECT_MSG(outcome.value().plan == reference.value().plan, detail);
    CSP_EXPECT_MSG(outcome.value().digest == reference.value().digest, detail);
  }

  // The same evidence in one fixed shuffled order twice is still one answer.
  csp_test::SeededRandom repeated(0x5EED0002ULL);
  Fleet once = fleet;
  Fleet twice = fleet;
  shuffle_evidence(once, repeated);
  shuffle_evidence(twice, repeated);
  const Result<PlacementPlan> first = once.plan();
  const Result<PlacementPlan> second = twice.plan();
  CSP_REQUIRE(first.has_value());
  CSP_REQUIRE(second.has_value());
  CSP_EXPECT_EQ(canonical_of(first.value()), canonical_of(second.value()));
}

// ---------------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------------

CSP_TEST(placement, capacity_separates_placement_refusal_and_indeterminacy) {
  // Enough evidence places.
  Fleet enough;
  enough.add_site("site-a");
  enough.add_capacity("site-a", "payments", 10);
  enough.add_compatibility("site-a", "payments", true);
  enough.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> placed = enough.plan();
  CSP_REQUIRE(placed.has_value());
  expect_planned(placed.value(), 1);
  CSP_EXPECT_EQ(sole_obligation(placed.value()).placements.front().capacity.evidenced_total.units(),
                std::int64_t{10});

  // Exactly enough is enough.
  Fleet exact;
  exact.add_site("site-a");
  exact.add_capacity("site-a", "payments", 4);
  exact.add_compatibility("site-a", "payments", true);
  exact.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> at_boundary = exact.plan();
  CSP_REQUIRE(at_boundary.has_value());
  expect_planned(at_boundary.value(), 1);

  // A definite shortfall is a refusal that names the capacity rule.
  Fleet short_fleet;
  short_fleet.add_site("site-a");
  short_fleet.add_capacity("site-a", "payments", 3);
  short_fleet.add_compatibility("site-a", "payments", true);
  short_fleet.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> refused = short_fleet.plan();
  CSP_REQUIRE(refused.has_value());
  CSP_EXPECT(rule_is_published("csp.rule.capacity-evidence"));
  expect_refused(refused.value(), "csp.rule.capacity-evidence",
                 "the capacity reported here is below what this obligation requires");

  // A measurement nobody supplied is not a shortfall: the plan is indeterminate.
  Fleet unknown;
  unknown.add_site("site-a");
  unknown.add_capacity_measured("site-a", "payments", Measurement<Quantity>::unknown());
  unknown.add_compatibility("site-a", "payments", true);
  unknown.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> undecided = unknown.plan();
  CSP_REQUIRE(undecided.has_value());
  expect_indeterminate(undecided.value(), "csp.rule.capacity-evidence",
                       "the capacity reported here is below the requirement and the evidence is incomplete, "
                       "so the shortfall is not established");

  // No capacity record at all is the same answer, for the same reason.
  Fleet absent;
  absent.add_site("site-a");
  absent.add_compatibility("site-a", "payments", true);
  absent.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> no_evidence = absent.plan();
  CSP_REQUIRE(no_evidence.has_value());
  expect_indeterminate(no_evidence.value(), "csp.rule.capacity-evidence",
                       "the capacity reported here is below the requirement and the evidence is incomplete, "
                       "so the shortfall is not established");

  // Two sites, one short and one sufficient: the sufficient one is chosen.
  Fleet two_sites;
  two_sites.add_site("site-a");
  two_sites.add_site("site-b");
  two_sites.add_capacity("site-a", "payments", 1);
  two_sites.add_capacity("site-b", "payments", 10);
  two_sites.add_compatibility("site-a", "payments", true);
  two_sites.add_compatibility("site-b", "payments", true);
  two_sites.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> chosen = two_sites.plan();
  CSP_REQUIRE(chosen.has_value());
  expect_planned(chosen.value(), 1);
  CSP_EXPECT(sole_obligation(chosen.value()).placements.front().site == id_of<SiteId>("site-b"));

  // Two short sites: the refusal is definite because both readings are complete.
  Fleet both_short;
  both_short.add_site("site-a");
  both_short.add_site("site-b");
  both_short.add_capacity("site-a", "payments", 1);
  both_short.add_capacity("site-b", "payments", 2);
  both_short.add_compatibility("site-a", "payments", true);
  both_short.add_compatibility("site-b", "payments", true);
  both_short.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> refused_both = both_short.plan();
  CSP_REQUIRE(refused_both.has_value());
  expect_refused(refused_both.value(), "csp.rule.capacity-evidence",
                 "the capacity reported here is below what this obligation requires");
}

// ---------------------------------------------------------------------------------
// Maintenance state
// ---------------------------------------------------------------------------------

CSP_TEST(placement, maintenance_state_decides_admission) {
  const MaintenanceState kUnavailable[] = {MaintenanceState::Maintenance, MaintenanceState::Draining,
                                           MaintenanceState::Offline};
  for (const MaintenanceState state : kUnavailable) {
    Fleet fleet;
    fleet.add_site_measured("site-a", Measurement<MaintenanceState>::known(state), std::string_view{});
    fleet.add_capacity("site-a", "payments", 10);
    fleet.add_compatibility("site-a", "payments", true);
    fleet.add_obligation("obligation-1", "payments", 4);
    const Result<PlacementPlan> outcome = fleet.plan();
    CSP_REQUIRE(outcome.has_value());
    CSP_EXPECT(rule_is_published("csp.rule.maintenance-state"));
    const std::string detail = std::string("the site is in maintenance state ") + to_string(state) +
                               ", which cannot take a new placement";
    expect_refused(outcome.value(), "csp.rule.maintenance-state", detail.c_str());
  }

  // Degraded is refused under the default policy and admitted when the policy allows it.
  Fleet degraded;
  degraded.add_site_measured("site-a", Measurement<MaintenanceState>::known(MaintenanceState::Degraded),
                             std::string_view{});
  degraded.add_capacity("site-a", "payments", 10);
  degraded.add_compatibility("site-a", "payments", true);
  degraded.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> refused_degraded = degraded.plan();
  CSP_REQUIRE(refused_degraded.has_value());
  expect_refused(refused_degraded.value(), "csp.rule.maintenance-state",
                 "the site is in maintenance state degraded, which cannot take a new placement");

  degraded.policy.allow_degraded_sites = true;
  const Result<PlacementPlan> admitted_degraded = degraded.plan();
  CSP_REQUIRE(admitted_degraded.has_value());
  expect_planned(admitted_degraded.value(), 1);
  CSP_EXPECT(sole_obligation(admitted_degraded.value()).placements.front().site == id_of<SiteId>("site-a"));

  // An unreported state is indeterminate under the default policy, and admitted only
  // when the policy says so.
  Fleet unreported;
  unreported.add_site_measured("site-a", Measurement<MaintenanceState>::unknown(), std::string_view{});
  unreported.add_capacity("site-a", "payments", 10);
  unreported.add_compatibility("site-a", "payments", true);
  unreported.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> undecided = unreported.plan();
  CSP_REQUIRE(undecided.has_value());
  expect_indeterminate(undecided.value(), "csp.rule.maintenance-state",
                       "nobody reported this site's maintenance state and this policy does not assume one");

  unreported.policy.allow_unknown_maintenance_state = true;
  const Result<PlacementPlan> admitted = unreported.plan();
  CSP_REQUIRE(admitted.has_value());
  expect_planned(admitted.value(), 1);
}

// ---------------------------------------------------------------------------------
// Service compatibility
// ---------------------------------------------------------------------------------

CSP_TEST(placement, compatibility_decides_admission) {
  // No record at all is indeterminate, never satisfied.
  Fleet absent;
  absent.add_site("site-a");
  absent.add_capacity("site-a", "payments", 10);
  absent.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> undecided = absent.plan();
  CSP_REQUIRE(undecided.has_value());
  CSP_EXPECT(rule_is_published("csp.rule.service-compatibility"));
  expect_indeterminate(undecided.value(), "csp.rule.service-compatibility",
                       "no compatibility record exists for this service class at this site");

  // A record that says nothing usable is indeterminate too.
  Fleet silent;
  silent.add_site("site-a");
  silent.add_capacity("site-a", "payments", 10);
  silent.add_compatibility_measured("site-a", "payments", Measurement<bool>::unknown());
  silent.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> unusable = silent.plan();
  CSP_REQUIRE(unusable.has_value());
  expect_indeterminate(unusable.value(), "csp.rule.service-compatibility",
                       "the compatibility record for this service class says nothing usable");

  // A known false is a refusal.
  Fleet incompatible;
  incompatible.add_site("site-a");
  incompatible.add_capacity("site-a", "payments", 10);
  incompatible.add_compatibility("site-a", "payments", false);
  incompatible.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> refused = incompatible.plan();
  CSP_REQUIRE(refused.has_value());
  expect_refused(refused.value(), "csp.rule.service-compatibility",
                 "the compatibility record states that this service class may not run here");

  // A known true places.
  Fleet compatible;
  compatible.add_site("site-a");
  compatible.add_capacity("site-a", "payments", 10);
  compatible.add_compatibility("site-a", "payments", true);
  compatible.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> placed = compatible.plan();
  CSP_REQUIRE(placed.has_value());
  expect_planned(placed.value(), 1);

  // A record for another service class does not answer for this one.
  Fleet other_class;
  other_class.add_site("site-a");
  other_class.add_capacity("site-a", "payments", 10);
  other_class.add_compatibility("site-a", "storage", true);
  other_class.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> wrong_class = other_class.plan();
  CSP_REQUIRE(wrong_class.has_value());
  expect_indeterminate(wrong_class.value(), "csp.rule.service-compatibility",
                       "no compatibility record exists for this service class at this site");
}

// ---------------------------------------------------------------------------------
// Jurisdiction
// ---------------------------------------------------------------------------------

CSP_TEST(placement, jurisdiction_decides_admission) {
  // A site in the wrong jurisdiction is refused.
  Fleet elsewhere;
  elsewhere.add_site_measured("site-a", Measurement<MaintenanceState>::known(MaintenanceState::Operational),
                              "region-us");
  elsewhere.add_capacity("site-a", "payments", 10);
  elsewhere.add_compatibility("site-a", "payments", true);
  Obligation& obligation = elsewhere.add_obligation("obligation-1", "payments", 4);
  obligation.allowed_jurisdictions.push_back(id_of<JurisdictionId>("region-eu"));
  const Result<PlacementPlan> refused = elsewhere.plan();
  CSP_REQUIRE(refused.has_value());
  CSP_EXPECT(rule_is_published("csp.rule.jurisdiction"));
  expect_refused(refused.value(), "csp.rule.jurisdiction",
                 "the site is in jurisdiction region-us, which this obligation does not allow");

  // The named jurisdiction places.
  Fleet inside;
  inside.add_site_measured("site-a", Measurement<MaintenanceState>::known(MaintenanceState::Operational),
                           "region-eu");
  inside.add_capacity("site-a", "payments", 10);
  inside.add_compatibility("site-a", "payments", true);
  Obligation& allowed = inside.add_obligation("obligation-1", "payments", 4);
  allowed.allowed_jurisdictions.push_back(id_of<JurisdictionId>("region-eu"));
  const Result<PlacementPlan> placed = inside.plan();
  CSP_REQUIRE(placed.has_value());
  expect_planned(placed.value(), 1);

  // An unrecorded jurisdiction is indeterminate unless the policy accepts one.
  Fleet unrecorded;
  unrecorded.add_site("site-a");
  unrecorded.add_capacity("site-a", "payments", 10);
  unrecorded.add_compatibility("site-a", "payments", true);
  Obligation& restricted = unrecorded.add_obligation("obligation-1", "payments", 4);
  restricted.allowed_jurisdictions.push_back(id_of<JurisdictionId>("region-eu"));
  const Result<PlacementPlan> undecided = unrecorded.plan();
  CSP_REQUIRE(undecided.has_value());
  expect_indeterminate(undecided.value(), "csp.rule.jurisdiction",
                       "the site's jurisdiction is unrecorded and this policy does not accept an unrecorded one");

  unrecorded.policy.allow_unknown_jurisdiction = true;
  const Result<PlacementPlan> admitted = unrecorded.plan();
  CSP_REQUIRE(admitted.has_value());
  expect_planned(admitted.value(), 1);

  // An obligation that states no jurisdictional requirement ignores an unrecorded one.
  Fleet unrestricted;
  unrestricted.add_site("site-a");
  unrestricted.add_capacity("site-a", "payments", 10);
  unrestricted.add_compatibility("site-a", "payments", true);
  unrestricted.add_obligation("obligation-1", "payments", 4);
  const Result<PlacementPlan> free = unrestricted.plan();
  CSP_REQUIRE(free.has_value());
  expect_planned(free.value(), 1);
}

// ---------------------------------------------------------------------------------
// Preferences
// ---------------------------------------------------------------------------------

CSP_TEST(placement, minimise_cost_orders_by_reported_cost_and_is_not_free_when_absent) {
  // Three sites: one cheap, one expensive, and one nobody priced.
  Fleet fleet;
  fleet.add_site("site-a");
  fleet.add_site("site-b");
  fleet.add_site("site-c");
  const char* kSites[] = {"site-a", "site-b", "site-c"};
  for (const char* site : kSites) {
    fleet.add_capacity(site, "payments", 10);
    fleet.add_compatibility(site, "payments", true);
  }
  fleet.add_cost("site-a", "payments", 30);
  fleet.add_cost("site-b", "payments", 10);
  // site-c has no cost record at all.
  fleet.add_obligation("obligation-1", "payments", 4);
  fleet.request.preferences.objectives.push_back(Preferences::Objective::MinimiseCost);

  const Result<PlacementPlan> outcome = fleet.plan();
  CSP_REQUIRE(outcome.has_value());
  expect_planned(outcome.value(), 1);
  // The cheapest reported site wins; the unpriced site does not win by being unpriced.
  CSP_EXPECT(sole_obligation(outcome.value()).placements.front().site == id_of<SiteId>("site-b"));

  // The criterion could not order every candidate, so it is recorded as indeterminate.
  bool saw_cost_criterion = false;
  for (const TieBreakRecord& record : outcome.value().tie_breaks) {
    if (record.criterion != "csp.preference.minimise-cost") {
      continue;
    }
    saw_cost_criterion = true;
    CSP_EXPECT(record.applied == Tri::Indeterminate);
    CSP_EXPECT(record.detail.find("2 of 3") != std::string::npos);
  }
  CSP_EXPECT(saw_cost_criterion);
  // The identity tie-break is total and always applies, and it lists the cost order.
  bool saw_identity = false;
  for (const TieBreakRecord& record : outcome.value().tie_breaks) {
    if (record.criterion != "csp.preference.site-identity") {
      continue;
    }
    saw_identity = true;
    CSP_EXPECT(record.applied == Tri::Satisfied);
    CSP_REQUIRE(record.ordered.size() == 3);
    CSP_EXPECT(record.ordered[0] == id_of<SiteId>("site-b"));
    CSP_EXPECT(record.ordered[1] == id_of<SiteId>("site-a"));
    CSP_EXPECT(record.ordered[2] == id_of<SiteId>("site-c"));
  }
  CSP_EXPECT(saw_identity);

  // Remove the unpriced candidate and the criterion becomes satisfied.
  Fleet priced;
  priced.add_site("site-a");
  priced.add_site("site-b");
  for (const char* site : {"site-a", "site-b"}) {
    priced.add_capacity(site, "payments", 10);
    priced.add_compatibility(site, "payments", true);
  }
  priced.add_cost("site-a", "payments", 30);
  priced.add_cost("site-b", "payments", 10);
  priced.add_obligation("obligation-1", "payments", 4);
  priced.request.preferences.objectives.push_back(Preferences::Objective::MinimiseCost);
  const Result<PlacementPlan> ordered = priced.plan();
  CSP_REQUIRE(ordered.has_value());
  expect_planned(ordered.value(), 1);
  CSP_EXPECT(sole_obligation(ordered.value()).placements.front().site == id_of<SiteId>("site-b"));
  bool saw_applied_criterion = false;
  for (const TieBreakRecord& record : ordered.value().tie_breaks) {
    if (record.criterion == "csp.preference.minimise-cost") {
      saw_applied_criterion = true;
      CSP_EXPECT(record.applied == Tri::Satisfied);
      CSP_EXPECT(record.detail.find("2 of 2") != std::string::npos);
    }
  }
  CSP_EXPECT(saw_applied_criterion);
}

// ---------------------------------------------------------------------------------
// Policy identity, freshness, and structural validation
// ---------------------------------------------------------------------------------

CSP_TEST(placement, policy_identity_and_generation_are_enforced) {
  const Fleet fleet = one_site_fleet();
  const Result<PlacementPlan> placed = fleet.plan();
  CSP_REQUIRE(placed.has_value());
  expect_planned(placed.value(), 1);

  Fleet other_identity = fleet;
  other_identity.policy.policy = id_of<PolicyId>("policy-2");
  EXPECT_FAILURE(other_identity.plan(), ErrorCategory::Conflict, "csp.policy.reference_mismatch");

  Fleet other_generation = fleet;
  other_generation.policy.generation = Generation::from_value(6);
  EXPECT_FAILURE(other_generation.plan(), ErrorCategory::Conflict, "csp.policy.reference_mismatch");

  Fleet other_reference = fleet;
  other_reference.request.policy.policy = id_of<PolicyId>("policy-3");
  EXPECT_FAILURE(other_reference.plan(), ErrorCategory::Conflict, "csp.policy.reference_mismatch");

  // A request that names no policy generation cannot be fenced at all.
  Fleet unset_generation = fleet;
  unset_generation.request.policy.generation = Generation::from_value(0);
  EXPECT_FAILURE(unset_generation.plan(), ErrorCategory::Invalid, "csp.request.missing_policy_generation");

  // The refusal names both sides so a reader can see the substitution it avoided.
  const Result<PlacementPlan> mismatch = other_identity.plan();
  CSP_REQUIRE(!mismatch.has_value());
  CSP_EXPECT(mismatch.error().message().find("policy-1") != std::string::npos);
  CSP_EXPECT(mismatch.error().message().find("policy-2") != std::string::npos);
}

CSP_TEST(placement, freshness_of_evidence_decides_admission) {
  // Two days old against a one-day default envelope: not fresh.
  Fleet stale = one_site_fleet();
  stale.snapshot.sites.front().provenance.observed_at =
      Instant::from_nanos(kEvaluated - 2 * 86400LL * kNanosPerSecond);
  const Result<PlacementPlan> refused = stale.plan();
  CSP_REQUIRE(refused.has_value());
  CSP_EXPECT(rule_is_published("csp.rule.evidence-freshness"));
  expect_indeterminate(refused.value(), "csp.rule.evidence-freshness",
                       "the record was observed before the freshness horizon this request set");

  // One hour old: inside the envelope.
  Fleet fresh = one_site_fleet();
  fresh.snapshot.sites.front().provenance.observed_at =
      Instant::from_nanos(kEvaluated - 3600LL * kNanosPerSecond);
  const Result<PlacementPlan> placed = fresh.plan();
  CSP_REQUIRE(placed.has_value());
  expect_planned(placed.value(), 1);
  CSP_EXPECT_EQ(placed.value().envelope.oldest_evidence_observed_at.nanos(),
                kEvaluated - 3600LL * kNanosPerSecond);

  // A request that narrows the envelope below the age of the evidence refuses it.
  Fleet narrow = one_site_fleet();
  narrow.request.freshness.max_evidence_age_nanos = 1;
  const Result<PlacementPlan> too_old = narrow.plan();
  CSP_REQUIRE(too_old.has_value());
  expect_indeterminate(too_old.value(), "csp.rule.evidence-freshness",
                       "the record was observed before the freshness horizon this request set");

  // A record with no observation time is refused while the request requires one.
  Fleet undated = one_site_fleet();
  undated.snapshot.sites.front().provenance.observed_at = Instant{};
  const Result<PlacementPlan> no_time = undated.plan();
  CSP_REQUIRE(no_time.has_value());
  expect_indeterminate(no_time.value(), "csp.rule.evidence-freshness",
                       "the record carries no observation time and the request requires one");

  // With the requirement switched off the same record is admitted, and the plan carries
  // no expiry claim that rests on a clock reading it never had. This pins the behaviour
  // of the engine: with require_observation_time false, freshness_of() answers Satisfied.
  Fleet accepting = one_site_fleet();
  accepting.request.freshness.require_observation_time = false;
  for (SiteRecord& site : accepting.snapshot.sites) {
    site.provenance.observed_at = Instant{};
  }
  for (CapacityRecord& record : accepting.snapshot.capacity) {
    record.provenance.observed_at = Instant{};
  }
  for (CompatibilityRecord& record : accepting.snapshot.compatibility) {
    record.provenance.observed_at = Instant{};
  }
  const Result<PlacementPlan> admitted = accepting.plan();
  CSP_REQUIRE(admitted.has_value());
  expect_planned(admitted.value(), 1);
  CSP_EXPECT(admitted.value().envelope.oldest_evidence_observed_at.is_zero());
}

CSP_TEST(placement, request_validation_refusals) {
  const Limits limits;
  const Fleet fleet = one_site_fleet();
  CSP_EXPECT_OK(request_validate(fleet.request, limits));

  PlacementRequest duplicate_obligation = fleet.request;
  duplicate_obligation.obligations.push_back(duplicate_obligation.obligations.front());
  EXPECT_FAILURE(request_validate(duplicate_obligation, limits), ErrorCategory::Conflict,
                 "csp.request.duplicate_obligation");

  PlacementRequest negative_capacity = fleet.request;
  negative_capacity.obligations.front().required_capacity = Quantity::from_units(-1);
  EXPECT_FAILURE(request_validate(negative_capacity, limits), ErrorCategory::OutOfRange,
                 "csp.request.negative_capacity");

  PlacementRequest no_placements = fleet.request;
  no_placements.obligations.front().primary_placements = 0;
  no_placements.obligations.front().recovery_placements = 0;
  EXPECT_FAILURE(request_validate(no_placements, limits), ErrorCategory::Invalid,
                 "csp.request.no_placements");

  PlacementRequest objective_without_recovery = fleet.request;
  objective_without_recovery.obligations.front().required_rto = Duration::from_nanos(1000);
  EXPECT_FAILURE(request_validate(objective_without_recovery, limits), ErrorCategory::Invalid,
                 "csp.request.objective_without_recovery");

  PlacementRequest empty_separation = fleet.request;
  empty_separation.obligations.front().separations.push_back(SeparationRequirement{});
  EXPECT_FAILURE(request_validate(empty_separation, limits), ErrorCategory::Invalid,
                 "csp.request.empty_separation");

  PlacementRequest self_dependency = fleet.request;
  LatencyRequirement self;
  self.peer.kind = DependencyEndpoint::Kind::Obligation;
  self.peer.obligation = fleet.request.obligations.front().obligation;
  self.max_latency = Duration::from_nanos(1000);
  self_dependency.obligations.front().latency_requirements.push_back(self);
  EXPECT_FAILURE(request_validate(self_dependency, limits), ErrorCategory::Invalid,
                 "csp.request.self_dependency");

  PlacementRequest unknown_peer = fleet.request;
  LatencyRequirement dangling;
  dangling.peer.kind = DependencyEndpoint::Kind::Obligation;
  dangling.peer.obligation = id_of<ObligationId>("obligation-absent");
  dangling.max_latency = Duration::from_nanos(1000);
  unknown_peer.obligations.front().latency_requirements.push_back(dangling);
  EXPECT_FAILURE(request_validate(unknown_peer, limits), ErrorCategory::NotFound,
                 "csp.request.unknown_peer_obligation");

  PlacementRequest duplicate_site = fleet.request;
  duplicate_site.allowed_sites.push_back(id_of<SiteId>("site-a"));
  duplicate_site.allowed_sites.push_back(id_of<SiteId>("site-a"));
  EXPECT_FAILURE(request_validate(duplicate_site, limits), ErrorCategory::Conflict,
                 "csp.request.duplicate_site");

  PlacementRequest negative_latency = fleet.request;
  LatencyRequirement backwards;
  backwards.peer.kind = DependencyEndpoint::Kind::SiteService;
  backwards.peer.site = id_of<SiteId>("site-a");
  backwards.peer.service_class = id_of<ServiceClassId>("payments");
  backwards.max_latency = Duration::from_nanos(-1);
  negative_latency.obligations.front().latency_requirements.push_back(backwards);
  EXPECT_FAILURE(request_validate(negative_latency, limits), ErrorCategory::OutOfRange,
                 "csp.request.negative_latency");

  PlacementRequest negative_validity = fleet.request;
  negative_validity.validity.validity_nanos = -1;
  EXPECT_FAILURE(request_validate(negative_validity, limits), ErrorCategory::OutOfRange,
                 "csp.request.negative_validity");

  PlacementRequest bounded = fleet.request;
  bounded.obligations.front().primary_placements = static_cast<std::uint32_t>(limits.max_placements_per_obligation) + 1u;
  EXPECT_FAILURE(request_validate(bounded, limits), ErrorCategory::BoundExceeded,
                 "csp.request.too_many_placements");
}

CSP_TEST(placement, snapshot_validation_refusals) {
  const Limits limits;
  Fleet fleet = one_site_fleet();
  CSP_EXPECT_OK(snapshot_validate(fleet.snapshot, limits));

  // Two readings of one site identity are a conflict, not a merge.
  SiteEvidenceSnapshot duplicate_site = fleet.snapshot;
  duplicate_site.sites.push_back(duplicate_site.sites.front());
  EXPECT_FAILURE(snapshot_validate(duplicate_site, limits), ErrorCategory::Conflict,
                 "csp.evidence.duplicate_identity");

  // The planner surfaces the same refusal, in the same category.
  Fleet duplicated = fleet;
  duplicated.snapshot.sites.push_back(duplicated.snapshot.sites.front());
  EXPECT_FAILURE(duplicated.plan(), ErrorCategory::Conflict, "csp.evidence.duplicate_identity");

  // A domain that contains itself is not a structure.
  SiteEvidenceSnapshot self_parent = fleet.snapshot;
  FailureDomainRecord domain;
  domain.domain = id_of<FailureDomainId>("feed-1");
  domain.kind = DomainKind::Power;
  domain.parent = domain.domain;
  domain.provenance = fleet.provenance("domain");
  self_parent.failure_domains.push_back(domain);
  EXPECT_FAILURE(snapshot_validate(self_parent, limits), ErrorCategory::Invalid,
                 "csp.evidence.self_parent");

  // A capacity reading below zero describes no capacity that exists.
  SiteEvidenceSnapshot negative_capacity = fleet.snapshot;
  CapacityRecord record;
  record.reference = id_of<CapacityRefId>("capacity-negative");
  record.site = id_of<SiteId>("site-a");
  record.service_class = id_of<ServiceClassId>("payments");
  record.kind = CapacityKind::Commitment;
  record.available = Measurement<Quantity>::known(Quantity::from_units(-5));
  record.provenance = fleet.provenance("capacity");
  negative_capacity.capacity.push_back(record);
  EXPECT_FAILURE(snapshot_validate(negative_capacity, limits), ErrorCategory::OutOfRange,
                 "csp.evidence.negative_capacity");

  // A negative latency is a time that runs backwards.
  SiteEvidenceSnapshot negative_latency = fleet.snapshot;
  LatencyRecord latency;
  latency.reference = id_of<DependencyId>("latency-negative");
  latency.from_site = id_of<SiteId>("site-a");
  latency.to_site = id_of<SiteId>("site-a");
  latency.statistic = LatencyStatistic::Max;
  latency.latency = Measurement<Duration>::known(Duration::from_nanos(-1));
  latency.provenance = fleet.provenance("latency");
  negative_latency.latency.push_back(latency);
  EXPECT_FAILURE(snapshot_validate(negative_latency, limits), ErrorCategory::OutOfRange,
                 "csp.evidence.negative_duration");

  // Risk is in parts per thousand.
  SiteEvidenceSnapshot bad_risk = fleet.snapshot;
  CostRiskRecord risk;
  risk.reference = id_of<EvidenceId>("cost-bad");
  risk.site = id_of<SiteId>("site-a");
  risk.cost_per_unit = Measurement<Quantity>::known(Quantity::from_units(1));
  risk.risk_per_mille = Measurement<std::int64_t>::known(1001);
  risk.provenance = fleet.provenance("cost");
  bad_risk.cost_risk.push_back(risk);
  EXPECT_FAILURE(snapshot_validate(bad_risk, limits), ErrorCategory::OutOfRange,
                 "csp.evidence.risk_range");

  // An identity that was never issued is absent where the evidence requires one.
  SiteEvidenceSnapshot missing_identity = fleet.snapshot;
  missing_identity.sites.push_back(SiteRecord{});
  EXPECT_FAILURE(snapshot_validate(missing_identity, limits), ErrorCategory::Invalid,
                 "csp.evidence.missing_identity");

  // A collection above its bound is refused before it is read.
  Limits tiny = limits;
  tiny.max_sites = 1;
  SiteEvidenceSnapshot two_sites = fleet.snapshot;
  two_sites.sites.push_back(two_sites.sites.front());
  two_sites.sites.back().site = id_of<SiteId>("site-b");
  EXPECT_FAILURE(snapshot_validate(two_sites, tiny), ErrorCategory::BoundExceeded,
                 "csp.evidence.bound_exceeded");

  // A snapshot with an unreadable domain graph is refused by the planner too.
  Fleet self_parenting = fleet;
  self_parenting.snapshot.failure_domains.push_back(domain);
  EXPECT_FAILURE(self_parenting.plan(), ErrorCategory::Invalid, "csp.evidence.self_parent");
}
