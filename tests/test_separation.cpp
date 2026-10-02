// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Separation: failure-domain containment, aliases, and the groups a requirement covers.
//
// A separation rule is evaluated between two placements of one obligation, and the
// search tries the site already chosen for that obligation first. Every fleet below
// therefore states allow_colocation so that the only rule left to decide a same-site
// pair is separation itself; otherwise the co-location rule would reject that trial
// first and hide which rule the refusal is really about.

#include <algorithm>
#include <cstddef>
#include <cstdint>
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
    request.request = id_of<RequestId>("req-separation");
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

  void add_site(std::string_view site) {
    SiteRecord record;
    record.site = id_of<SiteId>(site);
    record.maintenance = Measurement<MaintenanceState>::known(MaintenanceState::Operational);
    record.provenance = provenance("site");
    snapshot.sites.push_back(std::move(record));
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

  void add_capacity(std::string_view site, std::string_view service_class, std::int64_t units) {
    CapacityRecord record;
    record.reference = id_of<CapacityRefId>(fresh("capacity"));
    record.site = id_of<SiteId>(site);
    record.service_class = id_of<ServiceClassId>(service_class);
    record.kind = CapacityKind::Commitment;
    record.available = Measurement<Quantity>::known(Quantity::from_units(units));
    record.provenance = provenance("capacity-record");
    snapshot.capacity.push_back(std::move(record));
  }

  void add_compatibility(std::string_view site, std::string_view service_class) {
    CompatibilityRecord record;
    record.reference = id_of<EvidenceId>(fresh("compatibility"));
    record.site = id_of<SiteId>(site);
    record.service_class = id_of<ServiceClassId>(service_class);
    record.compatible = Measurement<bool>::known(true);
    record.provenance = provenance("compatibility-record");
    snapshot.compatibility.push_back(std::move(record));
  }

  void add_recovery(std::string_view site, std::string_view service_class) {
    RecoveryRecord record;
    record.reference = id_of<RecoveryRefId>(fresh("recovery"));
    record.site = id_of<SiteId>(site);
    record.service_class = id_of<ServiceClassId>(service_class);
    record.can_host_recovery = Measurement<bool>::known(true);
    record.provenance = provenance("recovery-record");
    snapshot.recovery.push_back(std::move(record));
  }

  /// Every site in this file can host the one service class the cases use.
  void make_hostable(std::string_view service_class) {
    for (const SiteRecord& site : snapshot.sites) {
      add_capacity(site.site.value(), service_class, 10);
      add_compatibility(site.site.value(), service_class);
    }
  }

  Obligation& add_obligation(std::string_view obligation, std::string_view service_class, std::int64_t capacity,
                             std::uint32_t primary, std::uint32_t recovery, bool allow_colocation) {
    Obligation record;
    record.obligation = id_of<ObligationId>(obligation);
    record.service_class = id_of<ServiceClassId>(service_class);
    record.required_capacity = Quantity::from_units(capacity);
    record.primary_placements = primary;
    record.recovery_placements = recovery;
    record.allow_colocation = allow_colocation;
    request.obligations.push_back(std::move(record));
    return request.obligations.back();
  }

  Obligation& obligation() { return request.obligations.front(); }

  std::vector<SiteId> placed_sites(const PlacementPlan& plan) const {
    std::vector<SiteId> sites;
    for (const SitePlacement& placement : plan.obligations.front().placements) {
      sites.push_back(placement.site);
    }
    return sites;
  }
};

SeparationRequirement kinds_rule(SeparationGroup group, std::vector<DomainKind> kinds) {
  SeparationRequirement requirement;
  requirement.group = group;
  requirement.separated_kinds = std::move(kinds);
  return requirement;
}

SeparationRequirement named_rule(SeparationGroup group, std::string_view domain) {
  SeparationRequirement requirement;
  requirement.group = group;
  requirement.forbidden_shared_domains.push_back(id_of<FailureDomainId>(domain));
  return requirement;
}

std::string violation_detail(std::string_view one, std::string_view two) {
  return "sites " + std::string(one) + " and " + std::string(two) +
         " share a failure domain this requirement forbids";
}

const ObligationPlacement& sole_obligation(const PlacementPlan& plan) {
  CSP_REQUIRE(plan.obligations.size() == 1);
  return plan.obligations.front();
}

void expect_planned(const PlacementPlan& plan, std::size_t placements) {
  CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Planned,
                 std::string("the plan was not planned: ") + to_string(plan.outcome));
  CSP_EXPECT(plan_is_applicable(plan));
  const ObligationPlacement& obligation = sole_obligation(plan);
  CSP_EXPECT(obligation.outcome == Tri::Satisfied);
  CSP_EXPECT_MSG(obligation.placements.size() == placements, "the plan selected the wrong number of placements");
}

void expect_refused(const PlacementPlan& plan, const char* detail) {
  CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Refused,
                 std::string("the plan was not refused: ") + to_string(plan.outcome));
  CSP_EXPECT(!plan_is_applicable(plan));
  CSP_REQUIRE(plan.refusal.has_value());
  CSP_EXPECT_MSG(plan.refusal->code == "csp.rule.failure-domain-separation",
                 "the refusal code was " + plan.refusal->code);
  const ObligationPlacement& obligation = sole_obligation(plan);
  CSP_EXPECT(obligation.outcome == Tri::Violated);
  CSP_EXPECT(obligation.placements.empty());
  CSP_EXPECT_MSG(obligation.detail == detail, "the refusal detail was: " + obligation.detail);
}

/// An indeterminate answer for a multi-placement obligation.
///
/// The engine records which rule decided a *violated* outcome, and that record survives
/// backtracking. For an undecided outcome the exhausted root frame writes the generic
/// selection token last, so the rule that left each pair undecided is not carried into
/// the refusal. This helper therefore asserts the property under test: the planner did
/// not decide, and it placed nothing.
void expect_undecided(const PlacementPlan& plan) {
  CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Indeterminate,
                 std::string("the plan was not indeterminate: ") + to_string(plan.outcome));
  CSP_EXPECT(plan.outcome != PlanOutcome::Planned);
  CSP_EXPECT(!plan_is_applicable(plan));
  CSP_REQUIRE(plan.obligations.size() == 1);
  CSP_EXPECT(plan.obligations.front().outcome == Tri::Indeterminate);
  CSP_EXPECT(plan.obligations.front().placements.empty());
  CSP_EXPECT(!plan.obligations.front().refusal_code.empty());
}

/// Sites a and b, with two distinct power feeds and one shared region.
Fleet power_and_region_fleet() {
  Fleet fleet;
  fleet.add_site("site-a");
  fleet.add_site("site-b");
  fleet.add_domain("feed-a", DomainKind::Power);
  fleet.add_domain("feed-b", DomainKind::Power);
  fleet.add_domain("region-1", DomainKind::Geography);
  fleet.add_assignment("site-a", "feed-a");
  fleet.add_assignment("site-a", "region-1");
  fleet.add_assignment("site-b", "feed-b");
  fleet.add_assignment("site-b", "region-1");
  fleet.make_hostable("payments");
  fleet.add_obligation("obligation-1", "payments", 4, 2, 0, true);
  return fleet;
}

}  // namespace

// ---------------------------------------------------------------------------------
// Kinds are not interchangeable
// ---------------------------------------------------------------------------------

CSP_TEST(separation, power_and_geography_are_not_interchangeable) {
  Fleet fleet = power_and_region_fleet();
  CSP_EXPECT(separation_group_from_string("all").has_value());

  // Different power feeds satisfy a Power rule, and the plan records both sites.
  fleet.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {DomainKind::Power}));
  const Result<PlacementPlan> by_power = fleet.plan();
  CSP_REQUIRE(by_power.has_value());
  expect_planned(by_power.value(), 2);
  const std::vector<SiteId> sites = fleet.placed_sites(by_power.value());
  CSP_REQUIRE(sites.size() == 2);
  CSP_EXPECT(sites[0] != sites[1]);
  CSP_EXPECT(sites[0] == id_of<SiteId>("site-a"));
  CSP_EXPECT(sites[1] == id_of<SiteId>("site-b"));
  // The resolved ancestry of each placement is recorded, one power feed each.
  for (const SitePlacement& placement : sole_obligation(by_power.value()).placements) {
    CSP_REQUIRE(placement.domains.size() == 2);
    bool saw_power = false;
    for (const DomainRef& domain : placement.domains) {
      if (domain.domain.value() == std::string("feed-a") || domain.domain.value() == std::string("feed-b")) {
        saw_power = true;
        CSP_EXPECT(domain.kind.has_value());
        CSP_EXPECT(domain.kind == DomainKind::Power);
        CSP_EXPECT_EQ(domain.depth, std::uint32_t{0});
      }
    }
    CSP_EXPECT(saw_power);
  }

  // One shared region violates a Geography rule.
  fleet.obligation().separations.clear();
  fleet.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {DomainKind::Geography}));
  const Result<PlacementPlan> by_geography = fleet.plan();
  CSP_REQUIRE(by_geography.has_value());
  expect_refused(by_geography.value(), violation_detail("site-a", "site-a").c_str());

  // Naming the shared region outright is a violation too, without naming any kind.
  fleet.obligation().separations.clear();
  fleet.obligation().separations.push_back(named_rule(SeparationGroup::All, "region-1"));
  const Result<PlacementPlan> by_name = fleet.plan();
  CSP_REQUIRE(by_name.has_value());
  expect_refused(by_name.value(), violation_detail("site-a", "site-a").c_str());

  // Naming a domain they do not share constrains nothing here.
  fleet.obligation().separations.clear();
  fleet.obligation().separations.push_back(named_rule(SeparationGroup::All, "region-9"));
  const Result<PlacementPlan> by_absent_name = fleet.plan();
  CSP_REQUIRE(by_absent_name.has_value());
  expect_planned(by_absent_name.value(), 2);
}

// ---------------------------------------------------------------------------------
// Containment and aliasing
// ---------------------------------------------------------------------------------

CSP_TEST(separation, containment_is_transitive) {
  Fleet fleet;
  fleet.add_site("site-a");
  fleet.add_site("site-b");
  // Two halls in one region: the halls differ, the region does not.
  fleet.add_domain("region-1", DomainKind::Geography);
  fleet.add_domain("hall-a", DomainKind::Physical, "region-1");
  fleet.add_domain("hall-b", DomainKind::Physical, "region-1");
  fleet.add_assignment("site-a", "hall-a");
  fleet.add_assignment("site-b", "hall-b");
  fleet.make_hostable("payments");
  fleet.add_obligation("obligation-1", "payments", 4, 2, 0, true);

  // The leaf kinds differ, so a rule naming the leaf kind is satisfied.
  fleet.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {DomainKind::Physical}));
  const Result<PlacementPlan> by_hall = fleet.plan();
  CSP_REQUIRE(by_hall.has_value());
  expect_planned(by_hall.value(), 2);
  // Each placement carries its whole ancestry: the hall at depth zero and the region
  // at depth one.
  bool saw_region_ancestry = false;
  for (const SitePlacement& placement : sole_obligation(by_hall.value()).placements) {
    CSP_REQUIRE(placement.domains.size() == 2);
    for (const DomainRef& domain : placement.domains) {
      if (domain.domain == id_of<FailureDomainId>("region-1")) {
        saw_region_ancestry = true;
        CSP_EXPECT(domain.kind == DomainKind::Geography);
        CSP_EXPECT_EQ(domain.depth, std::uint32_t{1});
      }
    }
  }
  CSP_EXPECT(saw_region_ancestry);

  // A rule naming the parent's kind catches the shared container.
  fleet.obligation().separations.clear();
  fleet.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {DomainKind::Geography}));
  const Result<PlacementPlan> by_region = fleet.plan();
  CSP_REQUIRE(by_region.has_value());
  expect_refused(by_region.value(), violation_detail("site-a", "site-a").c_str());

  // A rule naming the parent outright catches it as well.
  fleet.obligation().separations.clear();
  fleet.obligation().separations.push_back(named_rule(SeparationGroup::All, "region-1"));
  const Result<PlacementPlan> by_named_region = fleet.plan();
  CSP_REQUIRE(by_named_region.has_value());
  expect_refused(by_named_region.value(), violation_detail("site-a", "site-a").c_str());
}

CSP_TEST(separation, aliases_are_caught_only_when_declared) {
  Fleet fleet;
  fleet.add_site("site-a");
  fleet.add_site("site-b");
  // Two names for one power feed, and nothing shared between the sites otherwise.
  fleet.add_domain("feed-a", DomainKind::Power);
  fleet.add_domain("feed-b", DomainKind::Power);
  fleet.add_assignment("site-a", "feed-a");
  fleet.add_assignment("site-b", "feed-b");
  fleet.make_hostable("payments");
  fleet.add_obligation("obligation-1", "payments", 4, 2, 0, true);
  fleet.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {DomainKind::Power}));

  // Without the alias the two names are two domains, and the rule is satisfied.
  const Result<PlacementPlan> unaliased = fleet.plan();
  CSP_REQUIRE(unaliased.has_value());
  expect_planned(unaliased.value(), 2);
  bool saw_feed_a = false;
  bool saw_feed_b = false;
  for (const SitePlacement& placement : sole_obligation(unaliased.value()).placements) {
    for (const DomainRef& domain : placement.domains) {
      saw_feed_a = saw_feed_a || domain.domain == id_of<FailureDomainId>("feed-a");
      saw_feed_b = saw_feed_b || domain.domain == id_of<FailureDomainId>("feed-b");
    }
  }
  CSP_EXPECT(saw_feed_a);
  CSP_EXPECT(saw_feed_b);

  // With the alias declared the two names are one domain and the rule is violated.
  Fleet aliased = fleet;
  aliased.add_alias("feed-b", "feed-a");
  const Result<PlacementPlan> caught = aliased.plan();
  CSP_REQUIRE(caught.has_value());
  expect_refused(caught.value(), violation_detail("site-a", "site-a").c_str());

  // The plan records the resolved set: under the alias every placement names the
  // canonical identity, never the alias.
  Fleet recorded = fleet;
  recorded.add_alias("feed-b", "feed-a");
  recorded.obligation().separations.clear();
  recorded.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {DomainKind::Network}));
  const Result<PlacementPlan> resolved = recorded.plan();
  CSP_REQUIRE(resolved.has_value());
  expect_planned(resolved.value(), 2);
  for (const SitePlacement& placement : sole_obligation(resolved.value()).placements) {
    CSP_REQUIRE(placement.domains.size() == 1);
    CSP_EXPECT(placement.domains.front().domain == id_of<FailureDomainId>("feed-a"));
    CSP_EXPECT(placement.domains.front().kind == DomainKind::Power);
  }
}

// ---------------------------------------------------------------------------------
// Missing and undeclared evidence
// ---------------------------------------------------------------------------------

CSP_TEST(separation, a_site_without_membership_is_never_satisfied) {
  const DomainKind kKinds[] = {DomainKind::Power,    DomainKind::Cooling, DomainKind::Network,
                               DomainKind::Geography, DomainKind::Administrative, DomainKind::Physical,
                               DomainKind::Security};
  for (const DomainKind kind : kKinds) {
    Fleet fleet;
    fleet.add_site("site-a");
    fleet.add_site("site-b");
    fleet.add_domain("domain-b", kind);
    fleet.add_assignment("site-b", "domain-b");
    // site-a is assigned to nothing at all.
    fleet.make_hostable("payments");
    fleet.add_obligation("obligation-1", "payments", 4, 2, 0, true);
    fleet.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {kind}));
    const Result<PlacementPlan> outcome = fleet.plan();
    CSP_REQUIRE(outcome.has_value());
    CSP_EXPECT_MSG(outcome.value().outcome != PlanOutcome::Planned,
                   std::string("a rule naming ") + to_string(kind) +
                       " was satisfied for a site with no recorded membership");
    expect_undecided(outcome.value());

    // The control: record where site-a sits and the same rule is satisfied and both
    // sites are used. The indeterminacy above came from the missing membership.
    fleet.add_domain("domain-a", kind);
    fleet.add_assignment("site-a", "domain-a");
    const Result<PlacementPlan> decided = fleet.plan();
    CSP_REQUIRE(decided.has_value());
    expect_planned(decided.value(), 2);
  }
}

CSP_TEST(separation, an_undeclared_kind_leaves_the_rule_indeterminate) {
  // Both sites sit in one domain whose kind nobody declared.
  Fleet fleet;
  fleet.add_site("site-a");
  fleet.add_site("site-b");
  fleet.add_assignment("site-a", "mystery-1");
  fleet.add_assignment("site-b", "mystery-1");
  fleet.make_hostable("payments");
  fleet.add_obligation("obligation-1", "payments", 4, 2, 0, true);
  fleet.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {DomainKind::Power}));

  const Result<PlacementPlan> undecided = fleet.plan();
  CSP_REQUIRE(undecided.has_value());
  expect_undecided(undecided.value());

  // Naming the domain outright does not need its kind.
  fleet.obligation().separations.clear();
  fleet.obligation().separations.push_back(named_rule(SeparationGroup::All, "mystery-1"));
  const Result<PlacementPlan> named = fleet.plan();
  CSP_REQUIRE(named.has_value());
  expect_refused(named.value(), violation_detail("site-a", "site-a").c_str());

  // A rule naming a kind nobody has in common is still only undecided about the shared
  // undeclared domain: the sites' other memberships decide nothing here.
  fleet.obligation().separations.clear();
  fleet.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {DomainKind::Network}));
  const Result<PlacementPlan> other_kind = fleet.plan();
  CSP_REQUIRE(other_kind.has_value());
  expect_undecided(other_kind.value());

  // Publish the kind and the same rule becomes decidable: the domain is known not to be
  // the kind the rule names, so the pair is separated.
  Fleet declared = fleet;
  declared.obligation().separations.clear();
  declared.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {DomainKind::Power}));
  declared.add_domain("mystery-1", DomainKind::Network);
  const Result<PlacementPlan> satisfied = declared.plan();
  CSP_REQUIRE(satisfied.has_value());
  expect_planned(satisfied.value(), 2);
}

CSP_TEST(separation, a_violation_wins_over_an_indeterminacy) {
  // The pair shares one declared power feed and one domain nobody classified.
  Fleet fleet;
  fleet.add_site("site-a");
  fleet.add_site("site-b");
  fleet.add_domain("power-1", DomainKind::Power);
  fleet.add_assignment("site-a", "power-1");
  fleet.add_assignment("site-b", "power-1");
  fleet.add_assignment("site-a", "mystery-1");
  fleet.add_assignment("site-b", "mystery-1");
  fleet.make_hostable("payments");
  fleet.add_obligation("obligation-1", "payments", 4, 2, 0, true);

  // A rule naming only the unclassified domain cannot be decided.
  fleet.obligation().separations.push_back(kinds_rule(SeparationGroup::All, {DomainKind::Network}));
  const Result<PlacementPlan> undecided = fleet.plan();
  CSP_REQUIRE(undecided.has_value());
  expect_undecided(undecided.value());

  // A rule naming the declared kind is violated, and the violation is not weakened by
  // the second, undecidable shared domain.
  fleet.obligation().separations.clear();
  fleet.obligation().separations.push_back(
      kinds_rule(SeparationGroup::All, {DomainKind::Network, DomainKind::Power}));
  const Result<PlacementPlan> violated = fleet.plan();
  CSP_REQUIRE(violated.has_value());
  expect_refused(violated.value(), violation_detail("site-a", "site-a").c_str());
}

// ---------------------------------------------------------------------------------
// Structural refusals of the domain graph
// ---------------------------------------------------------------------------------

CSP_TEST(separation, domain_structure_refusals) {
  const Limits limits;

  // A containment cycle is contradictory, not merely deep.
  Fleet cycle;
  cycle.add_site("site-a");
  cycle.add_domain("domain-1", DomainKind::Physical, "domain-2");
  cycle.add_domain("domain-2", DomainKind::Physical, "domain-1");
  EXPECT_FAILURE(cycle.plan(), ErrorCategory::Conflict, "csp.domains.containment_cycle");

  // A chain longer than the configured depth is a budget refusal.
  Fleet deep;
  deep.add_site("site-a");
  deep.add_domain("level-1", DomainKind::Physical);
  deep.add_domain("level-2", DomainKind::Physical, "level-1");
  deep.add_domain("level-3", DomainKind::Physical, "level-2");
  deep.add_domain("level-4", DomainKind::Physical, "level-3");
  Limits shallow = limits;
  shallow.max_domain_depth = 2;
  EXPECT_FAILURE(deep.plan_with(shallow), ErrorCategory::BoundExceeded, "csp.domains.depth_exceeded");
  // The same structure is accepted when the depth allows it.
  const Result<PlacementPlan> allowed = deep.plan();
  CSP_EXPECT(allowed.has_value());

  // Two readings of one domain identity are a conflict.
  Fleet duplicate = cycle;
  duplicate.snapshot.failure_domains.clear();
  duplicate.add_domain("domain-1", DomainKind::Power);
  FailureDomainRecord second;
  second.domain = id_of<FailureDomainId>("domain-1");
  second.kind = DomainKind::Power;
  second.provenance = duplicate.provenance("domain");
  duplicate.snapshot.failure_domains.push_back(second);
  EXPECT_FAILURE(duplicate.plan(), ErrorCategory::Conflict, "csp.evidence.duplicate_identity");

  // Two aliased domains that disagree about their kind cannot both be true.
  Fleet kind_conflict;
  kind_conflict.add_site("site-a");
  kind_conflict.add_domain("feed-a", DomainKind::Power);
  kind_conflict.add_domain("feed-b", DomainKind::Geography);
  kind_conflict.add_alias("feed-b", "feed-a");
  EXPECT_FAILURE(kind_conflict.plan(), ErrorCategory::Conflict, "csp.domains.kind_conflict");

  // Two aliased domains that disagree about their container cannot both be true.
  Fleet parent_conflict;
  parent_conflict.add_site("site-a");
  parent_conflict.add_domain("feed-a", DomainKind::Power, "place-1");
  parent_conflict.add_domain("feed-b", DomainKind::Power, "place-2");
  parent_conflict.add_alias("feed-b", "feed-a");
  EXPECT_FAILURE(parent_conflict.plan(), ErrorCategory::Conflict, "csp.domains.parent_conflict");
}

// ---------------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------------

CSP_TEST(separation, groups_decide_which_pairs_are_compared) {
  // One primary and one recovery placement on two sites that share one power feed. The
  // obligation permits co-location and the policy permits a recovery placement on a
  // primary site, so separation is the only rule that can reject the pair.
  struct Case {
    SeparationGroup group;
    bool refused;
  };
  const Case kCases[] = {
      {SeparationGroup::All, true},
      {SeparationGroup::WithinRole, false},
      {SeparationGroup::AcrossRoles, true},
  };
  for (const Case& entry : kCases) {
    Fleet fleet;
    fleet.add_site("site-a");
    fleet.add_site("site-b");
    fleet.add_domain("power-1", DomainKind::Power);
    fleet.add_assignment("site-a", "power-1");
    fleet.add_assignment("site-b", "power-1");
    fleet.make_hostable("payments");
    fleet.add_recovery("site-a", "payments");
    fleet.add_recovery("site-b", "payments");
    fleet.policy.allow_recovery_on_primary_site = true;
    fleet.add_obligation("obligation-1", "payments", 4, 1, 1, true);
    fleet.obligation().separations.push_back(kinds_rule(entry.group, {DomainKind::Power}));
    const Result<PlacementPlan> outcome = fleet.plan();
    CSP_REQUIRE(outcome.has_value());
    if (entry.refused) {
      expect_refused(outcome.value(), violation_detail("site-a", "site-a").c_str());
    } else {
      expect_planned(outcome.value(), 2);
      // The group did not cover the primary-to-recovery pair, so both placements exist
      // even though the two sites share a power feed.
      const ObligationPlacement& obligation = sole_obligation(outcome.value());
      std::size_t primaries = 0;
      std::size_t recoveries = 0;
      for (const SitePlacement& placement : obligation.placements) {
        if (placement.role == PlacementRole::Primary) {
          ++primaries;
        } else {
          ++recoveries;
        }
      }
      CSP_EXPECT_EQ(primaries, std::size_t{1});
      CSP_EXPECT_EQ(recoveries, std::size_t{1});
    }
  }

  // Two primary placements on two sites that share one power feed.
  const Case kPrimaryCases[] = {
      {SeparationGroup::All, true},
      {SeparationGroup::WithinRole, true},
      {SeparationGroup::AcrossRoles, false},
  };
  for (const Case& entry : kPrimaryCases) {
    Fleet fleet;
    fleet.add_site("site-a");
    fleet.add_site("site-b");
    fleet.add_domain("power-1", DomainKind::Power);
    fleet.add_assignment("site-a", "power-1");
    fleet.add_assignment("site-b", "power-1");
    fleet.make_hostable("payments");
    fleet.add_obligation("obligation-1", "payments", 4, 2, 0, true);
    fleet.obligation().separations.push_back(kinds_rule(entry.group, {DomainKind::Power}));
    const Result<PlacementPlan> outcome = fleet.plan();
    CSP_REQUIRE(outcome.has_value());
    if (entry.refused) {
      expect_refused(outcome.value(), violation_detail("site-a", "site-a").c_str());
    } else {
      // AcrossRoles constrains only primary-to-recovery pairs, and there are none here.
      expect_planned(outcome.value(), 2);
    }
  }

  // A control: the same primary/recovery fleet with a rule naming a kind the sites do
  // not share is planned under every group.
  const SeparationGroup kGroups[] = {SeparationGroup::All, SeparationGroup::WithinRole,
                                     SeparationGroup::AcrossRoles};
  for (const SeparationGroup group : kGroups) {
    Fleet fleet;
    fleet.add_site("site-a");
    fleet.add_site("site-b");
    fleet.add_domain("power-1", DomainKind::Power);
    fleet.add_assignment("site-a", "power-1");
    fleet.add_assignment("site-b", "power-1");
    fleet.make_hostable("payments");
    fleet.add_recovery("site-a", "payments");
    fleet.add_recovery("site-b", "payments");
    fleet.policy.allow_recovery_on_primary_site = true;
    fleet.add_obligation("obligation-1", "payments", 4, 1, 1, true);
    fleet.obligation().separations.push_back(kinds_rule(group, {DomainKind::Network}));
    const Result<PlacementPlan> outcome = fleet.plan();
    CSP_REQUIRE(outcome.has_value());
    expect_planned(outcome.value(), 2);
  }
}
