// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Revalidation, from the outside.
//
// The three answers are holds, broken, and undecidable, and the cases below exist to
// pin the boundary between the last two. A fact that is now false is broken; a fact
// that can no longer be shown is undecidable, and reporting it as broken would claim a
// proof nobody has.

#include "test_harness.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"

using namespace csp;

namespace {

constexpr std::int64_t kBase = 1700000000000000000LL;
constexpr std::int64_t kMillis = 1000000LL;

SiteId site_id(const char* text) { return SiteId::parse(text).value(); }
ServiceClassId class_id(const char* text) { return ServiceClassId::parse(text).value(); }
PolicyId policy_id(const char* text) { return PolicyId::parse(text).value(); }
RequestId request_id(const char* text) { return RequestId::parse(text).value(); }
ObligationId obligation_id(const char* text) { return ObligationId::parse(text).value(); }
JurisdictionId jurisdiction_id(const char* text) { return JurisdictionId::parse(text).value(); }
FailureDomainId domain_id(const char* text) { return FailureDomainId::parse(text).value(); }
EvidenceId evidence_id(const char* text) { return EvidenceId::parse(text).value(); }
AuthorityId authority_id(const char* text) { return AuthorityId::parse(text).value(); }
CapacityRefId capacity_ref_id(const char* text) { return CapacityRefId::parse(text).value(); }
DependencyId dependency_id(const char* text) { return DependencyId::parse(text).value(); }

Provenance provenance_of(const char* record) {
  Provenance provenance;
  provenance.source_record = evidence_id(record);
  provenance.authority = authority_id("registry-authority");
  provenance.authority_generation = Generation::from_value(4);
  provenance.observed_at = Instant::from_nanos(kBase - 1000);
  return provenance;
}

SiteRecord make_site(const char* identity, const char* record) {
  SiteRecord site;
  site.site = site_id(identity);
  site.jurisdiction = jurisdiction_id("jur-1");
  site.maintenance = Measurement<MaintenanceState>::known(MaintenanceState::Operational);
  site.provenance = provenance_of(record);
  return site;
}

CapacityRecord make_capacity(const char* reference, const char* site, std::int64_t units, const char* record) {
  CapacityRecord capacity;
  capacity.reference = capacity_ref_id(reference);
  capacity.site = site_id(site);
  capacity.service_class = class_id("service-1");
  capacity.kind = CapacityKind::Commitment;
  capacity.available = Measurement<Quantity>::known(Quantity::from_units(units));
  capacity.provenance = provenance_of(record);
  return capacity;
}

CompatibilityRecord make_compatibility(const char* reference, const char* site, const char* record) {
  CompatibilityRecord compatibility;
  compatibility.reference = evidence_id(reference);
  compatibility.site = site_id(site);
  compatibility.service_class = class_id("service-1");
  compatibility.compatible = Measurement<bool>::known(true);
  compatibility.provenance = provenance_of(record);
  return compatibility;
}

LatencyRecord make_latency(const char* reference, const char* from, const char* to, std::int64_t nanos,
                           const char* record) {
  LatencyRecord latency;
  latency.reference = dependency_id(reference);
  latency.from_site = site_id(from);
  latency.to_site = site_id(to);
  latency.statistic = LatencyStatistic::Max;
  latency.latency = Measurement<Duration>::known(Duration::from_nanos(nanos));
  latency.provenance = provenance_of(record);
  return latency;
}

struct Scenario {
  PlacementRequest request;
  SiteEvidenceSnapshot snapshot;
  PlacementPolicy policy;
  PlanningContext context;
};

/// Two sites, well separated, each with capacity and compatibility, and a latency
/// requirement against a service that already runs elsewhere. Every fact the plan rests
/// on is therefore a separate record a case can remove or alter.
Scenario make_scenario(std::int64_t validity_nanos) {
  Scenario scenario;
  scenario.context.evaluation_instant = Instant::from_nanos(kBase);

  scenario.policy.policy = policy_id("policy-1");
  scenario.policy.generation = Generation::from_value(1);

  scenario.snapshot.generation = Generation::from_value(11);
  scenario.snapshot.captured_at = Instant::from_nanos(kBase - 1000);
  scenario.snapshot.sites.push_back(make_site("site-1", "site-record-1"));
  scenario.snapshot.sites.push_back(make_site("site-2", "site-record-2"));

  FailureDomainRecord first;
  first.domain = domain_id("domain-a");
  first.kind = DomainKind::Power;
  first.provenance = provenance_of("domain-record-a");
  scenario.snapshot.failure_domains.push_back(std::move(first));
  FailureDomainRecord second;
  second.domain = domain_id("domain-b");
  second.kind = DomainKind::Power;
  second.provenance = provenance_of("domain-record-b");
  scenario.snapshot.failure_domains.push_back(std::move(second));

  DomainAssignment assignment;
  assignment.site = site_id("site-1");
  assignment.domain = domain_id("domain-a");
  assignment.provenance = provenance_of("assignment-record-a");
  scenario.snapshot.domain_assignments.push_back(std::move(assignment));
  DomainAssignment other;
  other.site = site_id("site-2");
  other.domain = domain_id("domain-b");
  other.provenance = provenance_of("assignment-record-b");
  scenario.snapshot.domain_assignments.push_back(std::move(other));

  scenario.snapshot.capacity.push_back(make_capacity("capacity-1", "site-1", 20, "capacity-record-1"));
  scenario.snapshot.capacity.push_back(make_capacity("capacity-2", "site-2", 20, "capacity-record-2"));
  scenario.snapshot.compatibility.push_back(
      make_compatibility("compatibility-1", "site-1", "compatibility-record-1"));
  scenario.snapshot.compatibility.push_back(
      make_compatibility("compatibility-2", "site-2", "compatibility-record-2"));
  scenario.snapshot.latency.push_back(
      make_latency("latency-1", "site-1", "peer-site-1", 5 * kMillis, "latency-record-1"));
  scenario.snapshot.latency.push_back(
      make_latency("latency-2", "site-2", "peer-site-1", 5 * kMillis, "latency-record-2"));

  scenario.request.request = request_id("request-1");
  scenario.request.generation = Generation::from_value(1);
  scenario.request.policy.policy = policy_id("policy-1");
  scenario.request.policy.generation = Generation::from_value(1);
  scenario.request.validity.validity_nanos = validity_nanos;

  Obligation obligation;
  obligation.obligation = obligation_id("obligation-1");
  obligation.service_class = class_id("service-1");
  obligation.required_capacity = Quantity::from_units(10);
  obligation.primary_placements = 2;

  SeparationRequirement separation;
  separation.group = SeparationGroup::All;
  separation.separated_kinds.push_back(DomainKind::Power);
  obligation.separations.push_back(std::move(separation));

  LatencyRequirement latency;
  latency.peer.kind = DependencyEndpoint::Kind::SiteService;
  latency.peer.site = site_id("peer-site-1");
  latency.peer.service_class = class_id("service-1");
  latency.direction = LatencyDirection::FromPlacement;
  latency.statistic = LatencyStatistic::Max;
  latency.max_latency = Duration::from_nanos(10 * kMillis);
  latency.applies_to = PlacementRole::Primary;
  obligation.latency_requirements.push_back(std::move(latency));

  scenario.request.obligations.push_back(std::move(obligation));
  return scenario;
}

Result<PlacementPlan> plan_scenario(const Scenario& scenario) {
  const Planner planner;
  return planner.plan(scenario.request, scenario.snapshot, scenario.policy, scenario.context);
}

Result<RevalidationReport> revalidate_at(const Scenario& scenario, const PlacementPlan& plan,
                                         std::int64_t evaluation_nanos) {
  PlanningContext context;
  context.evaluation_instant = Instant::from_nanos(evaluation_nanos);
  return plan_revalidate(plan, scenario.request, scenario.snapshot, scenario.policy, context);
}

bool has_finding(const RevalidationReport& report, const char* condition, Tri outcome) {
  for (const RevalidationFinding& finding : report.findings) {
    if (finding.condition == condition && finding.outcome == outcome) {
      return true;
    }
  }
  return false;
}

std::string describe(const RevalidationReport& report) {
  std::string text = std::string("verdict ") + to_string(report.verdict);
  if (report.expired) {
    text += " expired";
  }
  for (const RevalidationFinding& finding : report.findings) {
    text += " | ";
    text += finding.condition;
    text += "=";
    text += to_string(finding.outcome);
  }
  return text;
}

}  // namespace

CSP_TEST(revalidate, same_snapshot_and_policy_holds) {
  const Scenario scenario = make_scenario(0);
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);
  CSP_REQUIRE(planned.value().obligations.size() == 1);
  CSP_REQUIRE(planned.value().obligations[0].placements.size() == 2);
  CSP_REQUIRE(planned.value().obligations[0].latency.size() == 2);

  Result<RevalidationReport> report = revalidate_at(scenario, planned.value(), kBase + 1000);
  CSP_REQUIRE(report.has_value());
  CSP_EXPECT_MSG(report.value().verdict == RevalidationVerdict::Holds, describe(report.value()));
  CSP_EXPECT(!report.value().expired);
  CSP_EXPECT_EQ(report.value().plan.value(), planned.value().plan.value());
  CSP_EXPECT_EQ(report.value().plan_digest.to_hex(), planned.value().digest.to_hex());
  CSP_EXPECT_EQ(report.value().evidence_generation.value(), std::uint64_t{11});
  CSP_EXPECT_EQ(report.value().policy_generation.value(), std::uint64_t{1});
}

CSP_TEST(revalidate, removed_site_is_broken_and_names_the_condition) {
  const Scenario scenario = make_scenario(0);
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);

  Scenario current = scenario;
  current.snapshot.sites.erase(current.snapshot.sites.begin());  // site-1 is no longer described
  current.snapshot.generation = Generation::from_value(12);

  Result<RevalidationReport> report = revalidate_at(current, planned.value(), kBase + 1000);
  CSP_REQUIRE(report.has_value());
  CSP_EXPECT_MSG(report.value().verdict == RevalidationVerdict::Broken, describe(report.value()));
  CSP_EXPECT_MSG(has_finding(report.value(), "csp.revalidate.site-removed", Tri::Violated),
                 describe(report.value()));
  CSP_EXPECT(!report.value().expired);
}

CSP_TEST(revalidate, offline_maintenance_is_broken) {
  const Scenario scenario = make_scenario(0);
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);

  Scenario current = scenario;
  current.snapshot.sites[0].maintenance = Measurement<MaintenanceState>::known(MaintenanceState::Offline);
  current.snapshot.generation = Generation::from_value(12);

  Result<RevalidationReport> report = revalidate_at(current, planned.value(), kBase + 1000);
  CSP_REQUIRE(report.has_value());
  CSP_EXPECT_MSG(report.value().verdict == RevalidationVerdict::Broken, describe(report.value()));
  CSP_EXPECT_MSG(has_finding(report.value(), "csp.revalidate.maintenance", Tri::Violated),
                 describe(report.value()));
}

CSP_TEST(revalidate, capacity_below_the_requirement_is_broken) {
  const Scenario scenario = make_scenario(0);
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);

  Scenario current = scenario;
  current.snapshot.capacity[0].available = Measurement<Quantity>::known(Quantity::from_units(1));
  current.snapshot.generation = Generation::from_value(12);

  Result<RevalidationReport> report = revalidate_at(current, planned.value(), kBase + 1000);
  CSP_REQUIRE(report.has_value());
  CSP_EXPECT_MSG(report.value().verdict == RevalidationVerdict::Broken, describe(report.value()));
  CSP_EXPECT_MSG(has_finding(report.value(), "csp.revalidate.capacity", Tri::Violated), describe(report.value()));
}

CSP_TEST(revalidate, removed_latency_record_is_undecidable_not_broken) {
  const Scenario scenario = make_scenario(0);
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);

  Scenario current = scenario;
  current.snapshot.latency.clear();
  current.snapshot.generation = Generation::from_value(12);

  Result<RevalidationReport> report = revalidate_at(current, planned.value(), kBase + 1000);
  CSP_REQUIRE(report.has_value());
  CSP_EXPECT_MSG(report.value().verdict == RevalidationVerdict::Undecidable, describe(report.value()));
  CSP_EXPECT_MSG(has_finding(report.value(), "csp.revalidate.latency", Tri::Indeterminate),
                 describe(report.value()));
  CSP_EXPECT(!has_finding(report.value(), "csp.revalidate.latency", Tri::Violated));
}

CSP_TEST(revalidate, removed_domain_assignment_is_undecidable_not_broken) {
  const Scenario scenario = make_scenario(0);
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);

  Scenario current = scenario;
  // site-2 is still described; where it sits is no longer recorded, so separation
  // between the two placements cannot be shown either way.
  current.snapshot.domain_assignments.pop_back();
  current.snapshot.generation = Generation::from_value(12);

  Result<RevalidationReport> report = revalidate_at(current, planned.value(), kBase + 1000);
  CSP_REQUIRE(report.has_value());
  CSP_EXPECT_MSG(report.value().verdict == RevalidationVerdict::Undecidable, describe(report.value()));
  CSP_EXPECT_MSG(has_finding(report.value(), "csp.revalidate.separation", Tri::Indeterminate),
                 describe(report.value()));
  CSP_EXPECT(!has_finding(report.value(), "csp.revalidate.separation", Tri::Violated));
}

CSP_TEST(revalidate, expired_plan_is_reported_expired_and_broken) {
  const Scenario scenario = make_scenario(1000 * kMillis);  // a one second validity window
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);
  CSP_REQUIRE(!planned.value().envelope.valid_until.is_zero());
  CSP_EXPECT_EQ(planned.value().envelope.valid_until.nanos(), kBase + 1000 * kMillis);

  Result<RevalidationReport> report = revalidate_at(scenario, planned.value(), kBase + 2000 * kMillis);
  CSP_REQUIRE(report.has_value());
  CSP_EXPECT(report.value().expired);
  CSP_EXPECT_MSG(report.value().verdict == RevalidationVerdict::Broken, describe(report.value()));
  CSP_EXPECT_MSG(has_finding(report.value(), "csp.revalidate.plan-expiry", Tri::Violated),
                 describe(report.value()));

  // Within its own window the same check does not report expiry.
  Result<RevalidationReport> within = revalidate_at(scenario, planned.value(), kBase + 10);
  CSP_REQUIRE(within.has_value());
  CSP_EXPECT(!within.value().expired);
}

CSP_TEST(revalidate, policy_of_another_identity_is_broken) {
  const Scenario scenario = make_scenario(0);
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);

  Scenario current = scenario;
  current.policy.policy = policy_id("policy-2");

  Result<RevalidationReport> report = revalidate_at(current, planned.value(), kBase + 1000);
  CSP_REQUIRE(report.has_value());
  CSP_EXPECT_MSG(report.value().verdict == RevalidationVerdict::Broken, describe(report.value()));
  CSP_EXPECT_MSG(has_finding(report.value(), "csp.revalidate.policy-identity", Tri::Violated),
                 describe(report.value()));
}

CSP_TEST(revalidate, newer_policy_generation_is_undecidable) {
  const Scenario scenario = make_scenario(0);
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);

  Scenario current = scenario;
  current.policy.generation = Generation::from_value(2);
  current.snapshot.generation = Generation::from_value(11);

  Result<RevalidationReport> report = revalidate_at(current, planned.value(), kBase + 1000);
  CSP_REQUIRE(report.has_value());
  CSP_EXPECT_MSG(report.value().verdict == RevalidationVerdict::Undecidable, describe(report.value()));
  CSP_EXPECT_MSG(has_finding(report.value(), "csp.revalidate.policy-generation", Tri::Indeterminate),
                 describe(report.value()));
  CSP_EXPECT_EQ(report.value().policy_generation.value(), std::uint64_t{2});
}

CSP_TEST(revalidate, a_different_request_is_a_conflict) {
  const Scenario scenario = make_scenario(0);
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);

  PlacementRequest other = scenario.request;
  other.request = request_id("request-2");
  PlanningContext context;
  context.evaluation_instant = Instant::from_nanos(kBase + 1000);

  Result<RevalidationReport> wrong_identity =
      plan_revalidate(planned.value(), other, scenario.snapshot, scenario.policy, context);
  CSP_EXPECT(!wrong_identity.has_value());
  if (!wrong_identity.has_value()) {
    CSP_EXPECT(wrong_identity.error().category() == ErrorCategory::Conflict);
    CSP_EXPECT_EQ(wrong_identity.error().code(), std::string("csp.revalidate.wrong_request"));
  }

  PlacementRequest other_generation = scenario.request;
  other_generation.generation = Generation::from_value(2);
  Result<RevalidationReport> wrong_generation =
      plan_revalidate(planned.value(), other_generation, scenario.snapshot, scenario.policy, context);
  CSP_EXPECT(!wrong_generation.has_value());
  if (!wrong_generation.has_value()) {
    CSP_EXPECT(wrong_generation.error().category() == ErrorCategory::Conflict);
    CSP_EXPECT_EQ(wrong_generation.error().code(), std::string("csp.revalidate.wrong_request"));
  }
}

CSP_TEST(revalidate, digest_that_does_not_match_content_is_integrity) {
  const Scenario scenario = make_scenario(0);
  Result<PlacementPlan> planned = plan_scenario(scenario);
  CSP_REQUIRE(planned.has_value());
  CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);

  PlacementPlan altered = planned.value();
  altered.nodes_explored += 1;  // the content moved; the digest and identity did not
  PlanningContext context;
  context.evaluation_instant = Instant::from_nanos(kBase + 1000);

  Result<RevalidationReport> report =
      plan_revalidate(altered, scenario.request, scenario.snapshot, scenario.policy, context);
  CSP_EXPECT(!report.has_value());
  if (!report.has_value()) {
    CSP_EXPECT(report.error().category() == ErrorCategory::Integrity);
    CSP_EXPECT_EQ(report.error().code(), std::string("csp.revalidate.digest_mismatch"));
  }

  // A plan with no digest at all has nothing to revalidate against, and says so rather
  // than re-deriving one and calling the result a check.
  PlacementPlan unsealed = planned.value();
  unsealed.digest = Digest{};
  Result<RevalidationReport> missing =
      plan_revalidate(unsealed, scenario.request, scenario.snapshot, scenario.policy, context);
  CSP_EXPECT(!missing.has_value());
  if (!missing.has_value()) {
    CSP_EXPECT(missing.error().category() == ErrorCategory::Invalid);
    CSP_EXPECT_EQ(missing.error().code(), std::string("csp.revalidate.no_digest"));
  }
}
