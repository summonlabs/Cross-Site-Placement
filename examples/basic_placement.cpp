// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// basic_placement: build a small fleet from a snapshot, place two obligations that must
// not share a power domain, print the plan and its digest, and assert that the plan is
// applicable. Nothing here reserves anything: a plan names sites and the evidence it read.

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"

namespace {

constexpr std::int64_t kObservedAtNanos = 1700000000000000000LL;

/// Every failure in this program is a defect in the program itself, because the evidence
/// and the request are authored here. It is reported and the exit status is nonzero, so
/// a broken example cannot be mistaken for a passing one.
int fail(const std::string& message) {
  std::cerr << "basic_placement: " << message << '\n';
  return 1;
}

template <class IdType>
IdType make_id(const std::string& text) {
  csp::Result<IdType> parsed = IdType::parse(text);
  if (!parsed) {
    std::cerr << "basic_placement: " << parsed.error().render() << '\n';
    std::exit(1);
  }
  return std::move(parsed).value();
}

csp::Instant observed_at() { return csp::Instant::from_nanos(kObservedAtNanos); }

csp::Provenance provenance(const std::string& authority, const std::string& record, std::uint64_t generation) {
  csp::Provenance provenance;
  provenance.source_record = make_id<csp::EvidenceId>(record);
  provenance.authority = make_id<csp::AuthorityId>(authority);
  provenance.authority_generation = csp::Generation::from_value(generation);
  provenance.observed_at = observed_at();
  return provenance;
}

/// The site ids, in the order this example builds them.
const std::vector<std::string>& site_names() {
  static const std::vector<std::string> kNames{"site-a", "site-b", "site-c", "site-d", "site-e", "site-f"};
  return kNames;
}

/// One power domain per site, three domains across six sites, so two placements of one
/// obligation can always be separated.
const std::vector<std::string>& power_domain_names() {
  static const std::vector<std::string> kNames{"power-1", "power-2", "power-3"};
  return kNames;
}

csp::SiteEvidenceSnapshot build_fleet() {
  csp::SiteEvidenceSnapshot evidence;
  evidence.generation = csp::Generation::from_value(21);
  evidence.captured_at = observed_at();

  const csp::JurisdictionId jurisdiction = make_id<csp::JurisdictionId>("jurisdiction-north");
  const csp::ServiceClassId service = make_id<csp::ServiceClassId>("class-web");

  std::vector<csp::FailureDomainId> domains;
  for (const std::string& name : power_domain_names()) {
    domains.push_back(make_id<csp::FailureDomainId>(name));
    csp::FailureDomainRecord record;
    record.domain = domains.back();
    record.kind = csp::DomainKind::Power;
    record.provenance = provenance("failure-domain-registry", "domain-observation-" + name, 5);
    evidence.failure_domains.push_back(std::move(record));
  }

  for (std::size_t index = 0; index < site_names().size(); ++index) {
    const std::string& name = site_names()[index];
    const csp::SiteId site = make_id<csp::SiteId>(name);

    csp::SiteRecord site_record;
    site_record.site = site;
    site_record.jurisdiction = jurisdiction;
    site_record.maintenance = csp::Measurement<csp::MaintenanceState>::known(csp::MaintenanceState::Operational);
    site_record.provenance = provenance("site-registry", "site-observation-" + name, 7);
    evidence.sites.push_back(std::move(site_record));

    csp::DomainAssignment assignment;
    assignment.site = site;
    assignment.domain = domains[index % domains.size()];
    assignment.provenance = provenance("failure-domain-registry", "membership-" + name, 5);
    evidence.domain_assignments.push_back(std::move(assignment));

    csp::CapacityRecord capacity;
    capacity.reference = make_id<csp::CapacityRefId>("capacity-" + name);
    capacity.site = site;
    capacity.service_class = service;
    capacity.kind = csp::CapacityKind::Commitment;
    capacity.available = csp::Measurement<csp::Quantity>::known(csp::Quantity::from_units(64));
    capacity.provenance = provenance("capacity-authority", "capacity-observation-" + name, 7);
    evidence.capacity.push_back(std::move(capacity));

    csp::CompatibilityRecord compatibility;
    compatibility.reference = make_id<csp::EvidenceId>("compatibility-" + name);
    compatibility.site = site;
    compatibility.service_class = service;
    compatibility.compatible = csp::Measurement<bool>::known(true);
    compatibility.provenance = provenance("compatibility-registry", "compatibility-observation-" + name, 7);
    evidence.compatibility.push_back(std::move(compatibility));
  }
  return evidence;
}

csp::PlacementPolicy build_policy() {
  csp::PlacementPolicy policy;
  policy.policy = make_id<csp::PolicyId>("policy-regional-default");
  policy.generation = csp::Generation::from_value(9);
  // Everything else keeps its default, and every default here is the reading that claims
  // the least: an unreported maintenance state is not operational, an unrecorded
  // jurisdiction is not a jurisdiction, and a recovery placement may not share a site
  // with a primary one.
  return policy;
}

csp::PlacementRequest build_request(const csp::PlacementPolicy& policy) {
  csp::PlacementRequest request;
  request.request = make_id<csp::RequestId>("request-basic-placement");
  request.generation = csp::Generation::from_value(3);
  request.policy.policy = policy.policy;
  request.policy.generation = policy.generation;

  for (const char* name : {"obligation-alpha", "obligation-beta"}) {
    csp::Obligation obligation;
    obligation.obligation = make_id<csp::ObligationId>(name);
    obligation.service_class = make_id<csp::ServiceClassId>("class-web");
    obligation.required_capacity = csp::Quantity::from_units(4);
    obligation.primary_placements = 2;
    csp::SeparationRequirement separation;
    separation.group = csp::SeparationGroup::All;
    separation.separated_kinds.push_back(csp::DomainKind::Power);
    obligation.separations.push_back(std::move(separation));
    request.obligations.push_back(std::move(obligation));
  }
  return request;
}

std::string power_domain(const csp::SitePlacement& placement) {
  for (const csp::DomainRef& domain : placement.domains) {
    if (domain.kind.has_value() && *domain.kind == csp::DomainKind::Power) {
      return domain.domain.value();
    }
  }
  return std::string("<unresolved>");
}

}  // namespace

int main() {
  const csp::SiteEvidenceSnapshot evidence = build_fleet();
  const csp::PlacementPolicy policy = build_policy();
  const csp::PlacementRequest request = build_request(policy);

  const csp::Planner planner;
  csp::PlanningContext context;
  context.evaluation_instant = observed_at();
  const csp::Result<csp::PlacementPlan> planned = planner.plan(request, evidence, policy, context);
  if (!planned) {
    return fail("planning failed: " + planned.error().render());
  }
  const csp::PlacementPlan& plan = planned.value();

  std::cout << "plan: " << plan.plan.value() << '\n';
  std::cout << "outcome: " << csp::to_string(plan.outcome) << '\n';
  std::cout << "nodes explored: " << plan.nodes_explored << '\n';
  for (const csp::ObligationPlacement& entry : plan.obligations) {
    std::cout << "obligation " << entry.obligation.value() << ": " << csp::to_string(entry.outcome) << '\n';
    for (const csp::SitePlacement& placement : entry.placements) {
      std::cout << "  " << csp::to_string(placement.role) << ' ' << placement.index << ' ' << placement.site.value()
                << " in power domain " << power_domain(placement) << " carrying "
                << placement.capacity_required.units() << " units\n";
    }
  }
  std::cout << "digest: " << plan.digest.to_hex() << '\n';

  if (!csp::plan_is_applicable(plan)) {
    return fail("the plan is not applicable");
  }
  if (plan.outcome != csp::PlanOutcome::Planned) {
    return fail("the plan outcome is not planned");
  }
  if (plan.digest.is_zero()) {
    return fail("the plan carries no digest");
  }
  if (plan.obligations.size() != request.obligations.size()) {
    return fail("the plan does not cover every obligation");
  }
  for (const csp::ObligationPlacement& entry : plan.obligations) {
    if (entry.placements.size() != 2) {
      return fail("obligation " + entry.obligation.value() + " does not have two placements");
    }
    const std::string first = power_domain(entry.placements[0]);
    const std::string second = power_domain(entry.placements[1]);
    if (first == second) {
      return fail("obligation " + entry.obligation.value() + " placed two sites in one power domain");
    }
  }
  std::cout << "basic_placement ok: the plan is applicable and its placements are power-separated\n";
  return 0;
}
