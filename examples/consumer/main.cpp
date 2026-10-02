// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// A minimal downstream consumer. It is built against an installed CrossSitePlacement
// package and nothing else, so it is the check that the installed package is usable on
// its own: it builds a two-site snapshot, places one obligation, and prints the identity
// and digest of the plan it got back.

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <cross_site_placement/cross_site_placement.hpp>

namespace {

constexpr std::int64_t kObservedAtNanos = 1700000000000000000LL;

template <class IdType>
IdType make_id(const std::string& text) {
  csp::Result<IdType> parsed = IdType::parse(text);
  if (!parsed) {
    std::cerr << "consumer: " << parsed.error().render() << '\n';
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

}  // namespace

int main() {
  const csp::ServiceClassId service = make_id<csp::ServiceClassId>("class-web");
  const csp::FailureDomainId power_one = make_id<csp::FailureDomainId>("power-one");
  const csp::FailureDomainId power_two = make_id<csp::FailureDomainId>("power-two");

  csp::SiteEvidenceSnapshot evidence;
  evidence.generation = csp::Generation::from_value(3);
  evidence.captured_at = observed_at();

  for (const csp::FailureDomainId& domain : {power_one, power_two}) {
    csp::FailureDomainRecord record;
    record.domain = domain;
    record.kind = csp::DomainKind::Power;
    record.provenance = provenance("failure-domain-registry", "domain-observation-" + domain.value(), 1);
    evidence.failure_domains.push_back(std::move(record));
  }

  const std::vector<std::pair<std::string, csp::FailureDomainId>> sites{
      {"site-one", power_one},
      {"site-two", power_two},
  };
  for (const std::pair<std::string, csp::FailureDomainId>& entry : sites) {
    const csp::SiteId site = make_id<csp::SiteId>(entry.first);

    csp::SiteRecord site_record;
    site_record.site = site;
    site_record.maintenance = csp::Measurement<csp::MaintenanceState>::known(csp::MaintenanceState::Operational);
    site_record.provenance = provenance("site-registry", "site-observation-" + entry.first, 1);
    evidence.sites.push_back(std::move(site_record));

    csp::DomainAssignment assignment;
    assignment.site = site;
    assignment.domain = entry.second;
    assignment.provenance = provenance("failure-domain-registry", "membership-" + entry.first, 1);
    evidence.domain_assignments.push_back(std::move(assignment));

    csp::CapacityRecord capacity;
    capacity.reference = make_id<csp::CapacityRefId>("capacity-" + entry.first);
    capacity.site = site;
    capacity.service_class = service;
    capacity.kind = csp::CapacityKind::Commitment;
    capacity.available = csp::Measurement<csp::Quantity>::known(csp::Quantity::from_units(8));
    capacity.provenance = provenance("capacity-authority", "capacity-observation-" + entry.first, 1);
    evidence.capacity.push_back(std::move(capacity));

    csp::CompatibilityRecord compatibility;
    compatibility.reference = make_id<csp::EvidenceId>("compatibility-" + entry.first);
    compatibility.site = site;
    compatibility.service_class = service;
    compatibility.compatible = csp::Measurement<bool>::known(true);
    compatibility.provenance = provenance("compatibility-registry", "compatibility-observation-" + entry.first, 1);
    evidence.compatibility.push_back(std::move(compatibility));
  }

  csp::PlacementPolicy policy;
  policy.policy = make_id<csp::PolicyId>("policy-consumer");
  policy.generation = csp::Generation::from_value(1);

  csp::PlacementRequest request;
  request.request = make_id<csp::RequestId>("request-consumer");
  request.generation = csp::Generation::from_value(1);
  request.policy.policy = policy.policy;
  request.policy.generation = policy.generation;

  csp::Obligation obligation;
  obligation.obligation = make_id<csp::ObligationId>("obligation-consumer");
  obligation.service_class = service;
  obligation.required_capacity = csp::Quantity::from_units(2);
  obligation.primary_placements = 1;
  request.obligations.push_back(std::move(obligation));

  const csp::Planner planner;
  csp::PlanningContext context;
  context.evaluation_instant = observed_at();
  const csp::Result<csp::PlacementPlan> planned = planner.plan(request, evidence, policy, context);
  if (!planned) {
    std::cerr << "consumer: planning failed: " << planned.error().render() << '\n';
    return 1;
  }
  const csp::PlacementPlan& plan = planned.value();
  if (!csp::plan_is_applicable(plan)) {
    std::cerr << "consumer: the plan is not applicable\n";
    return 1;
  }
  std::cout << "consumer ok\n";
  std::cout << "plan: " << plan.plan.value() << '\n';
  std::cout << "digest: " << plan.digest.to_hex() << '\n';
  return 0;
}
