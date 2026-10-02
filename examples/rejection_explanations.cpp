// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// rejection_explanations: construct a request that cannot be satisfied and print what the
// planner refused, which rule decided it, and the residual shortfall. The refusal is the
// point, so this example exits 0 when the refusal is exactly what it expected: a refusal
// is an answer, not a failure of the call.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"

namespace {

constexpr std::int64_t kObservedAtNanos = 1700000000000000000LL;
constexpr std::int64_t kRequiredCapacity = 8;

int fail(const std::string& message) {
  std::cerr << "rejection_explanations: " << message << '\n';
  return 1;
}

template <class IdType>
IdType make_id(const std::string& text) {
  csp::Result<IdType> parsed = IdType::parse(text);
  if (!parsed) {
    std::cerr << "rejection_explanations: " << parsed.error().render() << '\n';
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

/// Two sites, one power domain. Everything else about them is in order: both report a
/// known operational maintenance state, both are compatible with the service class, and
/// both evidence more than enough capacity. The only fact that stands in the way of the
/// request is that they are the same power domain, which is exactly the fact the request
/// asks about.
csp::SiteEvidenceSnapshot build_fleet() {
  csp::SiteEvidenceSnapshot evidence;
  evidence.generation = csp::Generation::from_value(31);
  evidence.captured_at = observed_at();

  const csp::FailureDomainId power = make_id<csp::FailureDomainId>("power-single");
  const csp::JurisdictionId jurisdiction = make_id<csp::JurisdictionId>("jurisdiction-north");
  const csp::ServiceClassId service = make_id<csp::ServiceClassId>("class-web");
  const std::vector<std::string> names{"site-north", "site-south"};

  csp::FailureDomainRecord domain;
  domain.domain = power;
  domain.kind = csp::DomainKind::Power;
  domain.provenance = provenance("failure-domain-registry", "domain-observation-power-single", 5);
  evidence.failure_domains.push_back(std::move(domain));

  for (const std::string& name : names) {
    const csp::SiteId site = make_id<csp::SiteId>(name);

    csp::SiteRecord site_record;
    site_record.site = site;
    site_record.jurisdiction = jurisdiction;
    site_record.maintenance = csp::Measurement<csp::MaintenanceState>::known(csp::MaintenanceState::Operational);
    site_record.provenance = provenance("site-registry", "site-observation-" + name, 7);
    evidence.sites.push_back(std::move(site_record));

    csp::DomainAssignment assignment;
    assignment.site = site;
    assignment.domain = power;
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
  return policy;
}

csp::Result<csp::PlacementPlan> place(const csp::SiteEvidenceSnapshot& evidence, const csp::PlacementPolicy& policy,
                                      const csp::PlacementRequest& request) {
  const csp::Planner planner;
  csp::PlanningContext context;
  context.evaluation_instant = observed_at();
  return planner.plan(request, evidence, policy, context);
}

/// One obligation that needs two placements. When separated is true it also carries the
/// requirement that the two placements must not share a power domain, and with two sites
/// that share one domain that requirement cannot be met.
csp::PlacementRequest build_request(const csp::PlacementPolicy& policy, bool separated,
                                    const std::string& name) {
  csp::PlacementRequest request;
  request.request = make_id<csp::RequestId>(name);
  request.generation = csp::Generation::from_value(4);
  request.policy.policy = policy.policy;
  request.policy.generation = policy.generation;

  csp::Obligation obligation;
  obligation.obligation = make_id<csp::ObligationId>("obligation-echo");
  obligation.service_class = make_id<csp::ServiceClassId>("class-web");
  obligation.required_capacity = csp::Quantity::from_units(kRequiredCapacity);
  obligation.primary_placements = 2;
  if (separated) {
    csp::SeparationRequirement separation;
    separation.group = csp::SeparationGroup::All;
    separation.separated_kinds.push_back(csp::DomainKind::Power);
    obligation.separations.push_back(std::move(separation));
  }
  request.obligations.push_back(std::move(obligation));
  return request;
}

/// The rule this request cannot satisfy. The rule token is what a reader looks up in
/// Planner::rule_tokens() to see where that check sits in the evaluation order.
constexpr const char* kDecidingRule = "csp.rule.failure-domain-separation";

bool rule_is_published() {
  const std::vector<std::string>& tokens = csp::Planner::rule_tokens();
  return std::find(tokens.begin(), tokens.end(), std::string(kDecidingRule)) != tokens.end();
}

}  // namespace

int main() {
  const csp::SiteEvidenceSnapshot evidence = build_fleet();
  const csp::PlacementPolicy policy = build_policy();
  const csp::PlacementRequest request = build_request(policy, true, "request-impossible-separation");

  const csp::Result<csp::PlacementPlan> planned = place(evidence, policy, request);
  if (!planned) {
    return fail("planning failed instead of refusing: " + planned.error().render());
  }
  const csp::PlacementPlan& plan = planned.value();

  std::cout << "plan: " << plan.plan.value() << '\n';
  std::cout << "outcome: " << csp::to_string(plan.outcome) << '\n';
  if (plan.refusal.has_value()) {
    std::cout << "refusal: " << csp::to_string(plan.refusal->category) << ": " << plan.refusal->code << ": "
              << plan.refusal->detail << '\n';
  }
  for (const csp::ObligationPlacement& entry : plan.obligations) {
    std::cout << "obligation " << entry.obligation.value() << ": " << csp::to_string(entry.outcome);
    if (!entry.refusal_code.empty()) {
      std::cout << " [" << entry.refusal_code << ']';
    }
    std::cout << '\n';
    if (!entry.detail.empty()) {
      std::cout << "  detail: " << entry.detail << '\n';
    }
  }
  std::cout << "deciding rule: " << kDecidingRule << " (published by this build: "
            << (rule_is_published() ? "yes" : "no") << ")\n";
  std::cout << "residual requirements: " << plan.residual.size() << '\n';
  for (const csp::ResidualRequirement& residual : plan.residual) {
    std::cout << "  obligation " << residual.obligation.value() << " requirement " << residual.requirement
              << " shortfall " << residual.shortfall.units() << " units, " << residual.placements_short
              << " placements short\n";
  }
  std::cout << "digest of the refusal: " << plan.digest.to_hex() << '\n';

  if (plan.outcome != csp::PlanOutcome::Refused) {
    return fail("the planner did not refuse this request, so the example demonstrates nothing");
  }
  if (csp::plan_is_applicable(plan)) {
    return fail("a refused plan is reported as applicable");
  }
  if (!plan.refusal.has_value()) {
    return fail("a refused plan carries no refusal to explain why");
  }
  if (!rule_is_published()) {
    return fail(std::string("the rule the example names is not published by this build: ") + kDecidingRule);
  }
  if (plan.residual.size() != 1 || plan.residual.front().placements_short != 2 ||
      plan.residual.front().shortfall.units() != 2 * kRequiredCapacity) {
    return fail("the residual shortfall does not state the two missing placements");
  }

  // What the plan reports first is a property of the search order: the second placement
  // tries the first candidate, which is the site the first placement already occupies.
  // The fact that makes the request impossible is the separation requirement, and the
  // only way to show that rather than assert it is to remove the requirement and watch
  // the identical request be placed.
  const csp::PlacementRequest unseparated = build_request(policy, false, "request-possible-without-separation");
  const csp::Result<csp::PlacementPlan> placed = place(evidence, policy, unseparated);
  if (!placed) {
    return fail("planning without the separation requirement failed: " + placed.error().render());
  }
  std::cout << "the same request with the separation requirement removed: "
            << csp::to_string(placed.value().outcome) << " at "
            << placed.value().plan.value() << '\n';
  if (!csp::plan_is_applicable(placed.value())) {
    return fail("the request without the separation requirement was not placed, so the example does not "
                "isolate the separation rule as the cause of the refusal");
  }
  std::cout << "rejection_explanations ok: the separation rule is what makes the request impossible, and only "
               "that rule\n";
  return 0;
}
