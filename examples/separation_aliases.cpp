// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// separation_aliases: two sites that look independent under two domain names but are one
// power domain through an alias record. Aliasing is the ordinary case, not a curiosity:
// two registries using two names for one feed is exactly how a separation rule gets
// satisfied by accident when aliases are ignored.
//
// The example shows three things, each against the same two sites:
//   * the merge itself, by placing one obligation on both sites with no separation rule
//     and reading the resolved power domain out of the plan;
//   * the separation rule refusing that same arrangement once it is asked for;
//   * what changes when the alias is absent - the same request is then placed, on two
//     sites the evidence calls two different power domains.

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"

namespace {

constexpr std::int64_t kObservedAtNanos = 1700000000000000000LL;

int fail(const std::string& message) {
  std::cerr << "separation_aliases: " << message << '\n';
  return 1;
}

template <class IdType>
IdType make_id(const std::string& text) {
  csp::Result<IdType> parsed = IdType::parse(text);
  if (!parsed) {
    std::cerr << "separation_aliases: " << parsed.error().render() << '\n';
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

/// The two names one feed is known by in two registries.
const std::string kPowerNorth = "power-north";
const std::string kPowerFeedNorth = "power-feed-north";

csp::SiteEvidenceSnapshot build_fleet(bool with_alias) {
  csp::SiteEvidenceSnapshot evidence;
  evidence.generation = csp::Generation::from_value(with_alias ? 41 : 42);
  evidence.captured_at = observed_at();

  const csp::JurisdictionId jurisdiction = make_id<csp::JurisdictionId>("jurisdiction-north");
  const csp::ServiceClassId service = make_id<csp::ServiceClassId>("class-web");
  const csp::FailureDomainId north = make_id<csp::FailureDomainId>(kPowerNorth);
  const csp::FailureDomainId feed = make_id<csp::FailureDomainId>(kPowerFeedNorth);

  for (const csp::FailureDomainId& domain : {north, feed}) {
    csp::FailureDomainRecord record;
    record.domain = domain;
    record.kind = csp::DomainKind::Power;
    record.provenance = provenance("failure-domain-registry", "domain-observation-" + domain.value(), 5);
    evidence.failure_domains.push_back(std::move(record));
  }
  if (with_alias) {
    csp::DomainAliasRecord alias;
    alias.domain = feed;
    alias.alias_of = north;
    alias.provenance = provenance("failure-domain-registry", "alias-observation-power-feed-north", 6);
    evidence.domain_aliases.push_back(std::move(alias));
  }

  const std::vector<std::pair<std::string, csp::FailureDomainId>> assignments{
      {"site-north-hall", north},
      {"site-south-hall", feed},
  };
  for (const std::pair<std::string, csp::FailureDomainId>& assignment_entry : assignments) {
    const std::string& name = assignment_entry.first;
    const csp::SiteId site = make_id<csp::SiteId>(name);

    csp::SiteRecord site_record;
    site_record.site = site;
    site_record.jurisdiction = jurisdiction;
    site_record.maintenance = csp::Measurement<csp::MaintenanceState>::known(csp::MaintenanceState::Operational);
    site_record.provenance = provenance("site-registry", "site-observation-" + name, 7);
    evidence.sites.push_back(std::move(site_record));

    csp::DomainAssignment domain_assignment;
    domain_assignment.site = site;
    domain_assignment.domain = assignment_entry.second;
    domain_assignment.provenance = provenance("failure-domain-registry", "membership-" + name, 5);
    evidence.domain_assignments.push_back(std::move(domain_assignment));

    csp::CapacityRecord capacity;
    capacity.reference = make_id<csp::CapacityRefId>("capacity-" + name);
    capacity.site = site;
    capacity.service_class = service;
    capacity.kind = csp::CapacityKind::Commitment;
    capacity.available = csp::Measurement<csp::Quantity>::known(csp::Quantity::from_units(32));
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

/// One obligation with two primary placements. When separated is true it also carries the
/// requirement that the two placements must not share a power domain.
csp::PlacementRequest build_request(const csp::PlacementPolicy& policy, bool separated,
                                    const std::string& name) {
  csp::PlacementRequest request;
  request.request = make_id<csp::RequestId>(name);
  request.generation = csp::Generation::from_value(5);
  request.policy.policy = policy.policy;
  request.policy.generation = policy.generation;

  csp::Obligation obligation;
  obligation.obligation = make_id<csp::ObligationId>("obligation-replica");
  obligation.service_class = make_id<csp::ServiceClassId>("class-web");
  obligation.required_capacity = csp::Quantity::from_units(4);
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

csp::Result<csp::PlacementPlan> place(const csp::SiteEvidenceSnapshot& evidence, const csp::PlacementPolicy& policy,
                                      const csp::PlacementRequest& request) {
  const csp::Planner planner;
  csp::PlanningContext context;
  context.evaluation_instant = observed_at();
  return planner.plan(request, evidence, policy, context);
}

std::string power_domain(const csp::SitePlacement& placement) {
  for (const csp::DomainRef& domain : placement.domains) {
    if (domain.kind.has_value() && *domain.kind == csp::DomainKind::Power) {
      return domain.domain.value();
    }
  }
  return std::string("<unresolved>");
}

/// The resolved power domain of every placement in a one-obligation plan, in plan order.
std::vector<std::string> resolved_power_domains(const csp::PlacementPlan& plan) {
  std::vector<std::string> domains;
  for (const csp::ObligationPlacement& entry : plan.obligations) {
    for (const csp::SitePlacement& placement : entry.placements) {
      domains.push_back(power_domain(placement));
    }
  }
  return domains;
}

}  // namespace

int main() {
  const csp::PlacementPolicy policy = build_policy();
  const csp::SiteEvidenceSnapshot aliased = build_fleet(true);
  const csp::SiteEvidenceSnapshot unaliased = build_fleet(false);
  const csp::PlacementRequest unconstrained = build_request(policy, false, "request-alias-merge");
  const csp::PlacementRequest separated = build_request(policy, true, "request-alias-separation");

  // 1. The merge, read out of a plan that places both sites because nothing forbids it.
  const csp::Result<csp::PlacementPlan> merged = place(aliased, policy, unconstrained);
  if (!merged) {
    return fail("planning the alias-merge request failed: " + merged.error().render());
  }
  const std::vector<std::string> merged_domains = resolved_power_domains(merged.value());
  if (!csp::plan_is_applicable(merged.value()) || merged_domains.size() != 2) {
    return fail("the alias-merge request did not place two sites");
  }
  std::cout << "both sites under the alias, with no separation requirement:\n";
  for (const csp::ObligationPlacement& entry : merged.value().obligations) {
    for (const csp::SitePlacement& placement : entry.placements) {
      std::cout << "  " << placement.site.value() << " resolves to power domain " << power_domain(placement)
                << '\n';
    }
  }
  if (merged_domains[0] != merged_domains[1]) {
    return fail("the alias did not merge the two domain names into one resolved power domain");
  }

  // 2. The rule catches it.
  const csp::Result<csp::PlacementPlan> refused = place(aliased, policy, separated);
  if (!refused) {
    return fail("planning the separated request failed: " + refused.error().render());
  }
  std::cout << "the same two sites with a power-domain separation requirement:\n";
  std::cout << "  outcome: " << csp::to_string(refused.value().outcome) << '\n';
  if (refused.value().refusal.has_value()) {
    std::cout << "  refusal: " << csp::to_string(refused.value().refusal->category) << ": "
              << refused.value().refusal->code << ": " << refused.value().refusal->detail << '\n';
  }
  if (refused.value().outcome != csp::PlanOutcome::Refused) {
    return fail("the planner placed two replicas on one feed under two names");
  }

  // 3. The same request without the alias.
  const csp::Result<csp::PlacementPlan> separate = place(unaliased, policy, separated);
  if (!separate) {
    return fail("planning the unaliased snapshot failed: " + separate.error().render());
  }
  const std::vector<std::string> separate_domains = resolved_power_domains(separate.value());
  std::cout << "the same request with the alias absent:\n";
  std::cout << "  outcome: " << csp::to_string(separate.value().outcome) << '\n';
  for (const csp::ObligationPlacement& entry : separate.value().obligations) {
    for (const csp::SitePlacement& placement : entry.placements) {
      std::cout << "  " << placement.site.value() << " resolves to power domain " << power_domain(placement)
                << '\n';
    }
  }
  std::cout << "  digest: " << separate.value().digest.to_hex() << '\n';
  if (!csp::plan_is_applicable(separate.value()) || separate_domains.size() != 2) {
    return fail("the plan made without the alias does not carry two placements");
  }
  if (separate_domains[0] == separate_domains[1]) {
    return fail("without the alias the two sites still resolve to one power domain");
  }
  // The two snapshots differ in exactly one record, so the difference between refusing and
  // placing is the alias and nothing else.
  if (aliased.domain_aliases.size() != 1 || !unaliased.domain_aliases.empty()) {
    return fail("the two snapshots differ in something other than the alias record");
  }
  std::cout << "separation_aliases ok: the alias makes two names one power domain, the rule refuses that, and "
               "the same request is placed once the alias is absent\n";
  return 0;
}
