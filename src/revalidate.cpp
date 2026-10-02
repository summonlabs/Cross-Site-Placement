// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Revalidation.
//
// A plan is a statement about a world that moves. This asks a narrow question: does the
// plan still hold against a newer snapshot and policy? It answers holds, broken, or
// undecidable, and the third is not a synonym for either of the others. Nothing here
// produces a new plan and nothing here modifies the old one.

#include "cross_site_placement/revalidate.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "engine_internal.hpp"

namespace csp {
namespace {

constexpr std::array<std::pair<RevalidationVerdict, const char*>, 3> kVerdicts{{
    {RevalidationVerdict::Holds, "holds"},
    {RevalidationVerdict::Broken, "broken"},
    {RevalidationVerdict::Undecidable, "undecidable"},
}};

Status push_finding(RevalidationReport& report, const Limits& limits, const char* condition, Tri outcome,
                    std::string detail) {
  if (report.findings.size() >= limits.max_trace_entries) {
    return fail(ErrorCategory::BoundExceeded, "csp.revalidate.bound_exceeded",
                "the revalidation findings reached the configured bound");
  }
  RevalidationFinding finding;
  finding.condition = condition;
  finding.outcome = outcome;
  finding.detail = std::move(detail);
  report.findings.push_back(std::move(finding));
  return success();
}

bool placement_is_usable(const detail::EvidenceIndex& index, std::size_t site_index,
                         const PlacementPolicy& policy) {
  const Measurement<MaintenanceState>& state = index.sites[site_index].site.maintenance;
  if (!state.is_known()) {
    return policy.allow_unknown_maintenance_state;
  }
  if (state.value() == MaintenanceState::Operational) {
    return true;
  }
  return policy.allow_degraded_sites && state.value() == MaintenanceState::Degraded;
}

}  // namespace

const char* to_string(RevalidationVerdict verdict) noexcept {
  switch (verdict) {
    case RevalidationVerdict::Holds:
      return "holds";
    case RevalidationVerdict::Broken:
      return "broken";
    case RevalidationVerdict::Undecidable:
    default:
      return "undecidable";
  }
}

std::optional<RevalidationVerdict> revalidation_verdict_from_string(std::string_view token) noexcept {
  for (const auto& entry : kVerdicts) {
    if (token == entry.second) {
      return entry.first;
    }
  }
  return std::nullopt;
}

Result<RevalidationReport> plan_revalidate(const PlacementPlan& plan, const PlacementRequest& request,
                                           const SiteEvidenceSnapshot& current,
                                           const PlacementPolicy& current_policy,
                                           const PlanningContext& context) {
  const Limits limits;
  Status status = plan_validate(plan, limits);
  if (!status) {
    return status.error();
  }
  if (plan.digest.is_zero()) {
    return fail(ErrorCategory::Invalid, "csp.revalidate.no_digest",
                "the plan carries no digest, so there is nothing to revalidate against");
  }
  if (plan_compute_digest(plan) != plan.digest) {
    return fail(ErrorCategory::Integrity, "csp.revalidate.digest_mismatch",
                "the plan digest does not match its content, so the plan has been altered");
  }
  if (request.request != plan.request || request.generation != plan.request_generation) {
    return fail(ErrorCategory::Conflict, "csp.revalidate.wrong_request",
                "the request supplied is not the request this plan answered");
  }
  if (!context.evaluation_instant.is_zero() && !plan.envelope.evaluated_at.is_zero() &&
      context.evaluation_instant < plan.envelope.evaluated_at) {
    return fail(ErrorCategory::Invalid, "csp.revalidate.time_travel",
                "the evaluation instant precedes the plan's own, so the check would be against an older world");
  }

  status = request_validate(request, limits);
  if (!status) {
    return status.error();
  }
  status = snapshot_validate(current, limits);
  if (!status) {
    return status.error();
  }
  Result<detail::EvidenceIndex> built = detail::build_index(current, limits);
  if (!built) {
    return built.error();
  }
  const detail::EvidenceIndex& index = built.value();

  detail::WorkBudget budget(limits.max_search_nodes);
  RevalidationReport report;
  report.plan = plan.plan;
  report.plan_digest = plan.digest;
  report.evidence_generation = current.generation;
  report.policy_generation = current_policy.generation;

  if (!plan.envelope.valid_until.is_zero() && !context.evaluation_instant.is_zero() &&
      context.evaluation_instant > plan.envelope.valid_until) {
    report.expired = true;
    status = push_finding(report, limits, "csp.revalidate.plan-expiry", Tri::Violated,
                          "the plan's own validity window has closed at the evaluation instant");
    if (!status) {
      return status.error();
    }
  }

  if (current.generation != plan.envelope.evidence_generation) {
    status = push_finding(report, limits, "csp.revalidate.evidence-generation", Tri::Indeterminate,
                          "the evidence generation moved from " +
                              std::to_string(plan.envelope.evidence_generation.value()) + " to " +
                              std::to_string(current.generation.value()) +
                              "; every fact below is re-checked, but the world it describes is not the one the "
                              "plan was made from");
  } else {
    status = push_finding(report, limits, "csp.revalidate.evidence-generation", Tri::Satisfied,
                          "the evidence generation is unchanged");
  }
  if (!status) {
    return status.error();
  }

  if (current_policy.policy != request.policy.policy) {
    status = push_finding(report, limits, "csp.revalidate.policy-identity", Tri::Violated,
                          "the policy supplied is not the policy the request named");
    if (!status) {
      return status.error();
    }
  } else if (current_policy.generation != plan.envelope.policy_generation) {
    status = push_finding(report, limits, "csp.revalidate.policy-generation", Tri::Indeterminate,
                          "the policy generation moved from " +
                              std::to_string(plan.envelope.policy_generation.value()) + " to " +
                              std::to_string(current_policy.generation.value()) +
                              "; admissibility is not re-derived here, so the caller must re-plan");
    if (!status) {
      return status.error();
    }
  }

  const Instant horizon = detail::freshness_horizon(request.freshness, limits, context.evaluation_instant);

  for (const ObligationPlacement& placed : plan.obligations) {
    const auto obligation_it =
        std::find_if(request.obligations.begin(), request.obligations.end(),
                     [&placed](const Obligation& obligation) { return obligation.obligation == placed.obligation; });
    if (obligation_it == request.obligations.end()) {
      status = push_finding(report, limits, "csp.revalidate.obligation-removed", Tri::Violated,
                            "obligation " + placed.obligation.value() + " is not part of the supplied request");
      if (!status) {
        return status.error();
      }
      continue;
    }
    const Obligation& obligation = *obligation_it;

    for (const SitePlacement& placement : placed.placements) {
      const std::optional<std::size_t> site_index = index.find_site(placement.site);
      if (!site_index.has_value()) {
        status = push_finding(report, limits, "csp.revalidate.site-removed", Tri::Violated,
                              "site " + placement.site.value() + " is no longer described by the evidence");
        if (!status) {
          return status.error();
        }
        continue;
      }
      if (!placement_is_usable(index, *site_index, current_policy)) {
        status = push_finding(report, limits, "csp.revalidate.maintenance", Tri::Violated,
                              "site " + placement.site.value() +
                                  " is no longer in a maintenance state this policy admits");
        if (!status) {
          return status.error();
        }
      } else if (!index.sites[*site_index].site.maintenance.is_known()) {
        status = push_finding(report, limits, "csp.revalidate.maintenance", Tri::Indeterminate,
                              "site " + placement.site.value() + " no longer reports a maintenance state");
        if (!status) {
          return status.error();
        }
      }

      Quantity evidenced = Quantity::from_units(0);
      bool incomplete = false;
      const std::vector<detail::CapacityEntry>* entries = index.capacity_for(*site_index);
      if (entries != nullptr) {
        for (const detail::CapacityEntry& entry : *entries) {
          if (entry.service_class != obligation.service_class || !entry.available.is_known()) {
            incomplete = incomplete || entry.service_class == obligation.service_class;
            continue;
          }
          if (current_policy.require_commitment_capacity && entry.kind != CapacityKind::Commitment) {
            continue;
          }
          if (!current_policy.allow_offer_capacity && entry.kind == CapacityKind::Offer) {
            continue;
          }
          const Result<Quantity> sum = evidenced.checked_add(entry.available.value());
          if (!sum) {
            return sum.error();
          }
          evidenced = sum.value();
        }
      } else {
        incomplete = true;
      }
      if (evidenced < placement.capacity_required) {
        status = push_finding(report, limits, "csp.revalidate.capacity",
                              incomplete ? Tri::Indeterminate : Tri::Violated,
                              "site " + placement.site.value() + " no longer evidences the capacity this "
                              "placement was made against");
        if (!status) {
          return status.error();
        }
      }

      const detail::CompatibilityEntry* compatible =
          index.compatibility_for(*site_index, obligation.service_class);
      if (compatible == nullptr || !compatible->compatible.is_known()) {
        status = push_finding(report, limits, "csp.revalidate.compatibility", Tri::Indeterminate,
                              "site " + placement.site.value() +
                                  " no longer states whether this service class may run there");
        if (!status) {
          return status.error();
        }
      } else if (!compatible->compatible.value()) {
        status = push_finding(report, limits, "csp.revalidate.compatibility", Tri::Violated,
                              "site " + placement.site.value() +
                                  " now states that this service class may not run there");
        if (!status) {
          return status.error();
        }
      }
    }

    for (const SeparationRequirement& requirement : obligation.separations) {
      for (std::size_t lhs = 0; lhs < placed.placements.size(); ++lhs) {
        for (std::size_t rhs = lhs + 1; rhs < placed.placements.size(); ++rhs) {
          const SitePlacement& left = placed.placements[lhs];
          const SitePlacement& right = placed.placements[rhs];
          const bool applies = requirement.group == SeparationGroup::All ||
                               (requirement.group == SeparationGroup::WithinRole && left.role == right.role) ||
                               (requirement.group == SeparationGroup::AcrossRoles && left.role != right.role);
          if (!applies) {
            continue;
          }
          const detail::SeparationCheck check =
              index.domains.separate(left.site, right.site, requirement.separated_kinds,
                                     requirement.forbidden_shared_domains);
          if (check.outcome == Tri::Satisfied) {
            continue;
          }
          status = push_finding(report, limits, "csp.revalidate.separation", check.outcome,
                                "sites " + left.site.value() + " and " + right.site.value() +
                                    (check.outcome == Tri::Violated
                                         ? " now share a failure domain this requirement forbids"
                                         : " can no longer be shown to be separated"));
          if (!status) {
            return status.error();
          }
        }
      }
    }

    for (const LatencyRequirement& requirement : obligation.latency_requirements) {
      for (const SitePlacement& placement : placed.placements) {
        if (placement.role != requirement.applies_to) {
          continue;
        }
        std::vector<SiteId> peers;
        if (requirement.peer.kind == DependencyEndpoint::Kind::SiteService) {
          peers.push_back(requirement.peer.site);
        } else {
          const auto peer_plan =
              std::find_if(plan.obligations.begin(), plan.obligations.end(),
                           [&requirement](const ObligationPlacement& entry) {
                             return entry.obligation == requirement.peer.obligation;
                           });
          if (peer_plan == plan.obligations.end()) {
            continue;
          }
          for (const SitePlacement& peer : peer_plan->placements) {
            peers.push_back(peer.site);
          }
        }
        for (const SiteId& peer : peers) {
          const SiteId& from_site =
              requirement.direction == LatencyDirection::FromPlacement ? placement.site : peer;
          const SiteId& to_site = requirement.direction == LatencyDirection::FromPlacement ? peer : placement.site;
          const detail::LatencyOutcome outcome =
              detail::resolve_latency(requirement, from_site, to_site, index, current_policy, limits, horizon,
                                      request.freshness.require_observation_time, budget);
          if (outcome.outcome == Tri::Satisfied) {
            continue;
          }
          status = push_finding(report, limits, "csp.revalidate.latency", outcome.outcome, outcome.detail);
          if (!status) {
            return status.error();
          }
        }
      }
    }
  }

  bool broken = report.expired;
  bool undecidable = false;
  for (const RevalidationFinding& finding : report.findings) {
    if (finding.outcome == Tri::Violated) {
      broken = true;
    } else if (finding.outcome == Tri::Indeterminate) {
      undecidable = true;
    }
  }
  report.verdict = broken ? RevalidationVerdict::Broken
                          : (undecidable ? RevalidationVerdict::Undecidable : RevalidationVerdict::Holds);
  return report;
}

}  // namespace csp
