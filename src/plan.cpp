// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The plan as a value: its structure, its digest, and its identity.
//
// A plan is sealed rather than assembled in place. Sealing computes the digest over the
// canonical encoding of everything except the identity and the digest themselves, and
// then derives the identity from the digest. That ordering is what makes the identity a
// function of the content instead of a counter, so two processes that answer the same
// question produce plans that compare equal.

#include "cross_site_placement/plan.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cross_site_placement/text.hpp"

namespace csp {
namespace {

constexpr std::array<std::pair<PlanOutcome, const char*>, 3> kOutcomes{{
    {PlanOutcome::Planned, "planned"},
    {PlanOutcome::Refused, "refused"},
    {PlanOutcome::Indeterminate, "indeterminate"},
}};

Status bounded(std::size_t size, std::size_t limit, const char* what) {
  if (size > limit) {
    return fail(ErrorCategory::BoundExceeded, "csp.plan.bound_exceeded",
                std::string("the plan carries ") + std::to_string(size) + " " + what +
                    " entries, above the configured bound of " + std::to_string(limit));
  }
  return success();
}

}  // namespace

bool plan_is_applicable(const PlacementPlan& plan) noexcept { return plan.outcome == PlanOutcome::Planned; }

const char* to_string(PlanOutcome outcome) noexcept {
  switch (outcome) {
    case PlanOutcome::Planned:
      return "planned";
    case PlanOutcome::Refused:
      return "refused";
    case PlanOutcome::Indeterminate:
      return "indeterminate";
  }
  return "indeterminate";
}

std::optional<PlanOutcome> plan_outcome_from_string(std::string_view token) noexcept {
  for (const auto& entry : kOutcomes) {
    if (token == entry.second) {
      return entry.first;
    }
  }
  return std::nullopt;
}

Digest plan_compute_digest(const PlacementPlan& plan) {
  const Result<std::string> bytes = plan_canonical_bytes(plan);
  if (!bytes) {
    return Digest{};
  }
  return Digest::of(bytes.value());
}

Status plan_validate(const PlacementPlan& plan, const Limits& limits) {
  if (!plan.request.valid()) {
    return fail(ErrorCategory::Invalid, "csp.plan.missing_request",
                "the plan names no request, so nothing identifies the question it answered");
  }
  if (!plan.request_generation.is_set()) {
    return fail(ErrorCategory::Invalid, "csp.plan.missing_generation",
                "the plan carries no request generation");
  }
  Status status = bounded(plan.obligations.size(), limits.max_obligations, "obligation");
  if (!status) return status;
  status = bounded(plan.trace.size(), limits.max_trace_entries, "trace");
  if (!status) return status;
  status = bounded(plan.residual.size(), limits.max_residual_entries, "residual");
  if (!status) return status;
  status = bounded(plan.tie_breaks.size(), limits.max_tie_break_entries, "tie-break");
  if (!status) return status;
  if (plan.envelope.revalidate_when.empty()) {
    return fail(ErrorCategory::Invalid, "csp.plan.no_revalidation_conditions",
                "the plan states no condition under which it must be recomputed, which would claim the world "
                "does not move");
  }

  std::size_t total_placements = 0;
  std::optional<ObligationId> previous;
  for (const ObligationPlacement& placement : plan.obligations) {
    if (!placement.obligation.valid()) {
      return fail(ErrorCategory::Invalid, "csp.plan.missing_obligation", "an obligation entry names no obligation");
    }
    if (previous.has_value() && !(*previous < placement.obligation)) {
      return fail(ErrorCategory::Invalid, "csp.plan.obligation_order",
                  "obligations are not in a strictly increasing identity order, so the plan is not canonical");
    }
    previous = placement.obligation;
    if (placement.outcome == Tri::Satisfied && placement.placements.empty()) {
      return fail(ErrorCategory::Invalid, "csp.plan.empty_placement",
                  "an obligation is reported as placed with no placement to show for it");
    }
    for (const SitePlacement& site : placement.placements) {
      if (!site.site.valid()) {
        return fail(ErrorCategory::Invalid, "csp.plan.missing_site", "a placement names no site");
      }
      if (site.capacity.references.empty()) {
        // A placement that names no capacity reference is a placement with no evidence
        // behind it, which is exactly the fabrication this boundary exists to prevent.
        return fail(ErrorCategory::Invalid, "csp.plan.unevidenced_placement",
                    "a placement names no capacity reference, so nothing shows the site can hold it");
      }
    }
    const std::array<PlacementRole, 2> roles{{PlacementRole::Primary, PlacementRole::Recovery}};
    for (const PlacementRole role : roles) {
      std::vector<std::uint32_t> indices;
      std::vector<SiteId> sites;
      for (const SitePlacement& site : placement.placements) {
        if (site.role != role) {
          continue;
        }
        indices.push_back(site.index);
        sites.push_back(site.site);
      }
      std::sort(indices.begin(), indices.end());
      for (std::size_t position = 0; position < indices.size(); ++position) {
        if (indices[position] != position) {
          return fail(ErrorCategory::Invalid, "csp.plan.placement_index",
                      "placements of one role are not numbered contiguously from zero");
        }
      }
      std::sort(sites.begin(), sites.end());
      if (std::adjacent_find(sites.begin(), sites.end()) != sites.end()) {
        return fail(ErrorCategory::Conflict, "csp.plan.duplicate_site",
                    "one obligation has two placements of one role on one site");
      }
    }
    total_placements += placement.placements.size();
  }
  if (total_placements > limits.max_plan_sites) {
    return fail(ErrorCategory::BoundExceeded, "csp.plan.too_many_sites",
                "the plan places more sites than the configured bound allows");
  }

  if (plan.outcome == PlanOutcome::Planned) {
    for (const ObligationPlacement& placement : plan.obligations) {
      if (placement.outcome != Tri::Satisfied) {
        return fail(ErrorCategory::Invalid, "csp.plan.inconsistent_outcome",
                    "the plan is reported as planned while an obligation is not");
      }
    }
    if (plan.refusal.has_value()) {
      return fail(ErrorCategory::Invalid, "csp.plan.refusal_present",
                  "a planned plan carries a refusal, which states two things at once");
    }
  } else if (!plan.refusal.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.plan.refusal_missing",
                "a plan that is not planned must say why, so a caller is not left to guess");
  }
  return success();
}

void plan_seal(PlacementPlan& plan) {
  plan.plan = PlanId{};
  plan.digest = Digest{};
  const Digest digest = plan_compute_digest(plan);
  plan.digest = digest;
  const std::string hex = digest.to_hex();
  const Result<PlanId> identity = PlanId::parse("plan-" + hex.substr(0, kPlanIdentityHexChars));
  if (identity) {
    plan.plan = identity.value();
  }
}

}  // namespace csp
