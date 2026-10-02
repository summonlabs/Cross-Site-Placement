// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Revalidation.
//
// A plan is a statement about a world that keeps moving. Revalidation asks a narrow
// question: does this plan still hold against this newer snapshot and policy? It does
// not produce a new plan, and it does not modify the old one. Its three answers are
// holds, broken, and undecidable, and the third is not a synonym for either of the
// other two.

#ifndef CROSS_SITE_PLACEMENT_REVALIDATE_HPP
#define CROSS_SITE_PLACEMENT_REVALIDATE_HPP

#include <string>
#include <vector>

#include "cross_site_placement/engine.hpp"
#include "cross_site_placement/plan.hpp"

namespace csp {

enum class RevalidationVerdict : std::uint8_t {
  /// Every fact the plan rested on is still true, or still within its freshness window.
  Holds = 0,
  /// At least one fact the plan rested on is now false. The plan must not be used.
  Broken = 1,
  /// Nothing was shown to be false, and nothing was shown to be true either. A caller
  /// that treats undecidable as holds is treating an absence of evidence as evidence.
  Undecidable = 2,
};

const char* to_string(RevalidationVerdict verdict) noexcept;
std::optional<RevalidationVerdict> revalidation_verdict_from_string(std::string_view token) noexcept;

struct RevalidationFinding {
  /// Stable token naming the condition that was checked.
  std::string condition;
  Tri outcome = Tri::Indeterminate;
  std::optional<ObligationId> obligation;
  std::optional<SiteId> site;
  std::string detail;
};

struct RevalidationReport {
  PlanId plan;
  Digest plan_digest;
  RevalidationVerdict verdict = RevalidationVerdict::Undecidable;
  std::vector<RevalidationFinding> findings;
  /// The generations the check was performed against, so a reader can tell which world
  /// the verdict is about.
  Generation evidence_generation;
  Generation policy_generation;
  /// True when the plan's own validity window had already closed at the evaluation
  /// instant. An expired plan is reported as expired rather than silently re-examined.
  bool expired = false;
};

/// Checks the plan against a newer snapshot and policy.
///
/// The original request is required as well as the plan, because the requirements the
/// plan satisfied are not restated inside it: a separation rule or a latency bound is a
/// property of the question, and re-checking the answer without the question would check
/// nothing.
///
/// Refuses with an error when the plan is structurally invalid, when its digest does not
/// match its content, when the request is not the request the plan answered, or when the
/// caller's instant precedes the plan's own evaluation instant, because revalidating a
/// plan against a world younger than the one it was made from is not a meaningful check.
[[nodiscard]] Result<RevalidationReport> plan_revalidate(const PlacementPlan& plan,
                                                         const PlacementRequest& request,
                                                         const SiteEvidenceSnapshot& current,
                                                         const PlacementPolicy& current_policy,
                                                         const PlanningContext& context);

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_REVALIDATE_HPP
