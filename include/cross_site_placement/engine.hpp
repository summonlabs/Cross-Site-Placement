// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The planner.
//
// The planner is a pure function of its arguments. It holds limits and nothing else: no
// cache, no clock, no mutable state, no I/O. Two calls with equal arguments return
// equal plans, in the same process or in two processes on two machines, whatever order
// the evidence was assembled in and however many workers evaluated it.
//
// Failures are separated into two kinds on purpose. A Result carrying an error means the
// question could not be evaluated at all: the input was malformed, the evidence
// contradicted itself, a bound was exceeded, or the caller cancelled. A Result carrying
// a plan means the question was evaluated, and the plan says whether an arrangement
// exists. Refusing to place something is an answer, not a failure.

#ifndef CROSS_SITE_PLACEMENT_ENGINE_HPP
#define CROSS_SITE_PLACEMENT_ENGINE_HPP

#include "cross_site_placement/cancellation.hpp"
#include "cross_site_placement/evidence.hpp"
#include "cross_site_placement/limits.hpp"
#include "cross_site_placement/plan.hpp"
#include "cross_site_placement/policy.hpp"
#include "cross_site_placement/request.hpp"

namespace csp {

struct PlanningContext {
  /// The instant the caller asserts the world was being evaluated at. Every freshness
  /// decision is made against this value. A default-constructed instant means the caller
  /// asserted no time; evidence then cannot be shown to be fresh, and the plan carries no
  /// expiry claim.
  Instant evaluation_instant;
  /// Optional. A cancelled call returns ErrorCategory::Cancelled and no plan.
  CancellationToken cancellation;
};

class Planner {
 public:
  /// Uses the default limits, which the caller can read back and reason about.
  Planner();
  explicit Planner(Limits limits);

  const Limits& limits() const noexcept { return limits_; }

  /// Answers the request.
  ///
  /// Order of evaluation, which is part of the contract because it decides which
  /// refusal a request with several defects reports first:
  ///   1. bounds and structural validation of the request, the snapshot, and the policy;
  ///   2. the policy reference the request named against the policy supplied;
  ///   3. the evidence snapshot's own consistency, including failure-domain containment
  ///      and alias closure;
  ///   4. per-obligation admissibility of each candidate site;
  ///   5. selection of an arrangement satisfying separation and latency;
  ///   6. preference ordering and tie-break recording;
  ///   7. sealing: digest, identity, and envelope.
  [[nodiscard]] Result<PlacementPlan> plan(const PlacementRequest& request,
                                           const SiteEvidenceSnapshot& evidence,
                                           const PlacementPolicy& policy,
                                           const PlanningContext& context) const;

  /// The rules this build evaluates, in the order it evaluates them, as stable tokens.
  /// Published so that a reader of a trace can tell an absent rule from a rule that
  /// passed, and so that the set is testable without reading the implementation.
  static const std::vector<std::string>& rule_tokens();

 private:
  Limits limits_;
};

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_ENGINE_HPP
