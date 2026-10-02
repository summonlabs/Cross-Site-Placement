// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The admissibility policy this boundary consumes.
//
// Policy is authored elsewhere. A request names a policy by identity and generation, and
// the caller supplies the policy document; if the two do not agree, planning refuses
// rather than planning against whichever policy happened to be passed in. That check
// exists because the failure mode it prevents is silent: a plan that looks like it
// followed the policy the request named, but did not.
//
// Every flag here resolves a question this boundary cannot answer from evidence, and
// every one of them defaults to the reading that claims the least. Nothing defaults to
// "assume it is fine".

#ifndef CROSS_SITE_PLACEMENT_POLICY_HPP
#define CROSS_SITE_PLACEMENT_POLICY_HPP

#include <cstddef>

#include "cross_site_placement/limits.hpp"
#include "cross_site_placement/strong_types.hpp"

namespace csp {

struct PlacementPolicy {
  PolicyId policy;
  Generation generation;

  /// May a site whose maintenance state is Degraded take a new placement?
  bool allow_degraded_sites = false;

  /// May a site whose maintenance state nobody reported take a new placement?
  ///
  /// False by default. Reading an unreported state as operational is inventing a health
  /// claim, which is the one thing this boundary must never do.
  bool allow_unknown_maintenance_state = false;

  /// May a site whose jurisdiction is unrecorded satisfy a jurisdictional constraint?
  ///
  /// False by default, and the site is still usable for obligations that state no
  /// jurisdictional requirement. Unknown is not a jurisdiction.
  bool allow_unknown_jurisdiction = false;

  /// May an offer, as opposed to a commitment, be counted as usable capacity?
  ///
  /// True by default because planning is not reservation: a plan that names the offers
  /// it leaned on is inspectable, and the caller can require commitments instead.
  bool allow_offer_capacity = true;

  /// When true, only commitments are counted, and a plan that would have needed an
  /// offer is refused rather than made with a weaker basis.
  bool require_commitment_capacity = false;

  /// May a latency bound be derived from a chain of maximum-statistic measurements when
  /// no direct measurement exists?
  ///
  /// A chain of maxima is a valid upper bound, so the derived value is not invented; it
  /// is computed from named evidence and the plan records the whole chain. Only the Max
  /// statistic may be composed this way: percentile bounds do not add.
  bool allow_derived_latency_bounds = true;

  /// Longest chain the derivation may use. Zero means the configured limit.
  std::size_t max_derived_hops = 0;

  /// May a recovery placement share a site with a primary placement of the same
  /// obligation when the separation rules do not already forbid it?
  bool allow_recovery_on_primary_site = false;
};

/// Validates a policy on its own terms, independent of any request.
[[nodiscard]] Status policy_validate(const PlacementPolicy& policy, const Limits& limits);

/// True when the policy identity and generation match the reference a request made.
/// A mismatch is reported with both sides named.
[[nodiscard]] bool policy_matches_reference(const PlacementPolicy& policy, const PolicyId& policy_id,
                                            Generation generation) noexcept;

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_POLICY_HPP
