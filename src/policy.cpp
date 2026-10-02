// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "cross_site_placement/policy.hpp"

#include <string>

namespace csp {

Status policy_validate(const PlacementPolicy& policy, const Limits& limits) {
  if (!policy.policy.valid()) {
    return fail(ErrorCategory::Invalid, "csp.policy.missing_identity",
                "the policy carries no identity, so a request cannot be checked against it");
  }
  if (!policy.generation.is_set()) {
    return fail(ErrorCategory::Invalid, "csp.policy.missing_generation",
                "the policy carries no generation; an unversioned policy cannot be fenced");
  }
  if (policy.allow_offer_capacity && policy.require_commitment_capacity) {
    // Both flags at once would mean offers count and do not count. Refusing the
    // combination is the only reading that does not silently pick one of them.
    return fail(ErrorCategory::Invalid, "csp.policy.contradictory_capacity",
                "allow_offer_capacity and require_commitment_capacity are both set, so the capacity basis is ambiguous");
  }
  if (policy.max_derived_hops > limits.max_derived_hops) {
    return fail(ErrorCategory::OutOfRange, "csp.policy.derived_hops",
                "max_derived_hops exceeds the configured bound of " + std::to_string(limits.max_derived_hops));
  }
  return success();
}

bool policy_matches_reference(const PlacementPolicy& policy, const PolicyId& policy_id,
                              Generation generation) noexcept {
  return policy.policy == policy_id && policy.generation == generation;
}

}  // namespace csp
