// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Text documents.
//
// Every value this boundary exchanges has a textual form, and the form is canonical: the
// same value always encodes to the same bytes, and those bytes are what the digest
// covers. The encoding is JSON with two restrictions the standard library's own writers
// would not give us: no floating-point numbers anywhere, and object keys in byte order.
//
// The decoders are the trust boundary. They are bounded, they never allocate before a
// declared count has been checked against both the configured bound and the bytes that
// remain, they reject unknown fields rather than ignoring them, and they validate the
// document version before reading anything else. A document written by a newer format is
// refused with ErrorCategory::Unsupported, never partially understood.

#ifndef CROSS_SITE_PLACEMENT_TEXT_HPP
#define CROSS_SITE_PLACEMENT_TEXT_HPP

#include <string>
#include <string_view>

#include "cross_site_placement/evidence.hpp"
#include "cross_site_placement/limits.hpp"
#include "cross_site_placement/plan.hpp"
#include "cross_site_placement/policy.hpp"
#include "cross_site_placement/request.hpp"

namespace csp {

[[nodiscard]] Result<std::string> request_to_document(const PlacementRequest& request, bool pretty);
[[nodiscard]] Result<PlacementRequest> request_from_document(std::string_view text, const Limits& limits);

[[nodiscard]] Result<std::string> snapshot_to_document(const SiteEvidenceSnapshot& snapshot, bool pretty);
[[nodiscard]] Result<SiteEvidenceSnapshot> snapshot_from_document(std::string_view text, const Limits& limits);

[[nodiscard]] Result<std::string> policy_to_document(const PlacementPolicy& policy, bool pretty);
[[nodiscard]] Result<PlacementPolicy> policy_from_document(std::string_view text, const Limits& limits);

[[nodiscard]] Result<std::string> plan_to_document(const PlacementPlan& plan, bool pretty);
[[nodiscard]] Result<PlacementPlan> plan_from_document(std::string_view text, const Limits& limits);

/// The exact bytes the plan digest is computed over. Exposed so that a caller can hash
/// them with their own implementation and compare, which is the only way to check that a
/// digest means what this library says it means.
[[nodiscard]] Result<std::string> plan_canonical_bytes(const PlacementPlan& plan);

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_TEXT_HPP
