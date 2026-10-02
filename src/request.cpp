// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "cross_site_placement/request.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace csp {
namespace {

constexpr std::array<std::pair<Preferences::Objective, const char*>, 4> kObjectives{{
    {Preferences::Objective::MinimiseSites, "minimise-sites"},
    {Preferences::Objective::MinimiseCost, "minimise-cost"},
    {Preferences::Objective::MinimiseRisk, "minimise-risk"},
    {Preferences::Objective::MaximiseDomainSpread, "maximise-domain-spread"},
}};

template <class Collection>
Status require_size(const Collection& collection, std::size_t bound, const char* kind) {
  if (collection.size() > bound) {
    return fail(ErrorCategory::BoundExceeded, "csp.request.bound_exceeded",
                "the request carries " + std::to_string(collection.size()) + " " + kind +
                    " entries, above the configured bound of " + std::to_string(bound));
  }
  return success();
}

template <class IdType>
Status require_valid_id(const IdType& id, const std::string& context) {
  if (!id.valid()) {
    return fail(ErrorCategory::Invalid, "csp.request.missing_identity", context + " identity is absent");
  }
  return success();
}

Status require_unique_ids(const std::vector<SiteId>& ids, const std::string& context) {
  std::vector<SiteId> sorted = ids;
  std::sort(sorted.begin(), sorted.end());
  if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
    return fail(ErrorCategory::Conflict, "csp.request.duplicate_site",
                context + " lists the same site more than once, which states two different things at once");
  }
  return success();
}

Status require_unique_jurisdictions(const std::vector<JurisdictionId>& ids, const std::string& context) {
  std::vector<JurisdictionId> sorted = ids;
  std::sort(sorted.begin(), sorted.end());
  if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
    return fail(ErrorCategory::Conflict, "csp.request.duplicate_jurisdiction",
                context + " lists the same jurisdiction more than once");
  }
  return success();
}

}  // namespace

const char* to_string(Preferences::Objective objective) noexcept {
  switch (objective) {
    case Preferences::Objective::MinimiseSites: return "minimise-sites";
    case Preferences::Objective::MinimiseCost: return "minimise-cost";
    case Preferences::Objective::MinimiseRisk: return "minimise-risk";
    case Preferences::Objective::MaximiseDomainSpread: return "maximise-domain-spread";
  }
  return "unknown";
}

std::optional<Preferences::Objective> preference_objective_from_string(std::string_view token) noexcept {
  for (const auto& entry : kObjectives) {
    if (token == entry.second) {
      return entry.first;
    }
  }
  return std::nullopt;
}

Status request_validate(const PlacementRequest& request, const Limits& limits) {
  Status status = require_valid_id(request.request, "request");
  if (!status) return status;
  if (!request.generation.is_set()) {
    return fail(ErrorCategory::Invalid, "csp.request.missing_generation",
                "the request carries no generation; without one a plan cannot be fenced against a retry");
  }
  status = require_valid_id(request.policy.policy, "policy reference");
  if (!status) return status;
  if (!request.policy.generation.is_set()) {
    return fail(ErrorCategory::Invalid, "csp.request.missing_policy_generation",
                "the request names a policy but no policy generation, so a stale policy could not be detected");
  }

  status = require_size(request.obligations, limits.max_obligations, "obligation");
  if (!status) return status;
  status = require_size(request.allowed_sites, limits.max_site_lists, "allowed site");
  if (!status) return status;
  status = require_size(request.forbidden_sites, limits.max_site_lists, "forbidden site");
  if (!status) return status;
  status = require_unique_ids(request.allowed_sites, "the request allow list");
  if (!status) return status;
  status = require_unique_ids(request.forbidden_sites, "the request deny list");
  if (!status) return status;
  status = require_size(request.preferences.objectives, kObjectives.size(), "preference");
  if (!status) return status;

  for (const Preferences::Objective objective : request.preferences.objectives) {
    const auto occurrences = std::count(request.preferences.objectives.begin(),
                                        request.preferences.objectives.end(), objective);
    if (occurrences > 1) {
      return fail(ErrorCategory::Invalid, "csp.request.duplicate_preference",
                  std::string("preference ") + to_string(objective) + " appears more than once in the ordering");
    }
  }

  if (request.validity.validity_nanos < 0) {
    return fail(ErrorCategory::OutOfRange, "csp.request.negative_validity",
                "the requested validity window is negative");
  }
  if (request.freshness.max_evidence_age_nanos < 0) {
    return fail(ErrorCategory::OutOfRange, "csp.request.negative_freshness",
                "the requested evidence age is negative");
  }

  std::vector<ObligationId> obligation_ids;
  obligation_ids.reserve(request.obligations.size());

  for (const Obligation& obligation : request.obligations) {
    const std::string context = "obligation " + obligation.obligation.value();
    status = require_valid_id(obligation.obligation, "obligation");
    if (!status) return status;
    status = require_valid_id(obligation.service_class, context + " service class");
    if (!status) return status;
    if (obligation.required_capacity.is_negative()) {
      return fail(ErrorCategory::OutOfRange, "csp.request.negative_capacity",
                  context + " requires a negative capacity, which no site can provide");
    }
    if (obligation.primary_placements == 0 && obligation.recovery_placements == 0) {
      return fail(ErrorCategory::Invalid, "csp.request.no_placements",
                  context + " asks for no placements at all");
    }
    const std::uint64_t total = static_cast<std::uint64_t>(obligation.primary_placements) +
                                static_cast<std::uint64_t>(obligation.recovery_placements);
    if (total > limits.max_placements_per_obligation) {
      return fail(ErrorCategory::BoundExceeded, "csp.request.too_many_placements",
                  context + " asks for " + std::to_string(total) + " placements, above the bound of " +
                      std::to_string(limits.max_placements_per_obligation));
    }
    if (obligation.required_rto.has_value() && obligation.required_rto->is_negative()) {
      return fail(ErrorCategory::OutOfRange, "csp.request.negative_rto",
                  context + " states a negative recovery time objective");
    }
    if (obligation.required_rpo.has_value() && obligation.required_rpo->is_negative()) {
      return fail(ErrorCategory::OutOfRange, "csp.request.negative_rpo",
                  context + " states a negative recovery point objective");
    }
    if ((obligation.required_rto.has_value() || obligation.required_rpo.has_value()) &&
        obligation.recovery_placements == 0) {
      return fail(ErrorCategory::Invalid, "csp.request.objective_without_recovery",
                  context + " states a recovery objective but asks for no recovery placement, so nothing would meet it");
    }

    status = require_size(obligation.allowed_jurisdictions, limits.max_jurisdiction_lists,
                          "allowed jurisdiction");
    if (!status) return status;
    status = require_size(obligation.allowed_sites, limits.max_site_lists, "allowed site");
    if (!status) return status;
    status = require_size(obligation.forbidden_sites, limits.max_site_lists, "forbidden site");
    if (!status) return status;
    status = require_size(obligation.separations, limits.max_separation_requirements, "separation");
    if (!status) return status;
    status = require_size(obligation.latency_requirements, limits.max_latency_requirements, "latency");
    if (!status) return status;

    status = require_unique_jurisdictions(obligation.allowed_jurisdictions,
                                          context + " jurisdiction allow list");
    if (!status) return status;
    status = require_unique_ids(obligation.allowed_sites, context + " allow list");
    if (!status) return status;
    status = require_unique_ids(obligation.forbidden_sites, context + " deny list");
    if (!status) return status;

    for (const SeparationRequirement& separation : obligation.separations) {
      status = require_size(separation.separated_kinds, limits.max_separated_kinds, "separated kind");
      if (!status) return status;
      if (separation.separated_kinds.empty() && separation.forbidden_shared_domains.empty()) {
        return fail(ErrorCategory::Invalid, "csp.request.empty_separation",
                    context + " has a separation requirement that names neither a domain kind nor a domain, "
                               "so it would constrain nothing while appearing to");
      }
      for (std::size_t index = 0; index < separation.separated_kinds.size(); ++index) {
        const auto occurrences = std::count(separation.separated_kinds.begin(),
                                            separation.separated_kinds.end(),
                                            separation.separated_kinds[index]);
        if (occurrences > 1) {
          return fail(ErrorCategory::Invalid, "csp.request.duplicate_separated_kind",
                      context + " names domain kind " + to_string(separation.separated_kinds[index]) +
                          " more than once in one separation requirement");
        }
      }
    }

    for (const LatencyRequirement& requirement : obligation.latency_requirements) {
      if (requirement.max_latency.is_negative()) {
        return fail(ErrorCategory::OutOfRange, "csp.request.negative_latency",
                    context + " states a negative latency bound");
      }
      if (requirement.peer.kind == DependencyEndpoint::Kind::Obligation) {
        status = require_valid_id(requirement.peer.obligation, context + " latency peer");
        if (!status) return status;
        if (requirement.peer.obligation == obligation.obligation) {
          return fail(ErrorCategory::Invalid, "csp.request.self_dependency",
                      context + " depends on itself, which constrains nothing");
        }
      } else {
        status = require_valid_id(requirement.peer.site, context + " latency peer site");
        if (!status) return status;
        status = require_valid_id(requirement.peer.service_class, context + " latency peer service class");
        if (!status) return status;
      }
    }

    obligation_ids.push_back(obligation.obligation);
  }

  std::sort(obligation_ids.begin(), obligation_ids.end());
  if (std::adjacent_find(obligation_ids.begin(), obligation_ids.end()) != obligation_ids.end()) {
    return fail(ErrorCategory::Conflict, "csp.request.duplicate_obligation",
                "two obligations share one identity, so a plan could not name one of them unambiguously");
  }

  // A latency requirement may name a peer obligation, and that peer has to exist in
  // this request. A dangling peer is refused here rather than left to produce an
  // indeterminate result later, because it is a defect in the request rather than a gap
  // in the evidence.
  for (const Obligation& obligation : request.obligations) {
    for (const LatencyRequirement& requirement : obligation.latency_requirements) {
      if (requirement.peer.kind != DependencyEndpoint::Kind::Obligation) {
        continue;
      }
      if (!std::binary_search(obligation_ids.begin(), obligation_ids.end(), requirement.peer.obligation)) {
        return fail(ErrorCategory::NotFound, "csp.request.unknown_peer_obligation",
                    "obligation " + obligation.obligation.value() + " depends on obligation " +
                        requirement.peer.obligation.value() + " which is not part of this request");
      }
    }
  }

  return success();
}

}  // namespace csp
