// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Per-site admissibility.
//
// Every rule below answers one question about one site for one obligation, and every
// one of them can answer "I do not know". The rules run in the order documented in the
// README, and the first rule that does not answer Satisfied is the one the plan names,
// so an explanation always points at a single cause rather than at a set of them.

#include "engine_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace csp::detail {
namespace {

/// Freshness of one record.
///
/// Staleness is not falsehood. A capacity reading from an hour ago does not say the site
/// is full; it says nothing about now. The rule therefore returns Indeterminate rather
/// than Violated, and the difference survives into the plan, where a reader can see that
/// the site was not refused but undecided.
Tri freshness_of(const EvidenceStamp& stamp, Instant horizon, bool require_observation_time,
                 std::string& why) {
  if (stamp.observed_at.is_zero()) {
    if (require_observation_time) {
      why = "the record carries no observation time and the request requires one";
      return Tri::Indeterminate;
    }
    why = "the record carries no observation time, which this request accepts";
    return Tri::Satisfied;
  }
  if (!horizon.is_zero() && stamp.observed_at < horizon) {
    why = "the record was observed before the freshness horizon this request set";
    return Tri::Indeterminate;
  }
  return Tri::Satisfied;
}

void note_observation(Instant observed, Instant& oldest, bool& seen) {
  if (observed.is_zero()) {
    return;
  }
  if (!seen || observed < oldest) {
    oldest = observed;
    seen = true;
  }
}

CandidateAssessment refused(const char* rule_token, std::string detail) {
  CandidateAssessment assessment;
  assessment.outcome = Tri::Violated;
  assessment.rule = rule_token;
  assessment.detail = std::move(detail);
  return assessment;
}

CandidateAssessment undecided(const char* rule_token, std::string detail) {
  CandidateAssessment assessment;
  assessment.outcome = Tri::Indeterminate;
  assessment.rule = rule_token;
  assessment.detail = std::move(detail);
  return assessment;
}

}  // namespace

Result<const CandidateAssessment*> assessment_for(const PlacementRequest& request, const Obligation& obligation,
                                                  const PlacementPolicy& policy, const Limits& limits,
                                                  const EvidenceIndex& index, ObligationContext& context,
                                                  std::size_t candidate_slot, PlacementRole role,
                                                  Instant evaluation_instant, const PlanningContext& planning,
                                                  WorkBudget& budget) {
  (void)planning;
  std::vector<std::optional<CandidateAssessment>>& cache =
      role == PlacementRole::Recovery ? context.recovery_assessments : context.primary_assessments;
  if (candidate_slot >= cache.size() || candidate_slot >= context.candidates.size()) {
    return fail(ErrorCategory::Internal, "csp.assessment.slot",
                "the candidate slot is outside the context it was asked about");
  }
  if (cache[candidate_slot].has_value()) {
    return &cache[candidate_slot].value();
  }

  const std::size_t site_index = context.candidates[candidate_slot];
  const SiteRecordEntry& site = index.sites[site_index];
  const Instant horizon = freshness_horizon(request.freshness, limits, evaluation_instant);
  const bool require_time = request.freshness.require_observation_time;

  CandidateAssessment assessment;
  assessment.oldest_observation = Instant{};
  bool saw_observation = false;

  // The deny list. The allow list was applied when the candidate list was built, so a
  // candidate that reaches this point is already allowed.
  const auto denied = [&obligation, &request](const SiteId& site_id) {
    return std::binary_search(obligation.forbidden_sites.begin(), obligation.forbidden_sites.end(), site_id) ||
           std::binary_search(request.forbidden_sites.begin(), request.forbidden_sites.end(), site_id);
  };
  if (denied(site.site.site)) {
    cache[candidate_slot] = refused(rule::kDenyList, "the site is on a deny list this request states");
    return &cache[candidate_slot].value();
  }

  // Freshness of the site record itself.
  {
    std::string why;
    if (freshness_of(site.site.stamp, horizon, require_time, why) != Tri::Satisfied) {
      assessment.evidence.push_back(make_ref("site", site.site.stamp));
      cache[candidate_slot] = undecided(rule::kFreshness, why);
      return &cache[candidate_slot].value();
    }
    note_observation(site.site.stamp.observed_at, assessment.oldest_observation, saw_observation);
    assessment.evidence.push_back(make_ref("site", site.site.stamp));
  }

  // Jurisdiction.
  if (!obligation.allowed_jurisdictions.empty()) {
    if (!site.site.jurisdiction.valid()) {
      if (!policy.allow_unknown_jurisdiction) {
        assessment.evidence.push_back(make_ref("site", site.site.stamp));
        cache[candidate_slot] =
            undecided(rule::kJurisdiction,
                      "the site's jurisdiction is unrecorded and this policy does not accept an unrecorded one");
        return &cache[candidate_slot].value();
      }
    } else if (!std::binary_search(obligation.allowed_jurisdictions.begin(),
                                   obligation.allowed_jurisdictions.end(), site.site.jurisdiction)) {
      assessment.evidence.push_back(make_ref("site", site.site.stamp));
      cache[candidate_slot] =
          refused(rule::kJurisdiction, "the site is in jurisdiction " + site.site.jurisdiction.value() +
                                           ", which this obligation does not allow");
      return &cache[candidate_slot].value();
    }
  }

  // Maintenance state.
  {
    const Measurement<MaintenanceState>& state = site.site.maintenance;
    if (!state.is_known()) {
      if (!policy.allow_unknown_maintenance_state) {
        assessment.evidence.push_back(make_ref("site", site.site.stamp));
        cache[candidate_slot] =
            undecided(rule::kMaintenance,
                      "nobody reported this site's maintenance state and this policy does not assume one");
        return &cache[candidate_slot].value();
      }
    } else if (state.value() != MaintenanceState::Operational) {
      const bool degraded_ok = policy.allow_degraded_sites && state.value() == MaintenanceState::Degraded;
      if (!degraded_ok) {
        assessment.evidence.push_back(make_ref("site", site.site.stamp));
        cache[candidate_slot] = refused(rule::kMaintenance,
                                        std::string("the site is in maintenance state ") +
                                            to_string(state.value()) + ", which cannot take a new placement");
        return &cache[candidate_slot].value();
      }
    }
  }

  // Service compatibility.
  {
    const CompatibilityEntry* entry = index.compatibility_for(site_index, obligation.service_class);
    if (entry == nullptr) {
      cache[candidate_slot] = undecided(rule::kCompatibility,
                                        "no compatibility record exists for this service class at this site");
      return &cache[candidate_slot].value();
    }
    std::string why;
    if (freshness_of(entry->stamp, horizon, require_time, why) != Tri::Satisfied) {
      assessment.evidence.push_back(make_ref("compatibility", entry->stamp));
      cache[candidate_slot] = undecided(rule::kCompatibility, why);
      return &cache[candidate_slot].value();
    }
    note_observation(entry->stamp.observed_at, assessment.oldest_observation, saw_observation);
    assessment.evidence.push_back(make_ref("compatibility", entry->stamp));
    if (!entry->compatible.is_known()) {
      cache[candidate_slot] =
          undecided(rule::kCompatibility, "the compatibility record for this service class says nothing usable");
      return &cache[candidate_slot].value();
    }
    if (!entry->compatible.value()) {
      cache[candidate_slot] = refused(rule::kCompatibility,
                                      "the compatibility record states that this service class may not run here");
      return &cache[candidate_slot].value();
    }
  }

  // Capacity.
  {
    const std::vector<CapacityEntry>* entries = index.capacity_for(site_index);
    const std::size_t entry_count = entries == nullptr ? 0 : entries->size();
    if (!budget.consume(1 + static_cast<std::uint64_t>(entry_count))) {
      return fail(ErrorCategory::BoundExceeded, "csp.search.budget",
                  "the planning work budget was exhausted while assessing capacity evidence");
    }
    Quantity total = Quantity::from_units(0);
    std::vector<CapacityRefId> references;
    bool includes_offers = false;
    bool incomplete = false;
    if (entries != nullptr) {
      for (const CapacityEntry& entry : *entries) {
        if (entry.service_class != obligation.service_class) {
          continue;
        }
        if (policy.require_commitment_capacity && entry.kind != CapacityKind::Commitment) {
          continue;
        }
        if (!policy.allow_offer_capacity && entry.kind == CapacityKind::Offer) {
          continue;
        }
        std::string why;
        if (freshness_of(entry.stamp, horizon, require_time, why) != Tri::Satisfied) {
          incomplete = true;
          continue;
        }
        note_observation(entry.stamp.observed_at, assessment.oldest_observation, saw_observation);
        assessment.evidence.push_back(make_ref("capacity", entry.stamp));
        if (!entry.available.is_known()) {
          incomplete = true;
          continue;
        }
        const Result<Quantity> sum = total.checked_add(entry.available.value());
        if (!sum) {
          return sum.error();
        }
        total = sum.value();
        references.push_back(entry.reference);
        if (entry.kind == CapacityKind::Offer) {
          includes_offers = true;
        }
      }
    }
    assessment.capacity_references = std::move(references);
    assessment.capacity_evidenced = total;
    assessment.capacity_includes_offers = includes_offers;

    if (total < obligation.required_capacity) {
      if (incomplete || assessment.capacity_references.empty()) {
        cache[candidate_slot] = undecided(
            rule::kCapacity,
            "the capacity reported here is below the requirement and the evidence is incomplete, so the "
            "shortfall is not established");
        cache[candidate_slot]->evidence = assessment.evidence;
        cache[candidate_slot]->oldest_observation = assessment.oldest_observation;
        return &cache[candidate_slot].value();
      }
      cache[candidate_slot] = refused(rule::kCapacity,
                                      "the capacity reported here is below what this obligation requires");
      cache[candidate_slot]->capacity_evidenced = total;
      cache[candidate_slot]->capacity_references = assessment.capacity_references;
      cache[candidate_slot]->capacity_includes_offers = includes_offers;
      cache[candidate_slot]->evidence = assessment.evidence;
      cache[candidate_slot]->oldest_observation = assessment.oldest_observation;
      return &cache[candidate_slot].value();
    }
  }

  // Recovery rules apply only to a recovery placement.
  if (role == PlacementRole::Recovery) {
    const RecoveryEntry* entry = index.recovery_for(site_index, obligation.service_class);
    if (entry == nullptr) {
      cache[candidate_slot] =
          undecided(rule::kRecoveryCapability,
                    "no recovery capability record exists for this service class at this site");
      return &cache[candidate_slot].value();
    }
    std::string why;
    if (freshness_of(entry->stamp, horizon, require_time, why) != Tri::Satisfied) {
      assessment.evidence.push_back(make_ref("recovery", entry->stamp));
      cache[candidate_slot] = undecided(rule::kRecoveryCapability, why);
      return &cache[candidate_slot].value();
    }
    note_observation(entry->stamp.observed_at, assessment.oldest_observation, saw_observation);
    assessment.evidence.push_back(make_ref("recovery", entry->stamp));
    if (!entry->can_host_recovery.is_known()) {
      cache[candidate_slot] =
          undecided(rule::kRecoveryCapability, "the recovery capability record states nothing usable");
      return &cache[candidate_slot].value();
    }
    if (!entry->can_host_recovery.value()) {
      cache[candidate_slot] =
          refused(rule::kRecoveryCapability, "the recovery capability record states this site cannot host a "
                                             "recovery placement of this service class");
      return &cache[candidate_slot].value();
    }
    if (obligation.required_rto.has_value()) {
      if (!entry->achievable_rto.is_known()) {
        cache[candidate_slot] = undecided(rule::kRecoveryObjective,
                                          "the recovery time this site can achieve is not reported");
        return &cache[candidate_slot].value();
      }
      if (entry->achievable_rto.value() > *obligation.required_rto) {
        cache[candidate_slot] =
            refused(rule::kRecoveryObjective,
                    "the recovery time this site can achieve is longer than the objective this obligation requires");
        return &cache[candidate_slot].value();
      }
    }
    if (obligation.required_rpo.has_value()) {
      if (!entry->achievable_rpo.is_known()) {
        cache[candidate_slot] = undecided(rule::kRecoveryObjective,
                                          "the recovery point this site can achieve is not reported");
        return &cache[candidate_slot].value();
      }
      if (entry->achievable_rpo.value() > *obligation.required_rpo) {
        cache[candidate_slot] =
            refused(rule::kRecoveryObjective,
                    "the recovery point this site can achieve is worse than the objective this obligation requires");
        return &cache[candidate_slot].value();
      }
    }
  }

  // Cost and risk are preferences, never constraints. They are read here so that the
  // ordering below does not have to walk the evidence again.
  if (const CostRiskEntry* entry = index.cost_risk_for(site_index, obligation.service_class)) {
    std::string why;
    if (freshness_of(entry->stamp, horizon, require_time, why) == Tri::Satisfied) {
      note_observation(entry->stamp.observed_at, assessment.oldest_observation, saw_observation);
      assessment.cost = entry->cost_per_unit;
      assessment.risk = entry->risk_per_mille;
      assessment.evidence.push_back(make_ref("cost-risk", entry->stamp));
    }
  }

  assessment.outcome = Tri::Satisfied;
  assessment.oldest_observation = saw_observation ? assessment.oldest_observation : Instant{};
  cache[candidate_slot] = std::move(assessment);
  return &cache[candidate_slot].value();
}

}  // namespace csp::detail
