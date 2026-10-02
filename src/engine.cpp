// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The planner entry point, and the canonical index every later phase reads.
//
// The order of the checks below is part of the contract rather than an implementation
// accident: a request with several defects reports the first one in this order, and the
// test suite pins it. Nothing in this file reads a clock, opens a file, or keeps state
// between calls.

#include "engine_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <numeric>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace csp::detail {
namespace {

const std::vector<std::string>& rule_token_storage() {
  // Listed in the order the planner evaluates them, which is what makes the list an
  // explanation rather than a catalogue: a reader can tell an absent rule from a rule
  // that ran and passed.
  static const std::vector<std::string> kTokens{
      rule::kRequestBounds,     rule::kSnapshotBounds, rule::kPolicyReference,
      rule::kDomainStructure,   rule::kAllowList,      rule::kDenyList,
      rule::kFreshness,         rule::kJurisdiction,   rule::kMaintenance,
      rule::kCompatibility,     rule::kCapacity,       rule::kRecoveryCapability,
      rule::kRecoveryObjective, rule::kColocation,     rule::kSeparation,
      rule::kLatency,           rule::kSelection,      rule::kPreference,
      rule::kSearchBudget,
  };
  return kTokens;
}

Error cancelled_error() {
  return fail(ErrorCategory::Cancelled, "csp.plan.cancelled",
              "the caller cancelled the planning call; a cancelled call reports no plan at all");
}

/// What kind of absence a refusal established. A rule that could not find capacity did
/// not find the arrangement available; a rule that found no site at all did not find it
/// either. Neither is doubt, so neither maps to Indeterminate.
ErrorCategory refusal_category_for(const std::string& rule_token) {
  if (rule_token == rule::kAllowList || rule_token == rule::kDenyList || rule_token == rule::kSelection) {
    return ErrorCategory::NotFound;
  }
  if (rule_token == rule::kFreshness) {
    return ErrorCategory::Stale;
  }
  if (rule_token == rule::kSearchBudget) {
    return ErrorCategory::BoundExceeded;
  }
  return ErrorCategory::Unavailable;
}

Status trace_phase(std::vector<ConstraintTraceEntry>& trace, const Limits& limits, const char* rule_token,
                   Tri outcome, std::string detail) {
  ConstraintTraceEntry entry;
  entry.rule = rule_token;
  entry.outcome = outcome;
  entry.detail = std::move(detail);
  return push_trace(trace, limits, std::move(entry));
}

}  // namespace

EvidenceRef make_ref(const char* kind, const EvidenceStamp& stamp) {
  EvidenceRef ref;
  ref.kind = kind;
  ref.record = stamp.record;
  ref.authority = stamp.authority;
  ref.authority_generation = stamp.generation;
  ref.document_digest = stamp.digest;
  return ref;
}

Status push_trace(std::vector<ConstraintTraceEntry>& trace, const Limits& limits, ConstraintTraceEntry entry) {
  if (trace.size() >= limits.max_trace_entries) {
    return fail(ErrorCategory::BoundExceeded, "csp.trace.bound_exceeded",
                "the constraint trace reached its configured bound of " +
                    std::to_string(limits.max_trace_entries) + " entries");
  }
  if (entry.detail.size() > kMaxDetailBytes) {
    entry.detail.resize(kMaxDetailBytes);
  }
  trace.push_back(std::move(entry));
  return success();
}

std::optional<std::size_t> EvidenceIndex::find_site(const SiteId& site) const noexcept {
  const auto it = std::lower_bound(sites.begin(), sites.end(), site,
                                   [](const SiteRecordEntry& entry, const SiteId& key) {
                                     return entry.site.site < key;
                                   });
  if (it == sites.end() || !(it->site.site == site)) {
    return std::nullopt;
  }
  return static_cast<std::size_t>(it - sites.begin());
}

const std::vector<CapacityEntry>* EvidenceIndex::capacity_for(std::size_t site_index) const noexcept {
  if (site_index >= sites.size()) {
    return nullptr;
  }
  return &sites[site_index].capacity;
}

const CompatibilityEntry* EvidenceIndex::compatibility_for(std::size_t site_index,
                                                          const ServiceClassId& service_class) const noexcept {
  if (site_index >= sites.size()) {
    return nullptr;
  }
  const std::vector<CompatibilityEntry>& entries = sites[site_index].compatibility;
  const auto it = std::lower_bound(entries.begin(), entries.end(), service_class,
                                   [](const CompatibilityEntry& entry, const ServiceClassId& key) {
                                     return entry.service_class < key;
                                   });
  if (it == entries.end() || !(it->service_class == service_class)) {
    return nullptr;
  }
  return &*it;
}

const RecoveryEntry* EvidenceIndex::recovery_for(std::size_t site_index,
                                                 const ServiceClassId& service_class) const noexcept {
  if (site_index >= sites.size()) {
    return nullptr;
  }
  const std::vector<RecoveryEntry>& entries = sites[site_index].recovery;
  const auto it = std::lower_bound(entries.begin(), entries.end(), service_class,
                                   [](const RecoveryEntry& entry, const ServiceClassId& key) {
                                     return entry.service_class < key;
                                   });
  if (it == entries.end() || !(it->service_class == service_class)) {
    return nullptr;
  }
  return &*it;
}

const CostRiskEntry* EvidenceIndex::cost_risk_for(std::size_t site_index,
                                                  const ServiceClassId& service_class) const noexcept {
  if (site_index >= sites.size()) {
    return nullptr;
  }
  const std::vector<CostRiskEntry>& entries = sites[site_index].cost_risk;
  const auto it = std::lower_bound(entries.begin(), entries.end(), service_class,
                                   [](const CostRiskEntry& entry, const ServiceClassId& key) {
                                     return entry.service_class < key;
                                   });
  if (it != entries.end() && it->service_class == service_class) {
    return &*it;
  }
  // A record that names no service class speaks for every class at that site.
  for (const CostRiskEntry& entry : entries) {
    if (!entry.service_class.valid()) {
      return &entry;
    }
  }
  return nullptr;
}

namespace {

/// Attaches every record of one collection to its site, preserving the order the
/// collection was sorted into. A record naming a site the snapshot does not describe is
/// dropped: it is not evidence about any candidate, and inventing a site from it would
/// be inventing a candidate.
template <class Entry>
void attach_by_site(std::vector<Entry>& entries, EvidenceIndex& index) {
  std::size_t cursor = 0;
  while (cursor < entries.size()) {
    const SiteId site = entries[cursor].site;
    const std::size_t begin = cursor;
    while (cursor < entries.size() && entries[cursor].site == site) {
      ++cursor;
    }
    const std::optional<std::size_t> position = index.find_site(site);
    if (!position.has_value()) {
      continue;
    }
    std::vector<Entry>& target = [&]() -> std::vector<Entry>& {
      if constexpr (std::is_same_v<Entry, CapacityEntry>) {
        return index.sites[*position].capacity;
      } else if constexpr (std::is_same_v<Entry, CompatibilityEntry>) {
        return index.sites[*position].compatibility;
      } else if constexpr (std::is_same_v<Entry, RecoveryEntry>) {
        return index.sites[*position].recovery;
      } else {
        return index.sites[*position].cost_risk;
      }
    }();
    target.insert(target.end(), std::make_move_iterator(entries.begin() + static_cast<std::ptrdiff_t>(begin)),
                  std::make_move_iterator(entries.begin() + static_cast<std::ptrdiff_t>(cursor)));
  }
}

template <class Entry, class TieBreak>
void sort_records(std::vector<Entry>& entries, TieBreak tie_break) {
  std::stable_sort(entries.begin(), entries.end(), [&tie_break](const Entry& lhs, const Entry& rhs) {
    if (lhs.site != rhs.site) {
      return lhs.site < rhs.site;
    }
    return tie_break(lhs, rhs);
  });
}

/// The candidate list of one obligation.
///
/// When the obligation, or the request, states an allow list, the candidates are drawn
/// from that list rather than filtered out of every site: an allow list is usually tiny
/// next to the fleet, and walking the fleet for each of many obligations would be work
/// proportional to a product of two externally supplied sizes.
std::vector<std::size_t> candidates_for(const PlacementRequest& request, const Obligation& obligation,
                                        const EvidenceIndex& index) {
  std::vector<SiteId> deny = request.forbidden_sites;
  deny.insert(deny.end(), obligation.forbidden_sites.begin(), obligation.forbidden_sites.end());
  std::sort(deny.begin(), deny.end());
  deny.erase(std::unique(deny.begin(), deny.end()), deny.end());
  const auto denied = [&deny](const SiteId& site) {
    return std::binary_search(deny.begin(), deny.end(), site);
  };

  const std::vector<SiteId>& allow = !obligation.allowed_sites.empty() ? obligation.allowed_sites
                                                                      : request.allowed_sites;
  std::vector<std::size_t> candidates;
  if (allow.empty()) {
    candidates.reserve(index.sites.size());
    for (std::size_t position = 0; position < index.sites.size(); ++position) {
      if (!denied(index.sites[position].site.site)) {
        candidates.push_back(position);
      }
    }
    return candidates;
  }

  std::vector<SiteId> sorted_allow = allow;
  std::sort(sorted_allow.begin(), sorted_allow.end());
  // Every entry of the allow list is represented at most once, even when the same site
  // appears in both the obligation list and the request list.
  for (std::size_t position = 0; position < index.sites.size(); ++position) {
    const SiteId& site = index.sites[position].site.site;
    if (std::binary_search(sorted_allow.begin(), sorted_allow.end(), site) && !denied(site)) {
      candidates.push_back(position);
    }
  }
  return candidates;
}

}  // namespace

Result<EvidenceIndex> build_index(const SiteEvidenceSnapshot& snapshot, const Limits& limits) {
  (void)limits;
  EvidenceIndex index;
  index.evidence_generation = snapshot.generation;
  index.captured_at = snapshot.captured_at;

  index.sites.resize(snapshot.sites.size());
  for (std::size_t position = 0; position < snapshot.sites.size(); ++position) {
    const SiteRecord& record = snapshot.sites[position];
    SiteRecordEntry& entry = index.sites[position];
    entry.site.site = record.site;
    entry.site.jurisdiction = record.jurisdiction;
    entry.site.maintenance = record.maintenance;
    entry.site.stamp.record = record.provenance.source_record;
    entry.site.stamp.authority = record.provenance.authority;
    entry.site.stamp.generation = record.provenance.authority_generation;
    entry.site.stamp.digest = record.provenance.document_digest;
    entry.site.stamp.observed_at = record.provenance.observed_at;
  }
  std::sort(index.sites.begin(), index.sites.end(),
            [](const SiteRecordEntry& lhs, const SiteRecordEntry& rhs) {
              return lhs.site.site < rhs.site.site;
            });

  std::vector<CapacityEntry> capacity;
  capacity.reserve(snapshot.capacity.size());
  for (const CapacityRecord& record : snapshot.capacity) {
    CapacityEntry entry;
    entry.site = record.site;
    entry.reference = record.reference;
    entry.service_class = record.service_class;
    entry.kind = record.kind;
    entry.available = record.available;
    entry.stamp.record = record.provenance.source_record;
    entry.stamp.authority = record.provenance.authority;
    entry.stamp.generation = record.provenance.authority_generation;
    entry.stamp.digest = record.provenance.document_digest;
    entry.stamp.observed_at = record.provenance.observed_at;
    capacity.push_back(std::move(entry));
  }
  sort_records(capacity, [](const CapacityEntry& lhs, const CapacityEntry& rhs) {
    if (lhs.service_class != rhs.service_class) {
      return lhs.service_class < rhs.service_class;
    }
    return lhs.reference < rhs.reference;
  });

  std::vector<CompatibilityEntry> compatibility;
  compatibility.reserve(snapshot.compatibility.size());
  for (const CompatibilityRecord& record : snapshot.compatibility) {
    CompatibilityEntry entry;
    entry.site = record.site;
    entry.service_class = record.service_class;
    entry.compatible = record.compatible;
    entry.stamp.record = record.provenance.source_record;
    entry.stamp.authority = record.provenance.authority;
    entry.stamp.generation = record.provenance.authority_generation;
    entry.stamp.digest = record.provenance.document_digest;
    entry.stamp.observed_at = record.provenance.observed_at;
    compatibility.push_back(std::move(entry));
  }
  sort_records(compatibility, [](const CompatibilityEntry& lhs, const CompatibilityEntry& rhs) {
    return lhs.service_class < rhs.service_class;
  });

  std::vector<RecoveryEntry> recovery;
  recovery.reserve(snapshot.recovery.size());
  for (const RecoveryRecord& record : snapshot.recovery) {
    RecoveryEntry entry;
    entry.site = record.site;
    entry.reference = record.reference;
    entry.service_class = record.service_class;
    entry.can_host_recovery = record.can_host_recovery;
    entry.achievable_rto = record.achievable_rto;
    entry.achievable_rpo = record.achievable_rpo;
    entry.stamp.record = record.provenance.source_record;
    entry.stamp.authority = record.provenance.authority;
    entry.stamp.generation = record.provenance.authority_generation;
    entry.stamp.digest = record.provenance.document_digest;
    entry.stamp.observed_at = record.provenance.observed_at;
    recovery.push_back(std::move(entry));
  }
  sort_records(recovery, [](const RecoveryEntry& lhs, const RecoveryEntry& rhs) {
    if (lhs.service_class != rhs.service_class) {
      return lhs.service_class < rhs.service_class;
    }
    return lhs.reference < rhs.reference;
  });

  std::vector<CostRiskEntry> cost_risk;
  cost_risk.reserve(snapshot.cost_risk.size());
  for (const CostRiskRecord& record : snapshot.cost_risk) {
    CostRiskEntry entry;
    entry.site = record.site;
    entry.service_class = record.service_class;
    entry.cost_per_unit = record.cost_per_unit;
    entry.risk_per_mille = record.risk_per_mille;
    entry.stamp.record = record.provenance.source_record;
    entry.stamp.authority = record.provenance.authority;
    entry.stamp.generation = record.provenance.authority_generation;
    entry.stamp.digest = record.provenance.document_digest;
    entry.stamp.observed_at = record.provenance.observed_at;
    cost_risk.push_back(std::move(entry));
  }
  sort_records(cost_risk,
               [](const CostRiskEntry& lhs, const CostRiskEntry& rhs) { return lhs.service_class < rhs.service_class; });

  attach_by_site(capacity, index);
  attach_by_site(compatibility, index);
  attach_by_site(recovery, index);
  attach_by_site(cost_risk, index);

  index.latency.reserve(snapshot.latency.size());
  for (const LatencyRecord& record : snapshot.latency) {
    LatencyEntry entry;
    entry.reference = record.reference;
    entry.from_site = record.from_site;
    entry.to_site = record.to_site;
    entry.statistic = record.statistic;
    entry.latency = record.latency;
    entry.stamp.record = record.provenance.source_record;
    entry.stamp.authority = record.provenance.authority;
    entry.stamp.generation = record.provenance.authority_generation;
    entry.stamp.digest = record.provenance.document_digest;
    entry.stamp.observed_at = record.provenance.observed_at;
    index.latency.push_back(std::move(entry));
  }
  std::sort(index.latency.begin(), index.latency.end(), [](const LatencyEntry& lhs, const LatencyEntry& rhs) {
    if (lhs.from_site != rhs.from_site) {
      return lhs.from_site < rhs.from_site;
    }
    if (lhs.to_site != rhs.to_site) {
      return lhs.to_site < rhs.to_site;
    }
    if (lhs.statistic != rhs.statistic) {
      return lhs.statistic < rhs.statistic;
    }
    return lhs.reference < rhs.reference;
  });

  Result<DomainGraph> domains = DomainGraph::build(snapshot, limits);
  if (!domains) {
    return domains.error();
  }
  index.domains = std::move(domains).value();
  return index;
}

Instant freshness_horizon(const FreshnessPolicy& policy, const Limits& limits, Instant evaluation_instant) {
  if (evaluation_instant.is_zero()) {
    return Instant{};
  }
  const std::int64_t age = policy.max_evidence_age_nanos > 0 ? policy.max_evidence_age_nanos
                                                             : limits.max_evidence_age_nanos;
  const std::int64_t nanos = evaluation_instant.nanos() - age;
  return Instant::from_nanos(nanos > 0 ? nanos : 0);
}

namespace {

/// Builds the per-obligation contexts in canonical order. Obligations are ordered by
/// identity rather than by their position in the request, so a request whose obligations
/// were assembled in a different order produces the same plan.
std::vector<ObligationContext> build_contexts(const PlacementRequest& request, const EvidenceIndex& index) {
  std::vector<std::size_t> order(request.obligations.size());
  std::iota(order.begin(), order.end(), std::size_t{0});
  std::stable_sort(order.begin(), order.end(), [&request](std::size_t lhs, std::size_t rhs) {
    return request.obligations[lhs].obligation < request.obligations[rhs].obligation;
  });

  std::vector<ObligationContext> contexts;
  contexts.reserve(request.obligations.size());
  for (const std::size_t position : order) {
    ObligationContext context;
    context.obligation = &request.obligations[position];
    context.candidates = candidates_for(request, *context.obligation, index);
    context.primary_assessments.resize(context.candidates.size());
    context.recovery_assessments.resize(context.candidates.size());
    contexts.push_back(std::move(context));
  }
  return contexts;
}

ObligationPlacement build_obligation_placement(const Obligation& obligation, const EvidenceIndex& index,
                                               const ObligationContext& context,
                                               const std::vector<Selection>& selections, Tri outcome,
                                               std::string refusal_code, std::string detail) {
  ObligationPlacement placement;
  placement.obligation = obligation.obligation;
  placement.outcome = outcome;
  placement.refusal_code = std::move(refusal_code);
  placement.detail = std::move(detail);

  for (const Selection& selection : selections) {
    const SiteRecordEntry& site = index.sites[selection.site_index];
    SitePlacement record;
    record.site = site.site.site;
    record.role = selection.role;
    record.index = selection.index;
    record.capacity_required = obligation.required_capacity;
    record.jurisdiction = site.site.jurisdiction;
    // The capacity basis is copied from the assessment that admitted the site, so the
    // plan names the exact references it leaned on rather than a summary of them.
    const std::vector<std::optional<CandidateAssessment>>& cache =
        selection.role == PlacementRole::Recovery ? context.recovery_assessments : context.primary_assessments;
    if (selection.candidate_slot < cache.size() && cache[selection.candidate_slot].has_value()) {
      const CandidateAssessment& assessment = cache[selection.candidate_slot].value();
      record.capacity.references = assessment.capacity_references;
      record.capacity.evidenced_total = assessment.capacity_evidenced;
      record.capacity.includes_offers = assessment.capacity_includes_offers;
    }
    for (const DomainRef& domain : index.domains.site_domains_by_index(selection.site_index)) {
      record.domains.push_back(domain);
    }
    placement.placements.push_back(std::move(record));
    placement.latency.insert(placement.latency.end(), selection.latency.begin(), selection.latency.end());
  }
  return placement;
}

}  // namespace

}  // namespace csp::detail

namespace csp {
namespace {
// The planner's member definitions live in csp, because a member function has to be
// defined in a namespace that encloses its class. These declarations name the internal
// machinery once so the definitions below read as prose rather than as a chain of
// qualified identifiers.
using detail::build_contexts;
using detail::build_index;
using detail::build_obligation_placement;
using detail::cancelled_error;
using detail::EvidenceIndex;
using detail::ObligationContext;
using detail::rule_token_storage;
using detail::refusal_category_for;
using detail::run_search;
using detail::SearchResult;
using detail::Selection;
using detail::trace_phase;
using detail::WorkBudget;

namespace rule = detail::rule;
}  // namespace

Result<PlacementPlan> Planner::plan(const PlacementRequest& request, const SiteEvidenceSnapshot& evidence,
                                    const PlacementPolicy& policy, const PlanningContext& context) const {
  const Limits& limits = limits_;
  Status status = limits_validate(limits);
  if (!status) {
    return status.error();
  }
  if (context.cancellation.is_cancelled()) {
    return cancelled_error();
  }

  std::vector<ConstraintTraceEntry> trace;

  status = request_validate(request, limits);
  if (!status) {
    return status.error();
  }
  status = trace_phase(trace, limits, rule::kRequestBounds, Tri::Satisfied,
                       "the request is within every configured bound and is structurally valid");
  if (!status) {
    return status.error();
  }

  status = snapshot_validate(evidence, limits);
  if (!status) {
    return status.error();
  }
  status = trace_phase(trace, limits, rule::kSnapshotBounds, Tri::Satisfied,
                       "the evidence snapshot is within every configured bound and is structurally valid");
  if (!status) {
    return status.error();
  }

  status = policy_validate(policy, limits);
  if (!status) {
    return status.error();
  }
  if (!policy_matches_reference(policy, request.policy.policy, request.policy.generation)) {
    return fail(ErrorCategory::Conflict, "csp.policy.reference_mismatch",
                "the request names policy " + request.policy.policy.value() + " at generation " +
                    std::to_string(request.policy.generation.value()) + " but the supplied policy is " +
                    policy.policy.value() + " at generation " + std::to_string(policy.generation.value()) +
                    "; planning against a policy the request did not name would be a silent substitution");
  }
  status = trace_phase(trace, limits, rule::kPolicyReference, Tri::Satisfied,
                       "the supplied policy is the identity and generation the request named");
  if (!status) {
    return status.error();
  }

  Result<EvidenceIndex> built = build_index(evidence, limits);
  if (!built) {
    return built.error();
  }
  EvidenceIndex& index = built.value();

  status = trace_phase(trace, limits, rule::kDomainStructure, Tri::Satisfied,
                       "failure-domain containment and aliases resolved into " +
                           std::to_string(index.domains.resolved_domain_count()) + " resolved memberships");
  if (!status) {
    return status.error();
  }

  if (context.cancellation.is_cancelled()) {
    return cancelled_error();
  }

  std::vector<ObligationContext> contexts = build_contexts(request, index);

  WorkBudget budget(limits.max_search_nodes);
  Result<SearchResult> search = run_search(request, policy, limits, index, contexts, budget,
                                           context.evaluation_instant, context, trace);
  if (!search) {
    return search.error();
  }

  if (context.cancellation.is_cancelled()) {
    return cancelled_error();
  }

  PlacementPlan plan;
  plan.request = request.request;
  plan.request_generation = request.generation;
  plan.trace = std::move(trace);
  plan.search_exhausted = budget.exhausted();
  plan.nodes_explored = budget.used();

  std::size_t violated = 0;
  std::size_t indeterminate = 0;
  const SearchResult& result = search.value();

  for (std::size_t position = 0; position < contexts.size(); ++position) {
    const Obligation& obligation = *contexts[position].obligation;
    const std::vector<Selection>& selections = result.per_obligation[position];
    const std::size_t expected = static_cast<std::size_t>(obligation.primary_placements) +
                                 static_cast<std::size_t>(obligation.recovery_placements);
    Tri outcome = Tri::Satisfied;
    std::string code;
    std::string detail;
    if (selections.size() < expected) {
      if (result.has_failing_obligation && result.failing_obligation_index == position) {
        outcome = result.outcome;
        code = result.refusal_code;
        detail = result.detail;
      } else {
        outcome = Tri::Indeterminate;
        code = "csp.obligation.not-reached";
        detail = "the search stopped before this obligation was reached, so nothing was proved about it";
      }
    }
    plan.obligations.push_back(build_obligation_placement(obligation, index, contexts[position], selections,
                                                          outcome, std::move(code), std::move(detail)));
    if (outcome == Tri::Violated) {
      ++violated;
    } else if (outcome == Tri::Indeterminate) {
      ++indeterminate;
    }
  }

  // Residual: what the plan could not satisfy, stated as a shortfall rather than as
  // prose, so a caller can act on it without parsing an explanation.
  for (const ObligationPlacement& placement : plan.obligations) {
    if (placement.outcome == Tri::Satisfied) {
      continue;
    }
    const auto obligation_it = std::find_if(
        contexts.begin(), contexts.end(), [&placement](const ObligationContext& entry) {
          return entry.obligation->obligation == placement.obligation;
        });
    if (obligation_it == contexts.end()) {
      continue;
    }
    const Obligation& obligation = *obligation_it->obligation;
    const std::size_t expected = static_cast<std::size_t>(obligation.primary_placements) +
                                 static_cast<std::size_t>(obligation.recovery_placements);
    ResidualRequirement residual;
    residual.obligation = obligation.obligation;
    residual.requirement = "csp.residual.placements";
    residual.placements_short = static_cast<std::uint32_t>(expected - placement.placements.size());
    const Result<Quantity> shortfall =
        obligation.required_capacity.checked_mul(static_cast<std::int64_t>(residual.placements_short));
    if (shortfall) {
      residual.shortfall = shortfall.value();
    }
    residual.detail = placement.detail;
    if (plan.residual.size() >= limits.max_residual_entries) {
      return fail(ErrorCategory::BoundExceeded, "csp.residual.bound_exceeded",
                  "the residual list reached its configured bound");
    }
    plan.residual.push_back(std::move(residual));
  }

  plan.tie_breaks = result.tie_breaks;

  if (violated > 0) {
    // A refusal is a proof, so its category describes the cause rather than doubt. The
    // deciding rule is what the per-obligation entry already names, and the mapping below
    // says what kind of absence that rule established.
    plan.outcome = PlanOutcome::Refused;
    Refusal refusal;
    refusal.category = refusal_category_for(result.refusal_code);
    refusal.code = result.refusal_code.empty() ? "csp.plan.no-arrangement" : result.refusal_code;
    refusal.detail = result.detail.empty()
                         ? "no arrangement of the requested placements satisfies every hard rule"
                         : result.detail;
    plan.refusal = std::move(refusal);
  } else if (indeterminate > 0) {
    plan.outcome = PlanOutcome::Indeterminate;
    Refusal refusal;
    refusal.category = ErrorCategory::Indeterminate;
    refusal.code = result.refusal_code.empty() ? "csp.plan.indeterminate" : result.refusal_code;
    refusal.detail = result.detail.empty()
                         ? "the evidence and the search budget did not decide this request either way"
                         : result.detail;
    plan.refusal = std::move(refusal);
  } else {
    plan.outcome = PlanOutcome::Planned;
  }

  // Freshness envelope.
  plan.envelope.evaluated_at = context.evaluation_instant;
  plan.envelope.request_generation = request.generation;
  plan.envelope.policy_generation = policy.generation;
  plan.envelope.evidence_generation = evidence.generation;
  plan.envelope.oldest_evidence_observed_at =
      result.saw_observation ? result.oldest_observation : Instant{};

  if (!context.evaluation_instant.is_zero()) {
    const std::int64_t validity =
        request.validity.validity_nanos > 0 ? request.validity.validity_nanos : limits.max_plan_validity_nanos;
    const std::int64_t until = context.evaluation_instant.nanos() + validity;
    plan.envelope.valid_until = Instant::from_nanos(until > 0 ? until : 0);
    plan.envelope.revalidate_when.push_back("csp.revalidate.plan-expiry");
  } else {
    plan.envelope.revalidate_when.push_back("csp.revalidate.no-evaluation-instant");
  }
  plan.envelope.revalidate_when.push_back("csp.revalidate.evidence-generation");
  plan.envelope.revalidate_when.push_back("csp.revalidate.policy-generation");
  plan.envelope.revalidate_when.push_back("csp.revalidate.site-maintenance");
  plan.envelope.revalidate_when.push_back("csp.revalidate.failure-domain-membership");
  plan.envelope.revalidate_when.push_back("csp.revalidate.capacity-references");
  plan.envelope.revalidate_when.push_back("csp.revalidate.latency-references");

  plan_seal(plan);
  return plan;
}

const std::vector<std::string>& Planner::rule_tokens() { return rule_token_storage(); }

Planner::Planner() = default;
Planner::Planner(Limits limits) : limits_(std::move(limits)) {}

}  // namespace csp
