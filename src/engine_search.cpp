// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The selection search.
//
// Obligations are placed in identity order and their placements one after another,
// because a latency requirement may name a peer obligation and a bound that crosses two
// obligations can only be decided once both ends are known. The search is a depth-first
// walk over the candidate order with backtracking, written iteratively rather than
// recursively: the number of placements is an externally supplied number, and a
// recursive walk would put it on the call stack.
//
// The first complete assignment the walk reaches is the answer. Because the walk tries
// candidates in the request's preference order and backtracks only when a choice cannot
// be completed, that assignment is the preferred one among those that satisfy every hard
// rule, and it is the same assignment on every run and in every process.

#include "engine_internal.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

#include "parallel.hpp"

namespace csp::detail {
namespace {

struct GlobalSlot {
  std::size_t obligation_index = 0;
  PlacementRole role = PlacementRole::Primary;
  std::uint32_t index = 0;
};

/// A rejected candidate, and why.
struct Rejection {
  Tri outcome = Tri::Indeterminate;
  std::string rule = rule::kSelection;
  std::string detail;
};

struct Acceptance {
  bool ok = false;
  Rejection rejection;
  std::vector<LatencyResolution> latency;
  Instant oldest_observation;
  bool saw_observation = false;
};

struct Frame {
  std::size_t global_slot = 0;
  std::size_t obligation_index = 0;
  std::size_t trial = 0;
  /// Sites already chosen for this obligation, tried before the ordered candidate list
  /// when the request asks for the fewest sites and the obligation permits co-location.
  std::vector<std::size_t> reuse;
  std::size_t violated = 0;
  std::size_t undecided = 0;
  Rejection first_violation;
  Rejection first_undecided;
  bool recorded = false;
};

struct Failure {
  bool set = false;
  std::size_t obligation_index = 0;
  Tri outcome = Tri::Indeterminate;
  std::string code;
  std::string detail;
};

std::string preference_token(Preferences::Objective objective) {
  return std::string("csp.preference.") + to_string(objective);
}

bool has_objective(const Preferences& preferences, Preferences::Objective objective) {
  return std::find(preferences.objectives.begin(), preferences.objectives.end(), objective) !=
         preferences.objectives.end();
}

/// Cost and risk sort keys. A quantity nobody reported sorts last and is never treated as
/// zero: a site with no cost on record does not become the cheapest site in the fleet.
using SortKey = std::pair<std::int64_t, std::int64_t>;

SortKey known_key(std::int64_t value) { return SortKey{0, value}; }
SortKey unknown_key() { return SortKey{1, 0}; }

/// Builds the candidate order for one obligation and the record of what each criterion
/// decided. The order is a total order in every case, because the site identity is the
/// final tie-break and is always available.
Status build_order(const PlacementRequest& request, const Obligation& obligation, const PlacementPolicy& policy,
                   const Limits& limits, const EvidenceIndex& index, ObligationContext& context,
                   Instant evaluation_instant, const PlanningContext& planning, WorkBudget& budget,
                   std::vector<std::size_t>& order, std::vector<TieBreakRecord>& records) {
  const std::size_t count = context.candidates.size();
  order.resize(count);
  std::iota(order.begin(), order.end(), std::size_t{0});

  const auto site_of = [&context, &index](std::size_t slot) -> const SiteId& {
    return index.sites[context.candidates[slot]].site.site;
  };

  const bool needs_cost = has_objective(request.preferences, Preferences::Objective::MinimiseCost);
  const bool needs_risk = has_objective(request.preferences, Preferences::Objective::MinimiseRisk);
  const bool needs_spread = has_objective(request.preferences, Preferences::Objective::MaximiseDomainSpread);
  const bool needs_assessment = needs_cost || needs_risk || needs_spread;

  std::vector<SortKey> cost(count, unknown_key());
  std::vector<SortKey> risk(count, unknown_key());
  std::vector<std::int64_t> spread(count, 0);
  std::size_t cost_known = 0;
  std::size_t risk_known = 0;

  if (needs_assessment) {
    const PlacementRole role = obligation.primary_placements > 0 ? PlacementRole::Primary : PlacementRole::Recovery;

    // The exact cost of assessing every candidate, computed before any of it is spent.
    // It is a function of the inputs, so reserving it up front is what keeps the budget a
    // property of the request rather than of the schedule: a pass that ran out of budget
    // partway through would leave a different set of candidates ordered depending on how
    // the work happened to be split.
    std::uint64_t reserve = 0;
    for (std::size_t slot = 0; slot < count; ++slot) {
      const std::vector<CapacityEntry>* entries = index.capacity_for(context.candidates[slot]);
      reserve += 1 + static_cast<std::uint64_t>(entries == nullptr ? 0 : entries->size());
    }

    std::atomic<std::size_t> first_failure{std::numeric_limits<std::size_t>::max()};
    std::atomic<std::size_t> cost_known_atomic{0};
    std::atomic<std::size_t> risk_known_atomic{0};

    const auto assess_one = [&](std::size_t slot) {
      Result<const CandidateAssessment*> assessed =
          assessment_for(request, obligation, policy, limits, index, context, slot, role, evaluation_instant,
                         planning, budget);
      if (!assessed) {
        std::size_t current = first_failure.load(std::memory_order_relaxed);
        while (slot < current &&
               !first_failure.compare_exchange_weak(current, slot, std::memory_order_relaxed)) {
        }
        return;
      }
      const CandidateAssessment& assessment = *assessed.value();
      if (needs_cost && assessment.cost.is_known()) {
        cost[slot] = known_key(assessment.cost.value().units());
        cost_known_atomic.fetch_add(1, std::memory_order_relaxed);
      }
      if (needs_risk && assessment.risk.is_known()) {
        risk[slot] = known_key(assessment.risk.value());
        risk_known_atomic.fetch_add(1, std::memory_order_relaxed);
      }
      if (needs_spread) {
        spread[slot] = static_cast<std::int64_t>(
            index.domains.site_domains_by_index(context.candidates[slot]).size());
      }
    };

    if (count >= limits.parallel_threshold && limits.worker_threads > 1 && budget.remaining() >= reserve) {
      detail::parallel_for(count, detail::ParallelOptions{limits.worker_threads, limits.parallel_threshold},
                           planning.cancellation, assess_one);
      const std::size_t failed_slot = first_failure.load(std::memory_order_relaxed);
      if (failed_slot != std::numeric_limits<std::size_t>::max()) {
        // The failing slot is re-run on the calling thread so that the error reported is
        // the one the sequential path would have produced, rather than whichever worker
        // lost the race.
        const Result<const CandidateAssessment*> assessed =
            assessment_for(request, obligation, policy, limits, index, context, failed_slot, role,
                           evaluation_instant, planning, budget);
        if (!assessed) {
          return assessed.error();
        }
      }
      cost_known = cost_known_atomic.load(std::memory_order_relaxed);
      risk_known = risk_known_atomic.load(std::memory_order_relaxed);
    } else {
      for (std::size_t slot = 0; slot < count; ++slot) {
        // On the calling thread the error is returned directly, so the caller sees the
        // real cause - a bound, or an arithmetic overflow - rather than a summary of it.
        Result<const CandidateAssessment*> assessed =
            assessment_for(request, obligation, policy, limits, index, context, slot, role, evaluation_instant,
                           planning, budget);
        if (!assessed) {
          return assessed.error();
        }
        const CandidateAssessment& assessment = *assessed.value();
        if (needs_cost && assessment.cost.is_known()) {
          cost[slot] = known_key(assessment.cost.value().units());
          ++cost_known;
        }
        if (needs_risk && assessment.risk.is_known()) {
          risk[slot] = known_key(assessment.risk.value());
          ++risk_known;
        }
        if (needs_spread) {
          spread[slot] = static_cast<std::int64_t>(
              index.domains.site_domains_by_index(context.candidates[slot]).size());
        }
      }
      // Nothing to read back here: on the calling thread the counters were incremented
      // in place. Reading the atomics would report zero, because no worker ever ran.
    }
  }

  std::stable_sort(order.begin(), order.end(), [&](std::size_t lhs, std::size_t rhs) {
    for (const Preferences::Objective objective : request.preferences.objectives) {
      switch (objective) {
        case Preferences::Objective::MinimiseCost:
          if (cost[lhs] != cost[rhs]) {
            return cost[lhs] < cost[rhs];
          }
          break;
        case Preferences::Objective::MinimiseRisk:
          if (risk[lhs] != risk[rhs]) {
            return risk[lhs] < risk[rhs];
          }
          break;
        case Preferences::Objective::MaximiseDomainSpread:
          if (spread[lhs] != spread[rhs]) {
            return spread[lhs] > spread[rhs];
          }
          break;
        case Preferences::Objective::MinimiseSites:
        default:
          break;
      }
    }
    return site_of(lhs) < site_of(rhs);
  });

  for (const Preferences::Objective objective : request.preferences.objectives) {
    TieBreakRecord record;
    record.criterion = preference_token(objective);
    switch (objective) {
      case Preferences::Objective::MinimiseCost:
        record.applied = needs_cost && cost_known == count ? Tri::Satisfied : Tri::Indeterminate;
        record.detail = std::to_string(cost_known) + " of " + std::to_string(count) +
                        " candidates have a reported cost; the rest sort last and are not treated as free";
        break;
      case Preferences::Objective::MinimiseRisk:
        record.applied = needs_risk && risk_known == count ? Tri::Satisfied : Tri::Indeterminate;
        record.detail = std::to_string(risk_known) + " of " + std::to_string(count) +
                        " candidates have a reported risk; the rest sort last and are not treated as safe";
        break;
      case Preferences::Objective::MaximiseDomainSpread:
        record.applied = count == 0 ? Tri::Indeterminate : Tri::Satisfied;
        record.detail = "candidates are ordered by how many resolved failure domains they belong to, most first";
        break;
      case Preferences::Objective::MinimiseSites:
      default:
        record.applied = Tri::Indeterminate;
        record.detail = "fewest sites is applied by the search, which tries a site already chosen for this "
                        "obligation before a new one when the obligation permits co-location";
        break;
    }
    records.push_back(std::move(record));
  }

  TieBreakRecord identity;
  identity.criterion = "csp.preference.site-identity";
  identity.applied = Tri::Satisfied;
  identity.detail = "site identity in byte order is the final tie-break and never yields";
  for (std::size_t slot = 0; slot < order.size() && slot < 16; ++slot) {
    identity.ordered.push_back(site_of(order[slot]));
  }
  records.push_back(std::move(identity));
  return success();
}

}  // namespace

Result<SearchResult> run_search(const PlacementRequest& request, const PlacementPolicy& policy,
                                const Limits& limits, const EvidenceIndex& index,
                                std::vector<ObligationContext>& contexts, WorkBudget& budget,
                                Instant evaluation_instant, const PlanningContext& planning,
                                std::vector<ConstraintTraceEntry>& trace) {
  SearchResult result;
  result.per_obligation.resize(contexts.size());

  std::vector<GlobalSlot> slots;
  for (std::size_t obligation_index = 0; obligation_index < contexts.size(); ++obligation_index) {
    const Obligation& obligation = *contexts[obligation_index].obligation;
    for (std::uint32_t position = 0; position < obligation.primary_placements; ++position) {
      slots.push_back(GlobalSlot{obligation_index, PlacementRole::Primary, position});
    }
    for (std::uint32_t position = 0; position < obligation.recovery_placements; ++position) {
      slots.push_back(GlobalSlot{obligation_index, PlacementRole::Recovery, position});
    }
  }

  Failure failure;
  const auto record_failure = [&failure](std::size_t obligation_index, Tri outcome, std::string code,
                                         std::string detail) {
    // A proof outranks doubt, and otherwise the first reason stands. Without the second
    // rule the last frame to exhaust would replace a specific cause - a shared power
    // domain, say - with the generic reason of the frame that happened to run last, which
    // is exactly the kind of explanation a caller cannot act on.
    if (failure.set) {
      if (failure.outcome == Tri::Violated) {
        return;
      }
      if (outcome != Tri::Violated) {
        return;
      }
    }
    failure.set = true;
    failure.obligation_index = obligation_index;
    failure.outcome = outcome;
    failure.code = std::move(code);
    failure.detail = std::move(detail);
  };

  // Order every obligation's candidates once. An obligation with no candidate at all is a
  // definite refusal: the site set it was allowed to use is empty.
  std::vector<std::vector<std::size_t>> orders(contexts.size());
  for (std::size_t obligation_index = 0; obligation_index < contexts.size(); ++obligation_index) {
    const Obligation& obligation = *contexts[obligation_index].obligation;
    Status status = build_order(request, obligation, policy, limits, index, contexts[obligation_index],
                                evaluation_instant, planning, budget, orders[obligation_index], result.tie_breaks);
    if (!status) {
      return status.error();
    }
    if (contexts[obligation_index].candidates.empty()) {
      record_failure(obligation_index, Tri::Violated, "csp.rule.selection",
                     "no site is available to obligation " + obligation.obligation.value() +
                         " after the allow and deny lists were applied");
    }
  }

  const bool prefer_reuse = has_objective(request.preferences, Preferences::Objective::MinimiseSites);

  const auto evaluate = [&](const GlobalSlot& slot, std::size_t candidate_slot,
                            Acceptance& acceptance) -> Status {
    const std::size_t obligation_index = slot.obligation_index;
    ObligationContext& context = contexts[obligation_index];
    const Obligation& obligation = *context.obligation;
    const std::size_t site_index = context.candidates[candidate_slot];
    const SiteId& site = index.sites[site_index].site.site;

    Result<const CandidateAssessment*> assessed =
        assessment_for(request, obligation, policy, limits, index, context, candidate_slot, slot.role,
                       evaluation_instant, planning, budget);
    if (!assessed) {
      return assessed.error();
    }
    const CandidateAssessment& assessment = *assessed.value();
    if (assessment.outcome != Tri::Satisfied) {
      acceptance.rejection.outcome = assessment.outcome;
      acceptance.rejection.rule = assessment.rule.empty() ? std::string(rule::kSelection) : assessment.rule;
      acceptance.rejection.detail = assessment.detail;
      return success();
    }
    if (!assessment.oldest_observation.is_zero()) {
      acceptance.oldest_observation = assessment.oldest_observation;
      acceptance.saw_observation = true;
    }

    std::vector<Selection>& chosen = result.per_obligation[obligation_index];

    // Co-location.
    for (const Selection& existing : chosen) {
      if (existing.site_index != site_index) {
        continue;
      }
      if (slot.role == PlacementRole::Recovery && existing.role == PlacementRole::Primary &&
          !policy.allow_recovery_on_primary_site) {
        acceptance.rejection.outcome = Tri::Violated;
        acceptance.rejection.rule = rule::kColocation;
        acceptance.rejection.detail =
            "a recovery placement may not share a site with a primary placement under this policy";
        return success();
      }
      if (!obligation.allow_colocation) {
        acceptance.rejection.outcome = Tri::Violated;
        acceptance.rejection.rule = rule::kColocation;
        acceptance.rejection.detail = "this obligation does not permit two of its placements on one site";
        return success();
      }
    }

    // Failure-domain separation between this placement and every placement of the same
    // obligation that the requirement's group covers.
    Tri separation = Tri::Satisfied;
    std::string separation_detail;
    for (const SeparationRequirement& requirement : obligation.separations) {
      for (const Selection& existing : chosen) {
        const bool applies = requirement.group == SeparationGroup::All ||
                             (requirement.group == SeparationGroup::WithinRole && existing.role == slot.role) ||
                             (requirement.group == SeparationGroup::AcrossRoles && existing.role != slot.role);
        if (!applies) {
          continue;
        }
        const SiteId& other = index.sites[existing.site_index].site.site;
        const SeparationCheck check =
            index.domains.separate(other, site, requirement.separated_kinds, requirement.forbidden_shared_domains);
        if (check.outcome == Tri::Violated) {
          separation = Tri::Violated;
          separation_detail = "sites " + other.value() + " and " + site.value() +
                              " share a failure domain this requirement forbids";
          break;
        }
        if (check.outcome == Tri::Indeterminate && separation == Tri::Satisfied) {
          separation = Tri::Indeterminate;
          separation_detail = "whether " + other.value() + " and " + site.value() +
                              " share a failure domain of a kind this requirement names cannot be decided from "
                              "the supplied evidence";
        }
      }
      if (separation == Tri::Violated) {
        break;
      }
    }
    if (separation != Tri::Satisfied) {
      acceptance.rejection.outcome = separation;
      acceptance.rejection.rule = rule::kSeparation;
      acceptance.rejection.detail = separation_detail;
      return success();
    }

    // Latency. Two directions have to be checked: this obligation's own requirements
    // against peers already placed, and the requirements of already placed obligations
    // that name this obligation. Between them every pair is decided exactly once, and a
    // requirement that names a peer placed later is decided when that peer is placed.
    const Instant horizon = freshness_horizon(request.freshness, limits, evaluation_instant);
    const auto check_pair = [&](const LatencyRequirement& requirement, const SiteId& from_site,
                                const SiteId& to_site, bool& rejected) -> Status {
      rejected = false;
      LatencyOutcome outcome = resolve_latency(requirement, from_site, to_site, index, policy, limits, horizon,
                                               request.freshness.require_observation_time, budget);
      if (outcome.outcome == Tri::Satisfied) {
        if (!outcome.oldest_observation.is_zero() &&
            (!acceptance.saw_observation || outcome.oldest_observation < acceptance.oldest_observation)) {
          acceptance.oldest_observation = outcome.oldest_observation;
          acceptance.saw_observation = true;
        }
        acceptance.latency.push_back(std::move(outcome.resolution));
        return success();
      }
      acceptance.rejection.outcome = outcome.outcome;
      acceptance.rejection.rule = rule::kLatency;
      acceptance.rejection.detail = outcome.detail;
      rejected = true;
      return success();
    };

    // Requirements of this obligation that name a peer which is fixed, or already placed.
    for (const LatencyRequirement& requirement : obligation.latency_requirements) {
      if (requirement.applies_to != slot.role) {
        continue;
      }
      bool rejected = false;
      if (requirement.peer.kind == DependencyEndpoint::Kind::SiteService) {
        const SiteId& peer_site = requirement.peer.site;
        const SiteId& from_site = requirement.direction == LatencyDirection::FromPlacement ? site : peer_site;
        const SiteId& to_site = requirement.direction == LatencyDirection::FromPlacement ? peer_site : site;
        Status status = check_pair(requirement, from_site, to_site, rejected);
        if (!status) {
          return status;
        }
        if (rejected) {
          return success();
        }
        continue;
      }
      for (std::size_t peer_index = 0; peer_index < contexts.size(); ++peer_index) {
        if (peer_index == obligation_index) {
          continue;
        }
        if (contexts[peer_index].obligation->obligation != requirement.peer.obligation) {
          continue;
        }
        for (const Selection& peer : result.per_obligation[peer_index]) {
          const SiteId& peer_site = index.sites[peer.site_index].site.site;
          const SiteId& from_site = requirement.direction == LatencyDirection::FromPlacement ? site : peer_site;
          const SiteId& to_site = requirement.direction == LatencyDirection::FromPlacement ? peer_site : site;
          Status status = check_pair(requirement, from_site, to_site, rejected);
          if (!status) {
            return status;
          }
          if (rejected) {
            return success();
          }
        }
      }
    }

    // Requirements of already placed obligations that name this one. A requirement whose
    // peer is placed later is decided here, from the other side, when that peer arrives.
    for (std::size_t other_index = 0; other_index < contexts.size(); ++other_index) {
      if (other_index == obligation_index) {
        continue;
      }
      const Obligation& other = *contexts[other_index].obligation;
      for (const LatencyRequirement& requirement : other.latency_requirements) {
        if (requirement.peer.kind != DependencyEndpoint::Kind::Obligation ||
            requirement.peer.obligation != obligation.obligation) {
          continue;
        }
        for (const Selection& peer : result.per_obligation[other_index]) {
          if (peer.role != requirement.applies_to) {
            continue;
          }
          bool rejected = false;
          const SiteId& peer_site = index.sites[peer.site_index].site.site;
          const SiteId& from_site = requirement.direction == LatencyDirection::FromPlacement ? peer_site : site;
          const SiteId& to_site = requirement.direction == LatencyDirection::FromPlacement ? site : peer_site;
          Status status = check_pair(requirement, from_site, to_site, rejected);
          if (!status) {
            return status;
          }
          if (rejected) {
            return success();
          }
        }
      }
    }

    acceptance.ok = true;
    return success();
  };

  std::vector<Frame> stack;
  Frame root;
  root.global_slot = 0;
  root.obligation_index = slots.empty() ? 0 : slots[0].obligation_index;
  stack.push_back(std::move(root));

  bool found = slots.empty();
  bool aborted = false;

  while (!stack.empty() && !found) {
    Frame& frame = stack.back();
    if (frame.global_slot >= slots.size()) {
      found = true;
      break;
    }
    if (planning.cancellation.is_cancelled()) {
      return fail(ErrorCategory::Cancelled, "csp.plan.cancelled", "the caller cancelled the planning call");
    }

    const std::size_t global_slot = frame.global_slot;
    const GlobalSlot slot = slots[global_slot];
    const std::size_t obligation_index = slot.obligation_index;
    const std::vector<std::size_t>& order = orders[obligation_index];
    const std::size_t reuse_count = frame.reuse.size();
    const std::size_t total_trials = reuse_count + order.size();

    if (frame.trial >= total_trials) {
      const Tri outcome = frame.violated > 0 && frame.undecided == 0 ? Tri::Violated : Tri::Indeterminate;
      const Rejection& reason = outcome == Tri::Violated ? frame.first_violation : frame.first_undecided;
      // Which rule decided is the useful part of a refusal, so the code names the rule
      // rather than a generic token; the caller maps it to a category.
      const std::string code = frame.violated == 0 && frame.undecided == 0 ? std::string("csp.rule.selection")
                                                                         : reason.rule;
      record_failure(obligation_index, outcome, code,
                     frame.violated == 0 && frame.undecided == 0
                         ? "no candidate site was available for this placement"
                         : (reason.detail.empty() ? std::string("no candidate satisfied this placement") : reason.detail));
      stack.pop_back();
      if (!stack.empty() && global_slot > 0) {
        const GlobalSlot previous = slots[global_slot - 1];
        std::vector<Selection>& undo = result.per_obligation[previous.obligation_index];
        if (!undo.empty()) {
          undo.pop_back();
        }
      }
      continue;
    }

    const std::size_t candidate_slot =
        frame.trial < reuse_count ? frame.reuse[frame.trial] : order[frame.trial - reuse_count];
    ++frame.trial;

    if (!budget.consume(1)) {
      aborted = true;
      break;
    }

    Acceptance acceptance;
    Status status = evaluate(slot, candidate_slot, acceptance);
    if (!status) {
      const Error& error = status.error();
      if (error.category() == ErrorCategory::BoundExceeded) {
        aborted = true;
        break;
      }
      return error;
    }
    if (!acceptance.ok) {
      if (acceptance.rejection.outcome == Tri::Violated) {
        if (frame.violated == 0) {
          frame.first_violation = acceptance.rejection;
        }
        ++frame.violated;
      } else {
        if (frame.undecided == 0) {
          frame.first_undecided = acceptance.rejection;
        }
        ++frame.undecided;
      }
      continue;
    }

    Selection selection;
    selection.site_index = contexts[obligation_index].candidates[candidate_slot];
    selection.candidate_slot = candidate_slot;
    selection.role = slot.role;
    selection.index = slot.index;
    selection.latency = std::move(acceptance.latency);
    result.per_obligation[obligation_index].push_back(std::move(selection));

    Frame next;
    next.global_slot = global_slot + 1;
    if (next.global_slot < slots.size()) {
      const GlobalSlot& next_slot = slots[next.global_slot];
      next.obligation_index = next_slot.obligation_index;
      if (prefer_reuse && contexts[next_slot.obligation_index].obligation->allow_colocation) {
        for (const Selection& existing : result.per_obligation[next_slot.obligation_index]) {
          const SiteId& existing_site = index.sites[existing.site_index].site.site;
          const std::vector<std::size_t>& candidates = contexts[next_slot.obligation_index].candidates;
          const auto it = std::lower_bound(candidates.begin(), candidates.end(), existing_site,
                                           [&index](std::size_t position, const SiteId& key) {
                                             return index.sites[position].site.site < key;
                                           });
          if (it != candidates.end() && index.sites[*it].site.site == existing_site) {
            next.reuse.push_back(static_cast<std::size_t>(it - candidates.begin()));
          }
        }
      }
    }
    stack.push_back(std::move(next));
  }

  if (aborted || budget.exhausted()) {
    result.outcome = Tri::Indeterminate;
    result.refusal_code = "csp.search.budget-exhausted";
    result.detail = "the planning work budget ran out before the search finished, so nothing was proved either way";
    result.has_failing_obligation = false;
    result.per_obligation.assign(contexts.size(), std::vector<Selection>{});
    return result;
  }

  if (!found) {
    result.outcome = failure.set ? failure.outcome : Tri::Indeterminate;
    result.refusal_code = failure.set ? failure.code : "csp.plan.undecided";
    result.detail = failure.set ? failure.detail : "the search found no complete arrangement and no definite refusal";
    if (failure.set) {
      result.has_failing_obligation = true;
      result.failing_obligation_index = failure.obligation_index;
    }
    return result;
  }

  result.outcome = Tri::Satisfied;

  // How old the world this plan reasoned about was: the oldest observation among the
  // evidence behind the placements actually selected, not among every record examined.
  Instant oldest;
  bool saw = false;
  for (std::size_t obligation_index = 0; obligation_index < contexts.size(); ++obligation_index) {
    const ObligationContext& context = contexts[obligation_index];
    const Obligation& obligation = *context.obligation;
    for (const Selection& selection : result.per_obligation[obligation_index]) {
      const std::vector<std::size_t>& candidates = context.candidates;
      const auto it = std::find_if(candidates.begin(), candidates.end(), [&index, &selection](std::size_t position) {
        return position == selection.site_index;
      });
      if (it == candidates.end()) {
        continue;
      }
      const std::size_t slot = static_cast<std::size_t>(it - candidates.begin());
      const std::vector<std::optional<CandidateAssessment>>& cache =
          selection.role == PlacementRole::Recovery ? context.recovery_assessments : context.primary_assessments;
      if (slot >= cache.size() || !cache[slot].has_value()) {
        continue;
      }
      const Instant observed = cache[slot]->oldest_observation;
      if (!observed.is_zero() && (!saw || observed < oldest)) {
        oldest = observed;
        saw = true;
      }
    }

    ConstraintTraceEntry entry;
    entry.rule = rule::kSelection;
    entry.outcome = Tri::Satisfied;
    entry.obligation = obligation.obligation;
    // The selection entry names every record the chosen sites were admitted on, so a
    // reader can go back to the authorities and check the reasoning without having to
    // reconstruct which candidate was chosen and re-run the rules.
    for (const Selection& selection : result.per_obligation[obligation_index]) {
      const std::vector<std::optional<CandidateAssessment>>& cache =
          selection.role == PlacementRole::Recovery ? context.recovery_assessments : context.primary_assessments;
      if (selection.candidate_slot >= cache.size() || !cache[selection.candidate_slot].has_value()) {
        continue;
      }
      const std::vector<EvidenceRef>& refs = cache[selection.candidate_slot].value().evidence;
      entry.evidence.insert(entry.evidence.end(), refs.begin(), refs.end());
    }
    entry.detail = std::to_string(result.per_obligation[obligation_index].size()) + " of " +
                   std::to_string(static_cast<std::size_t>(obligation.primary_placements) +
                                  static_cast<std::size_t>(obligation.recovery_placements)) +
                   " placements selected from " + std::to_string(context.candidates.size()) + " candidates";
    Status status = push_trace(trace, limits, std::move(entry));
    if (!status) {
      return status.error();
    }
  }
  result.oldest_observation = oldest;
  result.saw_observation = saw;
  return result;
}

}  // namespace csp::detail
