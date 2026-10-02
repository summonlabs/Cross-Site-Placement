// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Latency bounds.
//
// This boundary measures nothing. A bound is decided from records the fabric authority
// published, and when no record exists the answer is that nobody knows, not that the
// path is fast.
//
// Two kinds of answer are possible. A direct measurement for the exact ordered pair
// settles the bound immediately. When there is none, a chain of maximum-statistic
// measurements can still settle it, because the maximum of a sum is at most the sum of
// the maxima, so a chain of peaks is a valid upper bound for the whole path. Only the
// maximum statistic may be composed: percentiles do not add, and adding them would
// invent a number no instrument produced. The chain is recorded in full, so a reader can
// see exactly which records the derived bound rests on.

#include "engine_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "checked.hpp"

namespace csp::detail {
namespace {

constexpr std::int64_t kUnreached = -1;

struct ChainStep {
  DependencyId reference;
  EvidenceRef ref;
  Instant observed_at;
};

struct PathResult {
  bool found = false;
  Duration total;
  std::vector<ChainStep> steps;
};

/// Dijkstra over the maximum-statistic evidence graph.
///
/// Weights are elapsed times and therefore non-negative, so the first time a site is
/// settled its distance is final and a cycle in the evidence cannot change the answer.
/// The exploration is bounded in both hops and relaxations: a snapshot that describes a
/// dense graph must not be able to turn one bound into unbounded work. Ties are broken by
/// the site's position in the canonical index, never by which entry the queue happened to
/// return first, so the derived path is a function of the evidence alone.
PathResult derive_path(const EvidenceIndex& index, const SiteId& from_site, const SiteId& to_site,
                       std::size_t max_hops, std::uint64_t max_expansions, WorkBudget& budget) {
  PathResult result;
  const std::optional<std::size_t> start = index.find_site(from_site);
  const std::optional<std::size_t> goal = index.find_site(to_site);
  if (!start.has_value() || !goal.has_value()) {
    return result;
  }
  if (*start == *goal) {
    result.found = true;
    result.total = Duration::from_nanos(0);
    return result;
  }

  const std::size_t node_count = index.sites.size();
  std::vector<std::int64_t> distance(node_count, kUnreached);
  std::vector<std::size_t> hops(node_count, 0);
  std::vector<std::size_t> settled_from(node_count, 0);
  std::vector<const LatencyEntry*> via(node_count, nullptr);

  using QueueItem = std::pair<std::int64_t, std::size_t>;
  std::priority_queue<QueueItem, std::vector<QueueItem>, std::greater<QueueItem>> queue;
  std::uint64_t expansions = 0;
  distance[*start] = 0;
  queue.push(QueueItem{0, *start});

  while (!queue.empty()) {
    const QueueItem item = queue.top();
    queue.pop();
    const std::size_t node = item.second;
    if (item.first != distance[node]) {
      continue;
    }
    if (node == *goal) {
      break;
    }
    if (hops[node] >= max_hops) {
      continue;
    }
    // Two bounds: the derivation's own, which the caller configured, and the shared work
    // budget, so one path cannot spend the whole planning budget on its own.
    if (expansions >= max_expansions) {
      break;
    }
    ++expansions;
    if (!budget.consume(1)) {
      return result;
    }
    const SiteId& node_site = index.sites[node].site.site;
    const auto begin = std::lower_bound(index.latency.begin(), index.latency.end(), node_site,
                                        [](const LatencyEntry& entry, const SiteId& key) {
                                          return entry.from_site < key;
                                        });
    for (auto it = begin; it != index.latency.end() && it->from_site == node_site; ++it) {
      if (it->statistic != LatencyStatistic::Max || !it->latency.is_known()) {
        continue;
      }
      const std::optional<std::size_t> target = index.find_site(it->to_site);
      if (!target.has_value()) {
        continue;
      }
      const std::optional<std::int64_t> sum = checked_add(distance[node], it->latency.value().nanos());
      if (!sum.has_value()) {
        continue;
      }
      const std::size_t next_hops = hops[node] + 1;
      const bool better = distance[*target] == kUnreached || sum.value() < distance[*target] ||
                          (sum.value() == distance[*target] && next_hops < hops[*target]);
      if (!better) {
        continue;
      }
      distance[*target] = sum.value();
      hops[*target] = next_hops;
      settled_from[*target] = node;
      via[*target] = &*it;
      queue.push(QueueItem{distance[*target], *target});
    }
  }

  if (distance[*goal] == kUnreached) {
    return result;
  }
  result.found = true;
  result.total = Duration::from_nanos(distance[*goal]);
  std::size_t cursor = *goal;
  while (cursor != *start) {
    const LatencyEntry* entry = via[cursor];
    if (entry == nullptr) {
      result.found = false;
      result.steps.clear();
      return result;
    }
    ChainStep step;
    step.reference = entry->reference;
    step.ref = make_ref("latency", entry->stamp);
    step.observed_at = entry->stamp.observed_at;
    result.steps.push_back(std::move(step));
    cursor = settled_from[cursor];
  }
  std::reverse(result.steps.begin(), result.steps.end());
  return result;
}

}  // namespace

LatencyOutcome resolve_latency(const LatencyRequirement& requirement, const SiteId& from_site,
                               const SiteId& to_site, const EvidenceIndex& index,
                               const PlacementPolicy& policy, const Limits& limits, Instant horizon,
                               bool require_observation_time, WorkBudget& budget) {
  (void)limits;
  LatencyOutcome outcome;
  outcome.resolution.direction = requirement.direction;
  outcome.resolution.statistic = requirement.statistic;
  outcome.resolution.peer = from_site.value() + " to " + to_site.value();

  const auto begin = std::lower_bound(index.latency.begin(), index.latency.end(), from_site,
                                      [](const LatencyEntry& entry, const SiteId& key) {
                                        return entry.from_site < key;
                                      });
  const LatencyEntry* best = nullptr;
  bool saw_unusable = false;
  for (auto it = begin; it != index.latency.end() && it->from_site == from_site; ++it) {
    if (it->to_site != to_site) {
      continue;
    }
    if (!latency_statistic_covers(it->statistic, requirement.statistic)) {
      // A looser statistic is not evidence for a stricter bound. A peak does not bound a
      // tail, and a tail does not bound a peak.
      saw_unusable = true;
      continue;
    }
    if (!it->latency.is_known()) {
      saw_unusable = true;
      continue;
    }
    if (it->stamp.observed_at.is_zero()) {
      if (require_observation_time) {
        saw_unusable = true;
        continue;
      }
    } else if (!horizon.is_zero() && it->stamp.observed_at < horizon) {
      saw_unusable = true;
      continue;
    }
    if (best == nullptr || it->latency.value() < best->latency.value() ||
        (it->latency.value() == best->latency.value() && it->reference < best->reference)) {
      best = &*it;
    }
  }

  if (best != nullptr) {
    outcome.resolution.measured = best->latency.value();
    outcome.resolution.derived = false;
    outcome.resolution.chain.push_back(best->reference);
    outcome.evidence.push_back(make_ref("latency", best->stamp));
    if (!best->stamp.observed_at.is_zero()) {
      outcome.oldest_observation = best->stamp.observed_at;
      outcome.saw_observation = true;
    }
    outcome.outcome = best->latency.value() <= requirement.max_latency ? Tri::Satisfied : Tri::Violated;
    outcome.detail = outcome.outcome == Tri::Satisfied ? "a direct measurement satisfies the bound"
                                                       : "a direct measurement exceeds the bound";
    return outcome;
  }

  if (policy.allow_derived_latency_bounds) {
    const std::size_t max_hops = policy.max_derived_hops > 0 ? policy.max_derived_hops : limits.max_derived_hops;
    const PathResult derived =
        derive_path(index, from_site, to_site, max_hops, static_cast<std::uint64_t>(limits.max_derived_expansions),
                    budget);
    if (derived.found && !derived.steps.empty()) {
      outcome.resolution.measured = derived.total;
      outcome.resolution.derived = true;
      for (const ChainStep& step : derived.steps) {
        outcome.resolution.chain.push_back(step.reference);
        outcome.evidence.push_back(step.ref);
        if (!step.observed_at.is_zero() &&
            (!outcome.saw_observation || step.observed_at < outcome.oldest_observation)) {
          outcome.oldest_observation = step.observed_at;
          outcome.saw_observation = true;
        }
      }
      outcome.outcome = derived.total <= requirement.max_latency ? Tri::Satisfied : Tri::Violated;
      outcome.detail = outcome.outcome == Tri::Satisfied
                           ? "a chain of maximum-statistic measurements bounds the path within the requirement"
                           : "a chain of maximum-statistic measurements exceeds the requirement";
      return outcome;
    }
  }

  outcome.outcome = Tri::Indeterminate;
  outcome.detail = saw_unusable
                       ? "measurements exist for this pair but none of them is usable evidence for this bound"
                       : "no measurement of this pair exists in the supplied evidence, so the bound is unknown";
  return outcome;
}

}  // namespace csp::detail
