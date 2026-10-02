// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "domain_graph.hpp"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <numeric>
#include <string>
#include <utility>

namespace csp::detail {
namespace {

/// Union-find over domain identities. Union by size with ties broken by the smaller
/// index, so the resulting structure does not depend on the order the aliases arrived
/// in. The representative is then taken as the smallest identity in the class rather
/// than whatever the structure happened to root, which makes the canonical identity a
/// function of the set and nothing else.
class DisjointSet {
 public:
  explicit DisjointSet(std::size_t count) : parent_(count), size_(count, 1) {
    std::iota(parent_.begin(), parent_.end(), std::size_t{0});
  }

  std::size_t find(std::size_t value) {
    std::size_t root = value;
    while (parent_[root] != root) {
      root = parent_[root];
    }
    while (parent_[value] != root) {
      const std::size_t next = parent_[value];
      parent_[value] = root;
      value = next;
    }
    return root;
  }

  void unite(std::size_t lhs, std::size_t rhs) {
    lhs = find(lhs);
    rhs = find(rhs);
    if (lhs == rhs) {
      return;
    }
    if (size_[lhs] < size_[rhs] || (size_[lhs] == size_[rhs] && rhs < lhs)) {
      std::swap(lhs, rhs);
    }
    parent_[rhs] = lhs;
    size_[lhs] += size_[rhs];
  }

 private:
  std::vector<std::size_t> parent_;
  std::vector<std::size_t> size_;
};

std::uint8_t kind_rank(const std::optional<DomainKind>& kind) noexcept {
  return kind.has_value() ? static_cast<std::uint8_t>(*kind) : std::uint8_t{255};
}

template <class T>
std::optional<std::size_t> index_of(const std::vector<T>& sorted, const T& key) {
  const auto it = std::lower_bound(sorted.begin(), sorted.end(), key);
  if (it == sorted.end() || *it != key) {
    return std::nullopt;
  }
  return static_cast<std::size_t>(it - sorted.begin());
}

std::vector<DomainRef> sorted_by_domain(std::vector<DomainRef> refs) {
  std::sort(refs.begin(), refs.end(),
            [](const DomainRef& lhs, const DomainRef& rhs) { return lhs.domain < rhs.domain; });
  return refs;
}

}  // namespace

bool domain_ref_less(const DomainRef& lhs, const DomainRef& rhs) noexcept {
  const std::uint8_t lhs_rank = kind_rank(lhs.kind);
  const std::uint8_t rhs_rank = kind_rank(rhs.kind);
  if (lhs_rank != rhs_rank) {
    return lhs_rank < rhs_rank;
  }
  if (lhs.domain != rhs.domain) {
    return lhs.domain < rhs.domain;
  }
  return lhs.depth < rhs.depth;
}

Result<DomainGraph> DomainGraph::build(const SiteEvidenceSnapshot& snapshot, const Limits& limits) {
  DomainGraph graph;

  // Step 1: every identity that appears anywhere in the domain evidence, sorted so
  // that all later work is a function of the set and not of the order it arrived in.
  graph.ids_.reserve(snapshot.failure_domains.size() * 2 + snapshot.domain_assignments.size() +
                     snapshot.domain_aliases.size() * 2);
  for (const FailureDomainRecord& record : snapshot.failure_domains) {
    graph.ids_.push_back(record.domain);
    if (record.parent.has_value()) {
      graph.ids_.push_back(*record.parent);
    }
  }
  for (const DomainAssignment& assignment : snapshot.domain_assignments) {
    graph.ids_.push_back(assignment.domain);
  }
  for (const DomainAliasRecord& alias : snapshot.domain_aliases) {
    graph.ids_.push_back(alias.domain);
    graph.ids_.push_back(alias.alias_of);
  }
  std::sort(graph.ids_.begin(), graph.ids_.end());
  graph.ids_.erase(std::unique(graph.ids_.begin(), graph.ids_.end()), graph.ids_.end());

  graph.alias_root_.resize(graph.ids_.size());
  {
    DisjointSet sets(graph.ids_.size());
    for (const DomainAliasRecord& alias : snapshot.domain_aliases) {
      const std::optional<std::size_t> lhs = index_of(graph.ids_, alias.domain);
      const std::optional<std::size_t> rhs = index_of(graph.ids_, alias.alias_of);
      if (lhs.has_value() && rhs.has_value()) {
        sets.unite(*lhs, *rhs);
      }
    }
    std::vector<FailureDomainId> representatives;
    representatives.reserve(graph.ids_.size());
    for (std::size_t index = 0; index < graph.ids_.size(); ++index) {
      representatives.push_back(graph.ids_[sets.find(index)]);
    }
    // The canonical identity is the smallest one in the class, so it does not depend on
    // union order.
    std::vector<FailureDomainId> canonical_ids = representatives;
    std::sort(canonical_ids.begin(), canonical_ids.end());
    canonical_ids.erase(std::unique(canonical_ids.begin(), canonical_ids.end()), canonical_ids.end());
    for (std::size_t index = 0; index < graph.ids_.size(); ++index) {
      const std::optional<std::size_t> canonical = index_of(canonical_ids, representatives[index]);
      graph.alias_root_[index] = canonical.has_value() ? *canonical : 0;
    }
    std::vector<std::size_t> root_index(graph.ids_.size());
    for (std::size_t index = 0; index < graph.ids_.size(); ++index) {
      root_index[index] = graph.alias_root_[index];
    }
    // Re-key alias_root_ by position in ids_ rather than by position in the canonical
    // list, so canonical() below is a plain lookup.
    graph.nodes_.resize(canonical_ids.size());
    for (std::size_t index = 0; index < canonical_ids.size(); ++index) {
      graph.nodes_[index].domain = canonical_ids[index];
    }
    std::vector<std::size_t> canonical_of_id(graph.ids_.size());
    for (std::size_t index = 0; index < graph.ids_.size(); ++index) {
      canonical_of_id[index] = root_index[index];
    }
    graph.alias_root_ = std::move(canonical_of_id);
  }

  const auto node_index = [&graph](const FailureDomainId& domain) -> std::optional<std::size_t> {
    const auto it = std::lower_bound(graph.nodes_.begin(), graph.nodes_.end(), domain,
                                     [](const DomainGraph::Node& node, const FailureDomainId& key) {
                                       return node.domain < key;
                                     });
    if (it == graph.nodes_.end() || !(it->domain == domain)) {
      return std::nullopt;
    }
    return static_cast<std::size_t>(it - graph.nodes_.begin());
  };

  const auto canonical_of = [&graph](const FailureDomainId& domain) -> FailureDomainId {
    const std::optional<std::size_t> index = index_of(graph.ids_, domain);
    if (!index.has_value()) {
      return domain;
    }
    return graph.nodes_[graph.alias_root_[*index]].domain;
  };

  // Step 2: fold the declarations onto the canonical nodes, refusing a class whose
  // members disagree about what they are or what contains them.
  for (const FailureDomainRecord& record : snapshot.failure_domains) {
    const FailureDomainId domain = canonical_of(record.domain);
    const std::optional<std::size_t> index = node_index(domain);
    if (!index.has_value()) {
      continue;
    }
    Node& node = graph.nodes_[*index];
    if (node.kind.has_value() && *node.kind != record.kind) {
      return fail(ErrorCategory::Conflict, "csp.domains.kind_conflict",
                  "failure domain " + domain.value() + " is declared both as " +
                      to_string(*node.kind) + " and as " + to_string(record.kind) +
                      "; two kinds for one domain cannot both be true");
    }
    node.kind = record.kind;
    if (record.parent.has_value()) {
      const FailureDomainId parent = canonical_of(*record.parent);
      if (node.parent.has_value() && *node.parent != parent) {
        return fail(ErrorCategory::Conflict, "csp.domains.parent_conflict",
                    "failure domain " + domain.value() + " is contained by both " +
                        node.parent->value() + " and " + parent.value());
      }
      node.parent = parent;
    }
  }

  // Step 3: transitive ancestry, with a cycle refused rather than walked.
  std::vector<std::uint8_t> colour(graph.nodes_.size(), 0);  // 0 unvisited, 1 on stack, 2 done
  std::size_t resolved = 0;
  Status walk_status = success();

  std::function<Status(std::size_t)> walk = [&](std::size_t index) -> Status {
    if (colour[index] == 2) {
      return success();
    }
    if (colour[index] == 1) {
      return fail(ErrorCategory::Conflict, "csp.domains.containment_cycle",
                  "failure domain " + graph.nodes_[index].domain.value() +
                      " contains itself through a chain of containers; contradictory containment is not resolvable here");
    }
    colour[index] = 1;
    Node& node = graph.nodes_[index];
    std::vector<DomainRef> ancestry;
    ancestry.push_back(DomainRef{node.domain, node.kind, 0});
    if (node.parent.has_value()) {
      const std::optional<std::size_t> parent = node_index(*node.parent);
      if (!parent.has_value()) {
        return fail(ErrorCategory::Internal, "csp.domains.parent_missing",
                    "resolved containment refers to a domain that is not in the index");
      }
      const Status status = walk(*parent);
      if (!status) {
        return status;
      }
      for (const DomainRef& ref : graph.nodes_[*parent].ancestry) {
        const std::uint32_t depth = ref.depth + 1;
        if (depth > limits.max_domain_depth) {
          return fail(ErrorCategory::BoundExceeded, "csp.domains.depth_exceeded",
                      "the containment chain through " + node.domain.value() + " is longer than " +
                          std::to_string(limits.max_domain_depth) + " domains");
        }
        ancestry.push_back(DomainRef{ref.domain, ref.kind, depth});
      }
    }
    // Two paths can reach one domain at different distances; the shortest distance is
    // the one that means anything, and the rest are duplicates of one fact.
    std::sort(ancestry.begin(), ancestry.end(), domain_ref_less);
    std::vector<DomainRef> unique;
    unique.reserve(ancestry.size());
    for (const DomainRef& ref : ancestry) {
      if (!unique.empty() && unique.back().domain == ref.domain) {
        continue;
      }
      unique.push_back(ref);
    }
    resolved += unique.size();
    if (resolved > limits.max_resolved_domains) {
      return fail(ErrorCategory::BoundExceeded, "csp.domains.resolved_exceeded",
                  "the resolved failure-domain structure exceeds " +
                      std::to_string(limits.max_resolved_domains) + " entries");
    }
    node.ancestry = std::move(unique);
    colour[index] = 2;
    return success();
  };

  for (std::size_t index = 0; index < graph.nodes_.size(); ++index) {
    walk_status = walk(index);
    if (!walk_status) {
      return walk_status.error();
    }
  }

  // Step 4: per-site membership.
  graph.site_ids_.reserve(snapshot.sites.size());
  for (const SiteRecord& site : snapshot.sites) {
    graph.site_ids_.push_back(site.site);
  }
  std::sort(graph.site_ids_.begin(), graph.site_ids_.end());
  graph.site_ids_.erase(std::unique(graph.site_ids_.begin(), graph.site_ids_.end()), graph.site_ids_.end());
  graph.site_index_.assign(graph.site_ids_.size(), std::nullopt);
  graph.site_domains_.assign(graph.site_ids_.size(), {});

  for (std::size_t index = 0; index < graph.site_ids_.size(); ++index) {
    graph.site_index_[index] = index;
  }

  std::vector<std::size_t> assignment_order(snapshot.domain_assignments.size());
  std::iota(assignment_order.begin(), assignment_order.end(), std::size_t{0});
  std::stable_sort(assignment_order.begin(), assignment_order.end(),
                   [&snapshot](std::size_t lhs, std::size_t rhs) {
                     return snapshot.domain_assignments[lhs].site < snapshot.domain_assignments[rhs].site;
                   });

  std::size_t cursor = 0;
  while (cursor < assignment_order.size()) {
    const SiteId& site = snapshot.domain_assignments[assignment_order[cursor]].site;
    const std::optional<std::size_t> site_position = index_of(graph.site_ids_, site);
    std::vector<DomainRef> accumulated;
    while (cursor < assignment_order.size() &&
           snapshot.domain_assignments[assignment_order[cursor]].site == site) {
      const FailureDomainId domain = canonical_of(snapshot.domain_assignments[assignment_order[cursor]].domain);
      ++cursor;
      const std::optional<std::size_t> node = node_index(domain);
      if (!node.has_value()) {
        accumulated.push_back(DomainRef{domain, std::nullopt, 0});
        continue;
      }
      for (const DomainRef& ref : graph.nodes_[*node].ancestry) {
        accumulated.push_back(ref);
      }
    }
    std::sort(accumulated.begin(), accumulated.end(), domain_ref_less);
    std::vector<DomainRef> unique;
    unique.reserve(accumulated.size());
    for (const DomainRef& ref : accumulated) {
      if (!unique.empty() && unique.back().domain == ref.domain) {
        continue;
      }
      unique.push_back(ref);
    }
    resolved += unique.size();
    if (resolved > limits.max_resolved_domains) {
      return fail(ErrorCategory::BoundExceeded, "csp.domains.resolved_exceeded",
                  "the resolved failure-domain structure exceeds " +
                      std::to_string(limits.max_resolved_domains) + " entries");
    }
    if (site_position.has_value()) {
      graph.site_domains_[*site_position] = std::move(unique);
    }
  }

  graph.resolved_entries_ = resolved;
  return graph;
}

const std::vector<DomainRef>& DomainGraph::site_domains(const SiteId& site) const noexcept {
  static const std::vector<DomainRef> kEmpty;
  const std::optional<std::size_t> index = index_of(site_ids_, site);
  if (!index.has_value()) {
    return kEmpty;
  }
  return site_domains_[*index];
}

const std::vector<DomainRef>& DomainGraph::site_domains_by_index(std::size_t index) const noexcept {
  static const std::vector<DomainRef> kEmpty;
  if (index >= site_domains_.size()) {
    return kEmpty;
  }
  return site_domains_[index];
}

bool DomainGraph::has_membership(const SiteId& site) const noexcept {
  const std::optional<std::size_t> index = index_of(site_ids_, site);
  if (!index.has_value()) {
    return false;
  }
  return !site_domains_[*index].empty();
}

FailureDomainId DomainGraph::canonical(const FailureDomainId& domain) const {
  const std::optional<std::size_t> index = index_of(ids_, domain);
  if (!index.has_value()) {
    return domain;
  }
  return nodes_[alias_root_[*index]].domain;
}

SeparationCheck DomainGraph::separate(const SiteId& lhs_site, const SiteId& rhs_site,
                                      const std::vector<DomainKind>& kinds,
                                      const std::vector<FailureDomainId>& forbidden) const {
  SeparationCheck check;

  const std::optional<std::size_t> lhs_index = index_of(site_ids_, lhs_site);
  const std::optional<std::size_t> rhs_index = index_of(site_ids_, rhs_site);
  const bool lhs_known = lhs_index.has_value() && !site_domains_[*lhs_index].empty();
  const bool rhs_known = rhs_index.has_value() && !site_domains_[*rhs_index].empty();
  if (!lhs_known || !rhs_known) {
    // Nobody recorded where one of these sites sits. Two sites whose domains are
    // unknown may be one building, so reporting them as separated would assert the
    // exact fact the rule is asking about.
    check.outcome = Tri::Indeterminate;
    return check;
  }

  std::vector<FailureDomainId> forbidden_canonical;
  forbidden_canonical.reserve(forbidden.size());
  for (const FailureDomainId& domain : forbidden) {
    forbidden_canonical.push_back(canonical(domain));
  }
  std::sort(forbidden_canonical.begin(), forbidden_canonical.end());
  forbidden_canonical.erase(std::unique(forbidden_canonical.begin(), forbidden_canonical.end()),
                            forbidden_canonical.end());

  const std::vector<DomainRef> lhs = sorted_by_domain(site_domains_[*lhs_index]);
  const std::vector<DomainRef> rhs = sorted_by_domain(site_domains_[*rhs_index]);

  std::size_t lhs_cursor = 0;
  std::size_t rhs_cursor = 0;
  bool violated = false;
  while (lhs_cursor < lhs.size() && rhs_cursor < rhs.size()) {
    const DomainRef& left = lhs[lhs_cursor];
    const DomainRef& right = rhs[rhs_cursor];
    if (left.domain < right.domain) {
      ++lhs_cursor;
      continue;
    }
    if (right.domain < left.domain) {
      ++rhs_cursor;
      continue;
    }
    const bool named = std::binary_search(forbidden_canonical.begin(), forbidden_canonical.end(), left.domain);
    if (named) {
      violated = true;
      check.shared.push_back(left);
    } else if (!kinds.empty()) {
      if (left.kind.has_value()) {
        if (std::find(kinds.begin(), kinds.end(), *left.kind) != kinds.end()) {
          violated = true;
          check.shared.push_back(left);
        }
      } else {
        check.shared_unclassified.push_back(left);
      }
    }
    ++lhs_cursor;
    ++rhs_cursor;
  }

  if (violated) {
    check.outcome = Tri::Violated;
    check.shared_unclassified.clear();
    return check;
  }
  if (!check.shared_unclassified.empty()) {
    check.outcome = Tri::Indeterminate;
    return check;
  }
  check.outcome = Tri::Satisfied;
  return check;
}

}  // namespace csp::detail
