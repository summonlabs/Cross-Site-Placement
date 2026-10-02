// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The resolved failure-domain structure of a snapshot.
//
// Failure-domain membership arrives as three separate things: which domains exist and
// what contains what, which site is inside which domain, and which domains are two
// names for one thing. None of them is usable on its own. A separation rule has to be
// evaluated against the transitive closure of containment, because a shared root is a
// shared failure, and it has to be evaluated against alias-merged identities, because
// two registries naming one power feed twice is the ordinary case rather than the
// exotic one.
//
// This is also where failure independence is protected from being satisfied by
// accident. Two sites that share a domain of a kind the rule names are not independent,
// however many distinct leaf names they carry; two sites that share a domain whose kind
// nobody published cannot be shown to be independent, and the rule is left undecided
// rather than reported as satisfied.

#ifndef CSP_SRC_DOMAIN_GRAPH_HPP
#define CSP_SRC_DOMAIN_GRAPH_HPP

#include <cstddef>
#include <optional>
#include <vector>

#include "cross_site_placement/evidence.hpp"
#include "cross_site_placement/plan.hpp"

namespace csp::detail {

struct SeparationCheck {
  Tri outcome = Tri::Indeterminate;
  /// Shared domains that decided a violation.
  std::vector<DomainRef> shared;
  /// Shared domains nobody declared, which is why a rule naming kinds could not be
  /// decided. Empty when the outcome is Satisfied or came from a violation.
  std::vector<DomainRef> shared_unclassified;
};

class DomainGraph {
 public:
  DomainGraph() = default;

  /// Resolves containment and aliases. Refuses a containment cycle, two aliased
  /// domains that disagree about their kind or their container, a chain longer than the
  /// configured depth, and a resolved structure larger than the configured bound.
  [[nodiscard]] static Result<DomainGraph> build(const SiteEvidenceSnapshot& snapshot, const Limits& limits);

  /// Every domain the site is inside, directly or through containment, alias-merged,
  /// deduplicated by identity, and sorted by kind then identity then depth.
  [[nodiscard]] const std::vector<DomainRef>& site_domains(const SiteId& site) const noexcept;

  /// True when the snapshot records at least one membership for the site. A site with
  /// no membership is inside no known domain, which is not the same as being inside no
  /// domain.
  [[nodiscard]] bool has_membership(const SiteId& site) const noexcept;

  [[nodiscard]] std::size_t resolved_domain_count() const noexcept { return resolved_entries_; }

  /// The canonical identity of a domain after alias merging. A domain that never
  /// appeared is returned unchanged, so the call is safe on an unknown identity.
  [[nodiscard]] FailureDomainId canonical(const FailureDomainId& domain) const;

  /// Evaluates one pair of sites.
  ///
  /// A site whose membership nobody recorded is not independent of anything: two sites
  /// with no published domains may be one building, and reporting them as separated
  /// would be inventing the very fact the rule asks about. Such a pair is undecided.
  [[nodiscard]] SeparationCheck separate(const SiteId& lhs_site, const SiteId& rhs_site,
                                         const std::vector<DomainKind>& kinds,
                                         const std::vector<FailureDomainId>& forbidden) const;

  /// The resolved ancestry of a site, or an empty vector when it has none recorded.
  [[nodiscard]] const std::vector<DomainRef>& site_domains_by_index(std::size_t index) const noexcept;

 private:
  struct Node {
    FailureDomainId domain;
    std::optional<DomainKind> kind;
    std::optional<FailureDomainId> parent;
    std::vector<DomainRef> ancestry;
  };

  std::vector<FailureDomainId> ids_;
  std::vector<std::size_t> alias_root_;
  std::vector<Node> nodes_;
  std::vector<std::optional<std::size_t>> site_index_;
  std::vector<SiteId> site_ids_;
  std::vector<std::vector<DomainRef>> site_domains_;
  std::size_t resolved_entries_ = 0;
};

/// Canonical ordering for resolved domains: known kinds in their declared order, then
/// domains whose kind nobody published, each group ordered by identity and then by
/// distance. Exposed so the engine, the plan, and the tests all sort the same way.
[[nodiscard]] bool domain_ref_less(const DomainRef& lhs, const DomainRef& rhs) noexcept;

}  // namespace csp::detail

#endif  // CSP_SRC_DOMAIN_GRAPH_HPP
