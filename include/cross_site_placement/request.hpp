// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The question.
//
// A request states what has to be placed and what has to be true about where it goes.
// It states nothing about the world: every fact about a site arrives through the
// evidence snapshot. Keeping the two apart is what makes the same request answerable
// against yesterday's and today's world, and what makes a plan explainable in terms of
// evidence a reader can go and check.

#ifndef CROSS_SITE_PLACEMENT_REQUEST_HPP
#define CROSS_SITE_PLACEMENT_REQUEST_HPP

#include <cstdint>
#include <optional>
#include <vector>

#include "cross_site_placement/core.hpp"
#include "cross_site_placement/evidence.hpp"
#include "cross_site_placement/limits.hpp"
#include "cross_site_placement/strong_types.hpp"

namespace csp {

/// Every pair of placements in a group must avoid sharing any domain whose kind is
/// listed, and must avoid sharing any domain named outright.
///
/// The second list is what makes "must not share a forbidden common domain" checkable
/// when the requirement names one specific feed rather than a kind. Both lists are
/// evaluated against the resolved domain ancestry of each site, including domains
/// reached through containment and merged through aliases.
struct SeparationRequirement {
  SeparationGroup group = SeparationGroup::All;
  std::vector<DomainKind> separated_kinds;
  std::vector<FailureDomainId> forbidden_shared_domains;
};

/// One end of a latency requirement. Either an obligation in the same request, or a
/// service that already runs at a named site and that this request does not place.
struct DependencyEndpoint {
  enum class Kind : std::uint8_t {
    Obligation = 0,
    SiteService = 1,
  };

  Kind kind = Kind::Obligation;
  /// Set when kind is Obligation.
  ObligationId obligation;
  /// Set when kind is SiteService.
  SiteId site;
  /// Set when kind is SiteService: which service runs there.
  ServiceClassId service_class;

  friend bool operator==(const DependencyEndpoint& lhs, const DependencyEndpoint& rhs) noexcept {
    return lhs.kind == rhs.kind && lhs.obligation == rhs.obligation && lhs.site == rhs.site &&
           lhs.service_class == rhs.service_class;
  }
};

/// A bound on the time between a placement of this obligation and a peer.
struct LatencyRequirement {
  DependencyEndpoint peer;
  LatencyDirection direction = LatencyDirection::FromPlacement;
  /// The statistic the bound is expressed over. Evidence looser than this does not
  /// satisfy it.
  LatencyStatistic statistic = LatencyStatistic::Max;
  Duration max_latency;
  /// Which of this obligation's placements the bound applies to.
  PlacementRole applies_to = PlacementRole::Primary;
};

/// What has to be placed, and what has to be true about where.
struct Obligation {
  ObligationId obligation;
  ServiceClassId service_class;

  /// Capacity required at each placement, in the units the capacity authority reports.
  Quantity required_capacity;

  /// How many placements carry the service.
  std::uint32_t primary_placements = 1;

  /// How many recovery alternatives must exist. A recovery placement is a site that
  /// could take over; this boundary selects it and stops there. Bringing it up is the
  /// recovery authority's decision, not this one's.
  std::uint32_t recovery_placements = 0;

  /// Recovery objective the recovery placements must be able to meet, when required.
  std::optional<Duration> required_rto;
  std::optional<Duration> required_rpo;

  /// Jurisdictions this obligation may be placed in. Empty means the request states no
  /// jurisdictional constraint for this obligation.
  std::vector<JurisdictionId> allowed_jurisdictions;

  /// Sites this obligation may use. Empty means the request-level list applies, and an
  /// empty request-level list means every site in the evidence.
  std::vector<SiteId> allowed_sites;
  /// Sites this obligation may not use. Applied after the allow list, so a site in both
  /// lists is forbidden.
  std::vector<SiteId> forbidden_sites;

  std::vector<SeparationRequirement> separations;
  std::vector<LatencyRequirement> latency_requirements;

  /// May two placements of this obligation share one site?
  ///
  /// False by default. Two placements on one site are not two placements for the
  /// purposes of any availability argument, so allowing it is a deliberate, visible
  /// choice rather than an optimisation the planner makes on the caller's behalf.
  bool allow_colocation = false;
};

/// Which policy the request was written against.
struct PolicyRef {
  PolicyId policy;
  Generation generation;
};

/// How ties are broken when more than one arrangement satisfies every hard rule.
///
/// The objectives are a strict priority order: the first decides, and each later one
/// breaks only the ties the earlier ones left. The final tie-break is always the site
/// identity in byte order, which is why a total order always exists even when no
/// preference can be evaluated at all.
struct Preferences {
  enum class Objective : std::uint8_t {
    /// Fewest distinct sites.
    MinimiseSites = 0,
    /// Lowest reported cost per unit. A site with no reported cost does not win by
    /// virtue of the report being missing.
    MinimiseCost = 1,
    /// Lowest reported risk.
    MinimiseRisk = 2,
    /// Sites that belong to the most distinct resolved failure domains, most first.
    ///
    /// This is a per-site ordering, not a set-level maximisation: the search applies it
    /// before it checks separation, and the plan records it as a per-site criterion
    /// rather than claiming to have maximised anything about the chosen set.
    MaximiseDomainSpread = 3,
  };

  std::vector<Objective> objectives;
};

const char* to_string(Preferences::Objective objective) noexcept;
std::optional<Preferences::Objective> preference_objective_from_string(std::string_view token) noexcept;

/// How old evidence may be for this request.
struct FreshnessPolicy {
  /// Age beyond which evidence is refused. Zero means the configured limit applies.
  std::int64_t max_evidence_age_nanos = 0;
  /// When true, evidence that carries no observation time cannot satisfy a constraint.
  /// When false the caller accepts an unbounded age, and such evidence is usable; the
  /// plan's envelope then records a zero oldest observation, so a reader can see that the
  /// plan's evidence has no reported age at all rather than an age of zero.
  bool require_observation_time = true;
};

/// How long the plan claims to be usable for.
struct ValidityPolicy {
  /// Zero means the configured limit applies. The value is the claim, and the plan
  /// records it so that a reader can disagree with it explicitly rather than
  /// discovering it later.
  std::int64_t validity_nanos = 0;
};

struct PlacementRequest {
  RequestId request;
  /// The request's own generation. A retry of the same logical request with a newer
  /// generation is a different request, and plans from the two are not interchangeable.
  Generation generation;

  std::vector<Obligation> obligations;

  /// Sites any obligation may use, unless the obligation states its own list.
  std::vector<SiteId> allowed_sites;
  /// Sites no obligation may use. Applied after every allow list.
  std::vector<SiteId> forbidden_sites;

  PolicyRef policy;
  Preferences preferences;
  FreshnessPolicy freshness;
  ValidityPolicy validity;
};

/// Structural validation against the configured bounds.
///
/// Refuses: more obligations than the bound; a duplicate obligation identity, because
/// two obligations with one identity cannot both be placed distinctly; an unset or
/// invalid required identity; a negative required capacity; a placement count of zero
/// or above the bound; a separation requirement that names no kind and no domain, since
/// it would constrain nothing while looking as though it did; a latency requirement
/// whose peer is the obligation itself, which is not a constraint but a tautology; and
/// a latency requirement with a negative bound.
[[nodiscard]] Status request_validate(const PlacementRequest& request, const Limits& limits);

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_REQUEST_HPP
