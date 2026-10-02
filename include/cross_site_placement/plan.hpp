// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The answer.
//
// A plan is a proposal and an explanation. It names the sites, and for each site it
// names the exact evidence records it relied on, the constraints it evaluated, what it
// could not satisfy, and why it chose this arrangement over the others. It reserves
// nothing, consumes nothing, and installs nothing: there is no function in this header
// that could, and the capacity references in it are references, not holdings.
//
// A plan is also a value with an identity. Its digest covers its content, and its
// identity is derived from that digest, so two identical plans in two processes have
// one identity and a caller can compare them without comparing every field.

#ifndef CROSS_SITE_PLACEMENT_PLAN_HPP
#define CROSS_SITE_PLACEMENT_PLAN_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "cross_site_placement/core.hpp"
#include "cross_site_placement/error.hpp"
#include "cross_site_placement/evidence.hpp"
#include "cross_site_placement/limits.hpp"
#include "cross_site_placement/strong_types.hpp"

namespace csp {

/// An exact reference to a record this plan used, so that a reader can fetch the same
/// record from the authority that owns it and check the reasoning for themselves.
struct EvidenceRef {
  /// Stable token for the kind of record: site, failure-domain, domain-assignment,
  /// domain-alias, capacity, latency, recovery, compatibility, or cost-risk.
  std::string kind;
  EvidenceId record;
  AuthorityId authority;
  Generation authority_generation;
  Digest document_digest;
};

/// One domain a site belongs to, after containment and aliasing have been resolved.
struct DomainRef {
  FailureDomainId domain;
  /// Absent when the domain was never declared, only assigned to. An unknown kind is
  /// not any particular kind, and a separation rule that names kinds cannot be decided
  /// for a shared domain whose kind nobody published.
  std::optional<DomainKind> kind;
  /// Distance from the site's own assignment, zero being the domain the site was
  /// directly assigned to.
  std::uint32_t depth = 0;
};

/// The capacity references a placement leans on, and what they add up to.
struct CapacityBasis {
  std::vector<CapacityRefId> references;
  Quantity evidenced_total;
  /// True when at least one reference counted here is an offer rather than a
  /// commitment, so a reader can see that the placement rests on something the owning
  /// authority has not yet committed.
  bool includes_offers = false;
};

struct SitePlacement {
  SiteId site;
  PlacementRole role = PlacementRole::Primary;
  /// Position within the obligation and role. Part of the plan, because two placements
  /// of one obligation at two sites are still ordered, and the order has to be stable.
  std::uint32_t index = 0;
  /// Required capacity attributed to this site. This is what the obligation needs here;
  /// it is not a reservation and nothing was subtracted from anything to compute it.
  Quantity capacity_required;
  CapacityBasis capacity;
  /// The resolved domain ancestry, sorted canonically by kind then identity.
  std::vector<DomainRef> domains;
  JurisdictionId jurisdiction;
};

/// How a latency requirement resolved for one placement.
struct LatencyResolution {
  /// Bounded human-readable name of the peer endpoint.
  std::string peer;
  LatencyDirection direction = LatencyDirection::FromPlacement;
  LatencyStatistic statistic = LatencyStatistic::Max;
  Duration measured;
  /// True when the value came from a chain of maximum-statistic measurements rather
  /// than from a single record.
  bool derived = false;
  /// Every record the value rests on, in path order. Exactly one entry for a direct
  /// reading; the whole chain otherwise.
  std::vector<DependencyId> chain;
};

struct ObligationPlacement {
  ObligationId obligation;
  Tri outcome = Tri::Indeterminate;
  std::vector<SitePlacement> placements;
  std::vector<LatencyResolution> latency;
  /// Stable token naming why this obligation was not placed. Empty when it was.
  std::string refusal_code;
  std::string detail;
};

enum class PlanOutcome : std::uint8_t {
  /// Every obligation in the request was placed.
  Planned = 0,
  /// A proof that no arrangement satisfies the request as stated.
  Refused = 1,
  /// Not a proof of anything. The planner could not decide with the evidence and the
  /// budget it was given. Keeping this separate from Refused matters: a caller that
  /// reads the two alike will either retry forever or abandon a placement that exists.
  Indeterminate = 2,
};

const char* to_string(PlanOutcome outcome) noexcept;
std::optional<PlanOutcome> plan_outcome_from_string(std::string_view token) noexcept;

/// One rule, and what it decided. The trace records rules that were evaluated, not only
/// rules that refused, because an explanation that only shows failures cannot show why
/// the chosen arrangement was admissible.
struct ConstraintTraceEntry {
  /// Stable rule token, of the form csp.rule.<name>.
  std::string rule;
  Tri outcome = Tri::Indeterminate;
  std::optional<ObligationId> obligation;
  std::optional<SiteId> site;
  std::string detail;
  std::vector<EvidenceRef> evidence;
};

/// What the plan could not satisfy.
struct ResidualRequirement {
  ObligationId obligation;
  /// Stable token naming the requirement: capacity, placements, separation, latency,
  /// recovery-objective, jurisdiction, compatibility, maintenance, or freshness.
  std::string requirement;
  /// Capacity still unmet. Zero when the requirement is not a capacity requirement.
  Quantity shortfall;
  /// Placements still unmet.
  std::uint32_t placements_short = 0;
  std::string detail;
};

/// One preference, and what it decided.
struct TieBreakRecord {
  /// Stable token naming the criterion.
  std::string criterion;
  /// Satisfied when the criterion could order the sites, Indeterminate when the
  /// evidence it needs was absent. An indeterminate criterion never decides anything;
  /// the next one does.
  Tri applied = Tri::Indeterminate;
  /// The sites this criterion ordered, in the order it produced.
  std::vector<SiteId> ordered;
  std::string detail;
};

/// What the plan is a statement about.
struct FreshnessEnvelope {
  /// The instant the caller said the evidence was being evaluated at. The planner never
  /// reads a clock, so this value is the caller's assertion and is recorded as such.
  Instant evaluated_at;
  /// Oldest observation among the records the plan relied on.
  Instant oldest_evidence_observed_at;
  Generation evidence_generation;
  Generation policy_generation;
  Generation request_generation;
  /// evaluated_at plus the claimed validity. Zero when the caller asserted no instant,
  /// in which case the plan carries no expiry claim at all rather than a false one.
  Instant valid_until;
  /// Stable tokens naming conditions under which the plan must be recomputed rather
  /// than used. Always non-empty: a plan that never needs revalidation would be a plan
  /// that claims the world does not move.
  std::vector<std::string> revalidate_when;
};

/// Why the plan as a whole was refused.
struct Refusal {
  ErrorCategory category = ErrorCategory::Invalid;
  std::string code;
  std::string detail;
  std::vector<EvidenceRef> evidence;
};

struct PlacementPlan {
  /// Derived from the digest, so it is stable across processes and runs. Empty until
  /// the plan has been sealed.
  PlanId plan;
  PlanOutcome outcome = PlanOutcome::Indeterminate;

  RequestId request;
  Generation request_generation;

  /// Per-obligation detail. Populated for obligations that were placed even when the
  /// plan as a whole is not Planned, because a partly placed request is exactly the
  /// case a caller needs explained. A plan whose outcome is not Planned must not be
  /// applied; nothing in this library applies a plan at all.
  std::vector<ObligationPlacement> obligations;
  std::vector<ConstraintTraceEntry> trace;
  std::vector<ResidualRequirement> residual;
  std::vector<TieBreakRecord> tie_breaks;
  std::optional<Refusal> refusal;

  FreshnessEnvelope envelope;

  /// Search nodes actually expanded, and whether the budget ran out. Reported so that an
  /// indeterminate result can be distinguished from a refusal by a reader who was not
  /// watching the machine.
  std::uint64_t nodes_explored = 0;
  bool search_exhausted = false;

  /// SHA-256 over the canonical encoding of everything above except this field and the
  /// plan identity, which is itself derived from the digest.
  Digest digest;
};

/// True only for a plan whose outcome is Planned.
[[nodiscard]] bool plan_is_applicable(const PlacementPlan& plan) noexcept;

/// Structural validation: identities present, indices contiguous from zero per role,
/// no site listed twice for one role, trace and residual entries bounded, and every
/// capacity reference non-empty. Used by the document decoder and by the store before
/// publishing anything.
[[nodiscard]] Status plan_validate(const PlacementPlan& plan, const Limits& limits);

/// The digest described above. Deterministic and independent of container order.
[[nodiscard]] Digest plan_compute_digest(const PlacementPlan& plan);

/// Computes the digest and derives the identity from it. Called once by the planner and
/// by the decoder after a successful parse.
void plan_seal(PlacementPlan& plan);

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_PLAN_HPP
