// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The evidence this boundary consumes.
//
// Nothing in this header is authored here. Every record is a reading of something an
// adjacent authority owns: site identity and jurisdiction from the site registry,
// failure-domain membership from the failure-domain registry, capacity offers and
// commitments from the capacity authority, path measurements from the fabric
// authority, recovery capability from the recovery authority, compatibility from the
// compatibility registry, and cost and risk from whichever ledger owns them.
//
// Two consequences follow, and both are enforced rather than merely intended.
//
//   * A capacity record is read, never written. Planning does not decrement, reserve,
//     hold, or commit anything. The reference in the record is carried into the plan so
//     that a reader can go back to the authority and find out what really happened;
//     this library could not change it even if it wanted to, because it has no writer.
//
//   * A quantity nobody measured stays unmeasured. A missing latency is Unknown, not
//     zero; a missing failure-domain membership is Unknown, not "no shared domain". A
//     shared domain that could not be ruled out is exactly how failure independence
//     gets satisfied by accident, so unmeasured membership produces an indeterminate
//     separation result rather than a satisfied one.

#ifndef CROSS_SITE_PLACEMENT_EVIDENCE_HPP
#define CROSS_SITE_PLACEMENT_EVIDENCE_HPP

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "cross_site_placement/limits.hpp"
#include "cross_site_placement/measurement.hpp"
#include "cross_site_placement/strong_types.hpp"

namespace csp {

/// What kind of thing a failure domain is. Separation requirements name kinds, so that
/// two sites in the same region are not treated as sharing a power feed. A requirement
/// to separate by Power is not violated by a shared Geography domain, and a requirement
/// to separate by Geography is not satisfied by two different power feeds in one hall.
enum class DomainKind : std::uint8_t {
  Power = 0,
  Cooling = 1,
  Network = 2,
  Geography = 3,
  Administrative = 4,
  Physical = 5,
  Security = 6,
};

const char* to_string(DomainKind kind) noexcept;
std::optional<DomainKind> domain_kind_from_string(std::string_view token) noexcept;

enum class MaintenanceState : std::uint8_t {
  /// Available for new placements.
  Operational = 0,
  /// Available but impaired. Whether a degraded site may be used is a policy decision.
  Degraded = 1,
  /// Declared maintenance: existing work may run, new placements may not.
  Maintenance = 2,
  /// Being emptied. New placements may not be made.
  Draining = 3,
  /// Not available at all.
  Offline = 4,
};

const char* to_string(MaintenanceState state) noexcept;
std::optional<MaintenanceState> maintenance_state_from_string(std::string_view token) noexcept;

/// Whether a capacity reference is an offer or a commitment. The distinction is kept
/// because a plan that leans on an offer is a plan whose feasibility depends on
/// something the owning authority has not committed to, and a reader of the plan is
/// entitled to see that.
enum class CapacityKind : std::uint8_t {
  Offer = 0,
  Commitment = 1,
};

const char* to_string(CapacityKind kind) noexcept;
std::optional<CapacityKind> capacity_kind_from_string(std::string_view token) noexcept;

/// Which statistic a latency measurement is. A bound expressed over the maximum is
/// satisfied by a maximum measurement; a bound over the 99th percentile is not, because
/// a peak measurement says nothing about the tail and a tail measurement says nothing
/// about the peak. Requirements and measurements are matched on this, never reconciled
/// by assuming one stands for the other.
enum class LatencyStatistic : std::uint8_t {
  P50 = 0,
  P95 = 1,
  P99 = 2,
  Max = 3,
};

const char* to_string(LatencyStatistic statistic) noexcept;
std::optional<LatencyStatistic> latency_statistic_from_string(std::string_view token) noexcept;

/// True when a measurement taken at the first statistic is usable as evidence for a
/// requirement expressed at the second. A measurement must be at least as strict as the
/// requirement; otherwise it is not evidence for that requirement at all.
constexpr bool latency_statistic_covers(LatencyStatistic statistic, LatencyStatistic required) noexcept {
  return static_cast<std::uint8_t>(statistic) >= static_cast<std::uint8_t>(required);
}

/// Where a record came from and how old it is. Freshness is a property of the evidence
/// and of the instant the caller says it is being evaluated at; it is never a property
/// of when this process happened to read the bytes.
struct Provenance {
  /// Identity of the upstream record, in the upstream authority's namespace.
  EvidenceId source_record;
  /// Which authority produced it.
  AuthorityId authority;
  /// The upstream document's generation when it was read. A plan records this so that a
  /// reader can tell whether the plan was made against the same world it is reading
  /// about.
  Generation authority_generation;
  /// When the authority observed the fact. A default-constructed instant means the
  /// record carries no observation time, which makes it unusable for any freshness
  /// decision rather than infinitely fresh.
  Instant observed_at;
  /// When the observation expires, when the authority says so.
  std::optional<Instant> expires_at;
  /// Digest of the upstream document, when the caller has it. The zero digest means no
  /// digest was supplied and no comparison is possible.
  Digest document_digest;
};

/// A site as the site registry describes it.
struct SiteRecord {
  SiteId site;
  /// The jurisdiction the site sits in. An unset jurisdiction is unrecorded, which is
  /// not the same as any particular jurisdiction.
  JurisdictionId jurisdiction;
  /// Maintenance state. Unknown means nobody said; it is never read as operational.
  Measurement<MaintenanceState> maintenance;
  Provenance provenance;
};

/// A node in the failure-domain containment forest.
struct FailureDomainRecord {
  FailureDomainId domain;
  DomainKind kind;
  /// The domain that contains this one. Absent means this domain is a root.
  std::optional<FailureDomainId> parent;
  Provenance provenance;
};

/// This site is inside this domain. A site may carry several, of different kinds.
struct DomainAssignment {
  SiteId site;
  FailureDomainId domain;
  Provenance provenance;
};

/// This domain is the same physical domain as that one.
///
/// Aliasing is not a curiosity. Two registries using different names for one power feed
/// is the ordinary case, and a separation rule that ignores aliases will happily place
/// two replicas on one feed under two names and call them independent. Aliases are
/// therefore an explicit input, are merged transitively, and are checked for
/// contradictory membership.
struct DomainAliasRecord {
  FailureDomainId domain;
  FailureDomainId alias_of;
  Provenance provenance;
};

/// A capacity offer or commitment reference.
struct CapacityRecord {
  CapacityRefId reference;
  SiteId site;
  ServiceClassId service_class;
  CapacityKind kind;
  /// How much the owning authority reports as offered or committed. This is a reading
  /// of somebody else's ledger, not a reservation held here.
  Measurement<Quantity> available;
  Provenance provenance;
};

/// A directed path measurement between two sites.
struct LatencyRecord {
  DependencyId reference;
  SiteId from_site;
  SiteId to_site;
  LatencyStatistic statistic;
  Measurement<Duration> latency;
  Provenance provenance;
};

/// What a site can do for recovery of a service class.
struct RecoveryRecord {
  RecoveryRefId reference;
  SiteId site;
  ServiceClassId service_class;
  /// Whether this site can host a recovery placement of this class at all.
  Measurement<bool> can_host_recovery;
  /// Best recovery time objective the site can meet for this class.
  Measurement<Duration> achievable_rto;
  /// Best recovery point objective the site can meet for this class.
  Measurement<Duration> achievable_rpo;
  Provenance provenance;
};

/// Whether a service class may run on a site.
struct CompatibilityRecord {
  EvidenceId reference;
  SiteId site;
  ServiceClassId service_class;
  Measurement<bool> compatible;
  Provenance provenance;
};

/// Cost and risk as reported by whichever ledger owns them. Both are integers in units
/// this boundary does not interpret: it compares them, it never converts them.
struct CostRiskRecord {
  EvidenceId reference;
  SiteId site;
  /// An unset service class means the record applies to every class at that site.
  ServiceClassId service_class;
  Measurement<Quantity> cost_per_unit;
  /// Risk in parts per thousand, so that a preference can weigh it without a float.
  Measurement<std::int64_t> risk_per_mille;
  Provenance provenance;
};

/// A complete, self-consistent reading of the world at one generation.
///
/// The snapshot is a value. It is copied into a planning call and is not shared with
/// the caller afterwards, so a caller mutating its own copy cannot change a plan that
/// was computed from it, and a concurrent planning call cannot observe a half-written
/// one.
struct SiteEvidenceSnapshot {
  /// Generation of the snapshot as a whole. It is recorded in the plan so that a reader
  /// can fence a plan against a newer world.
  Generation generation;
  /// When the caller says this reading was taken.
  Instant captured_at;
  std::vector<SiteRecord> sites;
  std::vector<FailureDomainRecord> failure_domains;
  std::vector<DomainAssignment> domain_assignments;
  std::vector<DomainAliasRecord> domain_aliases;
  std::vector<CapacityRecord> capacity;
  std::vector<LatencyRecord> latency;
  std::vector<RecoveryRecord> recovery;
  std::vector<CompatibilityRecord> compatibility;
  std::vector<CostRiskRecord> cost_risk;
};

/// Structural validation of a snapshot against the configured bounds.
///
/// Refuses, in order: a collection larger than its bound; an invalid or empty identity
/// where one is required; a duplicate identity that would make two different readings
/// indistinguishable; a measurement whose value is outside its domain; and a
/// containment edge that makes a domain its own ancestor.
///
/// Duplicate evidence records are a conflict rather than a merge: two records with one
/// identity that disagree are exactly the case where choosing one of them would be
/// inventing a fact.
[[nodiscard]] Status snapshot_validate(const SiteEvidenceSnapshot& snapshot, const Limits& limits);

/// True when the provenance carries an observation time. Evidence without one cannot be
/// shown to be fresh, so it is refused rather than assumed current.
[[nodiscard]] bool provenance_has_time(const Provenance& provenance) noexcept;

/// Age of the observation at the given instant. An observation dated in the future is
/// clamped to zero age only within the configured clock skew; beyond that it is an
/// error, because a reading from the future is not evidence about now.
[[nodiscard]] Result<Duration> provenance_age(const Provenance& provenance, Instant evaluation_instant,
                                              const Limits& limits);

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_EVIDENCE_HPP
