// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Internal machinery of the planner.
//
// The snapshot arrives in whatever order the caller assembled it. Everything the
// planner reasons over is therefore copied once into sorted, index-based tables at the
// start of a call, and nothing after that point reads the caller's vectors again. That
// single step is what makes ingestion order irrelevant: two snapshots that differ only
// in the order of their records produce the same tables, and therefore the same plan.

#ifndef CSP_SRC_ENGINE_INTERNAL_HPP
#define CSP_SRC_ENGINE_INTERNAL_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "cross_site_placement/engine.hpp"
#include "cross_site_placement/plan.hpp"
#include "domain_graph.hpp"

namespace csp::detail {

/// Stable rule tokens. A trace names rules by these strings, and the tokens are part of
/// the contract: a reader that knows the token list can tell an absent rule from a rule
/// that ran and passed.
namespace rule {
inline constexpr const char* kRequestBounds = "csp.rule.request-bounds";
inline constexpr const char* kSnapshotBounds = "csp.rule.snapshot-bounds";
inline constexpr const char* kPolicyReference = "csp.rule.policy-reference";
inline constexpr const char* kDomainStructure = "csp.rule.domain-structure";
inline constexpr const char* kFreshness = "csp.rule.evidence-freshness";
inline constexpr const char* kAllowList = "csp.rule.site-allow-list";
inline constexpr const char* kDenyList = "csp.rule.site-deny-list";
inline constexpr const char* kJurisdiction = "csp.rule.jurisdiction";
inline constexpr const char* kMaintenance = "csp.rule.maintenance-state";
inline constexpr const char* kCompatibility = "csp.rule.service-compatibility";
inline constexpr const char* kCapacity = "csp.rule.capacity-evidence";
inline constexpr const char* kRecoveryCapability = "csp.rule.recovery-capability";
inline constexpr const char* kRecoveryObjective = "csp.rule.recovery-objective";
inline constexpr const char* kSeparation = "csp.rule.failure-domain-separation";
inline constexpr const char* kLatency = "csp.rule.latency-bound";
inline constexpr const char* kColocation = "csp.rule.colocation";
inline constexpr const char* kSelection = "csp.rule.selection";
inline constexpr const char* kPreference = "csp.rule.preference-order";
inline constexpr const char* kSearchBudget = "csp.rule.search-budget";
}  // namespace rule

/// A shared work budget. One budget covers candidate assessment and search expansion
/// together, because both are bounded work derived from externally supplied sizes, and a
/// separate budget for each would leave the product of the two unbounded.
///
/// The counters are atomic because the per-candidate assessment pass may run across
/// workers. The total consumed by a complete pass is a function of the inputs rather than
/// of the schedule, and the parallel pass is only taken when the whole pass is known to
/// fit the remaining budget, so exhaustion is never decided by which worker ran first.
class WorkBudget {
 public:
  explicit WorkBudget(std::uint64_t limit) noexcept : limit_(limit) {}

  /// Consumes the requested amount, or refuses and marks the budget exhausted when it
  /// would not fit. A refused consumption consumes nothing, so a caller can report
  /// exactly how far it got.
  bool consume(std::uint64_t amount) noexcept {
    if (exhausted_.load(std::memory_order_relaxed)) {
      return false;
    }
    std::uint64_t used = used_.load(std::memory_order_relaxed);
    for (;;) {
      if (amount > limit_ - used) {
        exhausted_.store(true, std::memory_order_relaxed);
        return false;
      }
      if (used_.compare_exchange_weak(used, used + amount, std::memory_order_relaxed)) {
        return true;
      }
    }
  }

  std::uint64_t used() const noexcept { return used_.load(std::memory_order_relaxed); }
  std::uint64_t limit() const noexcept { return limit_; }
  std::uint64_t remaining() const noexcept { return limit_ - used(); }
  bool exhausted() const noexcept { return exhausted_.load(std::memory_order_relaxed); }

 private:
  std::uint64_t limit_;
  std::atomic<std::uint64_t> used_{0};
  std::atomic<bool> exhausted_{false};
};

/// Where a piece of evidence came from, kept beside the value so that a plan can name the
/// exact records it relied on without a second lookup.
struct EvidenceStamp {
  EvidenceId record;
  AuthorityId authority;
  Generation generation;
  Digest digest;
  Instant observed_at;
};

[[nodiscard]] EvidenceRef make_ref(const char* kind, const EvidenceStamp& stamp);

struct SiteEntry {
  SiteId site;
  JurisdictionId jurisdiction;
  Measurement<MaintenanceState> maintenance;
  EvidenceStamp stamp;
};

struct CapacityEntry {
  CapacityRefId reference;
  ServiceClassId service_class;
  SiteId site;
  CapacityKind kind;
  Measurement<Quantity> available;
  EvidenceStamp stamp;
};

struct CompatibilityEntry {
  ServiceClassId service_class;
  SiteId site;
  Measurement<bool> compatible;
  EvidenceStamp stamp;
};

struct RecoveryEntry {
  RecoveryRefId reference;
  ServiceClassId service_class;
  SiteId site;
  Measurement<bool> can_host_recovery;
  Measurement<Duration> achievable_rto;
  Measurement<Duration> achievable_rpo;
  EvidenceStamp stamp;
};

struct LatencyEntry {
  DependencyId reference;
  SiteId from_site;
  SiteId to_site;
  LatencyStatistic statistic;
  Measurement<Duration> latency;
  EvidenceStamp stamp;
};

struct CostRiskEntry {
  ServiceClassId service_class;
  Measurement<Quantity> cost_per_unit;
  SiteId site;
  Measurement<std::int64_t> risk_per_mille;
  EvidenceStamp stamp;
};

struct SiteRecordEntry {
  SiteEntry site;
  std::vector<CapacityEntry> capacity;
  std::vector<CompatibilityEntry> compatibility;
  std::vector<RecoveryEntry> recovery;
  std::vector<CostRiskEntry> cost_risk;
};

/// The canonical view of one snapshot.
struct EvidenceIndex {
  std::vector<SiteRecordEntry> sites;
  std::vector<LatencyEntry> latency;
  DomainGraph domains;
  Generation evidence_generation;
  Instant captured_at;

  /// Position of a site in the sorted site list, or nullopt when the snapshot does not
  /// describe it at all.
  [[nodiscard]] std::optional<std::size_t> find_site(const SiteId& site) const noexcept;
  /// Every capacity reference recorded for one site, ordered by service class and then
  /// by reference identity. The caller narrows it to the class it is placing.
  [[nodiscard]] const std::vector<CapacityEntry>* capacity_for(std::size_t site_index) const noexcept;
  [[nodiscard]] const CompatibilityEntry* compatibility_for(std::size_t site_index,
                                                            const ServiceClassId& service_class) const noexcept;
  [[nodiscard]] const RecoveryEntry* recovery_for(std::size_t site_index,
                                                  const ServiceClassId& service_class) const noexcept;
  /// The cost and risk a preference should use: the entry for the class when one exists,
  /// otherwise the entry that names no class.
  [[nodiscard]] const CostRiskEntry* cost_risk_for(std::size_t site_index,
                                                   const ServiceClassId& service_class) const noexcept;
};

[[nodiscard]] Result<EvidenceIndex> build_index(const SiteEvidenceSnapshot& snapshot, const Limits& limits);

/// The verdict for one (obligation, site) pair.
struct CandidateAssessment {
  Tri outcome = Tri::Indeterminate;
  std::string rule;
  std::string detail;
  std::vector<EvidenceRef> evidence;
  std::vector<CapacityRefId> capacity_references;
  Quantity capacity_evidenced;
  bool capacity_includes_offers = false;
  Measurement<Quantity> cost;
  Measurement<std::int64_t> risk;
  /// Oldest observation among the records this assessment used, so that the plan can
  /// report how old the world it reasoned about was.
  Instant oldest_observation;
};

/// Everything the planner needs for one obligation, in canonical order.
struct ObligationContext {
  const Obligation* obligation = nullptr;
  /// Indices into EvidenceIndex::sites, in the order the request's allow list produced
  /// them and then by site identity, so the set is a function of the request alone.
  std::vector<std::size_t> candidates;
  /// Filled on first use; one slot per entry of candidates.
  std::vector<std::optional<CandidateAssessment>> primary_assessments;
  std::vector<std::optional<CandidateAssessment>> recovery_assessments;
};

/// One placed site, before the plan record is built.
struct Selection {
  std::size_t site_index = 0;
  /// Position of the site in the obligation's candidate list, so the plan can name the
  /// exact evidence the assessment behind this placement relied on.
  std::size_t candidate_slot = 0;
  PlacementRole role = PlacementRole::Primary;
  std::uint32_t index = 0;
  std::vector<LatencyResolution> latency;
};

/// The result of the joint selection search.
struct SearchResult {
  Tri outcome = Tri::Indeterminate;
  std::vector<std::vector<Selection>> per_obligation;
  std::string refusal_code;
  std::string detail;
  std::size_t failing_obligation_index = 0;
  bool has_failing_obligation = false;
  std::vector<TieBreakRecord> tie_breaks;
  /// Oldest observation among the evidence the search actually relied on.
  Instant oldest_observation;
  bool saw_observation = false;
};

/// Computes, or returns the cached, assessment of one site for one obligation.
[[nodiscard]] Result<const CandidateAssessment*> assessment_for(const PlacementRequest& request,
                                                                const Obligation& obligation,
                                                                const PlacementPolicy& policy, const Limits& limits,
                                                                const EvidenceIndex& index,
                                                                ObligationContext& context, std::size_t candidate_slot,
                                                                PlacementRole role, Instant evaluation_instant,
                                                                const PlanningContext& planning, WorkBudget& budget);

/// A resolved latency requirement between two placed sites.
struct LatencyOutcome {
  Tri outcome = Tri::Indeterminate;
  std::string detail;
  std::vector<EvidenceRef> evidence;
  LatencyResolution resolution;
  Instant oldest_observation;
  bool saw_observation = false;
};

[[nodiscard]] LatencyOutcome resolve_latency(const LatencyRequirement& requirement, const SiteId& from_site,
                                             const SiteId& to_site, const EvidenceIndex& index,
                                             const PlacementPolicy& policy, const Limits& limits,
                                             Instant horizon, bool require_observation_time, WorkBudget& budget);

[[nodiscard]] Result<SearchResult> run_search(const PlacementRequest& request, const PlacementPolicy& policy,
                                              const Limits& limits, const EvidenceIndex& index,
                                              std::vector<ObligationContext>& contexts, WorkBudget& budget,
                                              Instant evaluation_instant, const PlanningContext& planning,
                                              std::vector<ConstraintTraceEntry>& trace);

/// The oldest observation a request's freshness policy will accept, given the limits.
/// Evidence observed before this instant cannot support a claim.
[[nodiscard]] Instant freshness_horizon(const FreshnessPolicy& policy, const Limits& limits,
                                        Instant evaluation_instant);

/// Bounds helper shared by the request and snapshot checks in the engine.
[[nodiscard]] Status push_trace(std::vector<ConstraintTraceEntry>& trace, const Limits& limits,
                                ConstraintTraceEntry entry);

}  // namespace csp::detail

#endif  // CSP_SRC_ENGINE_INTERNAL_HPP
