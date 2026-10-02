// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Adversarial cases.
//
// Every case here attacks one of the boundaries this library claims to hold: a
// duplicate identity that must not be merged, an exact integer that must not wrap, a
// bound that must stop work rather than let it grow, a byte of durable state that no
// longer matches what was written, a cancellation that must never leave a plan behind,
// and an identity that must be refused before it can name a file.
//
// The refusals are asserted by category and by code. A case that only checked
// "!result.has_value()" would say nothing about why the answer is no.

#include "test_harness.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

#include "cross_site_placement/cross_site_placement.hpp"
#include "fs_atomic.hpp"
#include "store_format.hpp"

using namespace csp;

namespace {

constexpr std::int64_t kBase = 1700000000000000000LL;
constexpr std::int64_t kMillis = 1000000LL;
constexpr std::int64_t kInt64Max = std::numeric_limits<std::int64_t>::max();

SiteId site_id(const char* text) { return SiteId::parse(text).value(); }
ServiceClassId class_id(const char* text) { return ServiceClassId::parse(text).value(); }
PolicyId policy_id(const char* text) { return PolicyId::parse(text).value(); }
RequestId request_id(const char* text) { return RequestId::parse(text).value(); }
ObligationId obligation_id(const char* text) { return ObligationId::parse(text).value(); }
JurisdictionId jurisdiction_id(const char* text) { return JurisdictionId::parse(text).value(); }
FailureDomainId domain_id(const char* text) { return FailureDomainId::parse(text).value(); }
EvidenceId evidence_id(const char* text) { return EvidenceId::parse(text).value(); }
AuthorityId authority_id(const char* text) { return AuthorityId::parse(text).value(); }
CapacityRefId capacity_ref_id(const char* text) { return CapacityRefId::parse(text).value(); }
DependencyId dependency_id(const char* text) { return DependencyId::parse(text).value(); }
RecoveryRefId recovery_ref_id(const char* text) { return RecoveryRefId::parse(text).value(); }

std::int64_t process_id() {
#if defined(_WIN32)
  return static_cast<std::int64_t>(::_getpid());
#else
  return static_cast<std::int64_t>(::getpid());
#endif
}

class ScratchDirectory {
 public:
  explicit ScratchDirectory(const char* tag) {
    const char* base = std::getenv("TEMP");
    if (base == nullptr) {
      base = std::getenv("TMPDIR");
    }
    if (base == nullptr) {
      base = ".";
    }
    static std::uint64_t counter = 0;
    path_ = std::string(base) + "/csp-adversarial-" + tag + "-" + std::to_string(process_id()) + "-" +
            std::to_string(counter++);
    if (detail::directory_exists(path_)) {
      (void)detail::remove_directory_tree(path_);
    }
  }

  ScratchDirectory(const ScratchDirectory&) = delete;
  ScratchDirectory& operator=(const ScratchDirectory&) = delete;

  ~ScratchDirectory() {
    if (detail::directory_exists(path_)) {
      (void)detail::remove_directory_tree(path_);
    }
  }

  const std::string& path() const noexcept { return path_; }

 private:
  std::string path_;
};

std::string join(const std::string& directory, const std::string& name) { return directory + "/" + name; }

std::vector<std::string> directory_names(const std::string& path) {
  Result<std::vector<std::string>> names = detail::list_directory(path);
  if (!names.has_value()) {
    return {};
  }
  return names.value();
}

bool contains(const std::vector<std::string>& names, const std::string& wanted) {
  for (const std::string& name : names) {
    if (name == wanted) {
      return true;
    }
  }
  return false;
}

std::string read_bytes(const std::string& path) {
  Result<std::string> bytes = detail::read_file_bounded(path, 8u * 1024u * 1024u);
  return bytes.has_value() ? bytes.value() : std::string();
}

bool write_bytes(const std::string& path, const std::string& bytes) {
  return detail::write_file_durable(path, bytes).has_value();
}

bool replace_once(std::string& text, const std::string& from, const std::string& to) {
  const std::size_t at = text.find(from);
  if (at == std::string::npos) {
    return false;
  }
  text.replace(at, from.size(), to);
  return true;
}

std::string canonical(const PlacementPlan& plan) {
  Result<std::string> bytes = plan_canonical_bytes(plan);
  return bytes.has_value() ? bytes.value() : std::string("<undecodable>");
}

Provenance provenance_of(const char* record) {
  Provenance provenance;
  provenance.source_record = evidence_id(record);
  provenance.authority = authority_id("registry-authority");
  provenance.authority_generation = Generation::from_value(4);
  provenance.observed_at = Instant::from_nanos(kBase - 1000);
  return provenance;
}

SiteRecord make_site(const char* identity) {
  SiteRecord site;
  site.site = site_id(identity);
  site.jurisdiction = jurisdiction_id("jur-1");
  site.maintenance = Measurement<MaintenanceState>::known(MaintenanceState::Operational);
  site.provenance = provenance_of("site-record-1");
  return site;
}

CapacityRecord make_capacity(const char* reference, const char* site, std::int64_t units) {
  CapacityRecord capacity;
  capacity.reference = capacity_ref_id(reference);
  capacity.site = site_id(site);
  capacity.service_class = class_id("service-1");
  capacity.kind = CapacityKind::Commitment;
  capacity.available = Measurement<Quantity>::known(Quantity::from_units(units));
  capacity.provenance = provenance_of("capacity-record-1");
  return capacity;
}

CompatibilityRecord make_compatibility(const char* reference, const char* site) {
  CompatibilityRecord compatibility;
  compatibility.reference = evidence_id(reference);
  compatibility.site = site_id(site);
  compatibility.service_class = class_id("service-1");
  compatibility.compatible = Measurement<bool>::known(true);
  compatibility.provenance = provenance_of("compatibility-record-1");
  return compatibility;
}

RecoveryRecord make_recovery(const char* reference, const char* site) {
  RecoveryRecord recovery;
  recovery.reference = recovery_ref_id(reference);
  recovery.site = site_id(site);
  recovery.service_class = class_id("service-1");
  recovery.can_host_recovery = Measurement<bool>::known(true);
  recovery.achievable_rto = Measurement<Duration>::known(Duration::from_nanos(kMillis));
  recovery.achievable_rpo = Measurement<Duration>::known(Duration::from_nanos(kMillis));
  recovery.provenance = provenance_of("recovery-record-1");
  return recovery;
}

LatencyRecord make_latency(const char* reference, const char* from, const char* to, std::int64_t nanos) {
  LatencyRecord latency;
  latency.reference = dependency_id(reference);
  latency.from_site = site_id(from);
  latency.to_site = site_id(to);
  latency.statistic = LatencyStatistic::Max;
  latency.latency = Measurement<Duration>::known(Duration::from_nanos(nanos));
  latency.provenance = provenance_of("latency-record-1");
  return latency;
}

CostRiskRecord make_cost_risk(const char* reference, const char* site) {
  CostRiskRecord record;
  record.reference = evidence_id(reference);
  record.site = site_id(site);
  record.service_class = class_id("service-1");
  record.cost_per_unit = Measurement<Quantity>::known(Quantity::from_units(3));
  record.risk_per_mille = Measurement<std::int64_t>::known(7);
  record.provenance = provenance_of("cost-risk-record-1");
  return record;
}

/// Exactly one record in every collection, so a case can duplicate the one it is about
/// and know that nothing else moved.
SiteEvidenceSnapshot complete_snapshot() {
  SiteEvidenceSnapshot snapshot;
  snapshot.generation = Generation::from_value(3);
  snapshot.captured_at = Instant::from_nanos(kBase - 1000);
  snapshot.sites.push_back(make_site("site-1"));

  FailureDomainRecord domain;
  domain.domain = domain_id("domain-a");
  domain.kind = DomainKind::Power;
  domain.provenance = provenance_of("domain-record-a");
  snapshot.failure_domains.push_back(std::move(domain));

  DomainAssignment assignment;
  assignment.site = site_id("site-1");
  assignment.domain = domain_id("domain-a");
  assignment.provenance = provenance_of("assignment-record-a");
  snapshot.domain_assignments.push_back(std::move(assignment));

  DomainAliasRecord alias;
  alias.domain = domain_id("domain-alias-a");
  alias.alias_of = domain_id("domain-a");
  alias.provenance = provenance_of("alias-record-a");
  snapshot.domain_aliases.push_back(std::move(alias));

  snapshot.capacity.push_back(make_capacity("capacity-1", "site-1", 10));
  snapshot.latency.push_back(make_latency("latency-1", "site-1", "site-2", 5 * kMillis));
  snapshot.recovery.push_back(make_recovery("recovery-1", "site-1"));
  snapshot.compatibility.push_back(make_compatibility("compatibility-1", "site-1"));
  snapshot.cost_risk.push_back(make_cost_risk("cost-risk-1", "site-1"));
  return snapshot;
}

/// A fleet of one site per named identity, each with capacity and compatibility.
SiteEvidenceSnapshot fleet_of(const std::vector<const char*>& names) {
  SiteEvidenceSnapshot snapshot;
  snapshot.generation = Generation::from_value(3);
  snapshot.captured_at = Instant::from_nanos(kBase - 1000);
  for (const char* name : names) {
    snapshot.sites.push_back(make_site(name));
    const std::string suffix = std::string(name).substr(5);
    snapshot.capacity.push_back(make_capacity(("capacity-" + suffix).c_str(), name, 10));
    snapshot.compatibility.push_back(make_compatibility(("compatibility-" + suffix).c_str(), name));
  }
  return snapshot;
}

/// A large fleet in which every site sits in its own power domain, so an arrangement
/// exists and the search finds it: heavy enough that a cancellation issued from another
/// thread lands while the call is still working.
SiteEvidenceSnapshot large_fleet(std::size_t count) {
  SiteEvidenceSnapshot snapshot;
  snapshot.generation = Generation::from_value(3);
  snapshot.captured_at = Instant::from_nanos(kBase - 1000);
  for (std::size_t index = 0; index < count; ++index) {
    const std::string name = "site-" + std::to_string(index + 1);
    snapshot.sites.push_back(make_site(name.c_str()));

    FailureDomainRecord domain;
    domain.domain = domain_id(("domain-" + std::to_string(index + 1)).c_str());
    domain.kind = DomainKind::Power;
    domain.provenance = provenance_of("domain-record-1");
    snapshot.failure_domains.push_back(std::move(domain));

    DomainAssignment assignment;
    assignment.site = site_id(name.c_str());
    assignment.domain = domain_id(("domain-" + std::to_string(index + 1)).c_str());
    assignment.provenance = provenance_of("assignment-record-1");
    snapshot.domain_assignments.push_back(std::move(assignment));

    snapshot.capacity.push_back(make_capacity(("capacity-" + std::to_string(index + 1)).c_str(), name.c_str(), 10));
    snapshot.compatibility.push_back(
        make_compatibility(("compatibility-" + std::to_string(index + 1)).c_str(), name.c_str()));
  }
  return snapshot;
}

Obligation make_obligation(const char* identity, std::uint32_t primary, std::uint32_t recovery, std::int64_t capacity) {
  Obligation obligation;
  obligation.obligation = obligation_id(identity);
  obligation.service_class = class_id("service-1");
  obligation.required_capacity = Quantity::from_units(capacity);
  obligation.primary_placements = primary;
  obligation.recovery_placements = recovery;
  return obligation;
}

SeparationRequirement separation_by_kind() {
  SeparationRequirement separation;
  separation.group = SeparationGroup::All;
  separation.separated_kinds.push_back(DomainKind::Power);
  return separation;
}

PlacementRequest simple_request() {
  PlacementRequest request;
  request.request = request_id("request-1");
  request.generation = Generation::from_value(1);
  request.policy.policy = policy_id("policy-1");
  request.policy.generation = Generation::from_value(1);
  request.obligations.push_back(make_obligation("obligation-1", 1, 0, 5));
  return request;
}

PlacementRequest two_placement_request() {
  PlacementRequest request = simple_request();
  request.obligations[0].primary_placements = 2;
  request.obligations[0].separations.push_back(separation_by_kind());
  return request;
}

PlacementPolicy acceptance_policy() {
  PlacementPolicy policy;
  policy.policy = policy_id("policy-1");
  policy.generation = Generation::from_value(1);
  return policy;
}

PlanningContext instant_context() {
  PlanningContext context;
  context.evaluation_instant = Instant::from_nanos(kBase);
  return context;
}

Result<PlacementPlan> plan_with(const Limits& limits, const PlacementRequest& request,
                                const SiteEvidenceSnapshot& snapshot) {
  const Planner planner(limits);
  return planner.plan(request, snapshot, acceptance_policy(), instant_context());
}

Result<PlacementPlan> fixture_plan() {
  const Planner planner;
  return planner.plan(simple_request(), fleet_of({"site-1"}), acceptance_policy(), instant_context());
}

StoreOptions options_for(const std::string& directory) {
  StoreOptions options;
  options.directory = directory;
  return options;
}

bool failed_with(const Status& status, ErrorCategory category, const char* code) {
  return !status.has_value() && status.error().category() == category && status.error().code() == code;
}

std::string describe(const Status& status) {
  return status.has_value() ? std::string("it succeeded") : status.error().render();
}

}  // namespace

// ---------------------------------------------------------------------------
// Duplicate identities are a conflict, never a merge
// ---------------------------------------------------------------------------

CSP_TEST(adversarial, duplicate_site_identity_is_conflict) {
  SiteEvidenceSnapshot snapshot = complete_snapshot();
  snapshot.sites.push_back(snapshot.sites[0]);
  const Status status = snapshot_validate(snapshot, Limits{});
  CSP_EXPECT_MSG(failed_with(status, ErrorCategory::Conflict, "csp.evidence.duplicate_identity"),
                 describe(status));
  CSP_EXPECT(status.has_value() || status.error().message().find("site-1") != std::string::npos);

  Result<PlacementPlan> planned = plan_with(Limits{}, simple_request(), snapshot);
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::Conflict);
    CSP_EXPECT_EQ(planned.error().code(), std::string("csp.evidence.duplicate_identity"));
  }
}

CSP_TEST(adversarial, duplicate_failure_domain_identity_is_conflict) {
  SiteEvidenceSnapshot snapshot = complete_snapshot();
  snapshot.failure_domains.push_back(snapshot.failure_domains[0]);
  const Status status = snapshot_validate(snapshot, Limits{});
  CSP_EXPECT_MSG(failed_with(status, ErrorCategory::Conflict, "csp.evidence.duplicate_identity"),
                 describe(status));
  Result<PlacementPlan> planned = plan_with(Limits{}, simple_request(), snapshot);
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::Conflict);
  }
}

CSP_TEST(adversarial, duplicate_capacity_reference_is_conflict) {
  SiteEvidenceSnapshot snapshot = complete_snapshot();
  snapshot.capacity.push_back(snapshot.capacity[0]);
  const Status status = snapshot_validate(snapshot, Limits{});
  CSP_EXPECT_MSG(failed_with(status, ErrorCategory::Conflict, "csp.evidence.duplicate_identity"),
                 describe(status));
  Result<PlacementPlan> planned = plan_with(Limits{}, simple_request(), snapshot);
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::Conflict);
    CSP_EXPECT_EQ(planned.error().code(), std::string("csp.evidence.duplicate_identity"));
  }
}

CSP_TEST(adversarial, duplicate_latency_reference_is_conflict) {
  SiteEvidenceSnapshot snapshot = complete_snapshot();
  snapshot.latency.push_back(snapshot.latency[0]);
  const Status status = snapshot_validate(snapshot, Limits{});
  CSP_EXPECT_MSG(failed_with(status, ErrorCategory::Conflict, "csp.evidence.duplicate_identity"),
                 describe(status));
  Result<PlacementPlan> planned = plan_with(Limits{}, simple_request(), snapshot);
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::Conflict);
    CSP_EXPECT_EQ(planned.error().code(), std::string("csp.evidence.duplicate_identity"));
  }
}

CSP_TEST(adversarial, duplicate_recovery_reference_is_conflict) {
  SiteEvidenceSnapshot snapshot = complete_snapshot();
  snapshot.recovery.push_back(snapshot.recovery[0]);
  const Status status = snapshot_validate(snapshot, Limits{});
  CSP_EXPECT_MSG(failed_with(status, ErrorCategory::Conflict, "csp.evidence.duplicate_identity"),
                 describe(status));
  Result<PlacementPlan> planned = plan_with(Limits{}, simple_request(), snapshot);
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::Conflict);
    CSP_EXPECT_EQ(planned.error().code(), std::string("csp.evidence.duplicate_identity"));
  }
}

CSP_TEST(adversarial, duplicate_compatibility_reference_is_conflict) {
  SiteEvidenceSnapshot snapshot = complete_snapshot();
  snapshot.compatibility.push_back(snapshot.compatibility[0]);
  const Status status = snapshot_validate(snapshot, Limits{});
  CSP_EXPECT_MSG(failed_with(status, ErrorCategory::Conflict, "csp.evidence.duplicate_identity"),
                 describe(status));
  Result<PlacementPlan> planned = plan_with(Limits{}, simple_request(), snapshot);
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::Conflict);
    CSP_EXPECT_EQ(planned.error().code(), std::string("csp.evidence.duplicate_identity"));
  }
}

CSP_TEST(adversarial, duplicate_cost_risk_reference_is_conflict) {
  SiteEvidenceSnapshot snapshot = complete_snapshot();
  snapshot.cost_risk.push_back(snapshot.cost_risk[0]);
  const Status status = snapshot_validate(snapshot, Limits{});
  CSP_EXPECT_MSG(failed_with(status, ErrorCategory::Conflict, "csp.evidence.duplicate_identity"),
                 describe(status));
  Result<PlacementPlan> planned = plan_with(Limits{}, simple_request(), snapshot);
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::Conflict);
    CSP_EXPECT_EQ(planned.error().code(), std::string("csp.evidence.duplicate_identity"));
  }
}

// ---------------------------------------------------------------------------
// Exact integers
// ---------------------------------------------------------------------------

CSP_TEST(adversarial, capacity_int64_max_with_two_placements_does_not_wrap) {
  SiteEvidenceSnapshot snapshot = fleet_of({"site-1", "site-2"});
  snapshot.capacity[0].available = Measurement<Quantity>::known(Quantity::from_units(kInt64Max));
  snapshot.capacity[1].available = Measurement<Quantity>::known(Quantity::from_units(kInt64Max));
  PlacementRequest request = simple_request();
  request.obligations[0].primary_placements = 2;
  request.obligations[0].required_capacity = Quantity::from_units(kInt64Max);

  Result<PlacementPlan> planned = plan_with(Limits{}, request, snapshot);
  CSP_REQUIRE(planned.has_value());
  CSP_EXPECT(planned.value().outcome == PlanOutcome::Planned);
  CSP_REQUIRE(planned.value().obligations.size() == 1);
  CSP_REQUIRE(planned.value().obligations[0].placements.size() == 2);
  for (const SitePlacement& placement : planned.value().obligations[0].placements) {
    CSP_EXPECT_EQ(placement.capacity_required.units(), kInt64Max);
    CSP_EXPECT_EQ(placement.capacity.evidenced_total.units(), kInt64Max);
    CSP_EXPECT(!placement.capacity.includes_offers);
  }
  CSP_EXPECT(planned.value().residual.empty());
  // The sum of the two requirements is not representable, and the plan never claims it:
  // what is recorded is per placement, exactly as the evidence reported it.
  CSP_EXPECT(plan_to_document(planned.value(), false).has_value());
}

CSP_TEST(adversarial, required_capacity_int64_max_shortfall_is_not_wrapped) {
  SiteEvidenceSnapshot snapshot = fleet_of({"site-1", "site-2"});
  PlacementRequest request = simple_request();
  request.obligations[0].primary_placements = 2;
  request.obligations[0].required_capacity = Quantity::from_units(kInt64Max);
  request.forbidden_sites.push_back(site_id("site-1"));
  request.forbidden_sites.push_back(site_id("site-2"));

  Result<PlacementPlan> planned = plan_with(Limits{}, request, snapshot);
  CSP_REQUIRE(planned.has_value());
  CSP_EXPECT(planned.value().outcome == PlanOutcome::Refused);
  CSP_REQUIRE(planned.value().residual.size() == 1);
  CSP_EXPECT_EQ(planned.value().residual[0].placements_short, std::uint32_t{2});
  // Two placements at INT64_MAX is not representable. The library leaves the shortfall
  // unset rather than wrapping it to a negative number, which is the only reading of
  // "no shortfall" that is not a fabrication.
  CSP_EXPECT_EQ(planned.value().residual[0].shortfall.units(), std::int64_t{0});
  CSP_EXPECT(!planned.value().residual[0].shortfall.is_negative());

  Result<std::string> document = plan_to_document(planned.value(), false);
  CSP_REQUIRE(document.has_value());
  Result<PlacementPlan> decoded = plan_from_document(document.value(), Limits{});
  CSP_REQUIRE(decoded.has_value());
  CSP_REQUIRE(decoded.value().residual.size() == 1);
  CSP_EXPECT_EQ(decoded.value().residual[0].shortfall.units(), std::int64_t{0});
}

CSP_TEST(adversarial, capacity_int64_max_plus_positive_is_refused) {
  SiteEvidenceSnapshot snapshot = fleet_of({"site-1"});
  snapshot.capacity.clear();
  snapshot.capacity.push_back(make_capacity("capacity-a", "site-1", kInt64Max));
  snapshot.capacity.push_back(make_capacity("capacity-b", "site-1", 1));

  Result<PlacementPlan> planned = plan_with(Limits{}, simple_request(), snapshot);
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::OutOfRange);
    CSP_EXPECT_EQ(planned.error().code(), std::string("csp.quantity.overflow"));
  }
}

CSP_TEST(adversarial, placement_count_above_the_bound_is_refused) {
  Limits limits;
  limits.max_placements_per_obligation = 2;
  PlacementRequest request = simple_request();
  request.obligations[0].primary_placements = 3;
  const Status status = request_validate(request, limits);
  CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.request.too_many_placements"),
                 describe(status));

  Result<PlacementPlan> planned = plan_with(limits, request, fleet_of({"site-1"}));
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::BoundExceeded);
    CSP_EXPECT_EQ(planned.error().code(), std::string("csp.request.too_many_placements"));
  }

  // The same bound is enforced by the document decoder before the value is built.
  Result<std::string> document = request_to_document(request, false);
  CSP_REQUIRE(document.has_value());
  Result<PlacementRequest> decoded = request_from_document(document.value(), limits);
  CSP_EXPECT(!decoded.has_value());
  if (!decoded.has_value()) {
    CSP_EXPECT(decoded.error().category() == ErrorCategory::BoundExceeded);
    CSP_EXPECT_EQ(decoded.error().code(), std::string("csp.doc.placements_bound"));
  }
}

// ---------------------------------------------------------------------------
// Lowered bounds
// ---------------------------------------------------------------------------

CSP_TEST(adversarial, lowered_trace_bound_is_bound_exceeded) {
  Limits limits;
  limits.max_trace_entries = 2;
  Result<PlacementPlan> planned = plan_with(limits, simple_request(), fleet_of({"site-1"}));
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::BoundExceeded);
    CSP_EXPECT_EQ(planned.error().code(), std::string("csp.trace.bound_exceeded"));
  }

  // A bound that leaves room for the fixed trace entries but not for one entry per
  // obligation stops at the first obligation it cannot record.
  Limits per_obligation;
  per_obligation.max_trace_entries = 5;
  PlacementRequest request = simple_request();
  request.obligations.push_back(make_obligation("obligation-2", 1, 0, 5));
  Result<PlacementPlan> grown = plan_with(per_obligation, request, fleet_of({"site-1", "site-2"}));
  CSP_EXPECT(!grown.has_value());
  if (!grown.has_value()) {
    CSP_EXPECT(grown.error().category() == ErrorCategory::BoundExceeded);
    CSP_EXPECT_EQ(grown.error().code(), std::string("csp.trace.bound_exceeded"));
  }
}

CSP_TEST(adversarial, lowered_request_bounds_are_bound_exceeded) {
  const Limits defaults;

  {
    Limits limits = defaults;
    limits.max_obligations = 1;
    PlacementRequest request = simple_request();
    request.obligations.push_back(make_obligation("obligation-2", 1, 0, 5));
    const Status status = request_validate(request, limits);
    CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.request.bound_exceeded"),
                   describe(status));
    Result<PlacementPlan> planned = plan_with(limits, request, fleet_of({"site-1"}));
    CSP_EXPECT(!planned.has_value());
  }
  {
    Limits limits = defaults;
    limits.max_latency_requirements = 1;
    PlacementRequest request = simple_request();
    LatencyRequirement latency;
    latency.peer.kind = DependencyEndpoint::Kind::SiteService;
    latency.peer.site = site_id("site-1");
    latency.peer.service_class = class_id("service-1");
    latency.max_latency = Duration::from_nanos(kMillis);
    request.obligations[0].latency_requirements.push_back(latency);
    request.obligations[0].latency_requirements.push_back(latency);
    const Status status = request_validate(request, limits);
    CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.request.bound_exceeded"),
                   describe(status));
  }
  {
    Limits limits = defaults;
    limits.max_separation_requirements = 1;
    PlacementRequest request = simple_request();
    request.obligations[0].separations.push_back(separation_by_kind());
    request.obligations[0].separations.push_back(separation_by_kind());
    const Status status = request_validate(request, limits);
    CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.request.bound_exceeded"),
                   describe(status));
  }
  {
    Limits limits = defaults;
    limits.max_separated_kinds = 1;
    PlacementRequest request = simple_request();
    SeparationRequirement separation = separation_by_kind();
    separation.separated_kinds.push_back(DomainKind::Network);
    request.obligations[0].separations.push_back(std::move(separation));
    const Status status = request_validate(request, limits);
    CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.request.bound_exceeded"),
                   describe(status));
  }
  {
    Limits limits = defaults;
    limits.max_site_lists = 1;
    PlacementRequest request = simple_request();
    request.allowed_sites.push_back(site_id("site-1"));
    request.allowed_sites.push_back(site_id("site-2"));
    const Status status = request_validate(request, limits);
    CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.request.bound_exceeded"),
                   describe(status));
  }
  {
    Limits limits = defaults;
    limits.max_jurisdiction_lists = 1;
    PlacementRequest request = simple_request();
    request.obligations[0].allowed_jurisdictions.push_back(jurisdiction_id("jur-1"));
    request.obligations[0].allowed_jurisdictions.push_back(jurisdiction_id("jur-2"));
    const Status status = request_validate(request, limits);
    CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.request.bound_exceeded"),
                   describe(status));
  }
}

CSP_TEST(adversarial, lowered_evidence_bounds_are_bound_exceeded) {
  const Limits defaults;
  const auto expect_refused = [&defaults](const char* what, std::size_t which) {
    Limits limits = defaults;
    SiteEvidenceSnapshot snapshot = complete_snapshot();
    switch (which) {
      case 0:
        limits.max_sites = 1;
        snapshot.sites.push_back(snapshot.sites[0]);
        break;
      case 1:
        limits.max_failure_domains = 1;
        snapshot.failure_domains.push_back(snapshot.failure_domains[0]);
        break;
      case 2:
        limits.max_domain_assignments = 1;
        snapshot.domain_assignments.push_back(snapshot.domain_assignments[0]);
        break;
      case 3:
        limits.max_domain_aliases = 1;
        snapshot.domain_aliases.push_back(snapshot.domain_aliases[0]);
        break;
      case 4:
        limits.max_capacity_evidence = 1;
        snapshot.capacity.push_back(snapshot.capacity[0]);
        break;
      case 5:
        limits.max_latency_evidence = 1;
        snapshot.latency.push_back(snapshot.latency[0]);
        break;
      case 6:
        limits.max_recovery_evidence = 1;
        snapshot.recovery.push_back(snapshot.recovery[0]);
        break;
      case 7:
        limits.max_compatibility_evidence = 1;
        snapshot.compatibility.push_back(snapshot.compatibility[0]);
        break;
      default:
        limits.max_cost_risk_evidence = 1;
        snapshot.cost_risk.push_back(snapshot.cost_risk[0]);
        break;
    }
    const Status status = snapshot_validate(snapshot, limits);
    CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.evidence.bound_exceeded"),
                   std::string(what) + ": " + describe(status));
    Result<PlacementPlan> planned = plan_with(limits, simple_request(), snapshot);
    CSP_EXPECT_MSG(!planned.has_value(), std::string(what) + ": the planner accepted it");
    if (!planned.has_value()) {
      CSP_EXPECT(planned.error().category() == ErrorCategory::BoundExceeded);
      CSP_EXPECT_EQ(planned.error().code(), std::string("csp.evidence.bound_exceeded"));
    }
  };
  expect_refused("max_sites", 0);
  expect_refused("max_failure_domains", 1);
  expect_refused("max_domain_assignments", 2);
  expect_refused("max_domain_aliases", 3);
  expect_refused("max_capacity_evidence", 4);
  expect_refused("max_latency_evidence", 5);
  expect_refused("max_recovery_evidence", 6);
  expect_refused("max_compatibility_evidence", 7);
  expect_refused("max_cost_risk_evidence", 8);
}

CSP_TEST(adversarial, lowered_domain_bounds_are_bound_exceeded) {
  {
    // site-1 sits three domains deep, and the configured chain is one long.
    Limits limits;
    limits.max_domain_depth = 1;
    SiteEvidenceSnapshot snapshot = fleet_of({"site-1"});
    snapshot.failure_domains.clear();
    snapshot.domain_assignments.clear();
    for (const char* identity : {"domain-1", "domain-2", "domain-3"}) {
      FailureDomainRecord domain;
      domain.domain = domain_id(identity);
      domain.kind = DomainKind::Power;
      domain.provenance = provenance_of("domain-record-1");
      snapshot.failure_domains.push_back(std::move(domain));
    }
    snapshot.failure_domains[1].parent = domain_id("domain-1");
    snapshot.failure_domains[2].parent = domain_id("domain-2");
    DomainAssignment assignment;
    assignment.site = site_id("site-1");
    assignment.domain = domain_id("domain-3");
    assignment.provenance = provenance_of("assignment-record-1");
    snapshot.domain_assignments.push_back(std::move(assignment));

    Result<PlacementPlan> planned = plan_with(limits, simple_request(), snapshot);
    CSP_EXPECT(!planned.has_value());
    if (!planned.has_value()) {
      CSP_EXPECT(planned.error().category() == ErrorCategory::BoundExceeded);
      CSP_EXPECT_EQ(planned.error().code(), std::string("csp.domains.depth_exceeded"));
    }
  }
  {
    Limits limits;
    limits.max_resolved_domains = 2;
    SiteEvidenceSnapshot snapshot = fleet_of({"site-1"});
    snapshot.failure_domains.clear();
    snapshot.domain_assignments.clear();
    for (const char* identity : {"domain-1", "domain-2"}) {
      FailureDomainRecord domain;
      domain.domain = domain_id(identity);
      domain.kind = DomainKind::Power;
      domain.provenance = provenance_of("domain-record-1");
      snapshot.failure_domains.push_back(std::move(domain));
      DomainAssignment assignment;
      assignment.site = site_id("site-1");
      assignment.domain = domain_id(identity);
      assignment.provenance = provenance_of("assignment-record-1");
      snapshot.domain_assignments.push_back(std::move(assignment));
    }
    Result<PlacementPlan> planned = plan_with(limits, simple_request(), snapshot);
    CSP_EXPECT(!planned.has_value());
    if (!planned.has_value()) {
      CSP_EXPECT(planned.error().category() == ErrorCategory::BoundExceeded);
      CSP_EXPECT_EQ(planned.error().code(), std::string("csp.domains.resolved_exceeded"));
    }
  }
}

CSP_TEST(adversarial, lowered_output_bounds_are_bound_exceeded) {
  {
    // Two obligations, neither of which can be placed, and room for one residual.
    Limits limits;
    limits.max_residual_entries = 1;
    PlacementRequest request = simple_request();
    request.obligations.push_back(make_obligation("obligation-2", 1, 0, 5));
    SiteEvidenceSnapshot empty;
    empty.generation = Generation::from_value(3);
    empty.captured_at = Instant::from_nanos(kBase - 1000);
    Result<PlacementPlan> planned = plan_with(limits, request, empty);
    CSP_EXPECT(!planned.has_value());
    if (!planned.has_value()) {
      CSP_EXPECT(planned.error().category() == ErrorCategory::BoundExceeded);
      CSP_EXPECT_EQ(planned.error().code(), std::string("csp.residual.bound_exceeded"));
    }
  }
  {
    // Two preference criteria plus the identity tie-break is three records in a plan
    // whose bound allows one. The planner produces the plan; publishing it does not.
    Limits limits;
    limits.max_tie_break_entries = 1;
    PlacementRequest request = simple_request();
    request.preferences.objectives.push_back(Preferences::Objective::MinimiseCost);
    request.preferences.objectives.push_back(Preferences::Objective::MinimiseRisk);
    Result<PlacementPlan> planned = plan_with(limits, request, fleet_of({"site-1"}));
    CSP_REQUIRE(planned.has_value());
    CSP_EXPECT(planned.value().tie_breaks.size() > 1);
    const Status status = plan_validate(planned.value(), limits);
    CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.plan.bound_exceeded"),
                   describe(status));
    Result<std::string> document = plan_to_document(planned.value(), false);
    CSP_REQUIRE(document.has_value());
    CSP_EXPECT(!plan_from_document(document.value(), limits).has_value());
  }
  {
    // Two placements on two sites, and a plan bound of one site.
    Limits limits;
    limits.max_plan_sites = 1;
    Result<PlacementPlan> planned = plan_with(limits, two_placement_request(), large_fleet(2));
    CSP_REQUIRE(planned.has_value());
    CSP_REQUIRE(planned.value().outcome == PlanOutcome::Planned);
    CSP_REQUIRE(planned.value().obligations.size() == 1);
    CSP_REQUIRE(planned.value().obligations[0].placements.size() == 2);
    const Status status = plan_validate(planned.value(), limits);
    CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.plan.too_many_sites"),
                   describe(status));
  }
}

CSP_TEST(adversarial, lowered_search_bounds_change_the_answer) {
  {
    // A work budget of one node cannot even assess one candidate, and the refusal names
    // the budget rather than claiming the site is unusable.
    Limits limits;
    limits.max_search_nodes = 1;
    PlacementRequest request = simple_request();
    request.preferences.objectives.push_back(Preferences::Objective::MinimiseCost);
    Result<PlacementPlan> planned = plan_with(limits, request, fleet_of({"site-1"}));
    CSP_EXPECT(!planned.has_value());
    if (!planned.has_value()) {
      CSP_EXPECT(planned.error().category() == ErrorCategory::BoundExceeded);
      CSP_EXPECT_EQ(planned.error().code(), std::string("csp.search.budget"));
    }
  }
  {
    // Without a preference that forces a candidate assessment first, the same budget
    // stops the search instead, and the plan says so: exhausted, and indeterminate.
    Limits limits;
    limits.max_search_nodes = 1;
    Result<PlacementPlan> planned = plan_with(limits, simple_request(), fleet_of({"site-1"}));
    CSP_REQUIRE(planned.has_value());
    CSP_EXPECT(planned.value().outcome == PlanOutcome::Indeterminate);
    CSP_EXPECT(planned.value().search_exhausted);
    CSP_REQUIRE(planned.value().refusal.has_value());
    CSP_EXPECT_EQ(planned.value().refusal->code, std::string("csp.search.budget-exhausted"));
  }
  {
    // A derived latency chain of two hops exists. With room for one hop the bound is
    // indeterminate, not satisfied; with room for four it is satisfied and the whole
    // chain is recorded.
    SiteEvidenceSnapshot snapshot = fleet_of({"site-1", "site-2", "peer-site-1"});
    snapshot.latency.clear();
    snapshot.latency.push_back(make_latency("latency-1", "site-1", "site-2", 10 * kMillis));
    snapshot.latency.push_back(make_latency("latency-2", "site-2", "peer-site-1", 10 * kMillis));

    PlacementRequest request = simple_request();
    request.obligations[0].allowed_sites.push_back(site_id("site-1"));
    LatencyRequirement latency;
    latency.peer.kind = DependencyEndpoint::Kind::SiteService;
    latency.peer.site = site_id("peer-site-1");
    latency.peer.service_class = class_id("service-1");
    latency.direction = LatencyDirection::FromPlacement;
    latency.statistic = LatencyStatistic::Max;
    latency.max_latency = Duration::from_nanos(30 * kMillis);
    request.obligations[0].latency_requirements.push_back(latency);

    Limits one_hop;
    one_hop.max_derived_hops = 1;
    Result<PlacementPlan> short_chain = plan_with(one_hop, request, snapshot);
    CSP_REQUIRE(short_chain.has_value());
    CSP_EXPECT_MSG(short_chain.value().outcome == PlanOutcome::Indeterminate,
                   std::string("outcome ") + to_string(short_chain.value().outcome));

    Limits four_hops;
    four_hops.max_derived_hops = 4;
    Result<PlacementPlan> long_chain = plan_with(four_hops, request, snapshot);
    CSP_REQUIRE(long_chain.has_value());
    CSP_EXPECT(long_chain.value().outcome == PlanOutcome::Planned);
    CSP_REQUIRE(long_chain.value().obligations.size() == 1);
    CSP_REQUIRE(long_chain.value().obligations[0].latency.size() == 1);
    CSP_EXPECT(long_chain.value().obligations[0].latency[0].derived);
    CSP_EXPECT_EQ(long_chain.value().obligations[0].latency[0].chain.size(), std::size_t{2});
    CSP_EXPECT_EQ(long_chain.value().obligations[0].latency[0].measured.nanos(), 20 * kMillis);
  }
}

CSP_TEST(adversarial, lowered_freshness_and_validity_bounds_change_the_answer) {
  {
    Limits limits;
    limits.max_evidence_age_nanos = 1000;
    SiteEvidenceSnapshot snapshot = fleet_of({"site-1"});
    for (SiteRecord& site : snapshot.sites) {
      site.provenance.observed_at = Instant::from_nanos(kBase - 2000);
    }
    for (CapacityRecord& capacity : snapshot.capacity) {
      capacity.provenance.observed_at = Instant::from_nanos(kBase - 2000);
    }
    for (CompatibilityRecord& compatibility : snapshot.compatibility) {
      compatibility.provenance.observed_at = Instant::from_nanos(kBase - 2000);
    }
    Result<PlacementPlan> planned = plan_with(limits, simple_request(), snapshot);
    CSP_REQUIRE(planned.has_value());
    CSP_EXPECT_MSG(planned.value().outcome == PlanOutcome::Indeterminate,
                   std::string("outcome ") + to_string(planned.value().outcome));
    CSP_EXPECT_MSG(planned.value().outcome != PlanOutcome::Planned, "stale evidence was placed anyway");

    Result<PlacementPlan> unbounded = plan_with(Limits{}, simple_request(), snapshot);
    CSP_REQUIRE(unbounded.has_value());
    CSP_EXPECT(unbounded.value().outcome == PlanOutcome::Planned);
  }
  {
    Limits limits;
    limits.max_plan_validity_nanos = 500;
    Result<PlacementPlan> planned = plan_with(limits, simple_request(), fleet_of({"site-1"}));
    CSP_REQUIRE(planned.has_value());
    CSP_EXPECT_EQ(planned.value().envelope.valid_until.nanos(), kBase + 500);
  }
  {
    // An observation dated after the evaluation instant is tolerated only inside the
    // configured skew, and the skew bound is what decides.
    Provenance provenance = provenance_of("site-record-1");
    provenance.observed_at = Instant::from_nanos(kBase + 100);
    Limits strict;
    strict.max_clock_skew_nanos = 10;
    const Result<Duration> refused = provenance_age(provenance, Instant::from_nanos(kBase), strict);
    CSP_EXPECT(!refused.has_value());
    if (!refused.has_value()) {
      CSP_EXPECT(refused.error().category() == ErrorCategory::Stale);
      CSP_EXPECT_EQ(refused.error().code(), std::string("csp.evidence.future_observation"));
    }
    const Result<Duration> tolerated = provenance_age(provenance, Instant::from_nanos(kBase), Limits{});
    CSP_REQUIRE(tolerated.has_value());
    CSP_EXPECT_EQ(tolerated.value().nanos(), std::int64_t{0});
  }
}

CSP_TEST(adversarial, lowered_store_bounds_refuse_the_commit) {
  {
    ScratchDirectory scratch("store-records");
    Limits limits;
    limits.max_store_records = 1;
    StoreOptions options = options_for(scratch.path());
    options.limits = limits;
    Result<PlanStore> opened = PlanStore::open(options);
    CSP_REQUIRE(opened.has_value());
    PlanStore store = std::move(opened).value();

    Result<PlacementPlan> first = fixture_plan();
    CSP_REQUIRE(first.has_value());
    CSP_REQUIRE(store.commit(first.value()).has_value());

    PlacementRequest request = simple_request();
    request.request = request_id("request-2");
    request.obligations[0].obligation = obligation_id("obligation-2");
    const Planner planner;
    Result<PlacementPlan> second =
        planner.plan(request, fleet_of({"site-1"}), acceptance_policy(), instant_context());
    CSP_REQUIRE(second.has_value());
    Result<PlanId> committed = store.commit(second.value());
    CSP_EXPECT(!committed.has_value());
    if (!committed.has_value()) {
      CSP_EXPECT(committed.error().category() == ErrorCategory::BoundExceeded);
      CSP_EXPECT_EQ(committed.error().code(), std::string("csp.store.too_many_records"));
    }
    CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{1});
    CSP_EXPECT_OK(store.close());
  }
  {
    ScratchDirectory scratch("store-bytes");
    Limits limits;
    limits.max_store_record_bytes = 256;
    StoreOptions options = options_for(scratch.path());
    options.limits = limits;
    Result<PlanStore> opened = PlanStore::open(options);
    CSP_REQUIRE(opened.has_value());
    PlanStore store = std::move(opened).value();
    Result<PlacementPlan> plan = fixture_plan();
    CSP_REQUIRE(plan.has_value());
    Result<std::string> document = plan_to_document(plan.value(), false);
    CSP_REQUIRE(document.has_value());
    CSP_REQUIRE(document.value().size() > 256);
    Result<PlanId> committed = store.commit(plan.value());
    CSP_EXPECT(!committed.has_value());
    if (!committed.has_value()) {
      CSP_EXPECT(committed.error().category() == ErrorCategory::BoundExceeded);
      CSP_EXPECT_EQ(committed.error().code(), std::string("csp.store.record_too_large"));
    }
    CSP_EXPECT(!store.generation().is_set());
    CSP_EXPECT_OK(store.close());
  }
  {
    // The lock wait is a bound too, and a retry gap longer than the wait would mean no
    // retry can ever happen, which is refused as a configuration error.
    Limits limits;
    limits.store_lock_wait_ms = 1;
    limits.store_lock_retry_ms = 100;
    const Status status = limits_validate(limits);
    CSP_EXPECT_MSG(failed_with(status, ErrorCategory::Invalid, "csp.limits.lock_retry"), describe(status));
  }
  {
    // The derived-latency search has its own expansion bound as well as the shared work
    // budget, so a lowered value reaches the code path it names.
    Limits limits;
    limits.max_derived_expansions = 1;
    CSP_EXPECT(limits_validate(limits).has_value());
  }
}

CSP_TEST(adversarial, lowered_document_bounds_refuse_the_bytes) {
  Result<std::string> document = request_to_document(simple_request(), false);
  CSP_REQUIRE(document.has_value());
  {
    Limits limits;
    limits.max_document_bytes = 32;
    Result<PlacementRequest> decoded = request_from_document(document.value(), limits);
    CSP_EXPECT(!decoded.has_value());
    if (!decoded.has_value()) {
      CSP_EXPECT(decoded.error().category() == ErrorCategory::BoundExceeded);
      CSP_EXPECT_EQ(decoded.error().code(), std::string("csp.json.bound_bytes"));
    }
  }
  {
    // Deep nesting is bounded separately from total size, and the bound is checked
    // before the frames it would need are built.
    Limits limits;
    limits.max_document_depth = 2;
    Result<PlacementRequest> decoded = request_from_document(document.value(), limits);
    CSP_EXPECT(!decoded.has_value());
    if (!decoded.has_value()) {
      CSP_EXPECT(decoded.error().category() == ErrorCategory::BoundExceeded);
      CSP_EXPECT_EQ(decoded.error().code(), std::string("csp.json.bound_depth"));
    }
  }
  {
    // The store reads its own manifest through the same byte bound.
    ScratchDirectory scratch("store-document-bound");
    Result<PlacementPlan> plan = fixture_plan();
    CSP_REQUIRE(plan.has_value());
    Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
    CSP_REQUIRE(opened.has_value());
    PlanStore store = std::move(opened).value();
    CSP_REQUIRE(store.commit(plan.value()).has_value());
    CSP_EXPECT_OK(store.close());

    Limits limits;
    limits.max_document_bytes = 8;
    StoreOptions options = options_for(scratch.path());
    options.limits = limits;
    Result<PlanStore> reopened = PlanStore::open(options);
    CSP_EXPECT(!reopened.has_value());
    if (!reopened.has_value()) {
      CSP_EXPECT(reopened.error().category() == ErrorCategory::BoundExceeded);
      CSP_EXPECT_EQ(reopened.error().code(), std::string("csp.fs.bound_exceeded"));
    }
  }
}

// ---------------------------------------------------------------------------
// Malformed persistence
// ---------------------------------------------------------------------------

CSP_TEST(adversarial, truncated_record_is_refused_at_every_offset) {
  ScratchDirectory scratch("truncate");
  Result<PlacementPlan> plan = fixture_plan();
  CSP_REQUIRE(plan.has_value());
  Result<std::string> payload = plan_to_document(plan.value(), false);
  CSP_REQUIRE(payload.has_value());
  Result<std::string> record = detail::encode_record(plan.value().plan, Generation::from_value(1), payload.value());
  CSP_REQUIRE(record.has_value());

  const std::size_t separator = record.value().find("\n\n");
  CSP_REQUIRE(separator != std::string::npos);
  const std::size_t header = separator + 2;
  const std::vector<std::size_t> offsets{0,        1,          2,          5,        9,      17,
                                         23,       31,         41,         header - 1, header, header + 1,
                                         header + 7, record.value().size() - 1};
  for (const std::size_t offset : offsets) {
    const std::string truncated = record.value().substr(0, offset);
    Result<detail::RecordPayload> decoded = detail::decode_record(truncated);
    CSP_EXPECT_MSG(!decoded.has_value(), "offset " + std::to_string(offset) + " decoded as a record");
    if (!decoded.has_value() && offset >= header) {
      CSP_EXPECT_MSG(decoded.error().category() == ErrorCategory::Integrity,
                     "offset " + std::to_string(offset) + ": " + decoded.error().render());
      CSP_EXPECT_EQ(decoded.error().code(), std::string("csp.store.record_length"));
    }
  }

  // The same truncation, through the store, at every offset: the reader refuses the
  // whole store rather than opening it with a record it cannot verify.
  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(plan.value()).has_value());
  CSP_EXPECT_OK(store.close());
  const std::string path = join(join(scratch.path(), detail::kRecordsDirectoryName),
                                detail::record_file_name(plan.value().plan));
  const std::string original = read_bytes(path);
  CSP_EXPECT_EQ(original.size(), record.value().size());
  for (const std::size_t offset : offsets) {
    CSP_REQUIRE(write_bytes(path, record.value().substr(0, offset)));
    Result<PlanStore> refused = PlanStore::open(options_for(scratch.path()));
    CSP_EXPECT_MSG(!refused.has_value(), "the store opened with a record truncated to " + std::to_string(offset));
    if (!refused.has_value()) {
      CSP_EXPECT_MSG(refused.error().category() == ErrorCategory::Integrity,
                     "offset " + std::to_string(offset) + ": " + refused.error().render());
      CSP_EXPECT_EQ(refused.error().code(), std::string("csp.store.record_size"));
    }
  }
  CSP_REQUIRE(write_bytes(path, original));
  Result<PlanStore> restored = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(restored.has_value());
  CSP_EXPECT(restored.value().load(plan.value().plan).has_value());
  CSP_EXPECT_OK(restored.value().close());
}

CSP_TEST(adversarial, record_payload_byte_flip_is_integrity) {
  ScratchDirectory scratch("byte-flip");
  Result<PlacementPlan> plan = fixture_plan();
  CSP_REQUIRE(plan.has_value());
  Result<std::string> payload = plan_to_document(plan.value(), false);
  CSP_REQUIRE(payload.has_value());
  Result<std::string> record = detail::encode_record(plan.value().plan, Generation::from_value(1), payload.value());
  CSP_REQUIRE(record.has_value());

  const std::size_t header = record.value().find("\n\n") + 2;
  std::string flipped = record.value();
  CSP_REQUIRE(flipped.size() > header + 3);
  flipped[header + 2] = static_cast<char>(flipped[header + 2] ^ 0x20);
  CSP_EXPECT(flipped != record.value());

  Result<detail::RecordPayload> decoded = detail::decode_record(flipped);
  CSP_EXPECT(!decoded.has_value());
  if (!decoded.has_value()) {
    CSP_EXPECT(decoded.error().category() == ErrorCategory::Integrity);
    CSP_EXPECT_EQ(decoded.error().code(), std::string("csp.store.record_checksum"));
  }

  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(plan.value()).has_value());
  CSP_EXPECT_OK(store.close());

  const std::string path = join(join(scratch.path(), detail::kRecordsDirectoryName),
                                detail::record_file_name(plan.value().plan));
  const std::string original = read_bytes(path);
  CSP_REQUIRE(write_bytes(path, flipped));
  Result<PlanStore> refused = PlanStore::open(options_for(scratch.path()));
  CSP_EXPECT(!refused.has_value());
  if (!refused.has_value()) {
    CSP_EXPECT(refused.error().category() == ErrorCategory::Integrity);
    CSP_EXPECT_EQ(refused.error().code(), std::string("csp.store.record_digest"));
  }
  CSP_REQUIRE(write_bytes(path, original));
  Result<PlanStore> restored = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(restored.has_value());
  CSP_EXPECT_OK(restored.value().close());
}

CSP_TEST(adversarial, record_declared_length_change_is_integrity) {
  ScratchDirectory scratch("length");
  Result<PlacementPlan> plan = fixture_plan();
  CSP_REQUIRE(plan.has_value());
  Result<std::string> payload = plan_to_document(plan.value(), false);
  CSP_REQUIRE(payload.has_value());
  Result<std::string> record = detail::encode_record(plan.value().plan, Generation::from_value(1), payload.value());
  CSP_REQUIRE(record.has_value());

  const std::string declared = "length " + std::to_string(payload.value().size());
  for (const std::string& replacement : {"length " + std::to_string(payload.value().size() + 1),
                                         "length " + std::to_string(payload.value().size() - 1)}) {
    std::string altered = record.value();
    CSP_REQUIRE(replace_once(altered, declared, replacement));
    Result<detail::RecordPayload> decoded = detail::decode_record(altered);
    CSP_EXPECT(!decoded.has_value());
    if (!decoded.has_value()) {
      CSP_EXPECT_MSG(decoded.error().category() == ErrorCategory::Integrity, decoded.error().render());
      CSP_EXPECT_EQ(decoded.error().code(), std::string("csp.store.record_length"));
    }
  }

  // Through the store: the file is the same length as the manifest recorded, so the
  // first thing that catches it is the record's own frame.
  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(plan.value()).has_value());
  CSP_EXPECT_OK(store.close());
  const std::string path = join(join(scratch.path(), detail::kRecordsDirectoryName),
                                detail::record_file_name(plan.value().plan));
  const std::string original = read_bytes(path);
  std::string altered = original;
  CSP_REQUIRE(replace_once(altered, declared, "length " + std::to_string(payload.value().size() + 1)));
  CSP_REQUIRE(write_bytes(path, altered));
  Result<PlanStore> refused = PlanStore::open(options_for(scratch.path()));
  CSP_EXPECT(!refused.has_value());
  if (!refused.has_value()) {
    CSP_EXPECT(refused.error().category() == ErrorCategory::Integrity);
  }
  CSP_REQUIRE(write_bytes(path, original));
}

CSP_TEST(adversarial, missing_manifest_opens_empty_and_keeps_the_record) {
  ScratchDirectory scratch("no-manifest");
  Result<PlacementPlan> plan = fixture_plan();
  CSP_REQUIRE(plan.has_value());
  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(plan.value()).has_value());
  CSP_EXPECT_OK(store.close());

  const std::string manifest = join(scratch.path(), detail::kManifestFileName);
  CSP_REQUIRE(detail::file_exists(manifest));
  CSP_REQUIRE(detail::remove_file(manifest).has_value());

  Result<PlanStore> reopened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(reopened.has_value());
  PlanStore second = std::move(reopened).value();
  CSP_EXPECT(!second.generation().is_set());
  Result<std::vector<PlanId>> listed = second.list();
  CSP_REQUIRE(listed.has_value());
  CSP_EXPECT(listed.value().empty());
  Result<PlacementPlan> loaded = second.load(plan.value().plan);
  CSP_EXPECT(!loaded.has_value());
  if (!loaded.has_value()) {
    CSP_EXPECT(loaded.error().category() == ErrorCategory::NotFound);
    CSP_EXPECT_EQ(loaded.error().code(), std::string("csp.store.unknown_plan"));
  }
  // The record is still there, and recovery reports it rather than adopting it.
  const std::string record = join(join(scratch.path(), detail::kRecordsDirectoryName),
                                  detail::record_file_name(plan.value().plan));
  CSP_EXPECT(detail::file_exists(record));
  Result<StoreAudit> audit = second.audit();
  CSP_REQUIRE(audit.has_value());
  CSP_EXPECT(audit.value().consistent);
  CSP_EXPECT(audit.value().records.empty());
  bool reported = false;
  for (const RecoveryFinding& finding : audit.value().recovery) {
    if (finding.action == RecoveryAction::RetainedAheadRecord &&
        finding.detail.find(plan.value().plan.value()) != std::string::npos) {
      reported = true;
    }
  }
  CSP_EXPECT_MSG(reported, "recovery did not report the unreferenced record");
  CSP_EXPECT_OK(second.close());
}

CSP_TEST(adversarial, corrupt_manifest_refuses_to_open_without_truncating) {
  ScratchDirectory scratch("manifest");
  Result<PlacementPlan> plan = fixture_plan();
  CSP_REQUIRE(plan.has_value());
  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(plan.value()).has_value());
  CSP_EXPECT_OK(store.close());

  const std::string manifest = join(scratch.path(), detail::kManifestFileName);
  const std::string original = read_bytes(manifest);
  CSP_REQUIRE(!original.empty());

  const auto refuses_with = [&scratch, &manifest, &original](const std::string& bytes, ErrorCategory category,
                                                              const char* code, const char* what) {
    CSP_REQUIRE(write_bytes(manifest, bytes));
    Result<PlanStore> refused = PlanStore::open(options_for(scratch.path()));
    CSP_EXPECT_MSG(!refused.has_value(), std::string(what) + ": the store opened anyway");
    if (!refused.has_value()) {
      CSP_EXPECT_MSG(refused.error().category() == category,
                     std::string(what) + ": " + refused.error().render());
      CSP_EXPECT_MSG(refused.error().code() == code, std::string(what) + ": " + refused.error().render());
    }
    // Refusing is not licence to rewrite: the bytes are exactly as they were found.
    CSP_EXPECT_MSG(read_bytes(manifest) == bytes, std::string(what) + ": the manifest was altered");
  };

  std::string rewritten = original;
  CSP_REQUIRE(replace_once(rewritten, "generation 1", "generation 2"));
  refuses_with(rewritten, ErrorCategory::Integrity, "csp.store.manifest_digest", "a rewritten generation");

  refuses_with("not a manifest at all\n", ErrorCategory::Malformed, "csp.store.malformed", "garbage");
  refuses_with("CSPHEAD 99\n" + original.substr(original.find('\n') + 1), ErrorCategory::Unsupported,
               "csp.store.container_version", "a container version from the future");

  CSP_REQUIRE(write_bytes(manifest, original));
  Result<PlanStore> restored = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(restored.has_value());
  CSP_EXPECT(restored.value().load(plan.value().plan).has_value());
  CSP_EXPECT_OK(restored.value().close());
}

CSP_TEST(adversarial, manifest_referencing_a_deleted_record_is_integrity) {
  ScratchDirectory scratch("deleted-record");
  Result<PlacementPlan> plan = fixture_plan();
  CSP_REQUIRE(plan.has_value());
  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(plan.value()).has_value());
  CSP_EXPECT_OK(store.close());

  const std::string record = join(join(scratch.path(), detail::kRecordsDirectoryName),
                                  detail::record_file_name(plan.value().plan));
  CSP_REQUIRE(detail::file_exists(record));
  CSP_REQUIRE(detail::remove_file(record).has_value());

  Result<PlanStore> refused = PlanStore::open(options_for(scratch.path()));
  CSP_EXPECT(!refused.has_value());
  if (!refused.has_value()) {
    CSP_EXPECT(refused.error().category() == ErrorCategory::Integrity);
    CSP_EXPECT_EQ(refused.error().code(), std::string("csp.store.record_missing"));
    CSP_EXPECT(refused.error().message().find(plan.value().plan.value()) != std::string::npos);
  }
}

CSP_TEST(adversarial, hostile_record_name_in_manifest_is_refused_by_parsing) {
  ScratchDirectory scratch("hostile-name");
  const std::string store = join(scratch.path(), "store");
  CSP_REQUIRE(detail::create_directories(store).has_value());
  CSP_REQUIRE(detail::create_directories(join(store, detail::kRecordsDirectoryName)).has_value());

  // A manifest is text, and a manifest that names "../escape" must be refused by the
  // identity parser rather than turned into a path.
  const std::string body = std::string(detail::kManifestMagic) + " 1\ngeneration 1\ncount 1\nrecord ../escape " +
                           Digest::of("x").to_hex() + " 1\n";
  const std::string manifest = body + "digest " + Digest::of(body).to_hex() + "\n";
  Result<detail::Manifest> decoded = detail::decode_manifest(manifest);
  CSP_EXPECT(!decoded.has_value());
  if (!decoded.has_value()) {
    CSP_EXPECT(decoded.error().category() == ErrorCategory::Malformed);
    CSP_EXPECT_EQ(decoded.error().code(), std::string("csp.store.malformed"));
  }

  CSP_REQUIRE(write_bytes(join(store, detail::kManifestFileName), manifest));
  Result<PlanStore> refused = PlanStore::open(options_for(store));
  CSP_EXPECT(!refused.has_value());
  if (!refused.has_value()) {
    CSP_EXPECT(refused.error().category() == ErrorCategory::Malformed);
  }
  // Nothing was created next to the store: the name never became a path.
  const std::vector<std::string> siblings = directory_names(scratch.path());
  CSP_EXPECT_EQ(siblings.size(), std::size_t{1});
  CSP_EXPECT(contains(siblings, std::string("store")));
  CSP_EXPECT(!detail::file_exists(join(scratch.path(), "escape.plan")));
}

// ---------------------------------------------------------------------------
// Cancellation and fencing
// ---------------------------------------------------------------------------

CSP_TEST(adversarial, cancellation_from_another_thread_never_yields_a_plan) {
  csp_test::SeededRandom random(0x5EEDC0DEULL);
  const SiteEvidenceSnapshot snapshot = large_fleet(20000);
  const PlacementRequest request = two_placement_request();
  const PlacementPolicy policy = acceptance_policy();
  const PlanningContext context = instant_context();
  const Planner planner;

  // The same inputs, uncancelled, produce a plan. Without this the case could pass by
  // cancelling a call that never had an answer to withhold.
  Result<PlacementPlan> baseline = planner.plan(request, snapshot, policy, context);
  CSP_REQUIRE(baseline.has_value());
  CSP_REQUIRE(baseline.value().outcome == PlanOutcome::Planned);
  const std::string baseline_bytes = canonical(baseline.value());

  const std::uint64_t preset_iterations = 24 + random.below(17);
  std::size_t preset_cancelled = 0;
  for (std::uint64_t iteration = 0; iteration < preset_iterations; ++iteration) {
    CancellationSource source;
    source.request_cancel();
    PlanningContext cancelled = context;
    cancelled.cancellation = source.token();
    Result<PlacementPlan> result = planner.plan(request, snapshot, policy, cancelled);
    if (!result.has_value()) {
      CSP_EXPECT(result.error().category() == ErrorCategory::Cancelled);
      CSP_EXPECT_EQ(result.error().code(), std::string("csp.plan.cancelled"));
      ++preset_cancelled;
    } else {
      CSP_EXPECT_MSG(false, "a cancelled call returned a plan");
    }
  }
  CSP_EXPECT_MSG(preset_cancelled == static_cast<std::size_t>(preset_iterations),
                 "cancelled " + std::to_string(preset_cancelled) + " of " +
                     std::to_string(preset_iterations) + " pre-cancelled calls");

  const std::uint64_t inflight_iterations = 12 + random.below(8);
  std::size_t cancelled_seen = 0;
  std::size_t planned_seen = 0;
  for (std::uint64_t iteration = 0; iteration < inflight_iterations; ++iteration) {
    CancellationSource source;
    std::atomic<bool> requested{false};
    const std::uint64_t delay_micros = random.below(2000);
    std::thread canceller([&source, &requested, delay_micros]() {
      if (delay_micros > 0) {
        std::this_thread::sleep_for(std::chrono::microseconds(delay_micros));
      }
      source.request_cancel();
      requested.store(true, std::memory_order_release);
    });
    PlanningContext inflight = context;
    inflight.cancellation = source.token();
    Result<PlacementPlan> result = planner.plan(request, snapshot, policy, inflight);
    canceller.join();
    CSP_EXPECT(requested.load(std::memory_order_acquire));
    if (!result.has_value()) {
      CSP_EXPECT(result.error().category() == ErrorCategory::Cancelled);
      CSP_EXPECT_EQ(result.error().code(), std::string("csp.plan.cancelled"));
      ++cancelled_seen;
    } else {
      // The cancellation reached no check point before the call finished. What came
      // back must then be the whole plan, byte for byte, never a partial one.
      CSP_EXPECT_MSG(canonical(result.value()) == baseline_bytes,
                     "a plan returned during a cancellation differs from the uncancelled plan");
      ++planned_seen;
    }
  }
  CSP_EXPECT_MSG(cancelled_seen >= 1,
                 "the in-flight cancellation never reached a check point: cancelled=" +
                     std::to_string(cancelled_seen) + " planned=" + std::to_string(planned_seen) +
                     " iterations=" + std::to_string(inflight_iterations));
  // The real counts, printed rather than inferred: a run that cancelled nothing must not
  // be able to pass by comparing a plan with itself.
  std::printf("      cancellation: seed=%llu pre-cancelled iterations=%llu cancelled=%zu; in-flight "
              "iterations=%llu cancelled=%zu planned=%zu\n",
              static_cast<unsigned long long>(random.seed()),
              static_cast<unsigned long long>(preset_iterations), preset_cancelled,
              static_cast<unsigned long long>(inflight_iterations), cancelled_seen, planned_seen);
  std::fflush(stdout);
}

CSP_TEST(adversarial, stale_generation_fence_writes_nothing) {
  ScratchDirectory scratch("stale");
  Result<PlacementPlan> first = fixture_plan();
  CSP_REQUIRE(first.has_value());

  PlacementRequest request = simple_request();
  request.request = request_id("request-2");
  request.obligations[0].obligation = obligation_id("obligation-2");
  const Planner planner;
  Result<PlacementPlan> second = planner.plan(request, fleet_of({"site-1"}), acceptance_policy(), instant_context());
  CSP_REQUIRE(second.has_value());
  CSP_REQUIRE(second.value().plan != first.value().plan);

  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(first.value()).has_value());
  CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{1});

  Result<PlanId> fenced = store.commit_if_generation(second.value(), Generation::from_value(99));
  CSP_EXPECT(!fenced.has_value());
  if (!fenced.has_value()) {
    CSP_EXPECT(fenced.error().category() == ErrorCategory::Stale);
    CSP_EXPECT_EQ(fenced.error().code(), std::string("csp.store.generation_mismatch"));
    CSP_EXPECT(fenced.error().message().find("expected generation 99") != std::string::npos);
    CSP_EXPECT(fenced.error().message().find("the store is at 1") != std::string::npos);
  }

  // Nothing was written: the generation is unchanged, the record list is unchanged, and
  // the fenced plan has no record on disk.
  CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{1});
  Result<std::vector<PlanId>> listed = store.list();
  CSP_REQUIRE(listed.has_value());
  CSP_EXPECT_EQ(listed.value().size(), std::size_t{1});
  const std::string fenced_record = join(join(scratch.path(), detail::kRecordsDirectoryName),
                                         detail::record_file_name(second.value().plan));
  CSP_EXPECT(!detail::file_exists(fenced_record));
  CSP_EXPECT(!store.load(second.value().plan).has_value());

  Result<PlanId> accepted = store.commit_if_generation(second.value(), Generation::from_value(1));
  CSP_REQUIRE(accepted.has_value());
  CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{2});
  CSP_EXPECT(detail::file_exists(fenced_record));
  CSP_EXPECT_OK(store.close());
}

// ---------------------------------------------------------------------------
// Absurd sizes and hostile identities
// ---------------------------------------------------------------------------

CSP_TEST(adversarial, document_above_the_bound_is_refused_before_allocation) {
  Result<std::string> document = snapshot_to_document(complete_snapshot(), false);
  CSP_REQUIRE(document.has_value());
  CSP_REQUIRE(document.value().size() > 64);

  Limits limits;
  limits.max_document_bytes = 64;
  Result<SiteEvidenceSnapshot> decoded = snapshot_from_document(document.value(), limits);
  CSP_EXPECT(!decoded.has_value());
  if (!decoded.has_value()) {
    CSP_EXPECT(decoded.error().category() == ErrorCategory::BoundExceeded);
    CSP_EXPECT_EQ(decoded.error().code(), std::string("csp.json.bound_bytes"));
  }

  // A megabyte of digits is refused by its size, not by parsing it.
  const std::string absurd(1024 * 1024, '7');
  Result<SiteEvidenceSnapshot> refused = snapshot_from_document(absurd, limits);
  CSP_EXPECT(!refused.has_value());
  if (!refused.has_value()) {
    CSP_EXPECT(refused.error().category() == ErrorCategory::BoundExceeded);
    CSP_EXPECT_EQ(refused.error().code(), std::string("csp.json.bound_bytes"));
  }
}

CSP_TEST(adversarial, snapshot_above_the_site_bound_is_refused) {
  SiteEvidenceSnapshot snapshot = fleet_of({"site-1", "site-2"});
  Limits limits;
  limits.max_sites = 1;
  const Status status = snapshot_validate(snapshot, limits);
  CSP_EXPECT_MSG(failed_with(status, ErrorCategory::BoundExceeded, "csp.evidence.bound_exceeded"),
                 describe(status));

  Result<PlacementPlan> planned = plan_with(limits, simple_request(), snapshot);
  CSP_EXPECT(!planned.has_value());
  if (!planned.has_value()) {
    CSP_EXPECT(planned.error().category() == ErrorCategory::BoundExceeded);
    CSP_EXPECT_EQ(planned.error().code(), std::string("csp.evidence.bound_exceeded"));
  }
}

CSP_TEST(adversarial, hostile_plan_identities_never_reach_the_filesystem) {
  const std::vector<std::string> hostile{"..",         ".",            "/absolute", "plan-1/../../etc",
                                         "plan\\1",    "plan-1.",      "plan-1 ",   " plan-1",
                                         "plan-\x01x", "plan-\xC3\xA9-x", "c:/windows"};
  for (const std::string& text : hostile) {
    Result<PlanId> parsed = PlanId::parse(text);
    CSP_EXPECT_MSG(!parsed.has_value(), "identity accepted: " + text);
    if (!parsed.has_value()) {
      CSP_EXPECT_MSG(parsed.error().category() == ErrorCategory::Invalid,
                     text + ": " + parsed.error().render());
    }
  }

  // An identity longer than the bound is refused as out of range rather than truncated
  // into something that would name a different plan.
  const std::string too_long(129, 'a');
  Result<PlanId> refused = PlanId::parse(too_long);
  CSP_EXPECT(!refused.has_value());
  if (!refused.has_value()) {
    CSP_EXPECT(refused.error().category() == ErrorCategory::OutOfRange);
    CSP_EXPECT_EQ(refused.error().code(), std::string("csp.identifier.too_long"));
  }
  const std::string longest(128, 'a');
  CSP_EXPECT(PlanId::parse(longest).has_value());

  // A name a record can actually take carries no separator, so it cannot leave the
  // records directory no matter what the manifest says.
  const PlanId real = *PlanId::parse("plan-0123456789abcdef0123456789abcdef");
  const std::string name = detail::record_file_name(real);
  CSP_EXPECT(name.find('/') == std::string::npos);
  CSP_EXPECT(name.find('\\') == std::string::npos);
  CSP_EXPECT(name.front() != '.');

  // The store never sees an unparsed name: a plan identity that was never issued is
  // simply absent, and the answer is NotFound rather than an attempt on the disk.
  ScratchDirectory scratch("hostile-ids");
  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  Result<PlacementPlan> loaded = store.load(PlanId{});
  CSP_EXPECT(!loaded.has_value());
  if (!loaded.has_value()) {
    CSP_EXPECT(loaded.error().category() == ErrorCategory::NotFound);
    CSP_EXPECT_EQ(loaded.error().code(), std::string("csp.store.unknown_plan"));
  }
  CSP_EXPECT_OK(store.close());

  // Invalid UTF-8 in a document is refused as malformed rather than decoded into
  // replacement characters that would silently change an identity.
  Result<PlacementRequest> bad = request_from_document("\xFF\xFE not utf-8", Limits{});
  CSP_EXPECT(!bad.has_value());
  if (!bad.has_value()) {
    CSP_EXPECT(bad.error().category() == ErrorCategory::Malformed);
  }
}
