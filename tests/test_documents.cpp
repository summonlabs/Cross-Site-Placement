// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Documents: the textual forms of a snapshot and a plan, the decoder as a trust
// boundary, the configured collection bounds, and the structural validation of a plan.
//
// The decoder cases are stated as refusals rather than as successes on purpose: what a
// hostile reader needs to know is which documents this build will not accept, and why.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"
#include "test_harness.hpp"

using namespace csp;

namespace {

constexpr std::int64_t kObserved = 1700000000000000000LL;
constexpr std::int64_t kEvaluated = kObserved + 1000000000LL;

/// The harness's CSP_EXPECT_CATEGORY substitutes its second parameter into the member
/// call `error().category()`, so a category constant cannot be passed through it. This
/// helper asserts the same property, and the code as well where a code is given.
template <class T>
void expect_failure(const Result<T>& result, ErrorCategory wanted, const char* code, const char* expression,
                    const char* file, int line) {
  const bool failed = !result.has_value();
  (void)csp_test::check(failed, expression, file, line, failed ? std::string() : std::string("it succeeded"));
  if (!failed) {
    return;
  }
  (void)csp_test::check(result.error().category() == wanted, expression, file, line, result.error().render());
  if (code != nullptr) {
    (void)csp_test::check(result.error().code() == code, expression, file, line, result.error().render());
  }
}

#define EXPECT_FAILURE(expression, wanted_category, wanted_code) \
  expect_failure((expression), (wanted_category), (wanted_code), #expression, __FILE__, __LINE__)

/// Parses an identity the fixture already knows is well formed.
template <class IdType>
IdType id_of(std::string_view text) {
  const Result<IdType> parsed = IdType::parse(text);
  CSP_REQUIRE(parsed.has_value());
  return parsed.value();
}

Provenance provenance_of(std::string_view record, std::int64_t observed_nanos) {
  Provenance provenance;
  provenance.source_record = id_of<EvidenceId>(record);
  provenance.authority = id_of<AuthorityId>("authority-1");
  provenance.authority_generation = Generation::from_value(9);
  provenance.observed_at = Instant::from_nanos(observed_nanos);
  return provenance;
}

/// A snapshot that carries at least one record of every collection, with parents,
/// aliases, and both the present and absent forms of every optional field.
SiteEvidenceSnapshot sample_snapshot() {
  SiteEvidenceSnapshot snapshot;
  snapshot.generation = Generation::from_value(11);
  snapshot.captured_at = Instant::from_nanos(kEvaluated);

  SiteRecord site_a;
  site_a.site = id_of<SiteId>("site-a");
  site_a.jurisdiction = id_of<JurisdictionId>("region-eu");
  site_a.maintenance = Measurement<MaintenanceState>::known(MaintenanceState::Operational);
  site_a.provenance = provenance_of("site-record-a", kObserved);
  snapshot.sites.push_back(site_a);

  SiteRecord site_b;
  site_b.site = id_of<SiteId>("site-b");
  // No jurisdiction, and nobody reported the maintenance state.
  site_b.maintenance = Measurement<MaintenanceState>::unknown();
  Provenance late = provenance_of("site-record-b", kObserved - 500);
  late.expires_at = Instant::from_nanos(kEvaluated + 1000);
  late.document_digest = Digest::of("site-record-b-document");
  site_b.provenance = late;
  snapshot.sites.push_back(site_b);

  FailureDomainRecord feed;
  feed.domain = id_of<FailureDomainId>("feed-1");
  feed.kind = DomainKind::Power;
  feed.provenance = provenance_of("domain-feed", kObserved);
  snapshot.failure_domains.push_back(feed);

  FailureDomainRecord region;
  region.domain = id_of<FailureDomainId>("region-1");
  region.kind = DomainKind::Geography;
  region.provenance = provenance_of("domain-region", kObserved);
  snapshot.failure_domains.push_back(region);

  FailureDomainRecord hall;
  hall.domain = id_of<FailureDomainId>("hall-1");
  hall.kind = DomainKind::Physical;
  hall.parent = id_of<FailureDomainId>("region-1");
  hall.provenance = provenance_of("domain-hall", kObserved);
  snapshot.failure_domains.push_back(hall);

  DomainAssignment assignment_a;
  assignment_a.site = site_a.site;
  assignment_a.domain = feed.domain;
  assignment_a.provenance = provenance_of("assignment-a", kObserved);
  snapshot.domain_assignments.push_back(assignment_a);

  DomainAssignment assignment_b;
  assignment_b.site = site_a.site;
  assignment_b.domain = hall.domain;
  assignment_b.provenance = provenance_of("assignment-b", kObserved);
  snapshot.domain_assignments.push_back(assignment_b);

  DomainAssignment assignment_c;
  assignment_c.site = site_b.site;
  assignment_c.domain = region.domain;
  assignment_c.provenance = provenance_of("assignment-c", kObserved);
  snapshot.domain_assignments.push_back(assignment_c);

  DomainAliasRecord alias;
  alias.domain = id_of<FailureDomainId>("feed-primary");
  alias.alias_of = feed.domain;
  alias.provenance = provenance_of("alias-a", kObserved);
  snapshot.domain_aliases.push_back(alias);

  CapacityRecord offer;
  offer.reference = id_of<CapacityRefId>("cap-1");
  offer.site = site_a.site;
  offer.service_class = id_of<ServiceClassId>("payments");
  offer.kind = CapacityKind::Offer;
  offer.available = Measurement<Quantity>::known(Quantity::from_units(10));
  offer.provenance = provenance_of("capacity-1", kObserved);
  snapshot.capacity.push_back(offer);

  CapacityRecord commitment;
  commitment.reference = id_of<CapacityRefId>("cap-2");
  commitment.site = site_a.site;
  commitment.service_class = offer.service_class;
  commitment.kind = CapacityKind::Commitment;
  commitment.available = Measurement<Quantity>::known(Quantity::from_units(5));
  commitment.provenance = provenance_of("capacity-2", kObserved);
  snapshot.capacity.push_back(commitment);

  CapacityRecord unavailable;
  unavailable.reference = id_of<CapacityRefId>("cap-3");
  unavailable.site = site_b.site;
  unavailable.service_class = offer.service_class;
  unavailable.kind = CapacityKind::Commitment;
  unavailable.available = Measurement<Quantity>::unavailable();
  unavailable.provenance = provenance_of("capacity-3", kObserved);
  snapshot.capacity.push_back(unavailable);

  LatencyRecord direct;
  direct.reference = id_of<DependencyId>("lat-1");
  direct.from_site = site_a.site;
  direct.to_site = site_b.site;
  direct.statistic = LatencyStatistic::Max;
  direct.latency = Measurement<Duration>::known(Duration::from_nanos(2000000));
  direct.provenance = provenance_of("latency-1", kObserved);
  snapshot.latency.push_back(direct);

  LatencyRecord undecided;
  undecided.reference = id_of<DependencyId>("lat-2");
  undecided.from_site = site_b.site;
  undecided.to_site = site_a.site;
  undecided.statistic = LatencyStatistic::P99;
  undecided.latency = Measurement<Duration>::unknown();
  undecided.provenance = provenance_of("latency-2", kObserved);
  snapshot.latency.push_back(undecided);

  RecoveryRecord recovery;
  recovery.reference = id_of<RecoveryRefId>("rec-1");
  recovery.site = site_a.site;
  recovery.service_class = offer.service_class;
  recovery.can_host_recovery = Measurement<bool>::known(true);
  recovery.achievable_rto = Measurement<Duration>::known(Duration::from_nanos(5000000));
  recovery.achievable_rpo = Measurement<Duration>::unknown();
  recovery.provenance = provenance_of("recovery-1", kObserved);
  snapshot.recovery.push_back(recovery);

  CompatibilityRecord compatible;
  compatible.reference = id_of<EvidenceId>("compat-1");
  compatible.site = site_a.site;
  compatible.service_class = offer.service_class;
  compatible.compatible = Measurement<bool>::known(true);
  compatible.provenance = provenance_of("compatibility-1", kObserved);
  snapshot.compatibility.push_back(compatible);

  CompatibilityRecord unsupported;
  unsupported.reference = id_of<EvidenceId>("compat-2");
  unsupported.site = site_b.site;
  unsupported.service_class = offer.service_class;
  unsupported.compatible = Measurement<bool>::unsupported();
  unsupported.provenance = provenance_of("compatibility-2", kObserved);
  snapshot.compatibility.push_back(unsupported);

  CostRiskRecord priced;
  priced.reference = id_of<EvidenceId>("cost-1");
  priced.site = site_a.site;
  priced.service_class = offer.service_class;
  priced.cost_per_unit = Measurement<Quantity>::known(Quantity::from_units(7));
  priced.risk_per_mille = Measurement<std::int64_t>::known(250);
  priced.provenance = provenance_of("cost-1", kObserved);
  snapshot.cost_risk.push_back(priced);

  CostRiskRecord unpriced;
  unpriced.reference = id_of<EvidenceId>("cost-2");
  unpriced.site = site_b.site;
  // No service class, and no reported cost.
  unpriced.cost_per_unit = Measurement<Quantity>::unknown();
  unpriced.risk_per_mille = Measurement<std::int64_t>::known(100);
  unpriced.provenance = provenance_of("cost-2", kObserved);
  snapshot.cost_risk.push_back(unpriced);
  return snapshot;
}

/// Which collection a bound case fills.
enum class Collection { Sites, FailureDomains, Capacity, Latency, Compatibility };

SiteEvidenceSnapshot snapshot_with_collection(Collection which, std::size_t count) {
  SiteEvidenceSnapshot snapshot;
  snapshot.generation = Generation::from_value(1);
  snapshot.captured_at = Instant::from_nanos(kEvaluated);
  // Every case starts with one site so the records below have a subject.
  SiteRecord site;
  site.site = id_of<SiteId>("site-0");
  site.maintenance = Measurement<MaintenanceState>::known(MaintenanceState::Operational);
  site.provenance = provenance_of("site-record-0", kObserved);
  snapshot.sites.push_back(site);
  if (which == Collection::Sites) {
    snapshot.sites.clear();
  }
  const ServiceClassId service = id_of<ServiceClassId>("payments");
  for (std::size_t index = 0; index < count; ++index) {
    const std::string suffix = std::to_string(index);
    if (which == Collection::Sites) {
      SiteRecord record;
      record.site = id_of<SiteId>("site-" + suffix);
      record.maintenance = Measurement<MaintenanceState>::known(MaintenanceState::Operational);
      record.provenance = provenance_of("site-record-" + suffix, kObserved);
      snapshot.sites.push_back(record);
    } else if (which == Collection::FailureDomains) {
      FailureDomainRecord record;
      record.domain = id_of<FailureDomainId>("domain-" + suffix);
      record.kind = DomainKind::Power;
      record.provenance = provenance_of("domain-record-" + suffix, kObserved);
      snapshot.failure_domains.push_back(record);
    } else if (which == Collection::Capacity) {
      CapacityRecord record;
      record.reference = id_of<CapacityRefId>("cap-" + suffix);
      record.site = site.site;
      record.service_class = service;
      record.kind = CapacityKind::Commitment;
      record.available = Measurement<Quantity>::known(Quantity::from_units(5));
      record.provenance = provenance_of("capacity-record-" + suffix, kObserved);
      snapshot.capacity.push_back(record);
    } else if (which == Collection::Latency) {
      LatencyRecord record;
      record.reference = id_of<DependencyId>("lat-" + suffix);
      record.from_site = site.site;
      record.to_site = site.site;
      record.statistic = LatencyStatistic::Max;
      record.latency = Measurement<Duration>::known(Duration::from_nanos(1000));
      record.provenance = provenance_of("latency-record-" + suffix, kObserved);
      snapshot.latency.push_back(record);
    } else {
      CompatibilityRecord record;
      record.reference = id_of<EvidenceId>("compat-" + suffix);
      record.site = site.site;
      record.service_class = service;
      record.compatible = Measurement<bool>::known(true);
      record.provenance = provenance_of("compatibility-record-" + suffix, kObserved);
      snapshot.compatibility.push_back(record);
    }
  }
  return snapshot;
}

Limits limits_with_bound(Collection which, std::size_t bound) {
  Limits limits;
  switch (which) {
    case Collection::Sites:
      limits.max_sites = bound;
      break;
    case Collection::FailureDomains:
      limits.max_failure_domains = bound;
      break;
    case Collection::Capacity:
      limits.max_capacity_evidence = bound;
      break;
    case Collection::Latency:
      limits.max_latency_evidence = bound;
      break;
    case Collection::Compatibility:
      limits.max_compatibility_evidence = bound;
      break;
  }
  return limits;
}

/// Replaces the first occurrence of a fragment, refusing the case when it is absent so
/// that a document this build no longer produces cannot silently pass as covered.
std::string replace_once(std::string text, std::string_view from, std::string_view to) {
  const std::size_t at = text.find(from);
  CSP_REQUIRE(at != std::string::npos);
  text.replace(at, from.size(), to);
  return text;
}

/// A plan that carries every field of the encoder, sealed so its digest is real.
PlacementPlan sample_plan() {
  PlacementPlan plan;
  plan.request = id_of<RequestId>("req-doc");
  plan.request_generation = Generation::from_value(3);
  plan.outcome = PlanOutcome::Planned;
  plan.nodes_explored = 17;
  plan.search_exhausted = false;

  ObligationPlacement obligation;
  obligation.obligation = id_of<ObligationId>("obligation-a");
  obligation.outcome = Tri::Satisfied;

  SitePlacement primary;
  primary.site = id_of<SiteId>("site-a");
  primary.role = PlacementRole::Primary;
  primary.index = 0;
  primary.capacity_required = Quantity::from_units(4);
  primary.capacity.references.push_back(id_of<CapacityRefId>("cap-1"));
  primary.capacity.references.push_back(id_of<CapacityRefId>("cap-2"));
  primary.capacity.evidenced_total = Quantity::from_units(15);
  primary.capacity.includes_offers = true;
  primary.domains.push_back(DomainRef{id_of<FailureDomainId>("feed-1"), DomainKind::Power, 0});
  primary.domains.push_back(DomainRef{id_of<FailureDomainId>("region-1"), DomainKind::Geography, 1});
  primary.jurisdiction = id_of<JurisdictionId>("region-eu");
  obligation.placements.push_back(primary);

  SitePlacement recovery;
  recovery.site = id_of<SiteId>("site-b");
  recovery.role = PlacementRole::Recovery;
  recovery.index = 0;
  recovery.capacity_required = Quantity::from_units(4);
  recovery.capacity.references.push_back(id_of<CapacityRefId>("cap-3"));
  recovery.capacity.evidenced_total = Quantity::from_units(6);
  recovery.capacity.includes_offers = false;
  // A domain nobody declared: the optional kind is simply absent.
  recovery.domains.push_back(DomainRef{id_of<FailureDomainId>("shared-9"), std::nullopt, 0});
  obligation.placements.push_back(recovery);

  LatencyResolution latency;
  latency.peer = "site-a to site-b";
  latency.direction = LatencyDirection::FromPlacement;
  latency.statistic = LatencyStatistic::Max;
  latency.measured = Duration::from_nanos(2000000);
  latency.derived = true;
  latency.chain.push_back(id_of<DependencyId>("lat-1"));
  latency.chain.push_back(id_of<DependencyId>("lat-2"));
  obligation.latency.push_back(latency);
  plan.obligations.push_back(obligation);

  ConstraintTraceEntry entry;
  entry.rule = "csp.rule.selection";
  entry.outcome = Tri::Satisfied;
  entry.obligation = obligation.obligation;
  entry.site = primary.site;
  entry.detail = "1 of 2 placements selected from 2 candidates";
  EvidenceRef full;
  full.kind = "capacity";
  full.record = id_of<EvidenceId>("cap-1");
  full.authority = id_of<AuthorityId>("capacity-authority");
  full.authority_generation = Generation::from_value(9);
  full.document_digest = Digest::of("capacity-document");
  EvidenceRef bare;
  bare.kind = "site";
  entry.evidence.push_back(full);
  entry.evidence.push_back(bare);
  plan.trace.push_back(entry);

  ResidualRequirement residual;
  residual.obligation = obligation.obligation;
  residual.requirement = "csp.residual.capacity";
  residual.shortfall = Quantity::from_units(2);
  residual.placements_short = 1;
  residual.detail = "a shortfall recorded so the residual encoder is exercised";
  plan.residual.push_back(residual);

  TieBreakRecord tie_break;
  tie_break.criterion = "csp.preference.minimise-cost";
  tie_break.applied = Tri::Indeterminate;
  tie_break.ordered.push_back(primary.site);
  tie_break.ordered.push_back(recovery.site);
  tie_break.detail = "1 of 2 candidates have a reported cost";
  plan.tie_breaks.push_back(tie_break);

  plan.envelope.evaluated_at = Instant::from_nanos(kEvaluated);
  plan.envelope.oldest_evidence_observed_at = Instant::from_nanos(kObserved);
  plan.envelope.evidence_generation = Generation::from_value(11);
  plan.envelope.policy_generation = Generation::from_value(5);
  plan.envelope.request_generation = Generation::from_value(3);
  plan.envelope.valid_until = Instant::from_nanos(kEvaluated + 900000000000LL);
  plan.envelope.revalidate_when.push_back("csp.revalidate.plan-expiry");
  plan.envelope.revalidate_when.push_back("csp.revalidate.evidence-generation");
  plan_seal(plan);
  return plan;
}

/// The same shape as sample_plan, refused: it exercises the refusal encoder and the
/// "no expiry claim" form of the envelope.
PlacementPlan sample_refused_plan() {
  PlacementPlan plan = sample_plan();
  plan.outcome = PlanOutcome::Refused;
  plan.obligations.front().outcome = Tri::Violated;
  plan.obligations.front().placements.clear();
  plan.obligations.front().latency.clear();
  plan.obligations.front().refusal_code = "csp.plan.no-arrangement";
  plan.obligations.front().detail = "the capacity reported here is below what this obligation requires";
  Refusal refusal;
  refusal.category = ErrorCategory::Invalid;
  refusal.code = "csp.plan.no-arrangement";
  refusal.detail = "no arrangement of the requested placements satisfies every hard rule";
  EvidenceRef reference;
  reference.kind = "capacity";
  reference.record = id_of<EvidenceId>("cap-9");
  refusal.evidence.push_back(reference);
  plan.refusal = refusal;
  plan.envelope.valid_until = Instant{};
  plan_seal(plan);
  return plan;
}

/// The document this build writes for an empty snapshot, kept as a literal so the
/// decoder cases can cut it up by exact byte.
const char* kMinimalSnapshotText =
    R"({"format":1,"kind":"snapshot","generation":1,"captured_at":0,"sites":[],"failure_domains":[],)"
    R"("domain_assignments":[],"domain_aliases":[],"capacity":[],"latency":[],"recovery":[],)"
    R"("compatibility":[],"cost_risk":[]})";

}  // namespace

// ---------------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------------

CSP_TEST(documents, snapshot_document_round_trips_every_collection) {
  const Limits limits;
  const SiteEvidenceSnapshot original = sample_snapshot();
  const Result<std::string> canonical = snapshot_to_document(original, false);
  CSP_REQUIRE(canonical.has_value());
  const Result<std::string> canonical_again = snapshot_to_document(original, false);
  CSP_REQUIRE(canonical_again.has_value());
  CSP_EXPECT_EQ(canonical.value(), canonical_again.value());

  const Result<SiteEvidenceSnapshot> decoded = snapshot_from_document(canonical.value(), limits);
  CSP_REQUIRE(decoded.has_value());
  const SiteEvidenceSnapshot& back = decoded.value();
  const Result<std::string> re_encoded = snapshot_to_document(back, false);
  CSP_REQUIRE(re_encoded.has_value());
  CSP_EXPECT_MSG(re_encoded.value() == canonical.value(),
                 "the canonical encoding of the decoded snapshot differs from the original");

  CSP_EXPECT_EQ(back.generation.value(), std::uint64_t{11});
  CSP_EXPECT_EQ(back.captured_at.nanos(), kEvaluated);
  CSP_EXPECT_EQ(back.sites.size(), std::size_t{2});
  CSP_EXPECT_EQ(back.failure_domains.size(), std::size_t{3});
  CSP_EXPECT_EQ(back.domain_assignments.size(), std::size_t{3});
  CSP_EXPECT_EQ(back.domain_aliases.size(), std::size_t{1});
  CSP_EXPECT_EQ(back.capacity.size(), std::size_t{3});
  CSP_EXPECT_EQ(back.latency.size(), std::size_t{2});
  CSP_EXPECT_EQ(back.recovery.size(), std::size_t{1});
  CSP_EXPECT_EQ(back.compatibility.size(), std::size_t{2});
  CSP_EXPECT_EQ(back.cost_risk.size(), std::size_t{2});

  // A parent edge survived, and it is a real edge rather than a copied string.
  bool saw_parent = false;
  for (const FailureDomainRecord& domain : back.failure_domains) {
    if (!(domain.domain == id_of<FailureDomainId>("hall-1"))) {
      continue;
    }
    saw_parent = true;
    CSP_EXPECT(domain.kind == DomainKind::Physical);
    CSP_EXPECT(domain.parent.has_value());
    if (domain.parent.has_value()) {
      CSP_EXPECT(*domain.parent == id_of<FailureDomainId>("region-1"));
    }
  }
  CSP_EXPECT(saw_parent);
  bool saw_root = false;
  for (const FailureDomainRecord& domain : back.failure_domains) {
    if (domain.domain == id_of<FailureDomainId>("feed-1")) {
      saw_root = true;
      CSP_EXPECT(!domain.parent.has_value());
      CSP_EXPECT(domain.kind == DomainKind::Power);
    }
  }
  CSP_EXPECT(saw_root);
  CSP_EXPECT(back.domain_aliases.front().domain == id_of<FailureDomainId>("feed-primary"));
  CSP_EXPECT(back.domain_aliases.front().alias_of == id_of<FailureDomainId>("feed-1"));

  // The measurements survived in their exact states, not collapsed to zero.
  bool saw_known_site = false;
  bool saw_unknown_site = false;
  for (const SiteRecord& site : back.sites) {
    if (site.site == id_of<SiteId>("site-a")) {
      saw_known_site = true;
      CSP_EXPECT(site.maintenance.is_known());
      CSP_EXPECT(site.jurisdiction == id_of<JurisdictionId>("region-eu"));
    } else {
      saw_unknown_site = true;
      CSP_EXPECT(site.maintenance.is_unknown());
      CSP_EXPECT(!site.jurisdiction.valid());
      CSP_EXPECT(site.provenance.expires_at.has_value());
      CSP_EXPECT(!site.provenance.document_digest.is_zero());
      CSP_EXPECT_EQ(site.provenance.observed_at.nanos(), kObserved - 500);
    }
  }
  CSP_EXPECT(saw_known_site);
  CSP_EXPECT(saw_unknown_site);

  bool saw_unavailable_capacity = false;
  for (const CapacityRecord& record : back.capacity) {
    if (record.reference == id_of<CapacityRefId>("cap-3")) {
      saw_unavailable_capacity = true;
      CSP_EXPECT(record.available.is_unavailable());
      CSP_EXPECT(record.kind == CapacityKind::Commitment);
    }
    if (record.reference == id_of<CapacityRefId>("cap-1")) {
      CSP_EXPECT(record.kind == CapacityKind::Offer);
      CSP_EXPECT(record.available.is_known());
      CSP_EXPECT_EQ(record.available.value().units(), std::int64_t{10});
    }
  }
  CSP_EXPECT(saw_unavailable_capacity);

  bool saw_unknown_latency = false;
  for (const LatencyRecord& record : back.latency) {
    if (record.reference == id_of<DependencyId>("lat-2")) {
      saw_unknown_latency = true;
      CSP_EXPECT(record.latency.is_unknown());
      CSP_EXPECT(record.statistic == LatencyStatistic::P99);
      CSP_EXPECT(record.from_site == id_of<SiteId>("site-b"));
      CSP_EXPECT(record.to_site == id_of<SiteId>("site-a"));
    }
  }
  CSP_EXPECT(saw_unknown_latency);

  CSP_EXPECT(back.recovery.front().can_host_recovery.is_known());
  CSP_EXPECT(back.recovery.front().can_host_recovery.value());
  CSP_EXPECT(back.recovery.front().achievable_rto.is_known());
  CSP_EXPECT(back.recovery.front().achievable_rpo.is_unknown());
  bool saw_unsupported = false;
  for (const CompatibilityRecord& record : back.compatibility) {
    if (record.reference == id_of<EvidenceId>("compat-2")) {
      saw_unsupported = true;
      CSP_EXPECT(record.compatible.is_unsupported());
    }
  }
  CSP_EXPECT(saw_unsupported);

  bool saw_unpriced = false;
  for (const CostRiskRecord& record : back.cost_risk) {
    if (record.reference == id_of<EvidenceId>("cost-2")) {
      saw_unpriced = true;
      // An absent service class is an absent fact, not an empty identity.
      CSP_EXPECT(!record.service_class.valid());
      CSP_EXPECT(record.cost_per_unit.is_unknown());
      CSP_EXPECT(record.risk_per_mille.is_known());
      CSP_EXPECT_EQ(record.risk_per_mille.value(), std::int64_t{100});
    }
  }
  CSP_EXPECT(saw_unpriced);
}

CSP_TEST(documents, snapshot_document_pretty_form_decodes_to_the_same_value) {
  const Limits limits;
  const SiteEvidenceSnapshot original = sample_snapshot();
  const Result<std::string> canonical = snapshot_to_document(original, false);
  CSP_REQUIRE(canonical.has_value());
  const Result<std::string> pretty = snapshot_to_document(original, true);
  CSP_REQUIRE(pretty.has_value());
  CSP_EXPECT(pretty.value() != canonical.value());
  const Result<SiteEvidenceSnapshot> decoded = snapshot_from_document(pretty.value(), limits);
  CSP_REQUIRE(decoded.has_value());
  const Result<std::string> re_encoded = snapshot_to_document(decoded.value(), false);
  CSP_REQUIRE(re_encoded.has_value());
  CSP_EXPECT_EQ(re_encoded.value(), canonical.value());
  // Trailing whitespace after the top-level value is not trailing content.
  const Result<SiteEvidenceSnapshot> padded = snapshot_from_document(canonical.value() + "\n", limits);
  CSP_EXPECT(padded.has_value());
}

CSP_TEST(documents, snapshot_decoder_refusals_carry_the_documented_category) {
  // Each refusal below is made against the default limits unless it is specifically about
  // a lowered bound, so there is no shared Limits object to carry here.
  const SiteEvidenceSnapshot sample = sample_snapshot();
  const Result<std::string> canonical = snapshot_to_document(sample, false);
  CSP_REQUIRE(canonical.has_value());
  const std::string& text = canonical.value();
  const std::string minimal = kMinimalSnapshotText;

  struct Refusal {
    const char* label;
    std::string document;
    ErrorCategory category;
    const char* code;
    Limits limits{};
  };
  std::vector<Refusal> refusals;
  refusals.push_back({"malformed JSON", R"({"format":1,)", ErrorCategory::Malformed,
                      "csp.json.unexpected_end"});
  refusals.push_back({"trailing content", text + "0", ErrorCategory::Malformed,
                      "csp.json.trailing_content"});
  refusals.push_back({"truncated document", text.substr(0, text.size() / 2), ErrorCategory::Malformed,
                      nullptr});
  refusals.push_back({"not JSON at all", "this is not a document", ErrorCategory::Malformed, nullptr});
  refusals.push_back({"a JSON array where an object belongs", "[1,2]", ErrorCategory::Invalid,
                      "csp.doc.not_object"});
  refusals.push_back({"an unknown field at the top level",
                      replace_once(minimal, R"("kind":"snapshot")", R"("bogus":1,"kind":"snapshot")"),
                      ErrorCategory::Unsupported, "csp.doc.unknown_field"});
  refusals.push_back({"an unknown field inside a measurement",
                      replace_once(text, R"({"state":"known","value":"operational"})",
                                   R"({"extra":1,"state":"known","value":"operational"})"),
                      ErrorCategory::Unsupported, "csp.doc.unknown_field"});
  refusals.push_back({"an unknown field inside a provenance record",
                      replace_once(text, R"("observed_at":1700000000000000000)",
                                   R"("observed_at":1700000000000000000,"zz":1)"),
                      ErrorCategory::Unsupported, "csp.doc.unknown_field"});
  refusals.push_back({"a later document version",
                      replace_once(minimal, R"("format":1)", R"("format":2)"), ErrorCategory::Unsupported,
                      "csp.doc.format_version"});
  refusals.push_back({"a version below the readable range",
                      replace_once(minimal, R"("format":1)", R"("format":0)"), ErrorCategory::Unsupported,
                      "csp.doc.format_version"});
  refusals.push_back({"the wrong document kind",
                      replace_once(minimal, R"("kind":"snapshot")", R"("kind":"plan")"),
                      ErrorCategory::Invalid, "csp.doc.kind"});
  refusals.push_back({"a missing required field", replace_once(minimal, R"("captured_at":0,)", ""),
                      ErrorCategory::NotFound, "csp.doc.missing_field"});
  refusals.push_back({"a missing required field deep in a record",
                      replace_once(text, R"("authority_generation":9,)", ""), ErrorCategory::NotFound,
                      "csp.doc.missing_field"});
  refusals.push_back({"a string where a number belongs",
                      replace_once(minimal, R"("generation":1)", R"("generation":"one")"),
                      ErrorCategory::Invalid, "csp.json.type"});
  refusals.push_back({"a string where a measurement object belongs",
                      replace_once(text, R"({"state":"known","value":"operational"})",
                                   R"("operational")"),
                      ErrorCategory::Invalid, "csp.doc.field_type"});
  refusals.push_back({"a value beside a non-known measurement state",
                      replace_once(text, R"({"state":"unknown"})", R"({"state":"unknown","value":1})"),
                      ErrorCategory::Invalid, "csp.doc.measurement_value"});
  refusals.push_back({"a known measurement with no value",
                      replace_once(text, R"({"state":"known","value":"operational"})",
                                   R"({"state":"known"})"),
                      ErrorCategory::Invalid, "csp.doc.measurement_value"});
  refusals.push_back({"a duplicate object member",
                      replace_once(minimal, R"("generation":1)", R"("generation":1,"generation":1)"),
                      ErrorCategory::Conflict, "csp.json.duplicate_key"});
  refusals.push_back({"an identity outside the alphabet",
                      replace_once(text, R"("site":"site-a")", R"("site":"site a")"),
                      ErrorCategory::Invalid, "csp.identifier.alphabet"});
  refusals.push_back({"a digest of the wrong length",
                      replace_once(text, R"("authority_generation":9)",
                                   R"("document_digest":"00","authority_generation":9)"),
                      ErrorCategory::Invalid, "csp.digest.length"});
  refusals.push_back({"an unknown maintenance state",
                      replace_once(text, R"("value":"operational")", R"("value":"rebooting")"),
                      ErrorCategory::Invalid, "csp.doc.maintenance_state"});
  // An array longer than the configured bound: the snapshot carries two sites and the
  // limit allows one.
  const SiteEvidenceSnapshot two_sites = snapshot_with_collection(Collection::Sites, 2);
  const Result<std::string> two_sites_document = snapshot_to_document(two_sites, false);
  CSP_REQUIRE(two_sites_document.has_value());
  refusals.push_back({"an array past its bound", two_sites_document.value(), ErrorCategory::BoundExceeded,
                      "csp.doc.array_bound", limits_with_bound(Collection::Sites, 1)});

  for (const Refusal& refusal : refusals) {
    const Result<SiteEvidenceSnapshot> decoded = snapshot_from_document(refusal.document, refusal.limits);
    const bool failed = !decoded.has_value();
    (void)csp_test::check(failed, refusal.label, __FILE__, __LINE__,
                          failed ? std::string() : std::string("it succeeded"));
    if (!failed) {
      continue;
    }
    (void)csp_test::check(decoded.error().category() == refusal.category, refusal.label, __FILE__, __LINE__,
                          decoded.error().render());
    if (refusal.code != nullptr) {
      (void)csp_test::check(decoded.error().code() == refusal.code, refusal.label, __FILE__, __LINE__,
                            decoded.error().render());
    }
  }
}

CSP_TEST(documents, collection_bounds_accept_exactly_the_bound) {
  const std::pair<Collection, const char*> kCollections[] = {
      {Collection::Sites, "sites"},
      {Collection::FailureDomains, "failure_domains"},
      {Collection::Capacity, "capacity"},
      {Collection::Latency, "latency"},
      {Collection::Compatibility, "compatibility"},
  };
  for (const auto& entry : kCollections) {
    constexpr std::size_t kBound = 3;
    const SiteEvidenceSnapshot at_bound = snapshot_with_collection(entry.first, kBound);
    const Result<std::string> at_bound_document = snapshot_to_document(at_bound, false);
    CSP_REQUIRE(at_bound_document.has_value());
    const Result<SiteEvidenceSnapshot> accepted =
        snapshot_from_document(at_bound_document.value(), limits_with_bound(entry.first, kBound));
    CSP_EXPECT_MSG(accepted.has_value(),
                   std::string(entry.second) + ": a document exactly at the bound was refused");
    if (!accepted.has_value()) {
      CSP_EXPECT_MSG(false, accepted.error().render());
    }

    const SiteEvidenceSnapshot past_bound = snapshot_with_collection(entry.first, kBound + 1);
    const Result<std::string> past_bound_document = snapshot_to_document(past_bound, false);
    CSP_REQUIRE(past_bound_document.has_value());
    const Result<SiteEvidenceSnapshot> refused =
        snapshot_from_document(past_bound_document.value(), limits_with_bound(entry.first, kBound));
    CSP_EXPECT_MSG(!refused.has_value(), std::string(entry.second) + ": one past the bound was accepted");
    if (!refused.has_value()) {
      CSP_EXPECT_MSG(refused.error().category() == ErrorCategory::BoundExceeded,
                     std::string(entry.second) + ": " + refused.error().render());
      CSP_EXPECT_MSG(refused.error().code() == "csp.doc.array_bound",
                     std::string(entry.second) + ": " + refused.error().render());
    }

    // A document with no entry of that collection is accepted with a bound of zero.
    const SiteEvidenceSnapshot empty = snapshot_with_collection(entry.first, 0);
    const Result<std::string> empty_document = snapshot_to_document(empty, false);
    CSP_REQUIRE(empty_document.has_value());
    const Result<SiteEvidenceSnapshot> empty_accepted =
        snapshot_from_document(empty_document.value(), limits_with_bound(entry.first, 0));
    CSP_EXPECT_MSG(empty_accepted.has_value(),
                   std::string(entry.second) + ": an empty collection was refused at a zero bound");
  }
}

// ---------------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------------

CSP_TEST(documents, plan_document_round_trips_and_recomputes_the_digest) {
  const Limits limits;
  const PlacementPlan original = sample_plan();
  CSP_EXPECT(!original.plan.value().empty());
  CSP_EXPECT(!original.digest.is_zero());
  CSP_EXPECT(original.digest == plan_compute_digest(original));

  const Result<std::string> canonical = plan_to_document(original, false);
  CSP_REQUIRE(canonical.has_value());
  const Result<PlacementPlan> decoded = plan_from_document(canonical.value(), limits);
  CSP_REQUIRE(decoded.has_value());
  CSP_EXPECT(decoded.value().digest == original.digest);
  CSP_EXPECT(decoded.value().plan == original.plan);
  CSP_EXPECT(decoded.value().plan.value() == original.plan.value());
  CSP_EXPECT(plan_compute_digest(decoded.value()) == decoded.value().digest);
  CSP_EXPECT(decoded.value().outcome == PlanOutcome::Planned);
  CSP_EXPECT(decoded.value().nodes_explored == 17);
  CSP_EXPECT(!decoded.value().search_exhausted);

  const Result<std::string> re_encoded = plan_to_document(decoded.value(), false);
  CSP_REQUIRE(re_encoded.has_value());
  CSP_EXPECT_EQ(re_encoded.value(), canonical.value());

  // The whole body survived.
  CSP_REQUIRE(decoded.value().obligations.size() == 1);
  const ObligationPlacement& obligation = decoded.value().obligations.front();
  CSP_EXPECT(obligation.outcome == Tri::Satisfied);
  CSP_EXPECT_EQ(obligation.placements.size(), std::size_t{2});
  CSP_EXPECT_EQ(obligation.placements.front().capacity.references.size(), std::size_t{2});
  CSP_EXPECT_EQ(obligation.placements.front().capacity.evidenced_total.units(), std::int64_t{15});
  CSP_EXPECT(obligation.placements.front().capacity.includes_offers);
  CSP_EXPECT_EQ(obligation.placements.front().domains.size(), std::size_t{2});
  CSP_EXPECT(obligation.placements.front().jurisdiction == id_of<JurisdictionId>("region-eu"));
  CSP_REQUIRE(obligation.placements.size() == 2);
  CSP_EXPECT(obligation.placements[1].role == PlacementRole::Recovery);
  CSP_REQUIRE(obligation.placements[1].domains.size() == 1);
  CSP_EXPECT(!obligation.placements[1].domains.front().kind.has_value());
  CSP_REQUIRE(obligation.latency.size() == 1);
  CSP_EXPECT(obligation.latency.front().derived);
  CSP_EXPECT(obligation.latency.front().statistic == LatencyStatistic::Max);
  CSP_EXPECT_EQ(obligation.latency.front().measured.nanos(), std::int64_t{2000000});
  CSP_EXPECT_EQ(obligation.latency.front().chain.size(), std::size_t{2});
  CSP_REQUIRE(decoded.value().trace.size() == 1);
  CSP_EXPECT_EQ(decoded.value().trace.front().evidence.size(), std::size_t{2});
  CSP_EXPECT(!decoded.value().trace.front().evidence.front().document_digest.is_zero());
  CSP_EXPECT(!decoded.value().trace.front().evidence[1].record.valid());
  CSP_REQUIRE(decoded.value().residual.size() == 1);
  CSP_EXPECT_EQ(decoded.value().residual.front().shortfall.units(), std::int64_t{2});
  CSP_REQUIRE(decoded.value().tie_breaks.size() == 1);
  CSP_EXPECT(decoded.value().tie_breaks.front().applied == Tri::Indeterminate);
  CSP_EXPECT_EQ(decoded.value().tie_breaks.front().ordered.size(), std::size_t{2});
  CSP_EXPECT_EQ(decoded.value().envelope.revalidate_when.size(), std::size_t{2});
  CSP_EXPECT(!decoded.value().refusal.has_value());

  // A refused plan round trips too, with its refusal and its empty expiry claim.
  const PlacementPlan refused = sample_refused_plan();
  const Result<std::string> refused_document = plan_to_document(refused, false);
  CSP_REQUIRE(refused_document.has_value());
  const Result<PlacementPlan> refused_decoded = plan_from_document(refused_document.value(), limits);
  CSP_REQUIRE(refused_decoded.has_value());
  CSP_EXPECT(refused_decoded.value().digest == refused.digest);
  CSP_EXPECT(refused_decoded.value().outcome == PlanOutcome::Refused);
  CSP_REQUIRE(refused_decoded.value().refusal.has_value());
  CSP_EXPECT(refused_decoded.value().refusal->category == ErrorCategory::Invalid);
  CSP_EXPECT_EQ(refused_decoded.value().refusal->code, std::string("csp.plan.no-arrangement"));
  CSP_EXPECT_EQ(refused_decoded.value().refusal->evidence.size(), std::size_t{1});
  CSP_EXPECT(refused_decoded.value().envelope.valid_until.is_zero());
  CSP_EXPECT(!plan_is_applicable(refused_decoded.value()));

  // The pretty form decodes to the same plan.
  const Result<std::string> pretty = plan_to_document(original, true);
  CSP_REQUIRE(pretty.has_value());
  const Result<PlacementPlan> from_pretty = plan_from_document(pretty.value(), limits);
  CSP_REQUIRE(from_pretty.has_value());
  CSP_EXPECT(from_pretty.value().digest == original.digest);
}

CSP_TEST(documents, plan_document_altered_by_one_byte_is_refused_as_integrity) {
  const Limits limits;
  const PlacementPlan original = sample_plan();
  const Result<std::string> canonical = plan_to_document(original, false);
  CSP_REQUIRE(canonical.has_value());

  const std::string altered = replace_once(canonical.value(), R"("nodes_explored":17)",
                                           R"("nodes_explored":18)");
  CSP_EXPECT(altered != canonical.value());
  const Result<PlacementPlan> decoded = plan_from_document(altered, limits);
  CSP_EXPECT_MSG(!decoded.has_value(), "a plan whose payload was altered by one byte decoded");
  if (!decoded.has_value()) {
    CSP_EXPECT(decoded.error().category() == ErrorCategory::Integrity);
    CSP_EXPECT_EQ(decoded.error().code(), std::string("csp.doc.digest_mismatch"));
  }

  // Flipping one hexadecimal digit of the digest is the same refusal.
  const std::string digest_hex = original.digest.to_hex();
  const char first = digest_hex.front();
  const std::string flipped(1, first == '0' ? '1' : '0');
  const std::string wrong_digest =
      replace_once(canonical.value(), R"("digest":")" + digest_hex, R"("digest":")" + flipped + digest_hex.substr(1));
  const Result<PlacementPlan> from_wrong_digest = plan_from_document(wrong_digest, limits);
  CSP_EXPECT(!from_wrong_digest.has_value());
  if (!from_wrong_digest.has_value()) {
    CSP_EXPECT(from_wrong_digest.error().category() == ErrorCategory::Integrity);
    CSP_EXPECT_EQ(from_wrong_digest.error().code(), std::string("csp.doc.digest_mismatch"));
  }
}

CSP_TEST(documents, plan_canonical_bytes_excludes_identity_and_digest) {
  const PlacementPlan original = sample_plan();
  const Result<std::string> canonical = plan_canonical_bytes(original);
  CSP_REQUIRE(canonical.has_value());
  const Result<std::string> canonical_again = plan_canonical_bytes(original);
  CSP_REQUIRE(canonical_again.has_value());
  CSP_EXPECT_EQ(canonical.value(), canonical_again.value());

  const Result<std::string> document = plan_to_document(original, false);
  CSP_REQUIRE(document.has_value());
  CSP_EXPECT(canonical.value() != document.value());
  // The identity-bearing document names the plan; the digest input does not.
  CSP_EXPECT(document.value().find(original.plan.value()) != std::string::npos);
  CSP_EXPECT(canonical.value().find(original.plan.value()) == std::string::npos);

  PlacementPlan changed = original;
  changed.plan = id_of<PlanId>("plan-0123456789abcdef0123456789abcdef");
  changed.digest = Digest::of("a digest that does not describe this plan");
  const Result<std::string> canonical_after = plan_canonical_bytes(changed);
  CSP_REQUIRE(canonical_after.has_value());
  CSP_EXPECT_EQ(canonical_after.value(), canonical.value());
  CSP_EXPECT(canonical_after.value().find(changed.plan.value()) == std::string::npos);
  // Changing either field alone changes the identity-bearing document.
  const Result<std::string> changed_document = plan_to_document(changed, false);
  CSP_REQUIRE(changed_document.has_value());
  CSP_EXPECT(changed_document.value() != document.value());

  // Sealing is a pure function of the content: clearing both fields and sealing again
  // restores the same digest and the same identity.
  PlacementPlan resealed = changed;
  plan_seal(resealed);
  CSP_EXPECT(resealed.digest == original.digest);
  CSP_EXPECT(resealed.plan == original.plan);
}

CSP_TEST(documents, plan_validate_refuses_structural_defects) {
  const Limits limits;
  const PlacementPlan baseline = sample_plan();
  CSP_EXPECT_OK(plan_validate(baseline, limits));

  // An obligation reported as placed with no placement to show for it.
  PlacementPlan empty_placement = baseline;
  empty_placement.obligations.front().placements.clear();
  EXPECT_FAILURE(plan_validate(empty_placement, limits), ErrorCategory::Invalid,
                 "csp.plan.empty_placement");

  // Two obligations whose identities are not strictly increasing.
  PlacementPlan unordered = baseline;
  ObligationPlacement earlier = baseline.obligations.front();
  earlier.obligation = id_of<ObligationId>("obligation-0");
  unordered.obligations.push_back(earlier);
  EXPECT_FAILURE(plan_validate(unordered, limits), ErrorCategory::Invalid, "csp.plan.obligation_order");

  // The same identity twice is not an ordering defect but a duplicate.
  PlacementPlan duplicated_obligation = baseline;
  duplicated_obligation.obligations.push_back(baseline.obligations.front());
  EXPECT_FAILURE(plan_validate(duplicated_obligation, limits), ErrorCategory::Invalid,
                 "csp.plan.obligation_order");

  // Two placements of one role on one site.
  PlacementPlan duplicate_site = baseline;
  SitePlacement second_primary = baseline.obligations.front().placements.front();
  second_primary.index = 1;
  duplicate_site.obligations.front().placements.push_back(second_primary);
  EXPECT_FAILURE(plan_validate(duplicate_site, limits), ErrorCategory::Conflict, "csp.plan.duplicate_site");

  // Indices that skip a number.
  PlacementPlan sparse_indices = baseline;
  SitePlacement third = baseline.obligations.front().placements.front();
  third.site = id_of<SiteId>("site-c");
  third.index = 2;
  sparse_indices.obligations.front().placements.push_back(third);
  EXPECT_FAILURE(plan_validate(sparse_indices, limits), ErrorCategory::Invalid,
                 "csp.plan.placement_index");

  // Not planned and carrying no refusal.
  PlacementPlan no_refusal = baseline;
  no_refusal.outcome = PlanOutcome::Indeterminate;
  no_refusal.refusal.reset();
  EXPECT_FAILURE(plan_validate(no_refusal, limits), ErrorCategory::Invalid, "csp.plan.refusal_missing");

  // Planned and carrying one.
  PlacementPlan refusal_with_plan = baseline;
  Refusal refusal;
  refusal.category = ErrorCategory::Indeterminate;
  refusal.code = "csp.plan.undecided";
  refusal.detail = "two things stated at once";
  refusal_with_plan.refusal = refusal;
  EXPECT_FAILURE(plan_validate(refusal_with_plan, limits), ErrorCategory::Invalid,
                 "csp.plan.refusal_present");

  // A plan with no request generation, and one with no revalidation condition.
  PlacementPlan no_generation = baseline;
  no_generation.request_generation = Generation::from_value(0);
  EXPECT_FAILURE(plan_validate(no_generation, limits), ErrorCategory::Invalid,
                 "csp.plan.missing_generation");
  PlacementPlan no_revalidation = baseline;
  no_revalidation.envelope.revalidate_when.clear();
  EXPECT_FAILURE(plan_validate(no_revalidation, limits), ErrorCategory::Invalid,
                 "csp.plan.no_revalidation_conditions");
}
