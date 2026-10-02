// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "cross_site_placement/evidence.hpp"

#include <algorithm>
#include <array>
#include <numeric>
#include <string>

namespace csp {
namespace {

template <class Enum, std::size_t N>
std::optional<Enum> lookup(const std::array<std::pair<Enum, const char*>, N>& table, std::string_view token) {
  for (const auto& entry : table) {
    if (token == entry.second) {
      return entry.first;
    }
  }
  return std::nullopt;
}

constexpr std::array<std::pair<DomainKind, const char*>, 7> kDomainKinds{{
    {DomainKind::Power, "power"},
    {DomainKind::Cooling, "cooling"},
    {DomainKind::Network, "network"},
    {DomainKind::Geography, "geography"},
    {DomainKind::Administrative, "administrative"},
    {DomainKind::Physical, "physical"},
    {DomainKind::Security, "security"},
}};

constexpr std::array<std::pair<MaintenanceState, const char*>, 5> kMaintenanceStates{{
    {MaintenanceState::Operational, "operational"},
    {MaintenanceState::Degraded, "degraded"},
    {MaintenanceState::Maintenance, "maintenance"},
    {MaintenanceState::Draining, "draining"},
    {MaintenanceState::Offline, "offline"},
}};

constexpr std::array<std::pair<CapacityKind, const char*>, 2> kCapacityKinds{{
    {CapacityKind::Offer, "offer"},
    {CapacityKind::Commitment, "commitment"},
}};

constexpr std::array<std::pair<LatencyStatistic, const char*>, 4> kLatencyStatistics{{
    {LatencyStatistic::P50, "p50"},
    {LatencyStatistic::P95, "p95"},
    {LatencyStatistic::P99, "p99"},
    {LatencyStatistic::Max, "max"},
}};

/// Sorts indices by a caller-supplied key and reports the first adjacent pair that
/// shares one. Duplicate identities are a conflict rather than a merge: two records
/// under one identity that disagree are exactly the case where keeping either would be
/// inventing a fact.
template <class Key>
Status require_unique(std::size_t count, const Key& key, const char* kind) {
  if (count < 2) {
    return success();
  }
  std::vector<std::size_t> order(count);
  std::iota(order.begin(), order.end(), std::size_t{0});
  std::stable_sort(order.begin(), order.end(),
                   [&key](std::size_t lhs, std::size_t rhs) { return key(lhs) < key(rhs); });
  for (std::size_t index = 1; index < order.size(); ++index) {
    if (key(order[index - 1]) == key(order[index])) {
      std::string message = "duplicate ";
      message += kind;
      message += " identity ";
      message += std::string(key(order[index]).view());
      message += " appears more than once; this boundary does not choose between two readings of one identity";
      return fail(ErrorCategory::Conflict, "csp.evidence.duplicate_identity", std::move(message));
    }
  }
  return success();
}

template <class IdType>
Status require_valid_id(const IdType& id, const char* kind) {
  if (!id.valid()) {
    std::string message = kind;
    message += " identity is absent where the evidence requires one";
    return fail(ErrorCategory::Invalid, "csp.evidence.missing_identity", std::move(message));
  }
  return success();
}

Status require_non_negative(const Measurement<Quantity>& measurement, const char* kind) {
  if (measurement.is_known() && measurement.value().is_negative()) {
    std::string message = kind;
    message += " is negative; a capacity reading that is below zero describes no capacity that exists";
    return fail(ErrorCategory::OutOfRange, "csp.evidence.negative_capacity", std::move(message));
  }
  return success();
}

Status require_non_negative(const Measurement<Duration>& measurement, const char* kind) {
  if (measurement.is_known() && measurement.value().is_negative()) {
    std::string message = kind;
    message += " is negative; a time that runs backwards is not a measurement";
    return fail(ErrorCategory::OutOfRange, "csp.evidence.negative_duration", std::move(message));
  }
  return success();
}

template <class Collection>
Status require_size(const Collection& collection, std::size_t bound, const char* kind) {
  if (collection.size() > bound) {
    std::string message = "evidence carries ";
    message += std::to_string(collection.size());
    message += " ";
    message += kind;
    message += " records, above the configured bound of ";
    message += std::to_string(bound);
    return fail(ErrorCategory::BoundExceeded, "csp.evidence.bound_exceeded", std::move(message));
  }
  return success();
}

}  // namespace

const char* to_string(DomainKind kind) noexcept {
  switch (kind) {
    case DomainKind::Power: return "power";
    case DomainKind::Cooling: return "cooling";
    case DomainKind::Network: return "network";
    case DomainKind::Geography: return "geography";
    case DomainKind::Administrative: return "administrative";
    case DomainKind::Physical: return "physical";
    case DomainKind::Security: return "security";
  }
  return "unknown";
}

const char* to_string(MaintenanceState state) noexcept {
  switch (state) {
    case MaintenanceState::Operational: return "operational";
    case MaintenanceState::Degraded: return "degraded";
    case MaintenanceState::Maintenance: return "maintenance";
    case MaintenanceState::Draining: return "draining";
    case MaintenanceState::Offline: return "offline";
  }
  return "unknown";
}

const char* to_string(CapacityKind kind) noexcept {
  return kind == CapacityKind::Commitment ? "commitment" : "offer";
}

const char* to_string(LatencyStatistic statistic) noexcept {
  switch (statistic) {
    case LatencyStatistic::P50: return "p50";
    case LatencyStatistic::P95: return "p95";
    case LatencyStatistic::P99: return "p99";
    case LatencyStatistic::Max: return "max";
  }
  return "unknown";
}

std::optional<DomainKind> domain_kind_from_string(std::string_view token) noexcept {
  return lookup(kDomainKinds, token);
}
std::optional<MaintenanceState> maintenance_state_from_string(std::string_view token) noexcept {
  return lookup(kMaintenanceStates, token);
}
std::optional<CapacityKind> capacity_kind_from_string(std::string_view token) noexcept {
  return lookup(kCapacityKinds, token);
}
std::optional<LatencyStatistic> latency_statistic_from_string(std::string_view token) noexcept {
  return lookup(kLatencyStatistics, token);
}

bool provenance_has_time(const Provenance& provenance) noexcept {
  return !provenance.observed_at.is_zero();
}

Result<Duration> provenance_age(const Provenance& provenance, Instant evaluation_instant, const Limits& limits) {
  if (!provenance_has_time(provenance)) {
    return fail(ErrorCategory::Stale, "csp.evidence.no_observation_time",
                "the record carries no observation time, so it cannot be shown to describe the present");
  }
  if (provenance.observed_at > evaluation_instant) {
    const Result<Duration> skew = elapsed(evaluation_instant, provenance.observed_at);
    if (!skew) {
      return skew.error();
    }
    if (skew.value().nanos() > limits.max_clock_skew_nanos) {
      return fail(ErrorCategory::Stale, "csp.evidence.future_observation",
                  "the observation is dated after the evaluation instant by more than the allowed clock skew");
    }
    return Duration::from_nanos(0);
  }
  return elapsed(provenance.observed_at, evaluation_instant);
}

Status snapshot_validate(const SiteEvidenceSnapshot& snapshot, const Limits& limits) {
  Status status = require_size(snapshot.sites, limits.max_sites, "site");
  if (!status) return status;
  status = require_size(snapshot.failure_domains, limits.max_failure_domains, "failure-domain");
  if (!status) return status;
  status = require_size(snapshot.domain_assignments, limits.max_domain_assignments, "domain-assignment");
  if (!status) return status;
  status = require_size(snapshot.domain_aliases, limits.max_domain_aliases, "domain-alias");
  if (!status) return status;
  status = require_size(snapshot.capacity, limits.max_capacity_evidence, "capacity");
  if (!status) return status;
  status = require_size(snapshot.latency, limits.max_latency_evidence, "latency");
  if (!status) return status;
  status = require_size(snapshot.recovery, limits.max_recovery_evidence, "recovery");
  if (!status) return status;
  status = require_size(snapshot.compatibility, limits.max_compatibility_evidence, "compatibility");
  if (!status) return status;
  status = require_size(snapshot.cost_risk, limits.max_cost_risk_evidence, "cost-risk");
  if (!status) return status;

  for (const SiteRecord& site : snapshot.sites) {
    status = require_valid_id(site.site, "site");
    if (!status) return status;
  }
  status = require_unique(
      snapshot.sites.size(), [&snapshot](std::size_t index) { return snapshot.sites[index].site; }, "site");
  if (!status) return status;

  for (const FailureDomainRecord& domain : snapshot.failure_domains) {
    status = require_valid_id(domain.domain, "failure-domain");
    if (!status) return status;
    if (domain.parent.has_value()) {
      status = require_valid_id(*domain.parent, "failure-domain parent");
      if (!status) return status;
      if (*domain.parent == domain.domain) {
        return fail(ErrorCategory::Invalid, "csp.evidence.self_parent",
                    "failure domain " + domain.domain.value() + " lists itself as its own container");
      }
    }
  }
  status = require_unique(
      snapshot.failure_domains.size(),
      [&snapshot](std::size_t index) { return snapshot.failure_domains[index].domain; }, "failure-domain");
  if (!status) return status;

  for (const DomainAssignment& assignment : snapshot.domain_assignments) {
    status = require_valid_id(assignment.site, "domain-assignment site");
    if (!status) return status;
    status = require_valid_id(assignment.domain, "domain-assignment domain");
    if (!status) return status;
  }

  for (const DomainAliasRecord& alias : snapshot.domain_aliases) {
    status = require_valid_id(alias.domain, "domain-alias domain");
    if (!status) return status;
    status = require_valid_id(alias.alias_of, "domain-alias target");
    if (!status) return status;
    if (alias.domain == alias.alias_of) {
      return fail(ErrorCategory::Invalid, "csp.evidence.self_alias",
                  "failure domain " + alias.domain.value() + " is aliased to itself, which asserts nothing");
    }
  }

  for (const CapacityRecord& record : snapshot.capacity) {
    status = require_valid_id(record.reference, "capacity reference");
    if (!status) return status;
    status = require_valid_id(record.site, "capacity site");
    if (!status) return status;
    status = require_valid_id(record.service_class, "capacity service class");
    if (!status) return status;
    status = require_non_negative(record.available, "reported capacity");
    if (!status) return status;
  }
  status = require_unique(
      snapshot.capacity.size(),
      [&snapshot](std::size_t index) { return snapshot.capacity[index].reference; }, "capacity reference");
  if (!status) return status;

  for (const LatencyRecord& record : snapshot.latency) {
    status = require_valid_id(record.reference, "latency reference");
    if (!status) return status;
    status = require_valid_id(record.from_site, "latency source site");
    if (!status) return status;
    status = require_valid_id(record.to_site, "latency target site");
    if (!status) return status;
    status = require_non_negative(record.latency, "reported latency");
    if (!status) return status;
  }
  status = require_unique(
      snapshot.latency.size(),
      [&snapshot](std::size_t index) { return snapshot.latency[index].reference; }, "latency reference");
  if (!status) return status;

  for (const RecoveryRecord& record : snapshot.recovery) {
    status = require_valid_id(record.reference, "recovery reference");
    if (!status) return status;
    status = require_valid_id(record.site, "recovery site");
    if (!status) return status;
    status = require_valid_id(record.service_class, "recovery service class");
    if (!status) return status;
    status = require_non_negative(record.achievable_rto, "achievable recovery time objective");
    if (!status) return status;
    status = require_non_negative(record.achievable_rpo, "achievable recovery point objective");
    if (!status) return status;
  }
  status = require_unique(
      snapshot.recovery.size(),
      [&snapshot](std::size_t index) { return snapshot.recovery[index].reference; }, "recovery reference");
  if (!status) return status;

  for (const CompatibilityRecord& record : snapshot.compatibility) {
    status = require_valid_id(record.reference, "compatibility reference");
    if (!status) return status;
    status = require_valid_id(record.site, "compatibility site");
    if (!status) return status;
    status = require_valid_id(record.service_class, "compatibility service class");
    if (!status) return status;
  }
  status = require_unique(
      snapshot.compatibility.size(),
      [&snapshot](std::size_t index) { return snapshot.compatibility[index].reference; },
      "compatibility reference");
  if (!status) return status;

  for (const CostRiskRecord& record : snapshot.cost_risk) {
    status = require_valid_id(record.reference, "cost-risk reference");
    if (!status) return status;
    status = require_valid_id(record.site, "cost-risk site");
    if (!status) return status;
    status = require_non_negative(record.cost_per_unit, "reported cost");
    if (!status) return status;
    if (record.risk_per_mille.is_known() &&
        (record.risk_per_mille.value() < 0 || record.risk_per_mille.value() > 1000)) {
      return fail(ErrorCategory::OutOfRange, "csp.evidence.risk_range",
                  "risk is reported in parts per thousand and must lie between 0 and 1000");
    }
  }
  status = require_unique(
      snapshot.cost_risk.size(),
      [&snapshot](std::size_t index) { return snapshot.cost_risk[index].reference; }, "cost-risk reference");
  if (!status) return status;

  return success();
}

}  // namespace csp
