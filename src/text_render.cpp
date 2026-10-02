// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The encoder.
//
// Every value this boundary exchanges has exactly one textual form. The form is produced
// by the code below and by nothing else, which is what makes the digest meaningful: a
// reader can re-encode a plan it decoded and get the same bytes, and a caller can hash
// those bytes with an entirely different implementation and get the same digest.
//
// Optional fields are omitted rather than written as null. An absent required field is a
// defect in the document, and an absent optional field is an absent fact; writing null
// for both would collapse that difference at the first hop.

#include "cross_site_placement/text.hpp"

#include <string>
#include <utility>
#include <vector>

#include "cross_site_placement/version.hpp"
#include "json.hpp"

namespace csp {
namespace {

using detail::JsonValue;

JsonValue string_value(const std::string& text) { return JsonValue::make_string(text); }

template <class Tag>
JsonValue id_value(const Id<Tag>& id) {
  return JsonValue::make_string(id.value());
}

JsonValue integer(std::int64_t value) { return JsonValue::make_int(value); }
JsonValue unsigned_integer(std::uint64_t value) { return JsonValue::make_uint(value); }
JsonValue boolean(bool value) { return JsonValue::make_bool(value); }
JsonValue nanos(Instant instant) { return integer(instant.nanos()); }
JsonValue duration_value(Duration duration) { return integer(duration.nanos()); }
JsonValue units(Quantity quantity) { return integer(quantity.units()); }

template <class IdType>
JsonValue id_array(const std::vector<IdType>& ids) {
  std::vector<JsonValue> items;
  items.reserve(ids.size());
  for (const IdType& id : ids) {
    items.push_back(id_value(id));
  }
  return JsonValue::make_array(std::move(items));
}

template <class T, class ValueFn>
JsonValue measurement_value(const Measurement<T>& measurement, ValueFn value_fn) {
  JsonValue object = JsonValue::make_object();
  object.set("state", string_value(to_string(measurement.state())));
  if (measurement.is_known()) {
    object.set("value", value_fn(measurement.value()));
  }
  return object;
}

JsonValue render_provenance(const Provenance& provenance) {
  JsonValue object = JsonValue::make_object();
  if (provenance.source_record.valid()) {
    object.set("source_record", id_value(provenance.source_record));
  }
  if (provenance.authority.valid()) {
    object.set("authority", id_value(provenance.authority));
  }
  object.set("authority_generation", unsigned_integer(provenance.authority_generation.value()));
  object.set("observed_at", nanos(provenance.observed_at));
  if (provenance.expires_at.has_value()) {
    object.set("expires_at", nanos(*provenance.expires_at));
  }
  if (!provenance.document_digest.is_zero()) {
    object.set("document_digest", string_value(provenance.document_digest.to_hex()));
  }
  return object;
}

JsonValue render_request(const PlacementRequest& request) {
  JsonValue object = JsonValue::make_object();
  object.set("format", integer(kDocumentFormatVersion));
  object.set("kind", string_value("request"));
  object.set("request", id_value(request.request));
  object.set("generation", unsigned_integer(request.generation.value()));

  JsonValue policy = JsonValue::make_object();
  policy.set("policy", id_value(request.policy.policy));
  policy.set("generation", unsigned_integer(request.policy.generation.value()));
  object.set("policy", std::move(policy));

  object.set("allowed_sites", id_array(request.allowed_sites));
  object.set("forbidden_sites", id_array(request.forbidden_sites));

  JsonValue preferences = JsonValue::make_object();
  std::vector<JsonValue> objectives;
  objectives.reserve(request.preferences.objectives.size());
  for (const Preferences::Objective objective : request.preferences.objectives) {
    objectives.push_back(string_value(to_string(objective)));
  }
  preferences.set("objectives", JsonValue::make_array(std::move(objectives)));
  object.set("preferences", std::move(preferences));

  JsonValue freshness = JsonValue::make_object();
  freshness.set("max_evidence_age_nanos", integer(request.freshness.max_evidence_age_nanos));
  freshness.set("require_observation_time", boolean(request.freshness.require_observation_time));
  object.set("freshness", std::move(freshness));

  JsonValue validity = JsonValue::make_object();
  validity.set("validity_nanos", integer(request.validity.validity_nanos));
  object.set("validity", std::move(validity));

  std::vector<JsonValue> obligations;
  obligations.reserve(request.obligations.size());
  for (const Obligation& obligation : request.obligations) {
    JsonValue item = JsonValue::make_object();
    item.set("obligation", id_value(obligation.obligation));
    item.set("service_class", id_value(obligation.service_class));
    item.set("required_capacity", units(obligation.required_capacity));
    item.set("primary_placements", unsigned_integer(obligation.primary_placements));
    item.set("recovery_placements", unsigned_integer(obligation.recovery_placements));
    if (obligation.required_rto.has_value()) {
      item.set("required_rto", duration_value(*obligation.required_rto));
    }
    if (obligation.required_rpo.has_value()) {
      item.set("required_rpo", duration_value(*obligation.required_rpo));
    }
    item.set("allowed_jurisdictions", id_array(obligation.allowed_jurisdictions));
    item.set("allowed_sites", id_array(obligation.allowed_sites));
    item.set("forbidden_sites", id_array(obligation.forbidden_sites));
    item.set("allow_colocation", boolean(obligation.allow_colocation));

    std::vector<JsonValue> separations;
    separations.reserve(obligation.separations.size());
    for (const SeparationRequirement& separation : obligation.separations) {
      JsonValue entry = JsonValue::make_object();
      entry.set("group", string_value(to_string(separation.group)));
      std::vector<JsonValue> kinds;
      kinds.reserve(separation.separated_kinds.size());
      for (const DomainKind kind : separation.separated_kinds) {
        kinds.push_back(string_value(to_string(kind)));
      }
      entry.set("separated_kinds", JsonValue::make_array(std::move(kinds)));
      entry.set("forbidden_shared_domains", id_array(separation.forbidden_shared_domains));
      separations.push_back(std::move(entry));
    }
    item.set("separations", JsonValue::make_array(std::move(separations)));

    std::vector<JsonValue> latencies;
    latencies.reserve(obligation.latency_requirements.size());
    for (const LatencyRequirement& requirement : obligation.latency_requirements) {
      JsonValue entry = JsonValue::make_object();
      JsonValue peer = JsonValue::make_object();
      peer.set("kind", string_value(requirement.peer.kind == DependencyEndpoint::Kind::Obligation
                                       ? "obligation"
                                       : "site-service"));
      if (requirement.peer.kind == DependencyEndpoint::Kind::Obligation) {
        peer.set("obligation", id_value(requirement.peer.obligation));
      } else {
        peer.set("site", id_value(requirement.peer.site));
        peer.set("service_class", id_value(requirement.peer.service_class));
      }
      entry.set("peer", std::move(peer));
      entry.set("direction", string_value(to_string(requirement.direction)));
      entry.set("statistic", string_value(to_string(requirement.statistic)));
      entry.set("max_latency", duration_value(requirement.max_latency));
      entry.set("applies_to", string_value(to_string(requirement.applies_to)));
      latencies.push_back(std::move(entry));
    }
    item.set("latency_requirements", JsonValue::make_array(std::move(latencies)));
    obligations.push_back(std::move(item));
  }
  object.set("obligations", JsonValue::make_array(std::move(obligations)));
  return object;
}

JsonValue render_snapshot(const SiteEvidenceSnapshot& snapshot) {
  JsonValue object = JsonValue::make_object();
  object.set("format", integer(kDocumentFormatVersion));
  object.set("kind", string_value("snapshot"));
  object.set("generation", unsigned_integer(snapshot.generation.value()));
  object.set("captured_at", nanos(snapshot.captured_at));

  std::vector<JsonValue> sites;
  sites.reserve(snapshot.sites.size());
  for (const SiteRecord& site : snapshot.sites) {
    JsonValue item = JsonValue::make_object();
    item.set("site", id_value(site.site));
    if (site.jurisdiction.valid()) {
      item.set("jurisdiction", id_value(site.jurisdiction));
    }
    item.set("maintenance", measurement_value(site.maintenance, [](MaintenanceState state) {
                return string_value(to_string(state));
              }));
    item.set("provenance", render_provenance(site.provenance));
    sites.push_back(std::move(item));
  }
  object.set("sites", JsonValue::make_array(std::move(sites)));

  std::vector<JsonValue> domains;
  domains.reserve(snapshot.failure_domains.size());
  for (const FailureDomainRecord& domain : snapshot.failure_domains) {
    JsonValue item = JsonValue::make_object();
    item.set("domain", id_value(domain.domain));
    item.set("kind", string_value(to_string(domain.kind)));
    if (domain.parent.has_value()) {
      item.set("parent", id_value(*domain.parent));
    }
    item.set("provenance", render_provenance(domain.provenance));
    domains.push_back(std::move(item));
  }
  object.set("failure_domains", JsonValue::make_array(std::move(domains)));

  std::vector<JsonValue> assignments;
  assignments.reserve(snapshot.domain_assignments.size());
  for (const DomainAssignment& assignment : snapshot.domain_assignments) {
    JsonValue item = JsonValue::make_object();
    item.set("site", id_value(assignment.site));
    item.set("domain", id_value(assignment.domain));
    item.set("provenance", render_provenance(assignment.provenance));
    assignments.push_back(std::move(item));
  }
  object.set("domain_assignments", JsonValue::make_array(std::move(assignments)));

  std::vector<JsonValue> aliases;
  aliases.reserve(snapshot.domain_aliases.size());
  for (const DomainAliasRecord& alias : snapshot.domain_aliases) {
    JsonValue item = JsonValue::make_object();
    item.set("domain", id_value(alias.domain));
    item.set("alias_of", id_value(alias.alias_of));
    item.set("provenance", render_provenance(alias.provenance));
    aliases.push_back(std::move(item));
  }
  object.set("domain_aliases", JsonValue::make_array(std::move(aliases)));

  std::vector<JsonValue> capacity;
  capacity.reserve(snapshot.capacity.size());
  for (const CapacityRecord& record : snapshot.capacity) {
    JsonValue item = JsonValue::make_object();
    item.set("reference", id_value(record.reference));
    item.set("site", id_value(record.site));
    item.set("service_class", id_value(record.service_class));
    item.set("kind", string_value(to_string(record.kind)));
    item.set("available", measurement_value(record.available, units));
    item.set("provenance", render_provenance(record.provenance));
    capacity.push_back(std::move(item));
  }
  object.set("capacity", JsonValue::make_array(std::move(capacity)));

  std::vector<JsonValue> latencies;
  latencies.reserve(snapshot.latency.size());
  for (const LatencyRecord& record : snapshot.latency) {
    JsonValue item = JsonValue::make_object();
    item.set("reference", id_value(record.reference));
    item.set("from_site", id_value(record.from_site));
    item.set("to_site", id_value(record.to_site));
    item.set("statistic", string_value(to_string(record.statistic)));
    item.set("latency", measurement_value(record.latency, duration_value));
    item.set("provenance", render_provenance(record.provenance));
    latencies.push_back(std::move(item));
  }
  object.set("latency", JsonValue::make_array(std::move(latencies)));

  std::vector<JsonValue> recovery;
  recovery.reserve(snapshot.recovery.size());
  for (const RecoveryRecord& record : snapshot.recovery) {
    JsonValue item = JsonValue::make_object();
    item.set("reference", id_value(record.reference));
    item.set("site", id_value(record.site));
    item.set("service_class", id_value(record.service_class));
    item.set("can_host_recovery", measurement_value(record.can_host_recovery, boolean));
    item.set("achievable_rto", measurement_value(record.achievable_rto, duration_value));
    item.set("achievable_rpo", measurement_value(record.achievable_rpo, duration_value));
    item.set("provenance", render_provenance(record.provenance));
    recovery.push_back(std::move(item));
  }
  object.set("recovery", JsonValue::make_array(std::move(recovery)));

  std::vector<JsonValue> compatibility;
  compatibility.reserve(snapshot.compatibility.size());
  for (const CompatibilityRecord& record : snapshot.compatibility) {
    JsonValue item = JsonValue::make_object();
    item.set("reference", id_value(record.reference));
    item.set("site", id_value(record.site));
    item.set("service_class", id_value(record.service_class));
    item.set("compatible", measurement_value(record.compatible, boolean));
    item.set("provenance", render_provenance(record.provenance));
    compatibility.push_back(std::move(item));
  }
  object.set("compatibility", JsonValue::make_array(std::move(compatibility)));

  std::vector<JsonValue> cost_risk;
  cost_risk.reserve(snapshot.cost_risk.size());
  for (const CostRiskRecord& record : snapshot.cost_risk) {
    JsonValue item = JsonValue::make_object();
    item.set("reference", id_value(record.reference));
    item.set("site", id_value(record.site));
    if (record.service_class.valid()) {
      item.set("service_class", id_value(record.service_class));
    }
    item.set("cost_per_unit", measurement_value(record.cost_per_unit, units));
    item.set("risk_per_mille", measurement_value(record.risk_per_mille, integer));
    item.set("provenance", render_provenance(record.provenance));
    cost_risk.push_back(std::move(item));
  }
  object.set("cost_risk", JsonValue::make_array(std::move(cost_risk)));
  return object;
}

JsonValue render_policy(const PlacementPolicy& policy) {
  JsonValue object = JsonValue::make_object();
  object.set("format", integer(kDocumentFormatVersion));
  object.set("kind", string_value("policy"));
  object.set("policy", id_value(policy.policy));
  object.set("generation", unsigned_integer(policy.generation.value()));
  object.set("allow_degraded_sites", boolean(policy.allow_degraded_sites));
  object.set("allow_unknown_maintenance_state", boolean(policy.allow_unknown_maintenance_state));
  object.set("allow_unknown_jurisdiction", boolean(policy.allow_unknown_jurisdiction));
  object.set("allow_offer_capacity", boolean(policy.allow_offer_capacity));
  object.set("require_commitment_capacity", boolean(policy.require_commitment_capacity));
  object.set("allow_derived_latency_bounds", boolean(policy.allow_derived_latency_bounds));
  object.set("max_derived_hops", unsigned_integer(policy.max_derived_hops));
  object.set("allow_recovery_on_primary_site", boolean(policy.allow_recovery_on_primary_site));
  return object;
}

JsonValue render_evidence_ref(const EvidenceRef& ref) {
  JsonValue object = JsonValue::make_object();
  object.set("kind", string_value(ref.kind));
  if (ref.record.valid()) {
    object.set("record", id_value(ref.record));
  }
  if (ref.authority.valid()) {
    object.set("authority", id_value(ref.authority));
  }
  object.set("authority_generation", unsigned_integer(ref.authority_generation.value()));
  if (!ref.document_digest.is_zero()) {
    object.set("document_digest", string_value(ref.document_digest.to_hex()));
  }
  return object;
}

JsonValue render_plan(const PlacementPlan& plan, bool include_identity) {
  JsonValue object = JsonValue::make_object();
  object.set("format", integer(kDocumentFormatVersion));
  object.set("kind", string_value("plan"));
  if (include_identity) {
    object.set("plan", id_value(plan.plan));
  }
  object.set("outcome", string_value(to_string(plan.outcome)));
  object.set("request", id_value(plan.request));
  object.set("request_generation", unsigned_integer(plan.request_generation.value()));

  std::vector<JsonValue> obligations;
  obligations.reserve(plan.obligations.size());
  for (const ObligationPlacement& placement : plan.obligations) {
    JsonValue item = JsonValue::make_object();
    item.set("obligation", id_value(placement.obligation));
    item.set("outcome", string_value(to_string(placement.outcome)));
    item.set("refusal_code", string_value(placement.refusal_code));
    item.set("detail", string_value(placement.detail));

    std::vector<JsonValue> sites;
    sites.reserve(placement.placements.size());
    for (const SitePlacement& site : placement.placements) {
      JsonValue entry = JsonValue::make_object();
      entry.set("site", id_value(site.site));
      entry.set("role", string_value(to_string(site.role)));
      entry.set("index", unsigned_integer(site.index));
      entry.set("capacity_required", units(site.capacity_required));
      JsonValue basis = JsonValue::make_object();
      basis.set("references", id_array(site.capacity.references));
      basis.set("evidenced_total", units(site.capacity.evidenced_total));
      basis.set("includes_offers", boolean(site.capacity.includes_offers));
      entry.set("capacity", std::move(basis));
      std::vector<JsonValue> domains;
      domains.reserve(site.domains.size());
      for (const DomainRef& domain : site.domains) {
        JsonValue node = JsonValue::make_object();
        node.set("domain", id_value(domain.domain));
        if (domain.kind.has_value()) {
          node.set("kind", string_value(to_string(*domain.kind)));
        }
        node.set("depth", unsigned_integer(domain.depth));
        domains.push_back(std::move(node));
      }
      entry.set("domains", JsonValue::make_array(std::move(domains)));
      if (site.jurisdiction.valid()) {
        entry.set("jurisdiction", id_value(site.jurisdiction));
      }
      sites.push_back(std::move(entry));
    }
    item.set("placements", JsonValue::make_array(std::move(sites)));

    std::vector<JsonValue> latencies;
    latencies.reserve(placement.latency.size());
    for (const LatencyResolution& resolution : placement.latency) {
      JsonValue entry = JsonValue::make_object();
      entry.set("peer", string_value(resolution.peer));
      entry.set("direction", string_value(to_string(resolution.direction)));
      entry.set("statistic", string_value(to_string(resolution.statistic)));
      entry.set("measured", duration_value(resolution.measured));
      entry.set("derived", boolean(resolution.derived));
      std::vector<JsonValue> chain;
      chain.reserve(resolution.chain.size());
      for (const DependencyId& step : resolution.chain) {
        chain.push_back(id_value(step));
      }
      entry.set("chain", JsonValue::make_array(std::move(chain)));
      latencies.push_back(std::move(entry));
    }
    item.set("latency", JsonValue::make_array(std::move(latencies)));
    obligations.push_back(std::move(item));
  }
  object.set("obligations", JsonValue::make_array(std::move(obligations)));

  std::vector<JsonValue> trace;
  trace.reserve(plan.trace.size());
  for (const ConstraintTraceEntry& entry : plan.trace) {
    JsonValue item = JsonValue::make_object();
    item.set("rule", string_value(entry.rule));
    item.set("outcome", string_value(to_string(entry.outcome)));
    if (entry.obligation.has_value()) {
      item.set("obligation", id_value(*entry.obligation));
    }
    if (entry.site.has_value()) {
      item.set("site", id_value(*entry.site));
    }
    item.set("detail", string_value(entry.detail));
    std::vector<JsonValue> evidence;
    evidence.reserve(entry.evidence.size());
    for (const EvidenceRef& ref : entry.evidence) {
      evidence.push_back(render_evidence_ref(ref));
    }
    item.set("evidence", JsonValue::make_array(std::move(evidence)));
    trace.push_back(std::move(item));
  }
  object.set("trace", JsonValue::make_array(std::move(trace)));

  std::vector<JsonValue> residual;
  residual.reserve(plan.residual.size());
  for (const ResidualRequirement& requirement : plan.residual) {
    JsonValue item = JsonValue::make_object();
    item.set("obligation", id_value(requirement.obligation));
    item.set("requirement", string_value(requirement.requirement));
    item.set("shortfall", units(requirement.shortfall));
    item.set("placements_short", unsigned_integer(requirement.placements_short));
    item.set("detail", string_value(requirement.detail));
    residual.push_back(std::move(item));
  }
  object.set("residual", JsonValue::make_array(std::move(residual)));

  std::vector<JsonValue> tie_breaks;
  tie_breaks.reserve(plan.tie_breaks.size());
  for (const TieBreakRecord& record : plan.tie_breaks) {
    JsonValue item = JsonValue::make_object();
    item.set("criterion", string_value(record.criterion));
    item.set("applied", string_value(to_string(record.applied)));
    item.set("ordered", id_array(record.ordered));
    item.set("detail", string_value(record.detail));
    tie_breaks.push_back(std::move(item));
  }
  object.set("tie_breaks", JsonValue::make_array(std::move(tie_breaks)));

  if (plan.refusal.has_value()) {
    JsonValue refusal = JsonValue::make_object();
    refusal.set("category", string_value(to_string(plan.refusal->category)));
    refusal.set("code", string_value(plan.refusal->code));
    refusal.set("detail", string_value(plan.refusal->detail));
    std::vector<JsonValue> evidence;
    evidence.reserve(plan.refusal->evidence.size());
    for (const EvidenceRef& ref : plan.refusal->evidence) {
      evidence.push_back(render_evidence_ref(ref));
    }
    refusal.set("evidence", JsonValue::make_array(std::move(evidence)));
    object.set("refusal", std::move(refusal));
  }

  JsonValue envelope = JsonValue::make_object();
  envelope.set("evaluated_at", nanos(plan.envelope.evaluated_at));
  envelope.set("oldest_evidence_observed_at", nanos(plan.envelope.oldest_evidence_observed_at));
  envelope.set("evidence_generation", unsigned_integer(plan.envelope.evidence_generation.value()));
  envelope.set("policy_generation", unsigned_integer(plan.envelope.policy_generation.value()));
  envelope.set("request_generation", unsigned_integer(plan.envelope.request_generation.value()));
  envelope.set("valid_until", nanos(plan.envelope.valid_until));
  std::vector<JsonValue> conditions;
  conditions.reserve(plan.envelope.revalidate_when.size());
  for (const std::string& condition : plan.envelope.revalidate_when) {
    conditions.push_back(string_value(condition));
  }
  envelope.set("revalidate_when", JsonValue::make_array(std::move(conditions)));
  object.set("envelope", std::move(envelope));

  object.set("nodes_explored", unsigned_integer(plan.nodes_explored));
  object.set("search_exhausted", boolean(plan.search_exhausted));
  if (include_identity) {
    object.set("digest", string_value(plan.digest.to_hex()));
  }
  return object;
}

}  // namespace

Result<std::string> request_to_document(const PlacementRequest& request, bool pretty) {
  const JsonValue value = render_request(request);
  return pretty ? detail::json_write_pretty(value) : detail::json_write_canonical(value);
}

Result<std::string> snapshot_to_document(const SiteEvidenceSnapshot& snapshot, bool pretty) {
  const JsonValue value = render_snapshot(snapshot);
  return pretty ? detail::json_write_pretty(value) : detail::json_write_canonical(value);
}

Result<std::string> policy_to_document(const PlacementPolicy& policy, bool pretty) {
  const JsonValue value = render_policy(policy);
  return pretty ? detail::json_write_pretty(value) : detail::json_write_canonical(value);
}

Result<std::string> plan_to_document(const PlacementPlan& plan, bool pretty) {
  const JsonValue value = render_plan(plan, true);
  return pretty ? detail::json_write_pretty(value) : detail::json_write_canonical(value);
}

Result<std::string> plan_canonical_bytes(const PlacementPlan& plan) {
  return detail::json_write_canonical(render_plan(plan, false));
}

}  // namespace csp
