// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The decoder, and therefore the trust boundary of this boundary.
//
// Everything here assumes the input is hostile. Nothing is allocated before the count
// that would size it has been checked against both the configured bound and the bytes
// that remain. Every collection is bounded. Unknown fields are refused rather than
// ignored, because a field this build does not understand is a fact it would otherwise
// silently drop. Every failure is a structured error with a stable code; there is no
// partially decoded value and no exception.
//
// The document format version is checked before anything else is read, so a document
// from a newer format is refused as unsupported rather than half-understood.
//
// Two families of readers appear below. parse_* reads one value that has already been
// located; read_* locates a member of an object and then parses it, so that a missing
// required field is reported as missing rather than as having the wrong type.

#include "cross_site_placement/text.hpp"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cross_site_placement/version.hpp"
#include "json.hpp"

namespace csp {
namespace {

using detail::JsonValue;

// The alternative is three lines of status plumbing per field, which would triple the
// length of this file without making a single check clearer. The macro is confined to
// this translation unit and undefined at the end of it.
#define CSP_DETAIL_CONCAT_INNER(lhs, rhs) lhs##rhs
#define CSP_DETAIL_CONCAT(lhs, rhs) CSP_DETAIL_CONCAT_INNER(lhs, rhs)
#define CSP_TRY(expression, ...)                                                     \
  do {                                                                               \
    const Status CSP_DETAIL_CONCAT(csp_status_, __LINE__) = (expression);             \
    if (!CSP_DETAIL_CONCAT(csp_status_, __LINE__)) {                                  \
      return CSP_DETAIL_CONCAT(csp_status_, __LINE__).error();                        \
    }                                                                                \
  } while (false)

Status missing_field(std::string_view what, std::string_view key) {
  return fail(ErrorCategory::NotFound, "csp.doc.missing_field",
              std::string(what) + " has no " + std::string(key) + " field");
}

Status wrong_type(std::string_view what, std::string_view key, const char* expected) {
  return fail(ErrorCategory::Invalid, "csp.doc.field_type",
              std::string(what) + " field " + std::string(key) + " is not " + expected);
}

Status reject_unknown(const JsonValue& object, std::initializer_list<const char*> known, std::string_view what) {
  for (const auto& entry : object.members()) {
    bool found = false;
    for (const char* key : known) {
      if (entry.first == key) {
        found = true;
        break;
      }
    }
    if (!found) {
      return fail(ErrorCategory::Unsupported, "csp.doc.unknown_field",
                  std::string(what) + " carries the unknown field " + entry.first +
                      "; refusing rather than dropping a fact this build does not understand");
    }
  }
  return success();
}

Status locate(const JsonValue& object, const char* key, std::string_view what, const JsonValue*& out) {
  out = object.find(key);
  if (out == nullptr) {
    return missing_field(what, key);
  }
  return success();
}

Status parse_string(const JsonValue& value, std::string_view what, std::string& out) {
  if (!value.is_string()) {
    return fail(ErrorCategory::Invalid, "csp.doc.field_type", std::string(what) + " is not a string");
  }
  out = value.as_string();
  return success();
}

Status parse_int(const JsonValue& value, std::string_view what, std::int64_t& out) {
  const Result<std::int64_t> parsed = value.require_int();
  if (!parsed) {
    return fail(parsed.error().category(), parsed.error().code(),
                std::string(what) + ": " + parsed.error().message());
  }
  out = parsed.value();
  return success();
}

Status parse_uint(const JsonValue& value, std::string_view what, std::uint64_t& out) {
  const Result<std::uint64_t> parsed = value.require_uint();
  if (!parsed) {
    return fail(parsed.error().category(), parsed.error().code(),
                std::string(what) + ": " + parsed.error().message());
  }
  out = parsed.value();
  return success();
}

Status parse_bool(const JsonValue& value, std::string_view what, bool& out) {
  const Result<bool> parsed = value.require_bool();
  if (!parsed) {
    return fail(parsed.error().category(), parsed.error().code(),
                std::string(what) + ": " + parsed.error().message());
  }
  out = parsed.value();
  return success();
}

Status parse_instant(const JsonValue& value, std::string_view what, Instant& out) {
  std::int64_t nanos = 0;
  CSP_TRY(parse_int(value, what, nanos));
  out = Instant::from_nanos(nanos);
  return success();
}

Status parse_duration(const JsonValue& value, std::string_view what, Duration& out) {
  std::int64_t nanos = 0;
  CSP_TRY(parse_int(value, what, nanos));
  out = Duration::from_nanos(nanos);
  return success();
}

Status parse_quantity(const JsonValue& value, std::string_view what, Quantity& out) {
  std::int64_t units = 0;
  CSP_TRY(parse_int(value, what, units));
  out = Quantity::from_units(units);
  return success();
}

Status parse_tri(const JsonValue& value, std::string_view what, Tri& out) {
  std::string token;
  CSP_TRY(parse_string(value, what, token));
  const std::optional<Tri> parsed = tri_from_string(token);
  if (!parsed.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.doc.outcome", std::string(what) + " names no known outcome");
  }
  out = *parsed;
  return success();
}

Status parse_maintenance(const JsonValue& value, std::string_view what, MaintenanceState& out) {
  std::string token;
  CSP_TRY(parse_string(value, what, token));
  const std::optional<MaintenanceState> parsed = maintenance_state_from_string(token);
  if (!parsed.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.doc.maintenance_state",
                std::string(what) + " names no known maintenance state");
  }
  out = *parsed;
  return success();
}

Status parse_domain_kind(const JsonValue& value, std::string_view what, DomainKind& out) {
  std::string token;
  CSP_TRY(parse_string(value, what, token));
  const std::optional<DomainKind> parsed = domain_kind_from_string(token);
  if (!parsed.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.doc.domain_kind", std::string(what) + " names no known domain kind");
  }
  out = *parsed;
  return success();
}

Status parse_statistic(const JsonValue& value, std::string_view what, LatencyStatistic& out) {
  std::string token;
  CSP_TRY(parse_string(value, what, token));
  const std::optional<LatencyStatistic> parsed = latency_statistic_from_string(token);
  if (!parsed.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.doc.latency_statistic",
                std::string(what) + " names no known latency statistic");
  }
  out = *parsed;
  return success();
}

Status parse_digest(const JsonValue& value, std::string_view what, Digest& out) {
  std::string token;
  CSP_TRY(parse_string(value, what, token));
  Result<Digest> parsed = Digest::parse_hex(token);
  if (!parsed) {
    return fail(parsed.error().category(), parsed.error().code(), std::string(what) + ": " + parsed.error().message());
  }
  out = parsed.value();
  return success();
}

template <class IdType>
Status parse_id(const JsonValue& value, std::string_view what, IdType& out) {
  std::string text;
  CSP_TRY(parse_string(value, what, text));
  Result<IdType> parsed = IdType::parse(text);
  if (!parsed) {
    return fail(parsed.error().category(), parsed.error().code(),
                std::string(what) + ": " + parsed.error().message());
  }
  out = parsed.value();
  return success();
}

Status read_string(const JsonValue& object, const char* key, std::string_view what, std::string& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_string(*value, what, out);
}

Status read_int(const JsonValue& object, const char* key, std::string_view what, std::int64_t& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_int(*value, what, out);
}

Status read_uint(const JsonValue& object, const char* key, std::string_view what, std::uint64_t& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_uint(*value, what, out);
}

Status read_bool(const JsonValue& object, const char* key, std::string_view what, bool& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_bool(*value, what, out);
}

Status read_duration(const JsonValue& object, const char* key, std::string_view what, Duration& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_duration(*value, what, out);
}

Status read_quantity(const JsonValue& object, const char* key, std::string_view what, Quantity& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_quantity(*value, what, out);
}

Status read_statistic(const JsonValue& object, const char* key, std::string_view what, LatencyStatistic& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_statistic(*value, what, out);
}

Status read_domain_kind(const JsonValue& object, const char* key, std::string_view what, DomainKind& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_domain_kind(*value, what, out);
}

Status read_tri(const JsonValue& object, const char* key, std::string_view what, Tri& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_tri(*value, what, out);
}

template <class IdType>
Status read_id(const JsonValue& object, const char* key, std::string_view what, IdType& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_id<IdType>(*value, what, out);
}

template <class IdType>
Status read_optional_id(const JsonValue& object, const char* key, std::string_view what, IdType& out) {
  const JsonValue* value = object.find(key);
  if (value == nullptr) {
    return success();
  }
  return parse_id<IdType>(*value, what, out);
}

Status read_object(const JsonValue& object, const char* key, std::string_view what, const JsonValue*& out) {
  CSP_TRY(locate(object, key, what, out));
  if (!out->is_object()) {
    return wrong_type(what, key, "an object");
  }
  return success();
}

template <class T, class ValueReader>
Status parse_measurement(const JsonValue& value, std::string_view what, ValueReader read_value, Measurement<T>& out) {
  if (!value.is_object()) {
    return fail(ErrorCategory::Invalid, "csp.doc.field_type", std::string(what) + " is not an object");
  }
  CSP_TRY(reject_unknown(value, {"state", "value"}, what));
  const JsonValue* state_value = nullptr;
  CSP_TRY(locate(value, "state", what, state_value));
  std::string token;
  CSP_TRY(parse_string(*state_value, what, token));
  const std::optional<MeasurementState> state = measurement_state_from_string(token);
  if (!state.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.doc.measurement_state",
                std::string(what) + " names an unknown measurement state " + token);
  }
  const JsonValue* carried = value.find("value");
  if (*state != MeasurementState::Known) {
    if (carried != nullptr) {
      return fail(ErrorCategory::Invalid, "csp.doc.measurement_value",
                  std::string(what) + " carries a value while its state is " + token);
    }
    if (*state == MeasurementState::Unsupported) {
      out = Measurement<T>::unsupported();
    } else if (*state == MeasurementState::Unavailable) {
      out = Measurement<T>::unavailable();
    } else {
      out = Measurement<T>::unknown();
    }
    return success();
  }
  if (carried == nullptr) {
    return fail(ErrorCategory::Invalid, "csp.doc.measurement_value",
                std::string(what) + " is known but carries no value");
  }
  T parsed{};
  CSP_TRY(read_value(*carried, what, parsed));
  out = Measurement<T>::known(std::move(parsed));
  return success();
}

template <class T, class ValueReader>
Status read_measurement(const JsonValue& object, const char* key, std::string_view what, ValueReader read_value,
                        Measurement<T>& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  return parse_measurement<T>(*value, what, read_value, out);
}

template <class IdType>
Status read_id_array(const JsonValue& object, const char* key, std::string_view what, std::size_t bound,
                     std::vector<IdType>& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  if (!value->is_array()) {
    return wrong_type(what, key, "an array");
  }
  if (value->items().size() > bound) {
    return fail(ErrorCategory::BoundExceeded, "csp.doc.array_bound",
                std::string(what) + " field " + key + " carries " + std::to_string(value->items().size()) +
                    " entries, above the bound of " + std::to_string(bound));
  }
  out.clear();
  out.reserve(value->items().size());
  for (const JsonValue& item : value->items()) {
    IdType id;
    CSP_TRY(parse_id<IdType>(item, what, id));
    out.push_back(std::move(id));
  }
  return success();
}

template <class Entry, class EntryReader>
Status read_entries(const JsonValue& object, const char* key, std::string_view what, std::size_t bound,
                    EntryReader read_entry, std::vector<Entry>& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(locate(object, key, what, value));
  if (!value->is_array()) {
    return wrong_type(what, key, "an array");
  }
  if (value->items().size() > bound) {
    return fail(ErrorCategory::BoundExceeded, "csp.doc.array_bound",
                std::string(what) + " field " + key + " carries " + std::to_string(value->items().size()) +
                    " entries, above the bound of " + std::to_string(bound));
  }
  out.clear();
  out.reserve(value->items().size());
  for (const JsonValue& item : value->items()) {
    Entry entry{};
    CSP_TRY(read_entry(item, what, entry));
    out.push_back(std::move(entry));
  }
  return success();
}

Status read_header(const JsonValue& object, const char* expected_kind, std::string_view what) {
  if (!object.is_object()) {
    return fail(ErrorCategory::Invalid, "csp.doc.not_object", std::string(what) + " is not an object");
  }
  std::int64_t version = 0;
  CSP_TRY(read_int(object, "format", what, version));
  if (version < kMinReadableDocumentVersion || version > kMaxReadableDocumentVersion) {
    return fail(ErrorCategory::Unsupported, "csp.doc.format_version",
                std::string(what) + " declares document format " + std::to_string(version) +
                    ", which this build does not implement");
  }
  std::string token;
  CSP_TRY(read_string(object, "kind", what, token));
  if (token != expected_kind) {
    return fail(ErrorCategory::Invalid, "csp.doc.kind",
                std::string(what) + " declares kind " + token + " where " + expected_kind + " was expected");
  }
  return success();
}

Status read_provenance(const JsonValue& object, const char* key, std::string_view what, Provenance& out) {
  const JsonValue* value = nullptr;
  CSP_TRY(read_object(object, key, what, value));
  CSP_TRY(reject_unknown(*value,
                         {"source_record", "authority", "authority_generation", "observed_at", "expires_at",
                          "document_digest"},
                         what));
  CSP_TRY(read_optional_id<EvidenceId>(*value, "source_record", what, out.source_record));
  CSP_TRY(read_optional_id<AuthorityId>(*value, "authority", what, out.authority));
  std::uint64_t generation = 0;
  CSP_TRY(read_uint(*value, "authority_generation", what, generation));
  out.authority_generation = Generation::from_value(generation);
  std::int64_t observed = 0;
  CSP_TRY(read_int(*value, "observed_at", what, observed));
  out.observed_at = Instant::from_nanos(observed);
  const JsonValue* expires = value->find("expires_at");
  if (expires != nullptr) {
    Instant instant;
    CSP_TRY(parse_instant(*expires, what, instant));
    out.expires_at = instant;
  }
  const JsonValue* digest = value->find("document_digest");
  if (digest != nullptr) {
    Digest parsed;
    CSP_TRY(parse_digest(*digest, what, parsed));
    out.document_digest = parsed;
  }
  return success();
}

Status read_obligation(const JsonValue& item, const Limits& limits, Obligation& out) {
  const std::string_view what = "an obligation entry";
  CSP_TRY(reject_unknown(item,
                         {"obligation", "service_class", "required_capacity", "primary_placements",
                          "recovery_placements", "required_rto", "required_rpo", "allowed_jurisdictions",
                          "allowed_sites", "forbidden_sites", "allow_colocation", "separations",
                          "latency_requirements"},
                         what));
  CSP_TRY(read_id<ObligationId>(item, "obligation", what, out.obligation));
  CSP_TRY(read_id<ServiceClassId>(item, "service_class", what, out.service_class));
  CSP_TRY(read_quantity(item, "required_capacity", what, out.required_capacity));
  std::uint64_t primary = 0;
  CSP_TRY(read_uint(item, "primary_placements", what, primary));
  if (primary > limits.max_placements_per_obligation) {
    return fail(ErrorCategory::BoundExceeded, "csp.doc.placements_bound",
                "an obligation asks for more placements than the bound allows");
  }
  out.primary_placements = static_cast<std::uint32_t>(primary);
  std::uint64_t recovery = 0;
  CSP_TRY(read_uint(item, "recovery_placements", what, recovery));
  if (recovery > limits.max_placements_per_obligation) {
    return fail(ErrorCategory::BoundExceeded, "csp.doc.placements_bound",
                "an obligation asks for more placements than the bound allows");
  }
  out.recovery_placements = static_cast<std::uint32_t>(recovery);
  if (item.find("required_rto") != nullptr) {
    Duration window{};
    CSP_TRY(read_duration(item, "required_rto", what, window));
    out.required_rto = window;
  }
  if (item.find("required_rpo") != nullptr) {
    Duration window{};
    CSP_TRY(read_duration(item, "required_rpo", what, window));
    out.required_rpo = window;
  }
  CSP_TRY(read_id_array<JurisdictionId>(item, "allowed_jurisdictions", what, limits.max_jurisdiction_lists,
                                        out.allowed_jurisdictions));
  CSP_TRY(read_id_array<SiteId>(item, "allowed_sites", what, limits.max_site_lists, out.allowed_sites));
  CSP_TRY(read_id_array<SiteId>(item, "forbidden_sites", what, limits.max_site_lists, out.forbidden_sites));
  CSP_TRY(read_bool(item, "allow_colocation", what, out.allow_colocation));

  CSP_TRY(read_entries<SeparationRequirement>(
      item, "separations", what, limits.max_separation_requirements,
      [&limits](const JsonValue& entry, std::string_view, SeparationRequirement& requirement) -> Status {
        const std::string_view separation_what = "a separation requirement";
        CSP_TRY(reject_unknown(entry, {"group", "separated_kinds", "forbidden_shared_domains"}, separation_what));
        std::string group_token;
        CSP_TRY(read_string(entry, "group", separation_what, group_token));
        const std::optional<SeparationGroup> group = separation_group_from_string(group_token);
        if (!group.has_value()) {
          return fail(ErrorCategory::Invalid, "csp.doc.separation_group",
                      "a separation requirement names no known group");
        }
        requirement.group = *group;
        const JsonValue* kinds = nullptr;
        CSP_TRY(locate(entry, "separated_kinds", separation_what, kinds));
        if (!kinds->is_array()) {
          return wrong_type(separation_what, "separated_kinds", "an array");
        }
        if (kinds->items().size() > limits.max_separated_kinds) {
          return fail(ErrorCategory::BoundExceeded, "csp.doc.array_bound",
                      "a separation requirement names more kinds than the bound allows");
        }
        for (const JsonValue& kind : kinds->items()) {
          DomainKind parsed{};
          CSP_TRY(parse_domain_kind(kind, separation_what, parsed));
          requirement.separated_kinds.push_back(parsed);
        }
        return read_id_array<FailureDomainId>(entry, "forbidden_shared_domains", separation_what,
                                              limits.max_failure_domains, requirement.forbidden_shared_domains);
      },
      out.separations));

  return read_entries<LatencyRequirement>(
      item, "latency_requirements", what, limits.max_latency_requirements,
      [](const JsonValue& entry, std::string_view, LatencyRequirement& requirement) -> Status {
        const std::string_view latency_what = "a latency requirement";
        CSP_TRY(reject_unknown(entry, {"peer", "direction", "statistic", "max_latency", "applies_to"},
                               latency_what));
        const JsonValue* peer = nullptr;
        CSP_TRY(read_object(entry, "peer", latency_what, peer));
        CSP_TRY(reject_unknown(*peer, {"kind", "obligation", "site", "service_class"}, "a latency peer"));
        std::string kind_token;
        CSP_TRY(read_string(*peer, "kind", "a latency peer", kind_token));
        if (kind_token == "obligation") {
          requirement.peer.kind = DependencyEndpoint::Kind::Obligation;
          CSP_TRY(read_id<ObligationId>(*peer, "obligation", "a latency peer", requirement.peer.obligation));
        } else if (kind_token == "site-service") {
          requirement.peer.kind = DependencyEndpoint::Kind::SiteService;
          CSP_TRY(read_id<SiteId>(*peer, "site", "a latency peer", requirement.peer.site));
          CSP_TRY(read_id<ServiceClassId>(*peer, "service_class", "a latency peer",
                                          requirement.peer.service_class));
        } else {
          return fail(ErrorCategory::Invalid, "csp.doc.peer_kind",
                      "a latency peer names neither an obligation nor a site service");
        }
        std::string direction_token;
        CSP_TRY(read_string(entry, "direction", latency_what, direction_token));
        const std::optional<LatencyDirection> direction = latency_direction_from_string(direction_token);
        if (!direction.has_value()) {
          return fail(ErrorCategory::Invalid, "csp.doc.direction",
                      "a latency requirement names no known direction");
        }
        requirement.direction = *direction;
        CSP_TRY(read_statistic(entry, "statistic", latency_what, requirement.statistic));
        CSP_TRY(read_duration(entry, "max_latency", latency_what, requirement.max_latency));
        std::string applies_token;
        CSP_TRY(read_string(entry, "applies_to", latency_what, applies_token));
        const std::optional<PlacementRole> role = placement_role_from_string(applies_token);
        if (!role.has_value()) {
          return fail(ErrorCategory::Invalid, "csp.doc.role",
                      "a latency requirement applies to no known role");
        }
        requirement.applies_to = *role;
        return success();
      },
      out.latency_requirements);
}

Status read_request_document(const JsonValue& object, const Limits& limits, PlacementRequest& out) {
  const std::string_view what = "the request document";
  CSP_TRY(read_header(object, "request", what));
  CSP_TRY(reject_unknown(object,
                         {"format", "kind", "request", "generation", "policy", "allowed_sites", "forbidden_sites",
                          "preferences", "freshness", "validity", "obligations"},
                         what));
  CSP_TRY(read_id<RequestId>(object, "request", what, out.request));
  std::uint64_t generation = 0;
  CSP_TRY(read_uint(object, "generation", what, generation));
  out.generation = Generation::from_value(generation);

  const JsonValue* policy = nullptr;
  CSP_TRY(read_object(object, "policy", what, policy));
  CSP_TRY(reject_unknown(*policy, {"policy", "generation"}, "the request policy reference"));
  CSP_TRY(read_id<PolicyId>(*policy, "policy", "the request policy reference", out.policy.policy));
  std::uint64_t policy_generation = 0;
  CSP_TRY(read_uint(*policy, "generation", "the request policy reference", policy_generation));
  out.policy.generation = Generation::from_value(policy_generation);

  CSP_TRY(read_id_array<SiteId>(object, "allowed_sites", what, limits.max_site_lists, out.allowed_sites));
  CSP_TRY(read_id_array<SiteId>(object, "forbidden_sites", what, limits.max_site_lists, out.forbidden_sites));

  const JsonValue* preferences = nullptr;
  CSP_TRY(read_object(object, "preferences", what, preferences));
  CSP_TRY(reject_unknown(*preferences, {"objectives"}, "the request preferences"));
  const JsonValue* objectives = nullptr;
  CSP_TRY(locate(*preferences, "objectives", "the request preferences", objectives));
  if (!objectives->is_array()) {
    return wrong_type("the request preferences", "objectives", "an array");
  }
  for (const JsonValue& item : objectives->items()) {
    std::string token;
    CSP_TRY(parse_string(item, "a preference objective", token));
    const std::optional<Preferences::Objective> parsed = preference_objective_from_string(token);
    if (!parsed.has_value()) {
      return fail(ErrorCategory::Invalid, "csp.doc.preference",
                  "the request names no known preference objective " + token);
    }
    out.preferences.objectives.push_back(*parsed);
  }

  const JsonValue* freshness = nullptr;
  CSP_TRY(read_object(object, "freshness", what, freshness));
  CSP_TRY(reject_unknown(*freshness, {"max_evidence_age_nanos", "require_observation_time"},
                         "the request freshness policy"));
  CSP_TRY(read_int(*freshness, "max_evidence_age_nanos", "the request freshness policy",
                   out.freshness.max_evidence_age_nanos));
  CSP_TRY(read_bool(*freshness, "require_observation_time", "the request freshness policy",
                    out.freshness.require_observation_time));

  const JsonValue* validity = nullptr;
  CSP_TRY(read_object(object, "validity", what, validity));
  CSP_TRY(reject_unknown(*validity, {"validity_nanos"}, "the request validity policy"));
  CSP_TRY(read_int(*validity, "validity_nanos", "the request validity policy", out.validity.validity_nanos));

  return read_entries<Obligation>(object, "obligations", what, limits.max_obligations,
                                  [&limits](const JsonValue& item, std::string_view, Obligation& obligation) {
                                    return read_obligation(item, limits, obligation);
                                  },
                                  out.obligations);
}

Status read_site_record(const JsonValue& item, std::string_view, SiteRecord& out) {
  const std::string_view what = "a site record";
  CSP_TRY(reject_unknown(item, {"site", "jurisdiction", "maintenance", "provenance"}, what));
  CSP_TRY(read_id<SiteId>(item, "site", what, out.site));
  CSP_TRY(read_optional_id<JurisdictionId>(item, "jurisdiction", what, out.jurisdiction));
  CSP_TRY(read_measurement<MaintenanceState>(item, "maintenance", what, parse_maintenance, out.maintenance));
  return read_provenance(item, "provenance", what, out.provenance);
}

Status read_domain_record(const JsonValue& item, std::string_view, FailureDomainRecord& out) {
  const std::string_view what = "a failure domain record";
  CSP_TRY(reject_unknown(item, {"domain", "kind", "parent", "provenance"}, what));
  CSP_TRY(read_id<FailureDomainId>(item, "domain", what, out.domain));
  CSP_TRY(read_domain_kind(item, "kind", what, out.kind));
  if (item.find("parent") != nullptr) {
    FailureDomainId parent;
    CSP_TRY(read_id<FailureDomainId>(item, "parent", what, parent));
    out.parent = std::move(parent);
  }
  return read_provenance(item, "provenance", what, out.provenance);
}

Status read_domain_assignment(const JsonValue& item, std::string_view, DomainAssignment& out) {
  const std::string_view what = "a domain assignment";
  CSP_TRY(reject_unknown(item, {"site", "domain", "provenance"}, what));
  CSP_TRY(read_id<SiteId>(item, "site", what, out.site));
  CSP_TRY(read_id<FailureDomainId>(item, "domain", what, out.domain));
  return read_provenance(item, "provenance", what, out.provenance);
}

Status read_domain_alias(const JsonValue& item, std::string_view, DomainAliasRecord& out) {
  const std::string_view what = "a domain alias";
  CSP_TRY(reject_unknown(item, {"domain", "alias_of", "provenance"}, what));
  CSP_TRY(read_id<FailureDomainId>(item, "domain", what, out.domain));
  CSP_TRY(read_id<FailureDomainId>(item, "alias_of", what, out.alias_of));
  return read_provenance(item, "provenance", what, out.provenance);
}

Status read_capacity_record(const JsonValue& item, std::string_view, CapacityRecord& out) {
  const std::string_view what = "a capacity record";
  CSP_TRY(reject_unknown(item, {"reference", "site", "service_class", "kind", "available", "provenance"}, what));
  CSP_TRY(read_id<CapacityRefId>(item, "reference", what, out.reference));
  CSP_TRY(read_id<SiteId>(item, "site", what, out.site));
  CSP_TRY(read_id<ServiceClassId>(item, "service_class", what, out.service_class));
  std::string token;
  CSP_TRY(read_string(item, "kind", what, token));
  const std::optional<CapacityKind> kind = capacity_kind_from_string(token);
  if (!kind.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.doc.capacity_kind", "a capacity record names no known kind");
  }
  out.kind = *kind;
  CSP_TRY(read_measurement<Quantity>(item, "available", what, parse_quantity, out.available));
  return read_provenance(item, "provenance", what, out.provenance);
}

Status read_latency_record(const JsonValue& item, std::string_view, LatencyRecord& out) {
  const std::string_view what = "a latency record";
  CSP_TRY(reject_unknown(item, {"reference", "from_site", "to_site", "statistic", "latency", "provenance"}, what));
  CSP_TRY(read_id<DependencyId>(item, "reference", what, out.reference));
  CSP_TRY(read_id<SiteId>(item, "from_site", what, out.from_site));
  CSP_TRY(read_id<SiteId>(item, "to_site", what, out.to_site));
  CSP_TRY(read_statistic(item, "statistic", what, out.statistic));
  CSP_TRY(read_measurement<Duration>(item, "latency", what, parse_duration, out.latency));
  return read_provenance(item, "provenance", what, out.provenance);
}

Status read_recovery_record(const JsonValue& item, std::string_view, RecoveryRecord& out) {
  const std::string_view what = "a recovery record";
  CSP_TRY(reject_unknown(item,
                         {"reference", "site", "service_class", "can_host_recovery", "achievable_rto",
                          "achievable_rpo", "provenance"},
                         what));
  CSP_TRY(read_id<RecoveryRefId>(item, "reference", what, out.reference));
  CSP_TRY(read_id<SiteId>(item, "site", what, out.site));
  CSP_TRY(read_id<ServiceClassId>(item, "service_class", what, out.service_class));
  CSP_TRY(read_measurement<bool>(item, "can_host_recovery", what, parse_bool, out.can_host_recovery));
  CSP_TRY(read_measurement<Duration>(item, "achievable_rto", what, parse_duration, out.achievable_rto));
  CSP_TRY(read_measurement<Duration>(item, "achievable_rpo", what, parse_duration, out.achievable_rpo));
  return read_provenance(item, "provenance", what, out.provenance);
}

Status read_compatibility_record(const JsonValue& item, std::string_view, CompatibilityRecord& out) {
  const std::string_view what = "a compatibility record";
  CSP_TRY(reject_unknown(item, {"reference", "site", "service_class", "compatible", "provenance"}, what));
  CSP_TRY(read_id<EvidenceId>(item, "reference", what, out.reference));
  CSP_TRY(read_id<SiteId>(item, "site", what, out.site));
  CSP_TRY(read_id<ServiceClassId>(item, "service_class", what, out.service_class));
  CSP_TRY(read_measurement<bool>(item, "compatible", what, parse_bool, out.compatible));
  return read_provenance(item, "provenance", what, out.provenance);
}

Status read_cost_risk_record(const JsonValue& item, std::string_view, CostRiskRecord& out) {
  const std::string_view what = "a cost and risk record";
  CSP_TRY(reject_unknown(item,
                         {"reference", "site", "service_class", "cost_per_unit", "risk_per_mille", "provenance"},
                         what));
  CSP_TRY(read_id<EvidenceId>(item, "reference", what, out.reference));
  CSP_TRY(read_id<SiteId>(item, "site", what, out.site));
  CSP_TRY(read_optional_id<ServiceClassId>(item, "service_class", what, out.service_class));
  CSP_TRY(read_measurement<Quantity>(item, "cost_per_unit", what, parse_quantity, out.cost_per_unit));
  CSP_TRY(read_measurement<std::int64_t>(item, "risk_per_mille", what, parse_int, out.risk_per_mille));
  return read_provenance(item, "provenance", what, out.provenance);
}

Status read_snapshot_document(const JsonValue& object, const Limits& limits, SiteEvidenceSnapshot& out) {
  const std::string_view what = "the evidence snapshot";
  CSP_TRY(read_header(object, "snapshot", what));
  CSP_TRY(reject_unknown(object,
                         {"format", "kind", "generation", "captured_at", "sites", "failure_domains",
                          "domain_assignments", "domain_aliases", "capacity", "latency", "recovery",
                          "compatibility", "cost_risk"},
                         what));
  std::uint64_t generation = 0;
  CSP_TRY(read_uint(object, "generation", what, generation));
  out.generation = Generation::from_value(generation);
  std::int64_t captured = 0;
  CSP_TRY(read_int(object, "captured_at", what, captured));
  out.captured_at = Instant::from_nanos(captured);
  CSP_TRY(read_entries<SiteRecord>(object, "sites", what, limits.max_sites, read_site_record, out.sites));
  CSP_TRY(read_entries<FailureDomainRecord>(object, "failure_domains", what, limits.max_failure_domains,
                                            read_domain_record, out.failure_domains));
  CSP_TRY(read_entries<DomainAssignment>(object, "domain_assignments", what, limits.max_domain_assignments,
                                         read_domain_assignment, out.domain_assignments));
  CSP_TRY(read_entries<DomainAliasRecord>(object, "domain_aliases", what, limits.max_domain_aliases,
                                          read_domain_alias, out.domain_aliases));
  CSP_TRY(read_entries<CapacityRecord>(object, "capacity", what, limits.max_capacity_evidence,
                                       read_capacity_record, out.capacity));
  CSP_TRY(read_entries<LatencyRecord>(object, "latency", what, limits.max_latency_evidence, read_latency_record,
                                      out.latency));
  CSP_TRY(read_entries<RecoveryRecord>(object, "recovery", what, limits.max_recovery_evidence,
                                       read_recovery_record, out.recovery));
  CSP_TRY(read_entries<CompatibilityRecord>(object, "compatibility", what, limits.max_compatibility_evidence,
                                            read_compatibility_record, out.compatibility));
  return read_entries<CostRiskRecord>(object, "cost_risk", what, limits.max_cost_risk_evidence,
                                      read_cost_risk_record, out.cost_risk);
}

Status read_policy_document(const JsonValue& object, const Limits& limits, PlacementPolicy& out) {
  (void)limits;
  const std::string_view what = "the policy document";
  CSP_TRY(read_header(object, "policy", what));
  CSP_TRY(reject_unknown(object,
                         {"format", "kind", "policy", "generation", "allow_degraded_sites",
                          "allow_unknown_maintenance_state", "allow_unknown_jurisdiction", "allow_offer_capacity",
                          "require_commitment_capacity", "allow_derived_latency_bounds", "max_derived_hops",
                          "allow_recovery_on_primary_site"},
                         what));
  CSP_TRY(read_id<PolicyId>(object, "policy", what, out.policy));
  std::uint64_t generation = 0;
  CSP_TRY(read_uint(object, "generation", what, generation));
  out.generation = Generation::from_value(generation);
  CSP_TRY(read_bool(object, "allow_degraded_sites", what, out.allow_degraded_sites));
  CSP_TRY(read_bool(object, "allow_unknown_maintenance_state", what, out.allow_unknown_maintenance_state));
  CSP_TRY(read_bool(object, "allow_unknown_jurisdiction", what, out.allow_unknown_jurisdiction));
  CSP_TRY(read_bool(object, "allow_offer_capacity", what, out.allow_offer_capacity));
  CSP_TRY(read_bool(object, "require_commitment_capacity", what, out.require_commitment_capacity));
  CSP_TRY(read_bool(object, "allow_derived_latency_bounds", what, out.allow_derived_latency_bounds));
  std::uint64_t hops = 0;
  CSP_TRY(read_uint(object, "max_derived_hops", what, hops));
  out.max_derived_hops = static_cast<std::size_t>(hops);
  return read_bool(object, "allow_recovery_on_primary_site", what, out.allow_recovery_on_primary_site);
}

Status read_evidence_ref(const JsonValue& item, std::string_view, EvidenceRef& out) {
  const std::string_view what = "an evidence reference";
  CSP_TRY(reject_unknown(item, {"kind", "record", "authority", "authority_generation", "document_digest"}, what));
  CSP_TRY(read_string(item, "kind", what, out.kind));
  CSP_TRY(read_optional_id<EvidenceId>(item, "record", what, out.record));
  CSP_TRY(read_optional_id<AuthorityId>(item, "authority", what, out.authority));
  std::uint64_t generation = 0;
  CSP_TRY(read_uint(item, "authority_generation", what, generation));
  out.authority_generation = Generation::from_value(generation);
  const JsonValue* digest = item.find("document_digest");
  if (digest != nullptr) {
    Digest parsed;
    CSP_TRY(parse_digest(*digest, what, parsed));
    out.document_digest = parsed;
  }
  return success();
}

Status read_site_placement(const JsonValue& item, std::string_view, SitePlacement& out) {
  const std::string_view what = "a placement";
  CSP_TRY(reject_unknown(item,
                         {"site", "role", "index", "capacity_required", "capacity", "domains", "jurisdiction"},
                         what));
  CSP_TRY(read_id<SiteId>(item, "site", what, out.site));
  std::string role_token;
  CSP_TRY(read_string(item, "role", what, role_token));
  const std::optional<PlacementRole> role = placement_role_from_string(role_token);
  if (!role.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.doc.role", "a placement names no known role");
  }
  out.role = *role;
  std::uint64_t index = 0;
  CSP_TRY(read_uint(item, "index", what, index));
  out.index = static_cast<std::uint32_t>(index);
  CSP_TRY(read_quantity(item, "capacity_required", what, out.capacity_required));
  const JsonValue* capacity = nullptr;
  CSP_TRY(read_object(item, "capacity", what, capacity));
  CSP_TRY(reject_unknown(*capacity, {"references", "evidenced_total", "includes_offers"},
                         "a placement capacity basis"));
  CSP_TRY(read_id_array<CapacityRefId>(*capacity, "references", "a placement capacity basis", 1u << 20,
                                       out.capacity.references));
  CSP_TRY(read_quantity(*capacity, "evidenced_total", "a placement capacity basis", out.capacity.evidenced_total));
  CSP_TRY(read_bool(*capacity, "includes_offers", "a placement capacity basis", out.capacity.includes_offers));
  const JsonValue* domains = nullptr;
  CSP_TRY(locate(item, "domains", what, domains));
  if (!domains->is_array()) {
    return wrong_type(what, "domains", "an array");
  }
  for (const JsonValue& node : domains->items()) {
    const std::string_view node_what = "a resolved failure domain";
    CSP_TRY(reject_unknown(node, {"domain", "kind", "depth"}, node_what));
    DomainRef ref;
    CSP_TRY(read_id<FailureDomainId>(node, "domain", node_what, ref.domain));
    if (node.find("kind") != nullptr) {
      DomainKind kind{};
      CSP_TRY(read_domain_kind(node, "kind", node_what, kind));
      ref.kind = kind;
    }
    std::uint64_t depth = 0;
    CSP_TRY(read_uint(node, "depth", node_what, depth));
    ref.depth = static_cast<std::uint32_t>(depth);
    out.domains.push_back(std::move(ref));
  }
  CSP_TRY(read_optional_id<JurisdictionId>(item, "jurisdiction", what, out.jurisdiction));
  return success();
}

Status read_latency_resolution(const JsonValue& item, std::string_view, LatencyResolution& out) {
  const std::string_view what = "a latency resolution";
  CSP_TRY(reject_unknown(item, {"peer", "direction", "statistic", "measured", "derived", "chain"}, what));
  CSP_TRY(read_string(item, "peer", what, out.peer));
  std::string direction_token;
  CSP_TRY(read_string(item, "direction", what, direction_token));
  const std::optional<LatencyDirection> direction = latency_direction_from_string(direction_token);
  if (!direction.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.doc.direction", "a latency resolution names no known direction");
  }
  out.direction = *direction;
  CSP_TRY(read_statistic(item, "statistic", what, out.statistic));
  Duration measured{};
  CSP_TRY(read_duration(item, "measured", what, measured));
  out.measured = measured;
  CSP_TRY(read_bool(item, "derived", what, out.derived));
  return read_id_array<DependencyId>(item, "chain", what, 1u << 20, out.chain);
}

Status read_obligation_placement(const JsonValue& item, std::string_view, ObligationPlacement& out) {
  const std::string_view what = "an obligation in a plan";
  CSP_TRY(reject_unknown(item, {"obligation", "outcome", "refusal_code", "detail", "placements", "latency"},
                         what));
  CSP_TRY(read_id<ObligationId>(item, "obligation", what, out.obligation));
  CSP_TRY(read_tri(item, "outcome", what, out.outcome));
  CSP_TRY(read_string(item, "refusal_code", what, out.refusal_code));
  CSP_TRY(read_string(item, "detail", what, out.detail));
  CSP_TRY(read_entries<SitePlacement>(item, "placements", what, 1u << 20, read_site_placement, out.placements));
  return read_entries<LatencyResolution>(item, "latency", what, 1u << 20, read_latency_resolution, out.latency);
}

Status read_trace_entry(const JsonValue& item, std::string_view, ConstraintTraceEntry& out) {
  const std::string_view what = "a trace entry";
  CSP_TRY(reject_unknown(item, {"rule", "outcome", "obligation", "site", "detail", "evidence"}, what));
  CSP_TRY(read_string(item, "rule", what, out.rule));
  CSP_TRY(read_tri(item, "outcome", what, out.outcome));
  if (item.find("obligation") != nullptr) {
    ObligationId id;
    CSP_TRY(read_id<ObligationId>(item, "obligation", what, id));
    out.obligation = std::move(id);
  }
  if (item.find("site") != nullptr) {
    SiteId id;
    CSP_TRY(read_id<SiteId>(item, "site", what, id));
    out.site = std::move(id);
  }
  CSP_TRY(read_string(item, "detail", what, out.detail));
  return read_entries<EvidenceRef>(item, "evidence", what, 1u << 20, read_evidence_ref, out.evidence);
}

Status read_residual(const JsonValue& item, std::string_view, ResidualRequirement& out) {
  const std::string_view what = "a residual requirement";
  CSP_TRY(reject_unknown(item, {"obligation", "requirement", "shortfall", "placements_short", "detail"}, what));
  CSP_TRY(read_id<ObligationId>(item, "obligation", what, out.obligation));
  CSP_TRY(read_string(item, "requirement", what, out.requirement));
  CSP_TRY(read_quantity(item, "shortfall", what, out.shortfall));
  std::uint64_t short_count = 0;
  CSP_TRY(read_uint(item, "placements_short", what, short_count));
  out.placements_short = static_cast<std::uint32_t>(short_count);
  return read_string(item, "detail", what, out.detail);
}

Status read_tie_break(const JsonValue& item, std::string_view, TieBreakRecord& out) {
  const std::string_view what = "a tie-break record";
  CSP_TRY(reject_unknown(item, {"criterion", "applied", "ordered", "detail"}, what));
  CSP_TRY(read_string(item, "criterion", what, out.criterion));
  CSP_TRY(read_tri(item, "applied", what, out.applied));
  CSP_TRY(read_id_array<SiteId>(item, "ordered", what, 1u << 20, out.ordered));
  return read_string(item, "detail", what, out.detail);
}

Status read_revalidation_condition(const JsonValue& item, std::string_view, std::string& out) {
  return parse_string(item, "a revalidation condition", out);
}

Status read_refusal(const JsonValue& item, std::string_view, Refusal& out) {
  const std::string_view what = "a refusal";
  CSP_TRY(reject_unknown(item, {"category", "code", "detail", "evidence"}, what));
  std::string category_token;
  CSP_TRY(read_string(item, "category", what, category_token));
  const std::optional<ErrorCategory> category = error_category_from_string(category_token);
  if (!category.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.doc.error_category", "a refusal names no known error category");
  }
  out.category = *category;
  CSP_TRY(read_string(item, "code", what, out.code));
  CSP_TRY(read_string(item, "detail", what, out.detail));
  return read_entries<EvidenceRef>(item, "evidence", what, 1u << 20, read_evidence_ref, out.evidence);
}

Status read_plan_envelope(const JsonValue& object, const Limits& limits, FreshnessEnvelope& out) {
  const JsonValue* envelope = nullptr;
  CSP_TRY(read_object(object, "envelope", "the plan document", envelope));
  CSP_TRY(reject_unknown(*envelope,
                         {"evaluated_at", "oldest_evidence_observed_at", "evidence_generation", "policy_generation",
                          "request_generation", "valid_until", "revalidate_when"},
                         "the plan freshness envelope"));
  std::int64_t evaluated = 0;
  CSP_TRY(read_int(*envelope, "evaluated_at", "the plan freshness envelope", evaluated));
  out.evaluated_at = Instant::from_nanos(evaluated);
  std::int64_t oldest = 0;
  CSP_TRY(read_int(*envelope, "oldest_evidence_observed_at", "the plan freshness envelope", oldest));
  out.oldest_evidence_observed_at = Instant::from_nanos(oldest);
  std::uint64_t evidence_generation = 0;
  CSP_TRY(read_uint(*envelope, "evidence_generation", "the plan freshness envelope", evidence_generation));
  out.evidence_generation = Generation::from_value(evidence_generation);
  std::uint64_t policy_generation = 0;
  CSP_TRY(read_uint(*envelope, "policy_generation", "the plan freshness envelope", policy_generation));
  out.policy_generation = Generation::from_value(policy_generation);
  std::uint64_t request_generation = 0;
  CSP_TRY(read_uint(*envelope, "request_generation", "the plan freshness envelope", request_generation));
  out.request_generation = Generation::from_value(request_generation);
  std::int64_t valid_until = 0;
  CSP_TRY(read_int(*envelope, "valid_until", "the plan freshness envelope", valid_until));
  out.valid_until = Instant::from_nanos(valid_until);
  return read_entries<std::string>(*envelope, "revalidate_when", "the plan freshness envelope",
                                   limits.max_trace_entries, read_revalidation_condition,
                                   out.revalidate_when);
}

Status read_plan_document(const JsonValue& object, const Limits& limits, PlacementPlan& out) {
  const std::string_view what = "the plan document";
  CSP_TRY(read_header(object, "plan", what));
  CSP_TRY(reject_unknown(object,
                         {"format", "kind", "plan", "outcome", "request", "request_generation", "obligations",
                          "trace", "residual", "tie_breaks", "refusal", "envelope", "nodes_explored",
                          "search_exhausted", "digest"},
                         what));
  CSP_TRY(read_id<PlanId>(object, "plan", what, out.plan));
  std::string outcome_token;
  CSP_TRY(read_string(object, "outcome", what, outcome_token));
  const std::optional<PlanOutcome> outcome = plan_outcome_from_string(outcome_token);
  if (!outcome.has_value()) {
    return fail(ErrorCategory::Invalid, "csp.doc.plan_outcome", "the plan names no known outcome");
  }
  out.outcome = *outcome;
  CSP_TRY(read_id<RequestId>(object, "request", what, out.request));
  std::uint64_t generation = 0;
  CSP_TRY(read_uint(object, "request_generation", what, generation));
  out.request_generation = Generation::from_value(generation);
  CSP_TRY(read_entries<ObligationPlacement>(object, "obligations", what, limits.max_obligations,
                                            read_obligation_placement, out.obligations));
  CSP_TRY(read_entries<ConstraintTraceEntry>(object, "trace", what, limits.max_trace_entries, read_trace_entry,
                                             out.trace));
  CSP_TRY(read_entries<ResidualRequirement>(object, "residual", what, limits.max_residual_entries, read_residual,
                                            out.residual));
  CSP_TRY(read_entries<TieBreakRecord>(object, "tie_breaks", what, limits.max_tie_break_entries, read_tie_break,
                                       out.tie_breaks));
  const JsonValue* refusal = object.find("refusal");
  if (refusal != nullptr) {
    Refusal parsed;
    CSP_TRY(read_refusal(*refusal, what, parsed));
    out.refusal = std::move(parsed);
  }
  CSP_TRY(read_plan_envelope(object, limits, out.envelope));
  std::uint64_t nodes = 0;
  CSP_TRY(read_uint(object, "nodes_explored", what, nodes));
  out.nodes_explored = nodes;
  CSP_TRY(read_bool(object, "search_exhausted", what, out.search_exhausted));
  const JsonValue* digest = nullptr;
  CSP_TRY(locate(object, "digest", what, digest));
  Digest parsed_digest;
  CSP_TRY(parse_digest(*digest, what, parsed_digest));
  out.digest = parsed_digest;
  return success();
}

detail::JsonLimits json_limits_for(const Limits& limits) {
  detail::JsonLimits json_limits;
  json_limits.max_bytes = limits.max_document_bytes;
  json_limits.max_depth = limits.max_document_depth;
  return json_limits;
}

}  // namespace

Result<PlacementRequest> request_from_document(std::string_view text, const Limits& limits) {
  Result<detail::JsonValue> parsed = detail::json_parse(text, json_limits_for(limits));
  if (!parsed) {
    return parsed.error();
  }
  PlacementRequest request;
  const Status status = read_request_document(parsed.value(), limits, request);
  if (!status) {
    return status.error();
  }
  return request;
}

Result<SiteEvidenceSnapshot> snapshot_from_document(std::string_view text, const Limits& limits) {
  Result<detail::JsonValue> parsed = detail::json_parse(text, json_limits_for(limits));
  if (!parsed) {
    return parsed.error();
  }
  SiteEvidenceSnapshot snapshot;
  const Status status = read_snapshot_document(parsed.value(), limits, snapshot);
  if (!status) {
    return status.error();
  }
  return snapshot;
}

Result<PlacementPolicy> policy_from_document(std::string_view text, const Limits& limits) {
  Result<detail::JsonValue> parsed = detail::json_parse(text, json_limits_for(limits));
  if (!parsed) {
    return parsed.error();
  }
  PlacementPolicy policy;
  const Status status = read_policy_document(parsed.value(), limits, policy);
  if (!status) {
    return status.error();
  }
  return policy;
}

Result<PlacementPlan> plan_from_document(std::string_view text, const Limits& limits) {
  Result<detail::JsonValue> parsed = detail::json_parse(text, json_limits_for(limits));
  if (!parsed) {
    return parsed.error();
  }
  PlacementPlan plan;
  Status status = read_plan_document(parsed.value(), limits, plan);
  if (!status) {
    return status.error();
  }
  status = plan_validate(plan, limits);
  if (!status) {
    return status.error();
  }
  if (plan_compute_digest(plan) != plan.digest) {
    return fail(ErrorCategory::Integrity, "csp.doc.digest_mismatch",
                "the plan digest does not match the plan content, so the document was altered or truncated");
  }
  return plan;
}

}  // namespace csp

#undef CSP_TRY
