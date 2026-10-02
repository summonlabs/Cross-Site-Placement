// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Properties, over randomized fleets.
//
// The centre of this file is a reference model that decides admissibility directly from
// the generated evidence. It never calls the planner: if it did, it would agree with the
// planner by construction and prove nothing. The model re-implements the documented
// rules - allow and deny lists, freshness, jurisdiction, maintenance state,
// compatibility, capacity, and separation over the resolved domain ancestry - and its
// verdict is compared with the planner's over hundreds of seeded fleets.
//
// The remaining cases pin the properties that must hold whatever the input is:
// determinism under repetition and under permutation of every input vector, the
// satisfaction of every hard rule by every plan that is published, the refusal to
// publish an indeterminate answer as a plan, and the round trip of every document
// through its own encoding.

#include "test_harness.hpp"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"

using namespace csp;

/// The harness offers CSP_REQUIRE for a bare condition and CSP_EXPECT_MSG for a
/// condition with a detail. A randomized case needs both at once: a required check that
/// names the iteration it stopped at. This is that check, spelled with the harness's own
/// primitives rather than a second registry of its own.
#define CSP_REQUIRE_MSG(condition, detail)                                                          do {                                                                                                if (!csp_test::check((condition), #condition, __FILE__, __LINE__, (detail))) {                      csp_test::abort_case();                                                                         }                                                                                               } while (false)

namespace {

constexpr std::int64_t kBase = 1700000000000000000LL;
constexpr std::int64_t kFresh = kBase - 1000;

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

Provenance provenance_of(const std::string& record, std::int64_t observed_at) {
  Provenance provenance;
  provenance.source_record = evidence_id(record.c_str());
  provenance.authority = authority_id("registry-authority");
  provenance.authority_generation = Generation::from_value(4);
  provenance.observed_at = Instant::from_nanos(observed_at);
  return provenance;
}

/// A three-valued verdict, used for a site, for an arrangement, and for the model's
/// answer as a whole: Satisfied means "definitely", Violated means "definitely not", and
/// Indeterminate means exactly what it says.
using Verdict = Tri;

DomainKind random_kind(csp_test::SeededRandom& random) {
  const DomainKind kinds[] = {DomainKind::Power, DomainKind::Network, DomainKind::Geography};
  return kinds[random.below(3)];
}

MaintenanceState random_maintenance(csp_test::SeededRandom& random, bool& known) {
  const MaintenanceState states[] = {MaintenanceState::Operational, MaintenanceState::Operational,
                                     MaintenanceState::Operational, MaintenanceState::Degraded,
                                     MaintenanceState::Maintenance, MaintenanceState::Offline};
  const std::uint64_t roll = random.below(8);
  if (roll == 0) {
    known = false;
    return MaintenanceState::Operational;
  }
  known = true;
  return states[random.below(6)];
}

// ---------------------------------------------------------------------------
// The reference model
// ---------------------------------------------------------------------------

/// Resolution of the failure-domain evidence, computed here from the raw records.
///
/// Identity merging, containment closure, per-site membership and the separation rule
/// are all re-derived rather than borrowed, because a model that asked the library how
/// two sites relate would only be checking that the library agrees with itself.
class ModelDomains {
 public:
  explicit ModelDomains(const SiteEvidenceSnapshot& snapshot) {
    std::vector<FailureDomainId> ids;
    for (const FailureDomainRecord& record : snapshot.failure_domains) {
      ids.push_back(record.domain);
      if (record.parent.has_value()) {
        ids.push_back(*record.parent);
      }
    }
    for (const DomainAssignment& assignment : snapshot.domain_assignments) {
      ids.push_back(assignment.domain);
    }
    for (const DomainAliasRecord& alias : snapshot.domain_aliases) {
      ids.push_back(alias.domain);
      ids.push_back(alias.alias_of);
    }
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    for (const FailureDomainId& id : ids) {
      parent_[id] = id;
    }
    for (const DomainAliasRecord& alias : snapshot.domain_aliases) {
      unite(alias.domain, alias.alias_of);
    }
    // The canonical identity of a merged class is its smallest member. One alias record
    // per class gives two members of size one each, and the library's union by size
    // therefore roots the class at the smaller of the two.
    for (const FailureDomainId& id : ids) {
      const FailureDomainId root = find(id);
      const auto existing = canonical_.find(root);
      if (existing == canonical_.end() || id < existing->second) {
        canonical_[root] = id;
      }
    }
    for (const FailureDomainId& id : ids) {
      canonical_[id] = canonical_[find(id)];
    }

    for (const FailureDomainRecord& record : snapshot.failure_domains) {
      const FailureDomainId domain = canonical(record.domain);
      kind_[domain] = record.kind;
      if (record.parent.has_value()) {
        container_[domain] = canonical(*record.parent);
      }
    }

    for (const SiteRecord& site : snapshot.sites) {
      std::vector<DomainRef> accumulated;
      for (const DomainAssignment& assignment : snapshot.domain_assignments) {
        if (assignment.site != site.site) {
          continue;
        }
        append_ancestry(canonical(assignment.domain), accumulated);
      }
      std::sort(accumulated.begin(), accumulated.end(), domain_ref_less);
      std::vector<DomainRef> unique;
      for (const DomainRef& ref : accumulated) {
        if (!unique.empty() && unique.back().domain == ref.domain) {
          continue;
        }
        unique.push_back(ref);
      }
      if (!unique.empty()) {
        ancestry_[site.site] = std::move(unique);
      }
    }
  }

  const std::vector<DomainRef>& ancestry(const SiteId& site) const {
    const auto found = ancestry_.find(site);
    return found == ancestry_.end() ? empty_ : found->second;
  }

  Verdict separate(const SiteId& lhs, const SiteId& rhs, const std::vector<DomainKind>& kinds,
                   const std::vector<FailureDomainId>& forbidden) const {
    const std::vector<DomainRef>& left = ancestry(lhs);
    const std::vector<DomainRef>& right = ancestry(rhs);
    if (left.empty() || right.empty()) {
      return Tri::Indeterminate;
    }
    std::vector<FailureDomainId> named;
    for (const FailureDomainId& domain : forbidden) {
      named.push_back(canonical(domain));
    }
    std::sort(named.begin(), named.end());
    named.erase(std::unique(named.begin(), named.end()), named.end());

    bool violated = false;
    bool unclassified = false;
    std::vector<DomainRef> lhs_sorted = left;
    std::vector<DomainRef> rhs_sorted = right;
    std::sort(lhs_sorted.begin(), lhs_sorted.end(), by_domain);
    std::sort(rhs_sorted.begin(), rhs_sorted.end(), by_domain);
    std::size_t left_cursor = 0;
    std::size_t right_cursor = 0;
    while (left_cursor < lhs_sorted.size() && right_cursor < rhs_sorted.size()) {
      const DomainRef& a = lhs_sorted[left_cursor];
      const DomainRef& b = rhs_sorted[right_cursor];
      if (a.domain < b.domain) {
        ++left_cursor;
        continue;
      }
      if (b.domain < a.domain) {
        ++right_cursor;
        continue;
      }
      ++left_cursor;
      ++right_cursor;
      if (std::binary_search(named.begin(), named.end(), a.domain)) {
        violated = true;
      } else if (!kinds.empty()) {
        if (a.kind.has_value()) {
          if (std::find(kinds.begin(), kinds.end(), *a.kind) != kinds.end()) {
            violated = true;
          }
        } else {
          unclassified = true;
        }
      }
    }
    if (violated) {
      return Tri::Violated;
    }
    return unclassified ? Tri::Indeterminate : Tri::Satisfied;
  }

 private:
  static bool by_domain(const DomainRef& lhs, const DomainRef& rhs) { return lhs.domain < rhs.domain; }

  static bool domain_ref_less(const DomainRef& lhs, const DomainRef& rhs) {
    const unsigned int lhs_rank = lhs.kind.has_value() ? static_cast<unsigned int>(*lhs.kind) : 255U;
    const unsigned int rhs_rank = rhs.kind.has_value() ? static_cast<unsigned int>(*rhs.kind) : 255U;
    if (lhs_rank != rhs_rank) {
      return lhs_rank < rhs_rank;
    }
    if (lhs.domain != rhs.domain) {
      return lhs.domain < rhs.domain;
    }
    return lhs.depth < rhs.depth;
  }

  FailureDomainId find(const FailureDomainId& id) const {
    const auto found = parent_.find(id);
    return found == parent_.end() ? id : found->second;
  }

  void unite(const FailureDomainId& lhs, const FailureDomainId& rhs) {
    const FailureDomainId left = find(lhs);
    const FailureDomainId right = find(rhs);
    if (left == right) {
      return;
    }
    const FailureDomainId smaller = left < right ? left : right;
    const FailureDomainId larger = left < right ? right : left;
    parent_[larger] = smaller;
  }

  void append_ancestry(const FailureDomainId& domain, std::vector<DomainRef>& out) const {
    FailureDomainId cursor = domain;
    std::uint32_t depth = 0;
    std::vector<FailureDomainId> seen;
    for (;;) {
      if (std::find(seen.begin(), seen.end(), cursor) != seen.end()) {
        return;  // a cycle cannot be resolved here either; the model refuses to walk it
      }
      seen.push_back(cursor);
      const auto kind = kind_.find(cursor);
      out.push_back(DomainRef{cursor, kind == kind_.end() ? std::optional<DomainKind>() : kind->second, depth});
      const auto container = container_.find(cursor);
      if (container == container_.end()) {
        return;
      }
      cursor = container->second;
      ++depth;
      if (depth > 64) {
        return;
      }
    }
  }

  FailureDomainId canonical(const FailureDomainId& id) const {
    const auto found = canonical_.find(id);
    return found == canonical_.end() ? id : found->second;
  }

  std::map<FailureDomainId, FailureDomainId> parent_;
  std::map<FailureDomainId, FailureDomainId> canonical_;
  std::map<FailureDomainId, std::optional<DomainKind>> kind_;
  std::map<FailureDomainId, FailureDomainId> container_;
  std::map<SiteId, std::vector<DomainRef>> ancestry_;
  std::vector<DomainRef> empty_;
};

struct SiteView {
  const SiteRecord* site = nullptr;
  Verdict verdict = Tri::Indeterminate;
  bool candidate = false;
  std::string rule;
};

/// The model's reading of one site for one obligation, from the raw evidence.
SiteView assess_site(const PlacementRequest& request, const Obligation& obligation, const PlacementPolicy& policy,
                     const SiteEvidenceSnapshot& snapshot, const SiteRecord& site) {
  SiteView view;
  view.site = &site;

  const std::vector<SiteId>& allow =
      !obligation.allowed_sites.empty() ? obligation.allowed_sites : request.allowed_sites;
  const bool allowed = allow.empty() || std::find(allow.begin(), allow.end(), site.site) != allow.end();
  const bool denied = std::find(obligation.forbidden_sites.begin(), obligation.forbidden_sites.end(), site.site) !=
                          obligation.forbidden_sites.end() ||
                      std::find(request.forbidden_sites.begin(), request.forbidden_sites.end(), site.site) !=
                          request.forbidden_sites.end();
  view.candidate = allowed && !denied;
  if (!view.candidate) {
    view.verdict = denied ? Tri::Violated : Tri::Indeterminate;
    view.rule = denied ? "deny-list" : "allow-list";
    return view;
  }

  const bool require_time = request.freshness.require_observation_time;
  if (site.provenance.observed_at.is_zero() && require_time) {
    view.verdict = Tri::Indeterminate;
    view.rule = "freshness";
    return view;
  }

  if (!obligation.allowed_jurisdictions.empty()) {
    if (!site.jurisdiction.valid()) {
      if (!policy.allow_unknown_jurisdiction) {
        view.verdict = Tri::Indeterminate;
        view.rule = "jurisdiction";
        return view;
      }
    } else if (std::find(obligation.allowed_jurisdictions.begin(), obligation.allowed_jurisdictions.end(),
                         site.jurisdiction) == obligation.allowed_jurisdictions.end()) {
      view.verdict = Tri::Violated;
      view.rule = "jurisdiction";
      return view;
    }
  }

  if (!site.maintenance.is_known()) {
    if (!policy.allow_unknown_maintenance_state) {
      view.verdict = Tri::Indeterminate;
      view.rule = "maintenance";
      return view;
    }
  } else if (site.maintenance.value() != MaintenanceState::Operational) {
    const bool degraded = policy.allow_degraded_sites && site.maintenance.value() == MaintenanceState::Degraded;
    if (!degraded) {
      view.verdict = Tri::Violated;
      view.rule = "maintenance";
      return view;
    }
  }

  const CompatibilityRecord* compatibility = nullptr;
  for (const CompatibilityRecord& record : snapshot.compatibility) {
    if (record.site == site.site && record.service_class == obligation.service_class) {
      compatibility = &record;
      break;
    }
  }
  if (compatibility == nullptr) {
    view.verdict = Tri::Indeterminate;
    view.rule = "compatibility";
    return view;
  }
  if (compatibility->provenance.observed_at.is_zero() && require_time) {
    view.verdict = Tri::Indeterminate;
    view.rule = "compatibility-freshness";
    return view;
  }
  if (!compatibility->compatible.is_known()) {
    view.verdict = Tri::Indeterminate;
    view.rule = "compatibility";
    return view;
  }
  if (!compatibility->compatible.value()) {
    view.verdict = Tri::Violated;
    view.rule = "compatibility";
    return view;
  }

  Quantity total = Quantity::from_units(0);
  bool any_record = false;
  bool incomplete = false;
  for (const CapacityRecord& record : snapshot.capacity) {
    if (record.site != site.site || record.service_class != obligation.service_class) {
      continue;
    }
    any_record = true;
    if (policy.require_commitment_capacity && record.kind != CapacityKind::Commitment) {
      continue;
    }
    if (!policy.allow_offer_capacity && record.kind == CapacityKind::Offer) {
      continue;
    }
    if (record.provenance.observed_at.is_zero() && require_time) {
      incomplete = true;
      continue;
    }
    if (!record.available.is_known()) {
      incomplete = true;
      continue;
    }
    total = Quantity::from_units(total.units() + record.available.value().units());
  }
  if (total < obligation.required_capacity) {
    if (incomplete || !any_record) {
      view.verdict = Tri::Indeterminate;
      view.rule = "capacity";
      return view;
    }
    view.verdict = Tri::Violated;
    view.rule = "capacity";
    return view;
  }

  view.verdict = Tri::Satisfied;
  view.rule = "admissible";
  return view;
}

bool group_covers(SeparationGroup group, PlacementRole lhs, PlacementRole rhs) {
  switch (group) {
    case SeparationGroup::All:
      return true;
    case SeparationGroup::WithinRole:
      return lhs == rhs;
    case SeparationGroup::AcrossRoles:
    default:
      return lhs != rhs;
  }
}

struct ModelAnswer {
  Verdict arrangement = Tri::Violated;  // Satisfied: one certainly exists
  bool any_unknown_candidate = false;
  std::size_t candidate_count = 0;
  std::vector<SiteView> sites;
};

/// Decides, from the generated evidence alone, whether an arrangement exists, might
/// exist, or certainly does not.
ModelAnswer model_answer(const PlacementRequest& request, const SiteEvidenceSnapshot& snapshot,
                         const PlacementPolicy& policy) {
  ModelAnswer answer;
  const ModelDomains domains(snapshot);
  if (request.obligations.empty()) {
    return answer;
  }
  const Obligation& obligation = request.obligations[0];
  for (const SiteRecord& site : snapshot.sites) {
    SiteView view = assess_site(request, obligation, policy, snapshot, site);
    if (view.candidate && view.verdict == Tri::Indeterminate) {
      answer.any_unknown_candidate = true;
    }
    if (view.candidate) {
      ++answer.candidate_count;
    }
    answer.sites.push_back(std::move(view));
  }

  std::vector<std::size_t> candidates;
  for (std::size_t index = 0; index < answer.sites.size(); ++index) {
    if (answer.sites[index].candidate) {
      candidates.push_back(index);
    }
  }

  const std::size_t needed = obligation.primary_placements + obligation.recovery_placements;
  const std::vector<PlacementRole> roles = [&obligation]() {
    std::vector<PlacementRole> built;
    for (std::uint32_t index = 0; index < obligation.primary_placements; ++index) {
      built.push_back(PlacementRole::Primary);
    }
    for (std::uint32_t index = 0; index < obligation.recovery_placements; ++index) {
      built.push_back(PlacementRole::Recovery);
    }
    return built;
  }();

  if (needed == 0 || candidates.size() < needed) {
    return answer;
  }

  std::vector<std::size_t> chosen;
  const std::function<void(std::size_t)> walk = [&](std::size_t start) {
    if (chosen.size() == needed) {
      bool all_admissible = true;
      bool all_possible = true;
      for (const std::size_t slot : chosen) {
        if (answer.sites[slot].verdict == Tri::Violated) {
          all_admissible = false;
          all_possible = false;
        } else if (answer.sites[slot].verdict == Tri::Indeterminate) {
          all_admissible = false;
        }
      }
      if (!all_possible) {
        return;
      }
      bool every_requirement_satisfied = true;
      for (const SeparationRequirement& requirement : obligation.separations) {
        for (std::size_t lhs = 0; lhs < chosen.size(); ++lhs) {
          for (std::size_t rhs = lhs + 1; rhs < chosen.size(); ++rhs) {
            if (!group_covers(requirement.group, roles[lhs], roles[rhs])) {
              continue;
            }
            const Verdict verdict =
                domains.separate(answer.sites[chosen[lhs]].site->site, answer.sites[chosen[rhs]].site->site,
                                 requirement.separated_kinds, requirement.forbidden_shared_domains);
            if (verdict == Tri::Violated) {
              return;  // this arrangement is impossible under this requirement
            }
            if (verdict == Tri::Indeterminate) {
              every_requirement_satisfied = false;
            }
          }
        }
      }
      if (all_admissible && every_requirement_satisfied) {
        answer.arrangement = Tri::Satisfied;
      } else if (answer.arrangement != Tri::Satisfied) {
        answer.arrangement = Tri::Indeterminate;
      }
      return;
    }
    for (std::size_t index = start; index < candidates.size(); ++index) {
      chosen.push_back(candidates[index]);
      walk(index + 1);
      chosen.pop_back();
      if (answer.arrangement == Tri::Satisfied) {
        return;
      }
    }
  };
  walk(0);
  return answer;
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

struct Generated {
  PlacementRequest request;
  SiteEvidenceSnapshot snapshot;
  PlacementPolicy policy;
};

Generated generate(csp_test::SeededRandom& random) {
  Generated generated;
  generated.snapshot.generation = Generation::from_value(5);
  generated.snapshot.captured_at = Instant::from_nanos(kFresh);
  generated.policy.policy = policy_id("policy-1");
  generated.policy.generation = Generation::from_value(1);

  const std::size_t class_count = 2 + static_cast<std::size_t>(random.below(3));
  std::vector<std::string> canonical;
  std::vector<std::optional<DomainKind>> kind;
  std::vector<std::optional<std::size_t>> container;
  for (std::size_t index = 0; index < class_count; ++index) {
    canonical.push_back(std::string("domain-") + static_cast<char>('a' + static_cast<int>(index)));
    container.push_back(std::nullopt);
    kind.push_back(std::nullopt);
  }
  for (std::size_t index = 0; index < class_count; ++index) {
    if (!random.one_in(4)) {
      kind[index] = random_kind(random);
      if (index > 0 && random.one_in(3)) {
        container[index] = static_cast<std::size_t>(random.below(index));
      }
    }
  }
  std::vector<std::pair<std::string, std::size_t>> aliases;
  for (std::size_t index = 0; index < class_count; ++index) {
    if (random.one_in(3)) {
      aliases.emplace_back(std::string("alias-") + static_cast<char>('a' + static_cast<int>(index)), index);
    }
  }

  for (std::size_t index = 0; index < class_count; ++index) {
    if (!kind[index].has_value()) {
      continue;
    }
    FailureDomainRecord record;
    record.domain = domain_id(canonical[index].c_str());
    record.kind = *kind[index];
    if (container[index].has_value()) {
      record.parent = domain_id(canonical[*container[index]].c_str());
    }
    record.provenance = provenance_of("domain-record-" + canonical[index], kFresh);
    generated.snapshot.failure_domains.push_back(std::move(record));
  }
  for (const auto& alias : aliases) {
    DomainAliasRecord record;
    record.domain = domain_id(alias.first.c_str());
    record.alias_of = domain_id(canonical[alias.second].c_str());
    record.provenance = provenance_of("alias-record-" + alias.first, kFresh);
    generated.snapshot.domain_aliases.push_back(std::move(record));
  }

  const std::size_t site_count = 3 + static_cast<std::size_t>(random.below(4));
  std::vector<std::string> site_names;
  for (std::size_t index = 0; index < site_count; ++index) {
    site_names.push_back("site-" + std::to_string(index + 1));
  }

  for (std::size_t index = 0; index < site_count; ++index) {
    const std::string& name = site_names[index];
    const bool observed = !random.one_in(10);
    SiteRecord site;
    site.site = site_id(name.c_str());
    if (!random.one_in(5)) {
      site.jurisdiction = jurisdiction_id("jur-1");
    }
    bool known = true;
    const MaintenanceState reported = random_maintenance(random, known);
    site.maintenance = known ? Measurement<MaintenanceState>::known(reported)
                             : Measurement<MaintenanceState>::unknown();
    site.provenance = provenance_of("site-record-" + name, observed ? kFresh : 0);
    generated.snapshot.sites.push_back(std::move(site));

    if (!random.one_in(5)) {
      CompatibilityRecord compatibility;
      compatibility.reference = evidence_id(("compatibility-" + name).c_str());
      compatibility.site = site_id(name.c_str());
      compatibility.service_class = class_id("service-1");
      const std::uint64_t roll = random.below(10);
      if (roll < 7) {
        compatibility.compatible = Measurement<bool>::known(true);
      } else if (roll < 9) {
        compatibility.compatible = Measurement<bool>::known(false);
      } else {
        compatibility.compatible = Measurement<bool>::unknown();
      }
      compatibility.provenance = provenance_of("compatibility-record-" + name, observed ? kFresh : 0);
      generated.snapshot.compatibility.push_back(std::move(compatibility));
    }

    const std::size_t capacity_count = static_cast<std::size_t>(random.below(3));
    for (std::size_t slot = 0; slot < capacity_count; ++slot) {
      CapacityRecord capacity;
      capacity.reference = capacity_ref_id(("capacity-" + name + "-" + std::to_string(slot)).c_str());
      capacity.site = site_id(name.c_str());
      capacity.service_class = class_id("service-1");
      capacity.kind = random.one_in(3) ? CapacityKind::Offer : CapacityKind::Commitment;
      if (random.one_in(5)) {
        capacity.available = Measurement<Quantity>::unknown();
      } else {
        capacity.available =
            Measurement<Quantity>::known(Quantity::from_units(random.between(1, 10)));
      }
      capacity.provenance = provenance_of("capacity-record-" + name, observed ? kFresh : 0);
      generated.snapshot.capacity.push_back(std::move(capacity));
    }

    if (random.one_in(6)) {
      continue;  // no recorded membership at all: separation involving it is undecided
    }
    const std::size_t assignment_count = 1 + static_cast<std::size_t>(random.below(2));
    for (std::size_t slot = 0; slot < assignment_count; ++slot) {
      const std::size_t which = static_cast<std::size_t>(random.below(class_count));
      std::string used = canonical[which];
      for (const auto& alias : aliases) {
        if (alias.second == which && random.one_in(2)) {
          used = alias.first;
        }
      }
      DomainAssignment assignment;
      assignment.site = site_id(name.c_str());
      assignment.domain = domain_id(used.c_str());
      assignment.provenance = provenance_of("assignment-record-" + name, kFresh);
      generated.snapshot.domain_assignments.push_back(std::move(assignment));
    }
  }

  generated.request.request = request_id("request-1");
  generated.request.generation = Generation::from_value(1);
  generated.request.policy.policy = policy_id("policy-1");
  generated.request.policy.generation = Generation::from_value(1);
  generated.request.freshness.require_observation_time = !random.one_in(2);
  if (random.one_in(2)) {
    const std::size_t wanted = static_cast<std::size_t>(random.below(site_count + 1));
    for (std::size_t index = 0; index < wanted; ++index) {
      const std::string& name = site_names[static_cast<std::size_t>(random.below(site_count))];
      if (std::find(generated.request.allowed_sites.begin(), generated.request.allowed_sites.end(),
                    site_id(name.c_str())) == generated.request.allowed_sites.end()) {
        generated.request.allowed_sites.push_back(site_id(name.c_str()));
      }
    }
  }
  if (random.one_in(4)) {
    generated.request.forbidden_sites.push_back(
        site_id(site_names[static_cast<std::size_t>(random.below(site_count))].c_str()));
  }

  Obligation obligation;
  obligation.obligation = obligation_id("obligation-1");
  obligation.service_class = class_id("service-1");
  obligation.required_capacity = Quantity::from_units(random.between(2, 12));
  obligation.primary_placements = static_cast<std::uint32_t>(1 + random.below(2));
  obligation.allow_colocation = false;
  if (random.one_in(4)) {
    obligation.allowed_jurisdictions.push_back(jurisdiction_id("jur-1"));
  }
  if (random.one_in(4)) {
    obligation.allowed_sites.push_back(
        site_id(site_names[static_cast<std::size_t>(random.below(site_count))].c_str()));
  }
  if (random.one_in(4)) {
    obligation.forbidden_sites.push_back(
        site_id(site_names[static_cast<std::size_t>(random.below(site_count))].c_str()));
  }
  if (!random.one_in(3)) {
    SeparationRequirement separation;
    separation.group = SeparationGroup::All;
    separation.separated_kinds.push_back(random_kind(random));
    if (random.one_in(3)) {
      const DomainKind second = random_kind(random);
      if (second != separation.separated_kinds[0]) {
        separation.separated_kinds.push_back(second);
      }
    }
    obligation.separations.push_back(std::move(separation));
  }
  generated.request.obligations.push_back(std::move(obligation));
  return generated;
}

PlanningContext instant_context() {
  PlanningContext context;
  context.evaluation_instant = Instant::from_nanos(kBase);
  return context;
}

Result<PlacementPlan> run(const Generated& generated) {
  const Planner planner;
  return planner.plan(generated.request, generated.snapshot, generated.policy, instant_context());
}

std::string describe(const ModelAnswer& answer, const PlacementPlan& plan) {
  std::string text = std::string("model=") + to_string(answer.arrangement) + " planner=" + to_string(plan.outcome) +
                     " candidates=" + std::to_string(answer.candidate_count) + " unknown=" +
                     std::to_string(answer.any_unknown_candidate ? 1 : 0);
  for (const SiteView& site : answer.sites) {
    text += " | ";
    text += site.site->site.value();
    text += "=";
    text += to_string(site.verdict);
    text += "(";
    text += site.rule;
    text += ")";
  }
  return text;
}

bool covers(const SeparationRequirement& requirement, PlacementRole lhs, PlacementRole rhs) {
  return group_covers(requirement.group, lhs, rhs);
}

template <class T>
void permute(std::vector<T>& values, csp_test::SeededRandom& random) {
  for (std::size_t index = values.size(); index > 1; --index) {
    const std::size_t other = static_cast<std::size_t>(random.below(index));
    std::swap(values[index - 1], values[other]);
  }
}

bool same_domain_refs(const std::vector<DomainRef>& lhs, const std::vector<DomainRef>& rhs) {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (std::size_t index = 0; index < lhs.size(); ++index) {
    if (!(lhs[index].domain == rhs[index].domain) || lhs[index].kind != rhs[index].kind ||
        lhs[index].depth != rhs[index].depth) {
      return false;
    }
  }
  return true;
}

}  // namespace

CSP_TEST(property, model_and_planner_agree_over_seeded_fleets) {
  csp_test::SeededRandom random(0xA11CEB0BULL);
  const std::uint64_t iterations = 400;
  std::size_t planned = 0;
  std::size_t refused = 0;
  std::size_t indeterminate = 0;
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    const Generated generated = generate(random);
    const ModelAnswer answer = model_answer(generated.request, generated.snapshot, generated.policy);
    Result<PlacementPlan> planned_result = run(generated);
    CSP_REQUIRE_MSG(planned_result.has_value(),
                    "iteration " + std::to_string(iteration) + ": the planner could not evaluate a structurally "
                    "valid fleet: " + planned_result.error().render());
    const PlacementPlan& plan = planned_result.value();
    const std::string context = "iteration " + std::to_string(iteration) + ": " + describe(answer, plan);

    switch (plan.outcome) {
      case PlanOutcome::Planned:
        ++planned;
        break;
      case PlanOutcome::Refused:
        ++refused;
        break;
      case PlanOutcome::Indeterminate:
      default:
        ++indeterminate;
        break;
    }

    // A plan is published only when the model can point at an arrangement that
    // satisfies every hard rule, and an arrangement that certainly exists is never
    // refused. The third case is weaker on purpose: the model proves impossibility, so
    // the planner may answer refused or undecidable, but never planned.
    if (answer.arrangement == Tri::Satisfied) {
      CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Planned, context);
    } else if (answer.arrangement == Tri::Violated) {
      CSP_EXPECT_MSG(plan.outcome != PlanOutcome::Planned, context);
      if (!answer.any_unknown_candidate) {
        CSP_EXPECT_MSG(plan.outcome == PlanOutcome::Refused, context);
      }
    } else {
      CSP_EXPECT_MSG(plan.outcome != PlanOutcome::Refused, context);
    }
    if (plan.outcome == PlanOutcome::Refused) {
      CSP_EXPECT_MSG(answer.arrangement != Tri::Satisfied, context);
    }

    // An indeterminate answer is never published as a plan, and with one obligation in
    // the request it is never a partly placed one either.
    CSP_EXPECT_EQ(plan_is_applicable(plan), plan.outcome == PlanOutcome::Planned);
    if (plan.outcome == PlanOutcome::Indeterminate) {
      CSP_REQUIRE(!plan.obligations.empty());
      CSP_EXPECT_MSG(plan.obligations[0].placements.empty(), context);
    }
  }
  CSP_EXPECT_MSG(planned + refused + indeterminate == iterations, "outcome accounting");
  CSP_EXPECT_MSG(planned > 0 && refused > 0 && indeterminate > 0,
                 "the generator produced no variety: planned=" + std::to_string(planned) +
                     " refused=" + std::to_string(refused) + " indeterminate=" + std::to_string(indeterminate));
  std::printf("      property: %llu fleets, planned=%zu refused=%zu indeterminate=%zu\n",
              static_cast<unsigned long long>(iterations), planned, refused, indeterminate);
  std::fflush(stdout);
}

CSP_TEST(property, every_published_plan_satisfies_every_hard_rule) {
  csp_test::SeededRandom random(0xBEEF1234ULL);
  const std::uint64_t iterations = 300;
  std::size_t checked_plans = 0;
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    const Generated generated = generate(random);
    Result<PlacementPlan> planned_result = run(generated);
    CSP_REQUIRE(planned_result.has_value());
    const PlacementPlan& plan = planned_result.value();
    if (plan.outcome != PlanOutcome::Planned) {
      continue;
    }
    ++checked_plans;
    const std::string context = "iteration " + std::to_string(iteration) + ": " + describe(model_answer(generated.request,
                                                                                                       generated.snapshot,
                                                                                                       generated.policy),
                                                                                           plan);
    const ModelDomains domains(generated.snapshot);
    CSP_REQUIRE(!plan.obligations.empty());
    const ObligationPlacement& placed = plan.obligations[0];
    const Obligation& obligation = generated.request.obligations[0];
    CSP_EXPECT_MSG(placed.outcome == Tri::Satisfied, context);
    CSP_EXPECT_EQ(placed.placements.size(),
                  static_cast<std::size_t>(obligation.primary_placements + obligation.recovery_placements));

    for (const SitePlacement& placement : placed.placements) {
      const std::vector<SiteId>& allow =
          !obligation.allowed_sites.empty() ? obligation.allowed_sites : generated.request.allowed_sites;
      if (!allow.empty()) {
        CSP_EXPECT_MSG(std::find(allow.begin(), allow.end(), placement.site) != allow.end(),
                       context + " | " + placement.site.value() + " is not on the allow list");
      }
      CSP_EXPECT_MSG(std::find(obligation.forbidden_sites.begin(), obligation.forbidden_sites.end(),
                               placement.site) == obligation.forbidden_sites.end(),
                     context + " | " + placement.site.value() + " is on the obligation deny list");
      CSP_EXPECT_MSG(std::find(generated.request.forbidden_sites.begin(), generated.request.forbidden_sites.end(),
                               placement.site) == generated.request.forbidden_sites.end(),
                     context + " | " + placement.site.value() + " is on the request deny list");

      // The placed site is one the model also calls admissible, read from the evidence
      // rather than from the plan.
      const SiteRecord* record = nullptr;
      for (const SiteRecord& site : generated.snapshot.sites) {
        if (site.site == placement.site) {
          record = &site;
        }
      }
      CSP_REQUIRE_MSG(record != nullptr, context + " | the plan names a site the evidence does not describe");
      const SiteView view =
          assess_site(generated.request, obligation, generated.policy, generated.snapshot, *record);
      CSP_EXPECT_MSG(view.verdict == Tri::Satisfied,
                     context + " | " + placement.site.value() + " is " + to_string(view.verdict) + " by " +
                         view.rule);
      CSP_EXPECT_EQ(placement.capacity_required.units(), obligation.required_capacity.units());

      Quantity evidenced = Quantity::from_units(0);
      for (const CapacityRecord& capacity : generated.snapshot.capacity) {
        if (capacity.site == placement.site && capacity.service_class == obligation.service_class &&
            capacity.available.is_known()) {
          evidenced = Quantity::from_units(evidenced.units() + capacity.available.value().units());
        }
      }
      CSP_EXPECT_MSG(evidenced.units() >= obligation.required_capacity.units(),
                     context + " | the evidence does not report the capacity the plan claims");

      // The ancestry the plan records is the one the model resolves from the raw
      // containment and alias records.
      CSP_EXPECT_MSG(same_domain_refs(placement.domains, domains.ancestry(placement.site)),
                     context + " | the recorded ancestry of " + placement.site.value() + " differs");
    }

    for (std::size_t lhs = 0; lhs < placed.placements.size(); ++lhs) {
      for (std::size_t rhs = lhs + 1; rhs < placed.placements.size(); ++rhs) {
        for (const SeparationRequirement& requirement : obligation.separations) {
          if (!covers(requirement, placed.placements[lhs].role, placed.placements[rhs].role)) {
            continue;
          }
          const Verdict verdict = domains.separate(placed.placements[lhs].site, placed.placements[rhs].site,
                                                   requirement.separated_kinds,
                                                   requirement.forbidden_shared_domains);
          CSP_EXPECT_MSG(verdict == Tri::Satisfied,
                         context + " | separation between " + placed.placements[lhs].site.value() + " and " +
                             placed.placements[rhs].site.value() + " is " + to_string(verdict));
        }
      }
    }
  }
  CSP_EXPECT_MSG(checked_plans > 0,
                 "no plan was published in " + std::to_string(iterations) + " generated fleets");
  std::printf("      property: %llu fleets, %zu published plans re-checked against the raw evidence\n",
              static_cast<unsigned long long>(iterations), checked_plans);
  std::fflush(stdout);
}

CSP_TEST(property, planning_is_deterministic_and_order_independent) {
  csp_test::SeededRandom random(0xD37E4D11ULL);
  const std::uint64_t iterations = 250;
  std::size_t compared = 0;
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    const Generated generated = generate(random);
    Result<PlacementPlan> first = run(generated);
    Result<PlacementPlan> second = run(generated);
    CSP_REQUIRE(first.has_value());
    CSP_REQUIRE(second.has_value());
    const std::string context = "iteration " + std::to_string(iteration);
    Result<std::string> first_bytes = plan_canonical_bytes(first.value());
    Result<std::string> second_bytes = plan_canonical_bytes(second.value());
    CSP_REQUIRE(first_bytes.has_value());
    CSP_REQUIRE(second_bytes.has_value());
    CSP_EXPECT_MSG(first_bytes.value() == second_bytes.value(), context + ": two runs disagree");
    CSP_EXPECT_MSG(first.value().plan.value() == second.value().plan.value(), context + ": identities differ");
    CSP_EXPECT_MSG(first.value().digest.to_hex() == second.value().digest.to_hex(), context + ": digests differ");

    Generated permuted = generated;
    permute(permuted.snapshot.sites, random);
    permute(permuted.snapshot.failure_domains, random);
    permute(permuted.snapshot.domain_assignments, random);
    permute(permuted.snapshot.domain_aliases, random);
    permute(permuted.snapshot.capacity, random);
    permute(permuted.snapshot.latency, random);
    permute(permuted.snapshot.recovery, random);
    permute(permuted.snapshot.compatibility, random);
    permute(permuted.snapshot.cost_risk, random);
    permute(permuted.request.obligations, random);
    permute(permuted.request.allowed_sites, random);
    permute(permuted.request.forbidden_sites, random);
    for (Obligation& obligation : permuted.request.obligations) {
      permute(obligation.allowed_jurisdictions, random);
      permute(obligation.allowed_sites, random);
      permute(obligation.forbidden_sites, random);
      permute(obligation.separations, random);
      permute(obligation.latency_requirements, random);
      for (SeparationRequirement& separation : obligation.separations) {
        permute(separation.separated_kinds, random);
        permute(separation.forbidden_shared_domains, random);
      }
    }
    Result<PlacementPlan> third = run(permuted);
    CSP_REQUIRE(third.has_value());
    Result<std::string> third_bytes = plan_canonical_bytes(third.value());
    CSP_REQUIRE(third_bytes.has_value());
    CSP_EXPECT_MSG(first_bytes.value() == third_bytes.value(),
                   context + ": permuting every input vector changed the plan");
    CSP_EXPECT_MSG(first.value().plan.value() == third.value().plan.value(),
                   context + ": permuting every input vector changed the identity");
    ++compared;
  }
  CSP_EXPECT_EQ(compared, static_cast<std::size_t>(iterations));
  std::printf("      property: %llu fleets planned twice and once more under permutation\n",
              static_cast<unsigned long long>(iterations));
  std::fflush(stdout);
}

CSP_TEST(property, every_generated_document_round_trips) {
  csp_test::SeededRandom random(0x5EEDF00DULL);
  const std::uint64_t iterations = 200;
  std::size_t documents = 0;
  std::size_t plans = 0;
  for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
    const Generated generated = generate(random);
    const std::string context = "iteration " + std::to_string(iteration);

    Result<std::string> request_bytes = request_to_document(generated.request, false);
    CSP_REQUIRE(request_bytes.has_value());
    Result<PlacementRequest> request_again = request_from_document(request_bytes.value(), Limits{});
    CSP_REQUIRE_MSG(request_again.has_value(), context + ": " + request_again.error().render());
    Result<std::string> request_second = request_to_document(request_again.value(), false);
    CSP_REQUIRE(request_second.has_value());
    CSP_EXPECT_MSG(request_second.value() == request_bytes.value(), context + ": request round trip");
    CSP_EXPECT_EQ(request_again.value().obligations.size(), generated.request.obligations.size());
    ++documents;

    Result<std::string> snapshot_bytes = snapshot_to_document(generated.snapshot, false);
    CSP_REQUIRE(snapshot_bytes.has_value());
    Result<SiteEvidenceSnapshot> snapshot_again = snapshot_from_document(snapshot_bytes.value(), Limits{});
    CSP_REQUIRE_MSG(snapshot_again.has_value(), context + ": " + snapshot_again.error().render());
    Result<std::string> snapshot_second = snapshot_to_document(snapshot_again.value(), false);
    CSP_REQUIRE(snapshot_second.has_value());
    CSP_EXPECT_MSG(snapshot_second.value() == snapshot_bytes.value(), context + ": snapshot round trip");
    CSP_EXPECT_EQ(snapshot_again.value().sites.size(), generated.snapshot.sites.size());
    CSP_EXPECT_EQ(snapshot_again.value().capacity.size(), generated.snapshot.capacity.size());
    ++documents;

    Result<std::string> policy_bytes = policy_to_document(generated.policy, false);
    CSP_REQUIRE(policy_bytes.has_value());
    Result<PlacementPolicy> policy_again = policy_from_document(policy_bytes.value(), Limits{});
    CSP_REQUIRE(policy_again.has_value());
    Result<std::string> policy_second = policy_to_document(policy_again.value(), false);
    CSP_REQUIRE(policy_second.has_value());
    CSP_EXPECT_MSG(policy_second.value() == policy_bytes.value(), context + ": policy round trip");
    ++documents;

    Result<PlacementPlan> planned = run(generated);
    CSP_REQUIRE(planned.has_value());
    Result<std::string> plan_bytes = plan_to_document(planned.value(), false);
    CSP_REQUIRE(plan_bytes.has_value());
    Result<PlacementPlan> plan_again = plan_from_document(plan_bytes.value(), Limits{});
    CSP_REQUIRE_MSG(plan_again.has_value(), context + ": " + plan_again.error().render());
    Result<std::string> plan_second = plan_to_document(plan_again.value(), false);
    CSP_REQUIRE(plan_second.has_value());
    CSP_EXPECT_MSG(plan_second.value() == plan_bytes.value(), context + ": plan round trip");
    CSP_EXPECT_EQ(plan_again.value().outcome, planned.value().outcome);
    CSP_EXPECT_EQ(plan_again.value().plan.value(), planned.value().plan.value());
    CSP_EXPECT_EQ(plan_again.value().digest.to_hex(), planned.value().digest.to_hex());
    // The canonical bytes the digest covers are a function of the value alone, so equal
    // bytes after a round trip is an equality check on the value.
    Result<std::string> canonical_first = plan_canonical_bytes(planned.value());
    Result<std::string> canonical_again = plan_canonical_bytes(plan_again.value());
    CSP_REQUIRE(canonical_first.has_value() && canonical_again.has_value());
    CSP_EXPECT_MSG(canonical_first.value() == canonical_again.value(), context + ": canonical bytes round trip");
    ++plans;
  }
  CSP_EXPECT_EQ(documents, static_cast<std::size_t>(iterations) * 3);
  CSP_EXPECT_EQ(plans, static_cast<std::size_t>(iterations));
  std::printf("      property: %zu documents and %zu plans round-tripped through encode then decode\n", documents,
              plans);
  std::fflush(stdout);
}
