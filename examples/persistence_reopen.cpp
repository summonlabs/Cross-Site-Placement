// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// persistence_reopen: commit plans to a durable store, close it, reopen it, load each plan
// back, and report the audit. The store lives in a directory under the system temporary
// directory and is removed when the program ends, whether it succeeded or not.

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"

namespace {

constexpr std::int64_t kObservedAtNanos = 1700000000000000000LL;

int fail(const std::string& message) {
  std::cerr << "persistence_reopen: " << message << '\n';
  return 1;
}

template <class IdType>
IdType make_id(const std::string& text) {
  csp::Result<IdType> parsed = IdType::parse(text);
  if (!parsed) {
    std::cerr << "persistence_reopen: " << parsed.error().render() << '\n';
    std::exit(1);
  }
  return std::move(parsed).value();
}

csp::Instant observed_at() { return csp::Instant::from_nanos(kObservedAtNanos); }

csp::Provenance provenance(const std::string& authority, const std::string& record, std::uint64_t generation) {
  csp::Provenance provenance;
  provenance.source_record = make_id<csp::EvidenceId>(record);
  provenance.authority = make_id<csp::AuthorityId>(authority);
  provenance.authority_generation = csp::Generation::from_value(generation);
  provenance.observed_at = observed_at();
  return provenance;
}

/// A directory that cleans up after itself. The store is durable, so this example has to
/// be explicit about removing the evidence of its own run: leaving it behind would make a
/// second run read the first run's records.
class TemporaryDirectory {
 public:
  explicit TemporaryDirectory(std::filesystem::path path) : path_(std::move(path)) {
    std::error_code code;
    std::filesystem::remove_all(path_, code);
  }

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  ~TemporaryDirectory() {
    std::error_code code;
    std::filesystem::remove_all(path_, code);
  }

  const std::filesystem::path& path() const { return path_; }

  /// Removes the directory now, so that a run can report that it did. The destructor
  /// calls this again, which is harmless.
  void remove() const {
    std::error_code code;
    std::filesystem::remove_all(path_, code);
  }

 private:
  std::filesystem::path path_;
};

csp::SiteEvidenceSnapshot build_fleet() {
  csp::SiteEvidenceSnapshot evidence;
  evidence.generation = csp::Generation::from_value(51);
  evidence.captured_at = observed_at();

  const csp::FailureDomainId power_one = make_id<csp::FailureDomainId>("power-one");
  const csp::FailureDomainId power_two = make_id<csp::FailureDomainId>("power-two");
  const csp::JurisdictionId jurisdiction = make_id<csp::JurisdictionId>("jurisdiction-north");
  const csp::ServiceClassId service = make_id<csp::ServiceClassId>("class-web");

  for (const csp::FailureDomainId& domain : {power_one, power_two}) {
    csp::FailureDomainRecord record;
    record.domain = domain;
    record.kind = csp::DomainKind::Power;
    record.provenance = provenance("failure-domain-registry", "domain-observation-" + domain.value(), 5);
    evidence.failure_domains.push_back(std::move(record));
  }

  const std::vector<std::pair<std::string, csp::FailureDomainId>> assignments{
      {"site-one", power_one},
      {"site-two", power_two},
  };
  for (const std::pair<std::string, csp::FailureDomainId>& entry : assignments) {
    const std::string& name = entry.first;
    const csp::SiteId site = make_id<csp::SiteId>(name);

    csp::SiteRecord site_record;
    site_record.site = site;
    site_record.jurisdiction = jurisdiction;
    site_record.maintenance = csp::Measurement<csp::MaintenanceState>::known(csp::MaintenanceState::Operational);
    site_record.provenance = provenance("site-registry", "site-observation-" + name, 7);
    evidence.sites.push_back(std::move(site_record));

    csp::DomainAssignment assignment;
    assignment.site = site;
    assignment.domain = entry.second;
    assignment.provenance = provenance("failure-domain-registry", "membership-" + name, 5);
    evidence.domain_assignments.push_back(std::move(assignment));

    csp::CapacityRecord capacity;
    capacity.reference = make_id<csp::CapacityRefId>("capacity-" + name);
    capacity.site = site;
    capacity.service_class = service;
    capacity.kind = csp::CapacityKind::Commitment;
    capacity.available = csp::Measurement<csp::Quantity>::known(csp::Quantity::from_units(16));
    capacity.provenance = provenance("capacity-authority", "capacity-observation-" + name, 7);
    evidence.capacity.push_back(std::move(capacity));

    csp::CompatibilityRecord compatibility;
    compatibility.reference = make_id<csp::EvidenceId>("compatibility-" + name);
    compatibility.site = site;
    compatibility.service_class = service;
    compatibility.compatible = csp::Measurement<bool>::known(true);
    compatibility.provenance = provenance("compatibility-registry", "compatibility-observation-" + name, 7);
    evidence.compatibility.push_back(std::move(compatibility));
  }
  return evidence;
}

csp::PlacementPolicy build_policy() {
  csp::PlacementPolicy policy;
  policy.policy = make_id<csp::PolicyId>("policy-regional-default");
  policy.generation = csp::Generation::from_value(9);
  return policy;
}

csp::PlacementRequest build_request(const csp::PlacementPolicy& policy, const std::string& name,
                                    std::uint64_t generation) {
  csp::PlacementRequest request;
  request.request = make_id<csp::RequestId>(name);
  request.generation = csp::Generation::from_value(generation);
  request.policy.policy = policy.policy;
  request.policy.generation = policy.generation;

  csp::Obligation obligation;
  obligation.obligation = make_id<csp::ObligationId>("obligation-" + name);
  obligation.service_class = make_id<csp::ServiceClassId>("class-web");
  obligation.required_capacity = csp::Quantity::from_units(4);
  obligation.primary_placements = 2;
  csp::SeparationRequirement separation;
  separation.group = csp::SeparationGroup::All;
  separation.separated_kinds.push_back(csp::DomainKind::Power);
  obligation.separations.push_back(std::move(separation));
  request.obligations.push_back(std::move(obligation));
  return request;
}

/// The plan as the store holds it: the canonical bytes, so a comparison here is a
/// comparison of what was written and not of two in-memory objects that happen to agree.
std::string canonical(const csp::PlacementPlan& plan) {
  csp::Result<std::string> bytes = csp::plan_canonical_bytes(plan);
  if (!bytes) {
    std::cerr << "persistence_reopen: " << bytes.error().render() << '\n';
    std::exit(1);
  }
  return std::move(bytes).value();
}

csp::StoreOptions store_options(const TemporaryDirectory& scratch) {
  csp::StoreOptions options;
  options.directory = scratch.path().string();
  return options;
}

}  // namespace

int main() {
  const TemporaryDirectory scratch(std::filesystem::temp_directory_path() / "csp-example-persistence-reopen");
  std::cout << "store directory: " << scratch.path().string() << '\n';

  const csp::SiteEvidenceSnapshot evidence = build_fleet();
  const csp::PlacementPolicy policy = build_policy();
  const csp::Planner planner;
  csp::PlanningContext context;
  context.evaluation_instant = observed_at();

  std::vector<csp::PlacementPlan> plans;
  for (const std::pair<std::string, std::uint64_t>& entry :
       {std::pair<std::string, std::uint64_t>{"request-store-one", 11},
        std::pair<std::string, std::uint64_t>{"request-store-two", 12}}) {
    const csp::PlacementRequest request = build_request(policy, entry.first, entry.second);
    const csp::Result<csp::PlacementPlan> planned = planner.plan(request, evidence, policy, context);
    if (!planned) {
      return fail("planning " + entry.first + " failed: " + planned.error().render());
    }
    if (!csp::plan_is_applicable(planned.value())) {
      return fail("planning " + entry.first + " did not produce an applicable plan");
    }
    plans.push_back(planned.value());
  }

  std::vector<csp::PlanId> committed;
  {
    csp::Result<csp::PlanStore> opened = csp::PlanStore::open(store_options(scratch));
    if (!opened) {
      return fail("opening the store failed: " + opened.error().render());
    }
    csp::PlanStore store = std::move(opened).value();
    for (const csp::PlacementPlan& plan : plans) {
      const csp::Result<csp::PlanId> identity = store.commit(plan);
      if (!identity) {
        return fail("committing " + plan.plan.value() + " failed: " + identity.error().render());
      }
      std::cout << "committed " << identity.value().value() << " at generation " << store.generation().value()
                << '\n';
      committed.push_back(identity.value());
    }
    const csp::Status closed = store.close();
    if (!closed) {
      return fail("closing the store failed: " + closed.error().render());
    }
    std::cout << "store closed\n";
  }

  {
    csp::Result<csp::PlanStore> opened = csp::PlanStore::open(store_options(scratch));
    if (!opened) {
      return fail("reopening the store failed: " + opened.error().render());
    }
    csp::PlanStore store = std::move(opened).value();
    std::cout << "store reopened at generation " << store.generation().value() << '\n';

    const csp::Result<std::vector<csp::PlanId>> listed = store.list();
    if (!listed) {
      return fail("listing the store failed: " + listed.error().render());
    }
    if (listed.value().size() != plans.size()) {
      return fail("the reopened store lists " + std::to_string(listed.value().size()) + " plans, expected " +
                  std::to_string(plans.size()));
    }
    for (const csp::PlanId& identity : listed.value()) {
      std::cout << "listed " << identity.value() << '\n';
    }

    for (std::size_t index = 0; index < committed.size(); ++index) {
      const csp::Result<csp::PlacementPlan> loaded = store.load(committed[index]);
      if (!loaded) {
        return fail("loading " + committed[index].value() + " failed: " + loaded.error().render());
      }
      if (loaded.value().plan != committed[index]) {
        return fail("the loaded plan carries a different identity than the one committed");
      }
      if (loaded.value().digest != plans[index].digest) {
        return fail("the loaded plan digest differs from the committed plan digest");
      }
      if (canonical(loaded.value()) != canonical(plans[index])) {
        return fail("the loaded plan is not byte-identical to the plan that was committed");
      }
      std::cout << "loaded " << loaded.value().plan.value() << " digest " << loaded.value().digest.to_hex()
                << " matches the committed plan byte for byte\n";
    }

    const csp::Result<csp::StoreAudit> audit = store.audit();
    if (!audit) {
      return fail("auditing the store failed: " + audit.error().render());
    }
    if (!audit.value().consistent) {
      return fail("the audit reports an inconsistent store");
    }
    std::cout << "audit: consistent " << (audit.value().consistent ? "true" : "false") << " generation "
              << audit.value().generation.value() << " records " << audit.value().records.size() << " record bytes "
              << audit.value().record_bytes << " manifest digest " << audit.value().manifest_digest.to_hex() << '\n';
    std::cout << "audit recovery findings: " << audit.value().recovery.size() << '\n';
    for (const csp::RecoveryFinding& finding : audit.value().recovery) {
      std::cout << "  " << csp::to_string(finding.action);
      if (!finding.detail.empty()) {
        std::cout << ": " << finding.detail;
      }
      std::cout << '\n';
    }
  }

  scratch.remove();
  std::cout << "removed: " << scratch.path().string() << " (exists: "
            << (std::filesystem::exists(scratch.path()) ? "yes" : "no") << ")\n";
  std::cout << "persistence_reopen ok: every committed plan survived a close and a reopen\n";
  return 0;
}
