// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// benchmark_planning: what a completed planning operation costs on this machine.
//
// What is measured, and what is not:
//   * Only completed operations are timed. A planning call is synchronous, so the
//     interval around it is the interval during which the planner finished the work;
//     there is no queue and no submission latency to accidentally measure instead.
//   * Every number is synthetic. The snapshots come from a fixed seed and a fixed
//     shape, so two runs measure the same work, and nothing here describes a real fleet.
//   * The clock is std::chrono::steady_clock. Wall-clock time and CPU time are not
//     interchangeable, and a process that reports one while calling it the other is
//     reporting a number it did not measure.
//   * A run that does not complete a plan is a failure of the benchmark, not a datum:
//     it is reported and the exit status is nonzero.
//
// The durable half of the boundary is measured separately and labelled as such, because
// encoding a plan and committing it to a store are different operations with different
// costs from planning one.
//
// usage: csp-benchmark [--scale=small|full] [--help]

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"

namespace {

constexpr std::int64_t kObservedAtNanos = 1700000000000000000LL;
constexpr std::uint64_t kSeed = 20260501ULL;

int fail(const std::string& message) {
  std::cerr << "csp-benchmark: " << message << '\n';
  return 1;
}

template <class IdType>
IdType make_id(const std::string& text) {
  csp::Result<IdType> parsed = IdType::parse(text);
  if (!parsed) {
    std::cerr << "csp-benchmark: " << parsed.error().render() << '\n';
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

/// A deterministic sequence of values drawn from a fixed seed. std::mt19937_64's bit
/// stream is fixed by the standard; the distribution adapters are not used because their
/// mapping from bits to values is implementation-defined, which would make two standard
/// libraries measure two different fleets.
class Generator {
 public:
  explicit Generator(std::uint64_t seed) : engine_(seed) {}

  std::uint64_t below(std::uint64_t bound) { return bound == 0 ? 0 : engine_() % bound; }

 private:
  std::mt19937_64 engine_;
};

std::string padded(std::size_t value, std::size_t width) {
  std::string text = std::to_string(value);
  if (text.size() < width) {
    text.insert(text.begin(), width - text.size(), '0');
  }
  return text;
}

/// A snapshot of a fleet that does not exist: one site per index, eight power domains and
/// sixteen geography domains cycled by index, one commitment of capacity and one
/// compatibility record per site, and a cost and risk record per site. Fully determined
/// by the site count and the fixed seed.
csp::SiteEvidenceSnapshot build_snapshot(std::size_t site_count) {
  csp::SiteEvidenceSnapshot evidence;
  evidence.generation = csp::Generation::from_value(101);
  evidence.captured_at = observed_at();

  const csp::ServiceClassId service = make_id<csp::ServiceClassId>("class-web");
  const std::size_t power_domains = 8;
  const std::size_t geography_domains = 16;

  Generator generator(kSeed);
  std::vector<csp::FailureDomainId> power;
  power.reserve(power_domains);
  for (std::size_t index = 0; index < power_domains; ++index) {
    power.push_back(make_id<csp::FailureDomainId>("power-" + padded(index, 2)));
    csp::FailureDomainRecord record;
    record.domain = power.back();
    record.kind = csp::DomainKind::Power;
    record.provenance = provenance("failure-domain-registry", "domain-observation-" + power.back().value(), 5);
    evidence.failure_domains.push_back(std::move(record));
  }
  std::vector<csp::FailureDomainId> geography;
  geography.reserve(geography_domains);
  for (std::size_t index = 0; index < geography_domains; ++index) {
    geography.push_back(make_id<csp::FailureDomainId>("geography-" + padded(index, 2)));
    csp::FailureDomainRecord record;
    record.domain = geography.back();
    record.kind = csp::DomainKind::Geography;
    record.provenance = provenance("failure-domain-registry", "domain-observation-" + geography.back().value(), 5);
    evidence.failure_domains.push_back(std::move(record));
  }

  evidence.sites.reserve(site_count);
  evidence.capacity.reserve(site_count);
  evidence.compatibility.reserve(site_count);
  evidence.cost_risk.reserve(site_count);
  evidence.domain_assignments.reserve(site_count * 2);

  for (std::size_t index = 0; index < site_count; ++index) {
    const std::string name = "site-" + padded(index, 8);
    const csp::SiteId site = make_id<csp::SiteId>(name);

    csp::SiteRecord site_record;
    site_record.site = site;
    site_record.jurisdiction = make_id<csp::JurisdictionId>("jurisdiction-north");
    site_record.maintenance = csp::Measurement<csp::MaintenanceState>::known(csp::MaintenanceState::Operational);
    site_record.provenance = provenance("site-registry", "site-observation-" + name, 7);
    evidence.sites.push_back(std::move(site_record));

    csp::DomainAssignment power_assignment;
    power_assignment.site = site;
    power_assignment.domain = power[index % power_domains];
    power_assignment.provenance = provenance("failure-domain-registry", "membership-power-" + name, 5);
    evidence.domain_assignments.push_back(std::move(power_assignment));
    csp::DomainAssignment geography_assignment;
    geography_assignment.site = site;
    geography_assignment.domain = geography[index % geography_domains];
    geography_assignment.provenance = provenance("failure-domain-registry", "membership-geography-" + name, 5);
    evidence.domain_assignments.push_back(std::move(geography_assignment));

    csp::CapacityRecord capacity;
    capacity.reference = make_id<csp::CapacityRefId>("capacity-" + name);
    capacity.site = site;
    capacity.service_class = service;
    capacity.kind = csp::CapacityKind::Commitment;
    capacity.available = csp::Measurement<csp::Quantity>::known(
        csp::Quantity::from_units(static_cast<std::int64_t>(64 + generator.below(64))));
    capacity.provenance = provenance("capacity-authority", "capacity-observation-" + name, 7);
    evidence.capacity.push_back(std::move(capacity));

    csp::CompatibilityRecord compatibility;
    compatibility.reference = make_id<csp::EvidenceId>("compatibility-" + name);
    compatibility.site = site;
    compatibility.service_class = service;
    compatibility.compatible = csp::Measurement<bool>::known(true);
    compatibility.provenance = provenance("compatibility-registry", "compatibility-observation-" + name, 7);
    evidence.compatibility.push_back(std::move(compatibility));

    csp::CostRiskRecord cost;
    cost.reference = make_id<csp::EvidenceId>("cost-" + name);
    cost.site = site;
    cost.service_class = service;
    cost.cost_per_unit = csp::Measurement<csp::Quantity>::known(
        csp::Quantity::from_units(static_cast<std::int64_t>(10 + generator.below(90))));
    cost.risk_per_mille = csp::Measurement<std::int64_t>::known(static_cast<std::int64_t>(generator.below(1001)));
    cost.provenance = provenance("cost-ledger", "cost-observation-" + name, 7);
    evidence.cost_risk.push_back(std::move(cost));
  }
  return evidence;
}

csp::PlacementPolicy build_policy() {
  csp::PlacementPolicy policy;
  policy.policy = make_id<csp::PolicyId>("policy-benchmark");
  policy.generation = csp::Generation::from_value(3);
  return policy;
}

/// Two obligations, two primary placements each, separated by power domain, with cost and
/// risk as the preference order. The preference order is what makes the planner assess
/// and order every candidate site, so the measured work scales with the fleet rather than
/// stopping at the first two sites it happens to try.
csp::PlacementRequest build_request(const csp::PlacementPolicy& policy, std::size_t obligations,
                                    const std::string& name) {
  csp::PlacementRequest request;
  request.request = make_id<csp::RequestId>(name);
  request.generation = csp::Generation::from_value(2);
  request.policy.policy = policy.policy;
  request.policy.generation = policy.generation;
  request.preferences.objectives = {csp::Preferences::Objective::MinimiseCost,
                                    csp::Preferences::Objective::MinimiseRisk};

  for (std::size_t index = 0; index < obligations; ++index) {
    csp::Obligation obligation;
    obligation.obligation = make_id<csp::ObligationId>("obligation-" + padded(index, 3));
    obligation.service_class = make_id<csp::ServiceClassId>("class-web");
    obligation.required_capacity = csp::Quantity::from_units(4);
    obligation.primary_placements = 2;
    csp::SeparationRequirement separation;
    separation.group = csp::SeparationGroup::All;
    separation.separated_kinds.push_back(csp::DomainKind::Power);
    obligation.separations.push_back(std::move(separation));
    request.obligations.push_back(std::move(obligation));
  }
  return request;
}

std::uint64_t nanos_between(std::chrono::steady_clock::time_point start,
                            std::chrono::steady_clock::time_point finish) {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(finish - start).count());
}

struct Summary {
  std::uint64_t median_ns = 0;
  std::uint64_t min_ns = 0;
};

/// The median is the lower middle of the sorted samples. With an even count there is no
/// single middle sample, and averaging two integers would report a value that was never
/// measured; the lower one was.
Summary summarize(std::vector<std::uint64_t> samples) {
  Summary summary;
  if (samples.empty()) {
    return summary;
  }
  std::sort(samples.begin(), samples.end());
  summary.min_ns = samples.front();
  summary.median_ns = samples[samples.size() / 2];
  return summary;
}

/// A directory under the system temporary directory that removes itself. The store is
/// durable by design, so a benchmark that left one behind would change what the next run
/// measures.
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

 private:
  std::filesystem::path path_;
};

struct Rung {
  std::size_t sites = 0;
  std::size_t obligations = 0;
  std::size_t reps = 0;
};

std::vector<Rung> ladder(bool full) {
  std::vector<Rung> rungs{
      Rung{1000, 2, 11},
      Rung{5000, 2, 7},
      Rung{20000, 2, 3},
  };
  if (full) {
    rungs.push_back(Rung{50000, 2, 3});
  }
  return rungs;
}

void print_usage(std::ostream& out) {
  out << "usage: csp-benchmark [--scale=small|full] [--help]\n"
      << "\n"
      << "  --scale=small  1000, 5000, and 20000 sites (the default; a run takes seconds)\n"
      << "  --scale=full   the same ladder plus 50000 sites\n"
      << "\n"
      << "Every number printed is measured with std::chrono::steady_clock on this machine\n"
      << "from synthetic inputs built from a fixed seed.\n";
}

}  // namespace

int main(int argc, char** argv) {
  bool full = false;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--help" || argument == "-h") {
      print_usage(std::cout);
      return 0;
    }
    if (argument == "--scale=small" || argument == "--scale" ) {
      continue;
    }
    if (argument == "--scale=full") {
      full = true;
      continue;
    }
    if (argument == "small") {
      continue;
    }
    if (argument == "full") {
      full = true;
      continue;
    }
    print_usage(std::cerr);
    return fail("unknown argument \"" + argument + "\"");
  }

  std::cout << "SYNTHETIC: every number below was measured on this machine from fleets generated by a fixed "
               "seed; none of it describes a real deployment.\n";
  std::cout << "scale: " << (full ? "full" : "small") << '\n';
  std::cout << "clock: std::chrono::steady_clock, nanoseconds\n";
  std::cout << '\n';
  std::cout << "planning (one completed planner.plan call, end to end):\n";
  std::cout << std::left << std::setw(8) << "sites" << std::setw(14) << "obligations" << std::setw(12)
            << "placements" << std::setw(6) << "reps" << std::setw(14) << "median_ns" << std::setw(14) << "min_ns"
            << std::setw(16) << "nodes_explored" << '\n';

  const csp::Planner planner;
  const csp::PlacementPolicy policy = build_policy();
  csp::PlanningContext context;
  context.evaluation_instant = observed_at();

  std::vector<csp::PlacementPlan> plans;
  std::size_t largest_sites = 0;
  for (const Rung& rung : ladder(full)) {
    const csp::SiteEvidenceSnapshot evidence = build_snapshot(rung.sites);
    const csp::PlacementRequest request = build_request(policy, rung.obligations, "request-benchmark");
    std::vector<std::uint64_t> samples;
    samples.reserve(rung.reps);
    std::size_t placements = 0;
    std::uint64_t nodes = 0;
    for (std::size_t rep = 0; rep < rung.reps; ++rep) {
      const auto start = std::chrono::steady_clock::now();
      const csp::Result<csp::PlacementPlan> planned = planner.plan(request, evidence, policy, context);
      const auto finish = std::chrono::steady_clock::now();
      if (!planned) {
        return fail("planning failed at " + std::to_string(rung.sites) + " sites: " + planned.error().render());
      }
      if (planned.value().outcome != csp::PlanOutcome::Planned) {
        return fail("the plan at " + std::to_string(rung.sites) + " sites is " +
                    csp::to_string(planned.value().outcome) + ", so there is no completed operation to time");
      }
      samples.push_back(nanos_between(start, finish));
      placements = 0;
      for (const csp::ObligationPlacement& entry : planned.value().obligations) {
        placements += entry.placements.size();
      }
      nodes = planned.value().nodes_explored;
      if (rep + 1 == rung.reps) {
        plans.push_back(planned.value());
        largest_sites = rung.sites;
      }
    }
    const Summary summary = summarize(samples);
    std::cout << std::left << std::setw(8) << rung.sites << std::setw(14) << rung.obligations << std::setw(12)
              << placements << std::setw(6) << rung.reps << std::setw(14) << summary.median_ns << std::setw(14)
              << summary.min_ns << std::setw(16) << nodes << '\n';
  }

  // The durable operations, measured separately because they are different work.
  std::cout << '\n';
  std::cout << "durable plan operations (labelled separately; not part of the planning numbers above):\n";
  std::cout << std::left << std::setw(16) << "operation" << std::setw(30) << "work" << std::setw(6) << "reps"
            << std::setw(14) << "median_ns" << std::setw(14) << "min_ns" << std::setw(10) << "bytes" << '\n';

  if (plans.empty()) {
    return fail("no plan was produced, so there is nothing durable to measure");
  }
  const csp::PlacementPlan& largest = plans.back();

  std::vector<std::uint64_t> encode_samples;
  std::size_t encoded_bytes = 0;
  for (std::size_t rep = 0; rep < (full ? 11 : 7); ++rep) {
    const auto start = std::chrono::steady_clock::now();
    const csp::Result<std::string> document = csp::plan_to_document(largest, false);
    // The digest covers the canonical bytes, which are not the document: the document also
    // carries the identity and the digest itself, and hashing those would be circular.
    const csp::Result<std::string> canonical = csp::plan_canonical_bytes(largest);
    const csp::Digest digest = csp::Digest::of(canonical.value_or(std::string()));
    const auto finish = std::chrono::steady_clock::now();
    if (!document) {
      return fail("encoding the plan document failed: " + document.error().render());
    }
    if (!canonical) {
      return fail("encoding the plan's canonical bytes failed: " + canonical.error().render());
    }
    if (digest != largest.digest) {
      return fail("the digest computed over the canonical bytes does not match the plan digest");
    }
    encoded_bytes = document.value().size();
    encode_samples.push_back(nanos_between(start, finish));
  }
  const Summary encode = summarize(encode_samples);
  std::cout << std::left << std::setw(16) << "encode+digest"
            << std::setw(30) << ("plan from " + std::to_string(largest_sites) + " sites")
            << std::setw(6) << encode_samples.size() << std::setw(14) << encode.median_ns << std::setw(14)
            << encode.min_ns << std::setw(10) << encoded_bytes << '\n';

  // A full durable commit of distinct plans. Committing one plan twice is idempotent and
  // writes nothing the second time, so distinct plans are what make each sample a real
  // commit rather than a re-read.
  const std::size_t commit_reps = full ? 16 : 8;
  const std::size_t commit_sites = 256;
  const TemporaryDirectory store_directory(std::filesystem::temp_directory_path() /
                                           "csp-benchmark-planning-store");
  std::vector<csp::PlacementPlan> commit_plans;
  commit_plans.reserve(commit_reps);
  {
    const csp::SiteEvidenceSnapshot evidence = build_snapshot(commit_sites);
    for (std::size_t index = 0; index < commit_reps; ++index) {
      const csp::PlacementRequest request =
          build_request(policy, 2, "request-commit-" + padded(index, 4));
      const csp::Result<csp::PlacementPlan> planned = planner.plan(request, evidence, policy, context);
      if (!planned || planned.value().outcome != csp::PlanOutcome::Planned) {
        return fail("preparing distinct plans for the commit measurement failed");
      }
      commit_plans.push_back(planned.value());
    }
  }

  csp::StoreOptions options;
  options.directory = store_directory.path().string();
  csp::Result<csp::PlanStore> opened = csp::PlanStore::open(options);
  if (!opened) {
    return fail("opening the benchmark store failed: " + opened.error().render());
  }
  csp::PlanStore store = std::move(opened).value();

  std::vector<std::uint64_t> commit_samples;
  commit_samples.reserve(commit_reps);
  for (const csp::PlacementPlan& plan : commit_plans) {
    const auto start = std::chrono::steady_clock::now();
    const csp::Result<csp::PlanId> identity = store.commit(plan);
    const auto finish = std::chrono::steady_clock::now();
    if (!identity) {
      return fail("committing a benchmark plan failed: " + identity.error().render());
    }
    commit_samples.push_back(nanos_between(start, finish));
  }
  const Summary commit = summarize(commit_samples);
  std::size_t record_bytes = 0;
  std::size_t records = 0;
  {
    const csp::Result<csp::StoreAudit> audit = store.audit();
    if (!audit) {
      return fail("auditing the benchmark store failed: " + audit.error().render());
    }
    if (!audit.value().consistent) {
      return fail("the benchmark store audit reports an inconsistent store");
    }
    record_bytes = audit.value().record_bytes;
    records = audit.value().records.size();
  }
  const csp::Status closed = store.close();
  if (!closed) {
    return fail("closing the benchmark store failed: " + closed.error().render());
  }

  std::cout << std::left << std::setw(16) << "store-commit"
            << std::setw(30) << ("distinct plans, " + std::to_string(commit_sites) + " sites")
            << std::setw(6) << commit_samples.size() << std::setw(14) << commit.median_ns << std::setw(14)
            << commit.min_ns << std::setw(10) << record_bytes << '\n';

  std::error_code code;
  std::filesystem::remove_all(store_directory.path(), code);
  std::cout << "store: " << records << " records, " << record_bytes << " record bytes, directory removed: "
            << (std::filesystem::exists(store_directory.path()) ? "no" : "yes") << '\n';
  return 0;
}
