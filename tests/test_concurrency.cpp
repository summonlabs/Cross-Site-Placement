// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Concurrency.
//
// Every worker in this file records what it saw and asserts nothing. The harness counts
// checks in plain integers, so a check made from a worker thread would be a data race
// and a required check would throw where nothing can catch it. The threads therefore
// write into slots that belong to them alone, and the case body - which runs on the
// main thread - asserts on what the slots hold once every thread has been joined.

#include "test_harness.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

using namespace csp;

/// The harness offers CSP_REQUIRE for a bare condition and CSP_EXPECT_MSG for a
/// condition with a detail. A randomized or threaded case needs both at once: a
/// required check that names what went wrong before it stops.
#define CSP_REQUIRE_MSG(condition, detail)                                                        \
  do {                                                                                            \
    if (!csp_test::check((condition), #condition, __FILE__, __LINE__, (detail))) {                \
      csp_test::abort_case();                                                                     \
    }                                                                                             \
  } while (false)

namespace {

constexpr std::int64_t kBase = 1700000000000000000LL;

SiteId site_id(const char* text) { return SiteId::parse(text).value(); }
ServiceClassId class_id(const char* text) { return ServiceClassId::parse(text).value(); }
PolicyId policy_id(const char* text) { return PolicyId::parse(text).value(); }
RequestId request_id(const char* text) { return RequestId::parse(text).value(); }
ObligationId obligation_id(const char* text) { return ObligationId::parse(text).value(); }
FailureDomainId domain_id(const char* text) { return FailureDomainId::parse(text).value(); }
EvidenceId evidence_id(const char* text) { return EvidenceId::parse(text).value(); }
AuthorityId authority_id(const char* text) { return AuthorityId::parse(text).value(); }
CapacityRefId capacity_ref_id(const char* text) { return CapacityRefId::parse(text).value(); }

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
    static std::atomic<std::uint64_t> counter{0};
    path_ = std::string(base) + "/csp-concurrency-" + tag + "-" + std::to_string(process_id()) + "-" +
            std::to_string(counter.fetch_add(1));
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
  site.jurisdiction = JurisdictionId::parse("jur-1").value();
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

/// A fleet in which every site sits in its own power domain with capacity and
/// compatibility, so every site is a candidate and separation is decidable.
SiteEvidenceSnapshot fleet(std::size_t count) {
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

SiteEvidenceSnapshot one_site_snapshot() { return fleet(1); }

PlacementRequest request_for(const char* identity, const char* obligation, std::uint64_t generation,
                             std::uint32_t placements) {
  PlacementRequest request;
  request.request = request_id(identity);
  request.generation = Generation::from_value(generation);
  request.policy.policy = policy_id("policy-1");
  request.policy.generation = Generation::from_value(1);

  Obligation entry;
  entry.obligation = obligation_id(obligation);
  entry.service_class = class_id("service-1");
  entry.required_capacity = Quantity::from_units(5);
  entry.primary_placements = placements;
  if (placements > 1) {
    SeparationRequirement separation;
    separation.group = SeparationGroup::All;
    separation.separated_kinds.push_back(DomainKind::Power);
    entry.separations.push_back(std::move(separation));
  }
  request.obligations.push_back(std::move(entry));
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

Result<PlacementPlan> plan_one(const char* identity, const char* obligation, std::uint64_t generation) {
  const Planner planner;
  return planner.plan(request_for(identity, obligation, generation, 1), one_site_snapshot(), acceptance_policy(),
                      instant_context());
}

std::string canonical(const PlacementPlan& plan) {
  Result<std::string> bytes = plan_canonical_bytes(plan);
  return bytes.has_value() ? bytes.value() : std::string("<undecodable>");
}

bool structured_error(const Error& error) {
  return !error.code().empty() && error.category() != ErrorCategory::Internal;
}

StoreOptions options_for(const std::string& directory) {
  StoreOptions options;
  options.directory = directory;
  return options;
}

}  // namespace

CSP_TEST(concurrency, worker_thread_budget_does_not_change_the_answer) {
  // Candidate evaluation is bounded by worker_threads and parallel_threshold, and the
  // answer must not depend on either. The fleet is well past the threshold, so a build
  // that did split the work would take the threaded path here.
  const SiteEvidenceSnapshot snapshot = fleet(700);
  const PlacementRequest request = request_for("request-1", "obligation-1", 1, 3);
  const PlacementPolicy policy = acceptance_policy();
  const PlanningContext context = instant_context();

  std::string baseline;
  std::string baseline_identity;
  for (const std::size_t workers : {std::size_t{0}, std::size_t{1}, std::size_t{2}, std::size_t{4}, std::size_t{8}}) {
    Limits limits;
    limits.worker_threads = workers;
    limits.parallel_threshold = 64;
    const Planner planner(limits);
    Result<PlacementPlan> planned = planner.plan(request, snapshot, policy, context);
    CSP_REQUIRE_MSG(planned.has_value(), "workers=" + std::to_string(workers) + ": " + planned.error().render());
    CSP_REQUIRE_MSG(planned.value().outcome == PlanOutcome::Planned,
                    "workers=" + std::to_string(workers) + ": outcome " + to_string(planned.value().outcome));
    CSP_REQUIRE_MSG(planned.value().obligations.size() == 1, "one obligation");
    CSP_REQUIRE_MSG(planned.value().obligations[0].placements.size() == 3,
                    "workers=" + std::to_string(workers) + ": " +
                        std::to_string(planned.value().obligations[0].placements.size()) + " placements");
    if (workers == 0) {
      baseline = canonical(planned.value());
      baseline_identity = planned.value().plan.value();
      continue;
    }
    CSP_EXPECT_MSG(canonical(planned.value()) == baseline,
                   "workers=" + std::to_string(workers) + ": the plan differs from the single-threaded one");
    CSP_EXPECT_MSG(planned.value().plan.value() == baseline_identity,
                   "workers=" + std::to_string(workers) + ": the identity differs");
  }
  CSP_EXPECT(!baseline.empty());
}

CSP_TEST(concurrency, many_threads_planning_one_immutable_snapshot_agree) {
  const SiteEvidenceSnapshot snapshot = fleet(300);
  const PlacementRequest request = request_for("request-1", "obligation-1", 1, 2);
  const PlacementPolicy policy = acceptance_policy();
  const PlanningContext context = instant_context();
  const Planner planner;

  Result<PlacementPlan> baseline = planner.plan(request, snapshot, policy, context);
  CSP_REQUIRE(baseline.has_value());
  const std::string expected = canonical(baseline.value());

  const std::size_t thread_count = 8;
  const std::size_t calls_per_thread = 8;
  const std::size_t total = thread_count * calls_per_thread;
  std::vector<std::string> results(total);
  std::vector<std::string> failures(total);
  std::vector<std::thread> workers;
  workers.reserve(thread_count);
  for (std::size_t worker = 0; worker < thread_count; ++worker) {
    workers.emplace_back([&planner, &request, &snapshot, &policy, &context, &results, &failures, expected, worker,
                          calls_per_thread]() {
      for (std::size_t call = 0; call < calls_per_thread; ++call) {
        const std::size_t slot = worker * calls_per_thread + call;
        Result<PlacementPlan> planned = planner.plan(request, snapshot, policy, context);
        if (!planned.has_value()) {
          failures[slot] = planned.error().render();
          continue;
        }
        results[slot] = canonical(planned.value());
        if (canonical(planned.value()) != expected) {
          results[slot] += " <differs from the single-threaded answer>";
        }
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }

  for (std::size_t slot = 0; slot < total; ++slot) {
    CSP_EXPECT_MSG(failures[slot].empty(), "slot " + std::to_string(slot) + ": " + failures[slot]);
    CSP_EXPECT_MSG(results[slot] == expected, "slot " + std::to_string(slot) + ": the answer differs");
  }
  std::printf("      concurrency: %zu planning calls on one immutable snapshot from %zu threads\n", total,
              thread_count);
  std::fflush(stdout);
}

CSP_TEST(concurrency, cancelling_one_call_leaves_the_others_alone) {
  const SiteEvidenceSnapshot snapshot = fleet(4000);
  const PlacementPolicy policy = acceptance_policy();
  const PlanningContext context = instant_context();
  const Planner planner;

  const PlacementRequest request = request_for("request-1", "obligation-1", 1, 2);
  Result<PlacementPlan> baseline = planner.plan(request, snapshot, policy, context);
  CSP_REQUIRE(baseline.has_value());
  const std::string expected = canonical(baseline.value());

  const std::size_t quiet_threads = 6;
  std::vector<std::string> quiet(quiet_threads);
  std::vector<std::string> quiet_failures(quiet_threads);
  CancellationSource source;
  std::string cancelled_result;
  std::string cancelled_failure;
  bool cancelled_caught = false;

  std::thread canceller([&source]() { source.request_cancel(); });
  std::vector<std::thread> workers;
  workers.reserve(quiet_threads + 1);
  for (std::size_t worker = 0; worker < quiet_threads; ++worker) {
    workers.emplace_back([&planner, &request, &snapshot, &policy, &context, &quiet, &quiet_failures, worker]() {
      Result<PlacementPlan> planned = planner.plan(request, snapshot, policy, context);
      if (!planned.has_value()) {
        quiet_failures[worker] = planned.error().render();
        return;
      }
      quiet[worker] = canonical(planned.value());
    });
  }
  workers.emplace_back([&planner, &request, &snapshot, &policy, &context, &source, &cancelled_result,
                        &cancelled_failure, &cancelled_caught]() {
    PlanningContext cancelled = context;
    cancelled.cancellation = source.token();
    Result<PlacementPlan> planned = planner.plan(request, snapshot, policy, cancelled);
    if (!planned.has_value()) {
      cancelled_failure = planned.error().render();
      if (planned.error().category() == ErrorCategory::Cancelled) {
        cancelled_caught = true;
      }
      return;
    }
    cancelled_result = canonical(planned.value());
  });
  for (std::thread& worker : workers) {
    worker.join();
  }
  canceller.join();

  for (std::size_t worker = 0; worker < quiet_threads; ++worker) {
    CSP_EXPECT_MSG(quiet_failures[worker].empty(),
                   "a call that was not cancelled failed: " + quiet_failures[worker]);
    CSP_EXPECT_MSG(quiet[worker] == expected, "a call that was not cancelled answered differently");
  }
  // The cancelled call either returned no plan at all, or finished before the
  // cancellation reached a check point - in which case it must carry the whole answer.
  if (cancelled_caught) {
    CSP_EXPECT(cancelled_failure.find("csp.plan.cancelled") != std::string::npos);
    CSP_EXPECT(cancelled_result.empty());
  } else {
    CSP_EXPECT_MSG(cancelled_result == expected, "the cancelled call returned a partial answer");
  }
  std::printf("      concurrency: %zu quiet calls on one snapshot, cancellation caught=%d\n", quiet_threads,
              cancelled_caught ? 1 : 0);
  std::fflush(stdout);
}

CSP_TEST(concurrency, readers_see_whole_plans_while_a_writer_commits) {
  ScratchDirectory scratch("readers");
  Result<PlacementPlan> stable = plan_one("request-1", "obligation-1", 1);
  CSP_REQUIRE(stable.has_value());
  const std::string stable_bytes = canonical(stable.value());

  std::vector<PlacementPlan> written;
  for (int index = 2; index <= 9; ++index) {
    Result<PlacementPlan> plan =
        plan_one(("request-" + std::to_string(index)).c_str(), ("obligation-" + std::to_string(index)).c_str(),
                 static_cast<std::uint64_t>(index));
    CSP_REQUIRE(plan.has_value());
    written.push_back(std::move(plan).value());
  }

  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(stable.value()).has_value());

  const std::size_t reader_count = 4;
  const std::size_t reader_rounds = 300;
  std::vector<std::vector<std::string>> problems(reader_count + 1);
  std::vector<std::size_t> observed(reader_count, 0);

  std::thread writer([&store, &written, &problems]() {
    for (const PlacementPlan& plan : written) {
      Result<PlanId> committed = store.commit(plan);
      if (!committed.has_value() && !structured_error(committed.error())) {
        problems[0].push_back("unstructured commit failure: " + committed.error().render());
      }
    }
  });

  std::vector<std::thread> readers;
  readers.reserve(reader_count);
  for (std::size_t reader = 0; reader < reader_count; ++reader) {
    readers.emplace_back([&store, &stable, &stable_bytes, &written, &problems, &observed, reader]() {
      for (std::size_t round = 0; round < reader_rounds; ++round) {
        Result<PlacementPlan> stable_load = store.load(stable.value().plan);
        if (!stable_load.has_value()) {
          problems[reader + 1].push_back("a committed plan became unreadable: " + stable_load.error().render());
        } else if (canonical(stable_load.value()) != stable_bytes) {
          problems[reader + 1].push_back("a committed plan read back differently");
        }
        const PlacementPlan& candidate = written[round % written.size()];
        Result<PlacementPlan> maybe = store.load(candidate.plan);
        if (maybe.has_value()) {
          ++observed[reader];
          if (canonical(maybe.value()) != canonical(candidate)) {
            problems[reader + 1].push_back("a record read back with different content");
          }
        } else if (maybe.error().code() != "csp.store.unknown_plan" || !structured_error(maybe.error())) {
          problems[reader + 1].push_back("an unreadable record produced an unstructured error: " +
                                         maybe.error().render());
        }
      }
    });
  }
  for (std::thread& reader : readers) {
    reader.join();
  }
  writer.join();

  for (const std::vector<std::string>& slot : problems) {
    CSP_EXPECT_MSG(slot.empty(), slot.empty() ? std::string() : slot[0]);
  }

  // Everything the writer committed is readable afterwards, and the store is consistent.
  Result<StoreAudit> audit = store.audit();
  CSP_REQUIRE(audit.has_value());
  CSP_EXPECT(audit.value().consistent);
  CSP_EXPECT_EQ(audit.value().generation.value(), static_cast<std::uint64_t>(written.size() + 1));
  CSP_EXPECT_EQ(audit.value().records.size(), written.size() + 1);
  CSP_EXPECT_OK(store.close());

  Result<PlanStore> reopened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(reopened.has_value());
  for (const PlacementPlan& plan : written) {
    Result<PlacementPlan> loaded = reopened.value().load(plan.plan);
    CSP_REQUIRE(loaded.has_value());
    CSP_EXPECT_EQ(canonical(loaded.value()), canonical(plan));
  }
  CSP_EXPECT_OK(reopened.value().close());
  std::size_t total_observed = 0;
  for (const std::size_t count : observed) {
    total_observed += count;
  }
  std::printf("      concurrency: %zu readers x %zu rounds, %zu loads of records the writer was publishing\n",
              reader_count, reader_rounds, total_observed);
  std::fflush(stdout);
}

CSP_TEST(concurrency, concurrent_commits_stay_consistent) {
  ScratchDirectory scratch("commits");
  const std::size_t thread_count = 6;
  std::vector<PlacementPlan> plans;
  for (std::size_t index = 0; index < thread_count; ++index) {
    Result<PlacementPlan> plan = plan_one(("request-" + std::to_string(index + 1)).c_str(),
                                          ("obligation-" + std::to_string(index + 1)).c_str(),
                                          static_cast<std::uint64_t>(index + 1));
    CSP_REQUIRE(plan.has_value());
    plans.push_back(std::move(plan).value());
  }

  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();

  std::vector<std::string> outcomes(thread_count);
  std::vector<bool> succeeded(thread_count, false);
  std::vector<std::thread> workers;
  workers.reserve(thread_count);
  for (std::size_t index = 0; index < thread_count; ++index) {
    workers.emplace_back([&store, &plans, &outcomes, &succeeded, index]() {
      Result<PlanId> committed = store.commit(plans[index]);
      if (committed.has_value()) {
        succeeded[index] = true;
        outcomes[index] = committed.value().value();
        return;
      }
      if (structured_error(committed.error())) {
        outcomes[index] = committed.error().render();
      } else {
        outcomes[index] = "unstructured: " + committed.error().render();
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }

  std::size_t committed_count = 0;
  for (std::size_t index = 0; index < thread_count; ++index) {
    CSP_EXPECT_MSG(!outcomes[index].empty(), "commit " + std::to_string(index) + " recorded nothing");
    if (succeeded[index]) {
      ++committed_count;
      CSP_EXPECT_EQ(outcomes[index], plans[index].plan.value());
    } else {
      CSP_EXPECT_MSG(outcomes[index].find("unstructured") == std::string::npos,
                     "commit " + std::to_string(index) + ": " + outcomes[index]);
    }
  }

  // The manifest stayed consistent throughout, and it references exactly the records
  // whose commits reported success.
  Result<StoreAudit> audit = store.audit();
  CSP_REQUIRE(audit.has_value());
  CSP_EXPECT(audit.value().consistent);
  CSP_EXPECT_EQ(audit.value().records.size(), committed_count);
  CSP_EXPECT_EQ(audit.value().generation.value(), static_cast<std::uint64_t>(committed_count));
  Result<std::vector<PlanId>> listed = store.list();
  CSP_REQUIRE(listed.has_value());
  CSP_EXPECT_EQ(listed.value().size(), committed_count);
  for (std::size_t index = 0; index < thread_count; ++index) {
    if (!succeeded[index]) {
      continue;
    }
    Result<PlacementPlan> loaded = store.load(plans[index].plan);
    CSP_REQUIRE(loaded.has_value());
    CSP_EXPECT_EQ(canonical(loaded.value()), canonical(plans[index]));
  }
  CSP_EXPECT_OK(store.close());

  Result<PlanStore> reopened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(reopened.has_value());
  Result<StoreAudit> second = reopened.value().audit();
  CSP_REQUIRE(second.has_value());
  CSP_EXPECT(second.value().consistent);
  CSP_EXPECT_EQ(second.value().generation.value(), static_cast<std::uint64_t>(committed_count));
  CSP_EXPECT_OK(reopened.value().close());
  std::printf("      concurrency: %zu concurrent commits on one store, %zu succeeded\n", thread_count,
              committed_count);
  std::fflush(stdout);
}

CSP_TEST(concurrency, stress_rounds_from_a_seed) {
  csp_test::SeededRandom random(0xC0FFEE1234ULL);
  const std::uint64_t rounds = 6 + random.below(6);
  std::size_t total_commits = 0;
  std::size_t total_loads = 0;
  std::size_t total_reads = 0;
  for (std::uint64_t round = 0; round < rounds; ++round) {
    ScratchDirectory scratch("stress");
    const std::size_t writer_count = 2 + static_cast<std::size_t>(random.below(3));
    const std::size_t reader_count = 2 + static_cast<std::size_t>(random.below(3));

    Result<PlacementPlan> stable = plan_one("request-stable", "obligation-stable", 1);
    CSP_REQUIRE(stable.has_value());
    const std::string stable_bytes = canonical(stable.value());

    std::vector<PlacementPlan> plans;
    for (std::size_t index = 0; index < writer_count; ++index) {
      Result<PlacementPlan> plan =
          plan_one(("request-r" + std::to_string(round) + "-" + std::to_string(index)).c_str(),
                   ("obligation-r" + std::to_string(round) + "-" + std::to_string(index)).c_str(),
                   static_cast<std::uint64_t>(index + 2));
      CSP_REQUIRE(plan.has_value());
      plans.push_back(std::move(plan).value());
    }

    Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
    CSP_REQUIRE(opened.has_value());
    PlanStore store = std::move(opened).value();
    CSP_REQUIRE(store.commit(stable.value()).has_value());

    std::atomic<std::size_t> committed{0};
    std::atomic<std::size_t> loads{0};
    std::atomic<std::size_t> reads{0};
    std::vector<std::vector<std::string>> problems(writer_count + reader_count);
    std::vector<std::thread> workers;
    workers.reserve(writer_count + reader_count);
    for (std::size_t index = 0; index < writer_count; ++index) {
      workers.emplace_back([&store, &plans, &committed, &problems, index]() {
        Result<PlanId> result = store.commit(plans[index]);
        if (result.has_value()) {
          committed.fetch_add(1);
        } else if (!structured_error(result.error())) {
          problems[index].push_back("unstructured commit failure: " + result.error().render());
        }
      });
    }
    const std::size_t reader_rounds = 50 + static_cast<std::size_t>(random.below(50));
    for (std::size_t index = 0; index < reader_count; ++index) {
      workers.emplace_back([&store, &stable, &stable_bytes, &plans, &loads, &reads, &problems, reader_rounds,
                            writer_count, index]() {
        for (std::size_t step = 0; step < reader_rounds; ++step) {
          Result<PlacementPlan> loaded = store.load(stable.value().plan);
          reads.fetch_add(1);
          if (!loaded.has_value() || canonical(loaded.value()) != stable_bytes) {
            problems[writer_count + index].push_back("the stable record was not readable throughout");
          }
          const PlacementPlan& candidate = plans[step % plans.size()];
          Result<PlacementPlan> maybe = store.load(candidate.plan);
          if (maybe.has_value()) {
            loads.fetch_add(1);
            if (canonical(maybe.value()) != canonical(candidate)) {
              problems[writer_count + index].push_back("a record read back torn");
            }
          } else if (maybe.error().code() != "csp.store.unknown_plan") {
            problems[writer_count + index].push_back("a load produced " + maybe.error().render());
          }
        }
      });
    }
    for (std::thread& worker : workers) {
      worker.join();
    }

    for (const std::vector<std::string>& slot : problems) {
      CSP_EXPECT_MSG(slot.empty(), slot.empty() ? std::string() : slot[0]);
    }
    Result<StoreAudit> audit = store.audit();
    CSP_REQUIRE(audit.has_value());
    CSP_EXPECT(audit.value().consistent);
    CSP_EXPECT_EQ(audit.value().records.size(), committed.load() + 1);
    CSP_EXPECT_EQ(audit.value().generation.value(), static_cast<std::uint64_t>(committed.load() + 1));
    CSP_EXPECT_OK(store.close());

    Result<PlanStore> reopened = PlanStore::open(options_for(scratch.path()));
    CSP_REQUIRE(reopened.has_value());
    Result<StoreAudit> second = reopened.value().audit();
    CSP_REQUIRE(second.has_value());
    CSP_EXPECT(second.value().consistent);
    CSP_EXPECT_EQ(second.value().records.size(), committed.load() + 1);
    CSP_EXPECT_OK(reopened.value().close());
    total_commits += committed.load();
    total_loads += loads.load();
    total_reads += reads.load();
  }
  CSP_EXPECT(total_commits > 0);
  CSP_EXPECT(total_loads > 0);
  std::printf("      concurrency: seed=%llu rounds=%llu, %zu rows read, %zu successful commits, %zu loads of "
              "records still being published\n",
              static_cast<unsigned long long>(random.seed()), static_cast<unsigned long long>(rounds), total_reads,
              total_commits, total_loads);
  std::fflush(stdout);
}

CSP_TEST(concurrency, parallel_candidate_ordering_matches_the_calling_thread) {
  // This is the case that actually takes the threaded path. The engine splits candidate
  // evaluation across workers only when the obligation has a per-site preference to order
  // by, the candidate count reaches parallel_threshold, more than one worker is allowed,
  // and the whole assessment pass is known to fit the remaining work budget. All four
  // hold here: 700 candidates, a threshold of 64, eight workers, and no other work spent.
  //
  // What is asserted is the invariance, which is the property that matters and the only
  // one observable through the public API: the answer must be byte-identical to the one
  // the calling thread alone produces. A build that dropped the parallel pass entirely
  // would also pass; a build that let the schedule reach the answer would not.
  const SiteEvidenceSnapshot snapshot = fleet(700);
  PlacementRequest request = request_for("request-1", "obligation-1", 1, 3);
  request.preferences.objectives = {Preferences::Objective::MinimiseCost, Preferences::Objective::MinimiseRisk,
                                    Preferences::Objective::MaximiseDomainSpread};
  const PlacementPolicy policy = acceptance_policy();
  const PlanningContext context = instant_context();

  std::string baseline;
  std::string baseline_identity;
  std::size_t baseline_nodes = 0;
  for (const std::size_t workers : {std::size_t{0}, std::size_t{2}, std::size_t{8}}) {
    Limits limits;
    limits.worker_threads = workers;
    limits.parallel_threshold = 64;
    const Planner planner(limits);
    Result<PlacementPlan> planned = planner.plan(request, snapshot, policy, context);
    CSP_REQUIRE_MSG(planned.has_value(), "workers=" + std::to_string(workers) + ": " + planned.error().render());
    CSP_REQUIRE_MSG(planned.value().outcome == PlanOutcome::Planned,
                    "workers=" + std::to_string(workers) + ": outcome " + to_string(planned.value().outcome));
    // The three criteria are all recorded, and each says whether it could be evaluated.
    CSP_EXPECT_EQ(planned.value().tie_breaks.size(), std::size_t{4});
    if (workers == 0) {
      baseline = canonical(planned.value());
      baseline_identity = planned.value().plan.value();
      baseline_nodes = planned.value().nodes_explored;
      CSP_EXPECT(!baseline.empty());
      continue;
    }
    CSP_EXPECT_MSG(canonical(planned.value()) == baseline,
                   "workers=" + std::to_string(workers) + ": the plan differs from the single-threaded one");
    CSP_EXPECT_MSG(planned.value().plan.value() == baseline_identity,
                   "workers=" + std::to_string(workers) + ": the identity differs");
    CSP_EXPECT_MSG(planned.value().nodes_explored == baseline_nodes,
                   "workers=" + std::to_string(workers) + ": the work consumed differs, so the budget was spent "
                   "in a different order");
  }
}
