// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The durable plan store, from the outside.
//
// Every case here drives the store through its public surface and checks what a reader
// would find on disk afterwards. A commit is visible only through the manifest, a
// compaction removes only what nothing references and what is already behind the
// committed generation, and a store that has been closed and reopened answers exactly
// what it answered before.

#include "test_harness.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
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

SiteId site_id(const char* text) { return SiteId::parse(text).value(); }
ServiceClassId class_id(const char* text) { return ServiceClassId::parse(text).value(); }
PolicyId policy_id(const char* text) { return PolicyId::parse(text).value(); }
RequestId request_id(const char* text) { return RequestId::parse(text).value(); }
ObligationId obligation_id(const char* text) { return ObligationId::parse(text).value(); }
PlanId plan_id(const char* text) { return PlanId::parse(text).value(); }

std::int64_t process_id() {
#if defined(_WIN32)
  return static_cast<std::int64_t>(::_getpid());
#else
  return static_cast<std::int64_t>(::getpid());
#endif
}

/// A directory under the platform temporary directory, removed when the case ends.
/// Nothing this suite creates is allowed to land in the repository.
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
    path_ = std::string(base) + "/csp-persistence-" + tag + "-" + std::to_string(process_id()) + "-" +
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

Provenance provenance_of(const char* record) {
  Provenance provenance;
  provenance.source_record = EvidenceId::parse(record).value();
  provenance.authority = AuthorityId::parse("registry-authority").value();
  provenance.authority_generation = Generation::from_value(4);
  provenance.observed_at = Instant::from_nanos(kBase - 1000);
  return provenance;
}

SiteEvidenceSnapshot one_site_snapshot() {
  SiteEvidenceSnapshot snapshot;
  snapshot.generation = Generation::from_value(11);
  snapshot.captured_at = Instant::from_nanos(kBase - 1000);

  SiteRecord site;
  site.site = site_id("site-1");
  site.jurisdiction = JurisdictionId::parse("jur-1").value();
  site.maintenance = Measurement<MaintenanceState>::known(MaintenanceState::Operational);
  site.provenance = provenance_of("site-record-1");
  snapshot.sites.push_back(std::move(site));

  CapacityRecord capacity;
  capacity.reference = CapacityRefId::parse("capacity-1").value();
  capacity.site = site_id("site-1");
  capacity.service_class = class_id("service-1");
  capacity.kind = CapacityKind::Commitment;
  capacity.available = Measurement<Quantity>::known(Quantity::from_units(10));
  capacity.provenance = provenance_of("capacity-record-1");
  snapshot.capacity.push_back(std::move(capacity));

  CompatibilityRecord compatibility;
  compatibility.reference = EvidenceId::parse("compatibility-1").value();
  compatibility.site = site_id("site-1");
  compatibility.service_class = class_id("service-1");
  compatibility.compatible = Measurement<bool>::known(true);
  compatibility.provenance = provenance_of("compatibility-record-1");
  snapshot.compatibility.push_back(std::move(compatibility));

  return snapshot;
}

PlacementRequest one_obligation_request(const char* identity, const char* obligation, std::uint64_t generation) {
  PlacementRequest request;
  request.request = request_id(identity);
  request.generation = Generation::from_value(generation);
  request.policy.policy = policy_id("policy-1");
  request.policy.generation = Generation::from_value(1);

  Obligation entry;
  entry.obligation = obligation_id(obligation);
  entry.service_class = class_id("service-1");
  entry.required_capacity = Quantity::from_units(5);
  entry.primary_placements = 1;
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

PlacementPlan plan_one(const char* identity, const char* obligation, std::uint64_t generation) {
  const Planner planner;
  Result<PlacementPlan> planned = planner.plan(one_obligation_request(identity, obligation, generation),
                                               one_site_snapshot(), acceptance_policy(), instant_context());
  if (!planned.has_value()) {
    std::printf("      the fixture could not be planned: %s\n", planned.error().render().c_str());
    std::fflush(stdout);
    return PlacementPlan{};
  }
  return std::move(planned).value();
}

StoreOptions options_for(const std::string& directory) {
  StoreOptions options;
  options.directory = directory;
  return options;
}

std::string canonical(const PlacementPlan& plan) {
  Result<std::string> bytes = plan_canonical_bytes(plan);
  return bytes.has_value() ? bytes.value() : std::string("<undecodable>");
}

std::string join(const std::string& directory, const std::string& name) {
  return directory + "/" + name;
}

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

}  // namespace

CSP_TEST(persistence, commit_close_reopen_load_byte_identical) {
  ScratchDirectory scratch("reopen");
  const PlacementPlan plan = plan_one("request-1", "obligation-1", 1);
  CSP_REQUIRE(plan.outcome == PlanOutcome::Planned);
  CSP_REQUIRE(plan.plan.valid());
  const std::string expected = canonical(plan);

  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_EXPECT_OK(store.commit(plan));
  CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{1});
  CSP_EXPECT_OK(store.close());

  Result<PlanStore> reopened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(reopened.has_value());
  PlanStore second = std::move(reopened).value();
  CSP_EXPECT_EQ(second.generation().value(), std::uint64_t{1});

  Result<PlacementPlan> loaded = second.load(plan.plan);
  CSP_REQUIRE(loaded.has_value());
  CSP_EXPECT_EQ(canonical(loaded.value()), expected);
  CSP_EXPECT_EQ(loaded.value().plan.value(), plan.plan.value());
  CSP_EXPECT_EQ(loaded.value().digest.to_hex(), plan.digest.to_hex());
  CSP_EXPECT(loaded.value().outcome == PlanOutcome::Planned);
  CSP_EXPECT_OK(second.close());
}

CSP_TEST(persistence, repeated_commit_idempotent_conflict_on_other_content) {
  ScratchDirectory scratch("idempotent");
  const PlacementPlan plan = plan_one("request-1", "obligation-1", 1);
  CSP_REQUIRE(plan.outcome == PlanOutcome::Planned);

  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();

  Result<PlanId> first = store.commit(plan);
  CSP_REQUIRE(first.has_value());
  CSP_EXPECT_EQ(first.value().value(), plan.plan.value());

  Result<PlanId> again = store.commit(plan);
  CSP_REQUIRE(again.has_value());
  CSP_EXPECT_EQ(again.value().value(), plan.plan.value());
  CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{1});
  Result<std::vector<PlanId>> listed = store.list();
  CSP_REQUIRE(listed.has_value());
  CSP_EXPECT_EQ(listed.value().size(), std::size_t{1});

  // The same identity carrying different content. The identity and the digest are left
  // as they were, so the store sees one identity with two readings and must refuse
  // rather than drop either.
  PlacementPlan altered = plan;
  altered.nodes_explored += 1;
  Result<PlanId> conflicted = store.commit(altered);
  CSP_EXPECT(!conflicted.has_value());
  if (!conflicted.has_value()) {
    CSP_EXPECT(conflicted.error().category() == ErrorCategory::Conflict);
    CSP_EXPECT_EQ(conflicted.error().code(), std::string("csp.store.identity_reuse"));
  }
  CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{1});
  Result<std::vector<PlanId>> after = store.list();
  CSP_REQUIRE(after.has_value());
  CSP_EXPECT_EQ(after.value().size(), std::size_t{1});
  CSP_EXPECT_OK(store.close());
}

CSP_TEST(persistence, audit_reports_a_consistent_store) {
  ScratchDirectory scratch("audit");
  const PlacementPlan plan = plan_one("request-1", "obligation-1", 1);
  CSP_REQUIRE(plan.outcome == PlanOutcome::Planned);

  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(plan).has_value());

  Result<StoreAudit> audit = store.audit();
  CSP_REQUIRE(audit.has_value());
  CSP_EXPECT(audit.value().consistent);
  CSP_EXPECT_EQ(audit.value().generation.value(), std::uint64_t{1});
  CSP_EXPECT_EQ(audit.value().records.size(), std::size_t{1});
  CSP_REQUIRE(!audit.value().records.empty());
  CSP_EXPECT_EQ(audit.value().records[0].value(), plan.plan.value());
  CSP_EXPECT(audit.value().record_bytes > 0);
  CSP_EXPECT(!audit.value().manifest_digest.is_zero());
  CSP_EXPECT_OK(store.close());
}

CSP_TEST(persistence, compact_removes_only_orphans_behind_the_generation) {
  ScratchDirectory scratch("compact");
  const PlacementPlan first = plan_one("request-1", "obligation-1", 1);
  const PlacementPlan second = plan_one("request-2", "obligation-2", 2);
  CSP_REQUIRE(first.outcome == PlanOutcome::Planned);
  CSP_REQUIRE(second.outcome == PlanOutcome::Planned);

  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(first).has_value());
  CSP_REQUIRE(store.commit(second).has_value());
  CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{2});

  const std::string records = join(scratch.path(), detail::kRecordsDirectoryName);
  const PlanId behind = plan_id("plan-0000000000000000000000000000beef");
  const PlanId ahead = plan_id("plan-0000000000000000000000000000ahead");
  const PlanId equal = plan_id("plan-0000000000000000000000000000e0a1");
  const PlanId undecodable = plan_id("plan-0000000000000000000000000000dead");

  // Three records no manifest references: one behind the committed generation, one
  // equal to it, one ahead of it, and one that is not a record at all. Only the first
  // is a commit nobody will ever see again.
  CSP_REQUIRE(detail::encode_record(behind, Generation::from_value(1), "orphan-behind").has_value());
  CSP_REQUIRE(detail::encode_record(equal, Generation::from_value(2), "orphan-equal").has_value());
  CSP_REQUIRE(detail::encode_record(ahead, Generation::from_value(3), "orphan-ahead").has_value());
  Result<std::string> behind_bytes = detail::encode_record(behind, Generation::from_value(1), "orphan-behind");
  Result<std::string> equal_bytes = detail::encode_record(equal, Generation::from_value(2), "orphan-equal");
  Result<std::string> ahead_bytes = detail::encode_record(ahead, Generation::from_value(3), "orphan-ahead");
  CSP_REQUIRE(behind_bytes.has_value() && equal_bytes.has_value() && ahead_bytes.has_value());
  CSP_REQUIRE(detail::write_file_durable(join(records, detail::record_file_name(behind)), behind_bytes.value())
                  .has_value());
  CSP_REQUIRE(detail::write_file_durable(join(records, detail::record_file_name(equal)), equal_bytes.value())
                  .has_value());
  CSP_REQUIRE(detail::write_file_durable(join(records, detail::record_file_name(ahead)), ahead_bytes.value())
                  .has_value());
  CSP_REQUIRE(detail::write_file_durable(join(records, detail::record_file_name(undecodable)), "not a record")
                  .has_value());

  CSP_EXPECT_OK(store.compact());

  CSP_EXPECT(!detail::file_exists(join(records, detail::record_file_name(behind))));
  CSP_EXPECT(detail::file_exists(join(records, detail::record_file_name(equal))));
  CSP_EXPECT(detail::file_exists(join(records, detail::record_file_name(ahead))));
  CSP_EXPECT(detail::file_exists(join(records, detail::record_file_name(undecodable))));
  CSP_EXPECT(detail::file_exists(join(records, detail::record_file_name(first.plan))));
  CSP_EXPECT(detail::file_exists(join(records, detail::record_file_name(second.plan))));

  Result<StoreAudit> audit = store.audit();
  CSP_REQUIRE(audit.has_value());
  CSP_EXPECT(audit.value().consistent);
  CSP_EXPECT_EQ(audit.value().records.size(), std::size_t{2});
  CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{2});
  CSP_EXPECT_OK(store.close());
}

CSP_TEST(persistence, reopen_after_several_commits_preserves_everything) {
  ScratchDirectory scratch("several");
  std::vector<PlacementPlan> plans;
  std::vector<std::string> expected;
  for (int index = 1; index <= 5; ++index) {
    const std::string identity = "request-" + std::to_string(index);
    const std::string obligation = "obligation-" + std::to_string(index);
    PlacementPlan plan = plan_one(identity.c_str(), obligation.c_str(), static_cast<std::uint64_t>(index));
    CSP_REQUIRE(plan.outcome == PlanOutcome::Planned);
    expected.push_back(canonical(plan));
    plans.push_back(std::move(plan));
  }

  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  for (const PlacementPlan& plan : plans) {
    CSP_REQUIRE(store.commit(plan).has_value());
  }
  CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{5});
  CSP_EXPECT_OK(store.close());

  Result<PlanStore> reopened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(reopened.has_value());
  PlanStore second = std::move(reopened).value();
  CSP_EXPECT_EQ(second.generation().value(), std::uint64_t{5});
  Result<std::vector<PlanId>> listed = second.list();
  CSP_REQUIRE(listed.has_value());
  CSP_EXPECT_EQ(listed.value().size(), std::size_t{5});
  for (std::size_t index = 0; index < plans.size(); ++index) {
    Result<PlacementPlan> loaded = second.load(plans[index].plan);
    CSP_REQUIRE(loaded.has_value());
    CSP_EXPECT_EQ(canonical(loaded.value()), expected[index]);
  }
  CSP_EXPECT_OK(second.close());
}

CSP_TEST(persistence, record_above_the_bound_is_refused_and_writes_nothing) {
  ScratchDirectory scratch("record-bound");
  const PlacementPlan plan = plan_one("request-1", "obligation-1", 1);
  CSP_REQUIRE(plan.outcome == PlanOutcome::Planned);
  Result<std::string> document = plan_to_document(plan, false);
  CSP_REQUIRE(document.has_value());

  StoreOptions options = options_for(scratch.path());
  options.limits.max_store_record_bytes = 256;
  Result<PlanStore> opened = PlanStore::open(options);
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(document.value().size() > options.limits.max_store_record_bytes);

  Result<PlanId> committed = store.commit(plan);
  CSP_EXPECT(!committed.has_value());
  if (!committed.has_value()) {
    CSP_EXPECT(committed.error().category() == ErrorCategory::BoundExceeded);
    CSP_EXPECT_EQ(committed.error().code(), std::string("csp.store.record_too_large"));
  }

  // Nothing was written: no record, no manifest, and the store still reports itself
  // empty rather than half-committed.
  CSP_EXPECT(!detail::file_exists(join(scratch.path(), detail::kManifestFileName)));
  const std::vector<std::string> records = directory_names(join(scratch.path(), detail::kRecordsDirectoryName));
  CSP_EXPECT_MSG(records.empty(), records.empty() ? std::string() : records[0]);
  Result<std::vector<PlanId>> listed = store.list();
  CSP_REQUIRE(listed.has_value());
  CSP_EXPECT(listed.value().empty());
  CSP_EXPECT(!store.generation().is_set());
  CSP_EXPECT_OK(store.close());
}

CSP_TEST(persistence, store_directory_holds_only_manifest_lock_and_records) {
  ScratchDirectory scratch("shape");
  const PlacementPlan first = plan_one("request-1", "obligation-1", 1);
  const PlacementPlan second = plan_one("request-2", "obligation-2", 2);
  CSP_REQUIRE(first.outcome == PlanOutcome::Planned);
  CSP_REQUIRE(second.outcome == PlanOutcome::Planned);

  Result<PlanStore> opened = PlanStore::open(options_for(scratch.path()));
  CSP_REQUIRE(opened.has_value());
  PlanStore store = std::move(opened).value();
  CSP_REQUIRE(store.commit(first).has_value());
  CSP_REQUIRE(store.commit(second).has_value());
  CSP_EXPECT_OK(store.compact());
  CSP_EXPECT(store.load(first.plan).has_value());
  CSP_EXPECT_OK(store.close());

  const std::vector<std::string> top = directory_names(scratch.path());
  CSP_EXPECT_EQ(top.size(), std::size_t{3});
  CSP_EXPECT(contains(top, std::string(detail::kManifestFileName)));
  CSP_EXPECT(contains(top, std::string(detail::kLockFileName)));
  CSP_EXPECT(contains(top, std::string(detail::kRecordsDirectoryName)));

  const std::vector<std::string> records = directory_names(join(scratch.path(), detail::kRecordsDirectoryName));
  CSP_EXPECT_EQ(records.size(), std::size_t{2});
  for (const std::string& name : records) {
    CSP_EXPECT_MSG(name.find(detail::kStagingMarker) == std::string::npos, name);
    CSP_EXPECT_MSG(name.size() > 5 && name.compare(name.size() - 5, 5, ".plan") == 0, name);
  }
}
