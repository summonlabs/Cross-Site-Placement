// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Multiprocess behaviour, with real operating-system processes.
//
// Every claim here rests on a second OS process launched through the helper. A thread
// is not a process, and nothing in this file is described as if it were: the threads
// this file does use are only launch vehicles for std::system, which blocks until its
// child has exited.
//
// No process is killed. The crash boundary is simulated by taking a real store
// directory and restoring the manifest it had before a commit, which is exactly the
// state a crash between the record write and the manifest write leaves behind.

#include "test_harness.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "cross_site_placement/cross_site_placement.hpp"
#include "fs_atomic.hpp"
#include "store_format.hpp"

#if !defined(CSP_MULTIPROCESS_HELPER)
#error "tests/test_multiprocess.cpp needs CSP_MULTIPROCESS_HELPER, which tests/CMakeLists.txt defines"
#endif

using namespace csp;

/// A required check that names what went wrong before it stops the case. The harness's
/// own CSP_REQUIRE carries no detail and CSP_EXPECT_MSG does not stop the case, and a
/// multiprocess case needs both at once.
#define CSP_REQUIRE_MSG(condition, detail)                                                          do {                                                                                                if (!csp_test::check((condition), #condition, __FILE__, __LINE__, (detail))) {                      csp_test::abort_case();                                                                         }                                                                                               } while (false)

namespace {

constexpr std::int64_t kBase = 1700000000000000000LL;

SiteId site_id(const char* text) { return SiteId::parse(text).value(); }
ServiceClassId class_id(const char* text) { return ServiceClassId::parse(text).value(); }
PolicyId policy_id(const char* text) { return PolicyId::parse(text).value(); }
RequestId request_id(const char* text) { return RequestId::parse(text).value(); }
ObligationId obligation_id(const char* text) { return ObligationId::parse(text).value(); }
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
    path_ = std::string(base) + "/csp-multiprocess-" + tag + "-" + std::to_string(process_id()) + "-" +
            std::to_string(counter.fetch_add(1));
    if (detail::directory_exists(path_)) {
      (void)detail::remove_directory_tree(path_);
    }
    // A helper process is redirected into this directory before any store creates it,
    // so the directory is created here rather than by the first store that opens.
    (void)detail::create_directories(path_);
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

std::string quote(const std::string& text) { return "\"" + text + "\""; }

std::string helper_command(std::initializer_list<std::string> arguments) {
  std::string command = quote(CSP_MULTIPROCESS_HELPER);
  for (const std::string& argument : arguments) {
    command += " ";
    command += quote(argument);
  }
  return command;
}

int exit_code_of(int status) {
#if defined(_WIN32)
  return status;
#else
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return -1;
#endif
}

std::string first_line(const std::string& text) {
  const std::size_t at = text.find('\n');
  std::string line = at == std::string::npos ? text : text.substr(0, at);
  while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
    line.pop_back();
  }
  return line;
}

struct HelperResult {
  int exit_code = -1;
  std::string line;
  bool ok = false;
  std::string token;
  std::string detail;
  std::string category;
  std::string code;
  std::int64_t elapsed_ms = 0;
};

/// std::system on Windows runs the command through cmd.exe, which strips the outer pair
/// of quotes from a command line that begins with one - and this command line begins
/// with the quoted path of the helper. Wrapping the whole line in a second pair is the
/// documented way to keep the first pair intact.
std::string system_command(const std::string& command) {
#if defined(_WIN32)
  if (!command.empty() && command.front() == '"') {
    return "\"" + command + "\"";
  }
#endif
  return command;
}

HelperResult run_helper(std::initializer_list<std::string> arguments, const std::string& output_path) {
  const std::string command = system_command(helper_command(arguments) + " > " + quote(output_path) + " 2>&1");
  const auto start = std::chrono::steady_clock::now();
  const int status = std::system(command.c_str());
  const auto stop = std::chrono::steady_clock::now();

  HelperResult result;
  result.exit_code = exit_code_of(status);
  result.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();
  Result<std::string> bytes = detail::read_file_bounded(output_path, 1u << 20);
  result.line = bytes.has_value() ? first_line(bytes.value()) : std::string("<no output>");
  if (result.line.compare(0, 3, "ok ") == 0) {
    result.ok = true;
    const std::size_t space = result.line.find(' ', 3);
    result.token = result.line.substr(3, space == std::string::npos ? std::string::npos : space - 3);
    result.detail = space == std::string::npos ? std::string() : result.line.substr(space + 1);
  } else if (result.line.compare(0, 6, "error ") == 0) {
    const std::string rest = result.line.substr(6);
    const std::size_t space = rest.find(' ');
    result.category = space == std::string::npos ? rest : rest.substr(0, space);
    result.code = space == std::string::npos ? std::string() : rest.substr(space + 1);
  }
  return result;
}

Provenance provenance_of(const char* record) {
  Provenance provenance;
  provenance.source_record = evidence_id(record);
  provenance.authority = authority_id("registry-authority");
  provenance.authority_generation = Generation::from_value(4);
  provenance.observed_at = Instant::from_nanos(kBase - 1000);
  return provenance;
}

SiteEvidenceSnapshot one_site_snapshot() {
  SiteEvidenceSnapshot snapshot;
  snapshot.generation = Generation::from_value(3);
  snapshot.captured_at = Instant::from_nanos(kBase - 1000);
  SiteRecord site;
  site.site = site_id("site-1");
  site.jurisdiction = JurisdictionId::parse("jur-1").value();
  site.maintenance = Measurement<MaintenanceState>::known(MaintenanceState::Operational);
  site.provenance = provenance_of("site-record-1");
  snapshot.sites.push_back(std::move(site));
  CapacityRecord capacity;
  capacity.reference = capacity_ref_id("capacity-1");
  capacity.site = site_id("site-1");
  capacity.service_class = class_id("service-1");
  capacity.kind = CapacityKind::Commitment;
  capacity.available = Measurement<Quantity>::known(Quantity::from_units(10));
  capacity.provenance = provenance_of("capacity-record-1");
  snapshot.capacity.push_back(std::move(capacity));
  CompatibilityRecord compatibility;
  compatibility.reference = evidence_id("compatibility-1");
  compatibility.site = site_id("site-1");
  compatibility.service_class = class_id("service-1");
  compatibility.compatible = Measurement<bool>::known(true);
  compatibility.provenance = provenance_of("compatibility-record-1");
  snapshot.compatibility.push_back(std::move(compatibility));
  return snapshot;
}

Result<PlacementPlan> make_plan(const char* identity, const char* obligation, std::uint64_t generation) {
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

  PlacementPolicy policy;
  policy.policy = policy_id("policy-1");
  policy.generation = Generation::from_value(1);

  PlanningContext context;
  context.evaluation_instant = Instant::from_nanos(kBase);
  const Planner planner;
  return planner.plan(request, one_site_snapshot(), policy, context);
}

std::string canonical(const PlacementPlan& plan) {
  Result<std::string> bytes = plan_canonical_bytes(plan);
  return bytes.has_value() ? bytes.value() : std::string("<undecodable>");
}

bool write_document(const std::string& path, const PlacementPlan& plan) {
  Result<std::string> document = plan_to_document(plan, false);
  if (!document.has_value()) {
    return false;
  }
  return detail::write_file_durable(path, document.value()).has_value();
}

bool contains(const std::vector<PlanId>& records, const PlanId& wanted) {
  for (const PlanId& record : records) {
    if (record == wanted) {
      return true;
    }
  }
  return false;
}

StoreOptions options_for(const std::string& directory) {
  StoreOptions options;
  options.directory = directory;
  return options;
}

}  // namespace

CSP_TEST(multiprocess, parent_reads_what_a_real_process_committed) {
  ScratchDirectory scratch("child-commit");
  const std::string store = join(scratch.path(), "store");
  const std::string document = join(scratch.path(), "plan.json");
  const std::string output = join(scratch.path(), "commit.out");

  Result<PlacementPlan> plan = make_plan("request-1", "obligation-1", 1);
  CSP_REQUIRE(plan.has_value());
  CSP_REQUIRE(plan.value().outcome == PlanOutcome::Planned);
  CSP_REQUIRE(write_document(document, plan.value()));

  const HelperResult committed = run_helper({"commit", store, document, "1000"}, output);
  CSP_REQUIRE_MSG(committed.exit_code == 0, "the helper exited " + std::to_string(committed.exit_code) + ": " +
                                                committed.line);
  CSP_REQUIRE_MSG(committed.ok, committed.line);
  CSP_EXPECT_EQ(committed.token, std::string("csp.helper.commit"));
  // The identity the child computed is the identity the parent computed: they are both
  // derived from the same canonical bytes.
  CSP_EXPECT_EQ(committed.detail, plan.value().plan.value());

  // The child has exited. What it committed is now the parent's to read.
  Result<PlanStore> opened = PlanStore::open(options_for(store));
  CSP_REQUIRE(opened.has_value());
  PlanStore parent_store = std::move(opened).value();
  CSP_EXPECT_EQ(parent_store.generation().value(), std::uint64_t{1});
  Result<PlacementPlan> loaded = parent_store.load(plan.value().plan);
  CSP_REQUIRE(loaded.has_value());
  CSP_EXPECT_EQ(canonical(loaded.value()), canonical(plan.value()));
  CSP_EXPECT_EQ(loaded.value().digest.to_hex(), plan.value().digest.to_hex());
  CSP_EXPECT_OK(parent_store.close());

  // A third real process reads the same record and reports the same digest.
  const HelperResult read_back = run_helper({"load", store, plan.value().plan.value(), "1000"},
                                            join(scratch.path(), "load.out"));
  CSP_REQUIRE_MSG(read_back.exit_code == 0, read_back.line);
  CSP_REQUIRE_MSG(read_back.ok, read_back.line);
  CSP_EXPECT_EQ(read_back.token, std::string("csp.helper.load"));
  CSP_EXPECT_EQ(read_back.detail, plan.value().plan.value() + " " + plan.value().digest.to_hex());
}

CSP_TEST(multiprocess, two_processes_committing_concurrently_stay_consistent) {
  ScratchDirectory scratch("two-commits");
  const std::string store = join(scratch.path(), "store");

  Result<PlacementPlan> first = make_plan("request-1", "obligation-1", 1);
  Result<PlacementPlan> second = make_plan("request-2", "obligation-2", 2);
  CSP_REQUIRE(first.has_value() && second.has_value());
  const std::string first_document = join(scratch.path(), "first.json");
  const std::string second_document = join(scratch.path(), "second.json");
  CSP_REQUIRE(write_document(first_document, first.value()));
  CSP_REQUIRE(write_document(second_document, second.value()));

  const std::string first_output = join(scratch.path(), "first.out");
  const std::string second_output = join(scratch.path(), "second.out");
  HelperResult first_result;
  HelperResult second_result;
  std::thread first_process([&]() { first_result = run_helper({"commit", store, first_document, "2000"}, first_output); });
  std::thread second_process(
      [&]() { second_result = run_helper({"commit", store, second_document, "2000"}, second_output); });
  first_process.join();
  second_process.join();

  // Each real process either committed or was refused with a structured error.
  for (const HelperResult* result : {&first_result, &second_result}) {
    if (result->ok) {
      CSP_EXPECT_EQ(result->token, std::string("csp.helper.commit"));
      CSP_EXPECT(result->exit_code == 0);
    } else {
      CSP_EXPECT_MSG(result->exit_code == 1, "unexpected exit " + std::to_string(result->exit_code) + ": " +
                                                 result->line);
      CSP_EXPECT_MSG(!result->code.empty() && !result->category.empty(), "unstructured refusal: " + result->line);
    }
  }
  CSP_EXPECT_MSG(first_result.ok || second_result.ok, "both real commits failed");

  std::vector<PlanId> succeeded;
  if (first_result.ok && first_result.detail == first.value().plan.value()) {
    succeeded.push_back(first.value().plan);
  }
  if (second_result.ok && second_result.detail == second.value().plan.value()) {
    succeeded.push_back(second.value().plan);
  }

  Result<PlanStore> opened = PlanStore::open(options_for(store));
  CSP_REQUIRE(opened.has_value());
  PlanStore parent_store = std::move(opened).value();
  Result<StoreAudit> audit = parent_store.audit();
  CSP_REQUIRE(audit.has_value());
  CSP_EXPECT(audit.value().consistent);
  CSP_EXPECT_EQ(audit.value().records.size(), succeeded.size());
  CSP_EXPECT_EQ(audit.value().generation.value(), static_cast<std::uint64_t>(succeeded.size()));
  for (const PlanId& identity : succeeded) {
    CSP_EXPECT_MSG(contains(audit.value().records, identity), "the audit does not list " + identity.value());
    Result<PlacementPlan> loaded = parent_store.load(identity);
    CSP_REQUIRE(loaded.has_value());
    const PlacementPlan& expected = identity == first.value().plan ? first.value() : second.value();
    CSP_EXPECT_EQ(canonical(loaded.value()), canonical(expected));
  }
  CSP_EXPECT_OK(parent_store.close());

  // A subsequent audit run in a real process agrees with the parent's reading.
  const HelperResult audited = run_helper({"audit", store, "1000"}, join(scratch.path(), "audit.out"));
  CSP_REQUIRE_MSG(audited.exit_code == 0, audited.line);
  CSP_REQUIRE_MSG(audited.ok, audited.line);
  CSP_EXPECT_EQ(audited.token, std::string("csp.helper.audit"));
  // The manifest lists its records in identity order, which is not the order the
  // commits were sent in, so the set is compared rather than the sequence.
  const std::string prefix = "1 " + std::to_string(succeeded.size()) + " " + std::to_string(succeeded.size());
  CSP_EXPECT_MSG(audited.detail.compare(0, prefix.size(), prefix) == 0,
                 "the child reported [" + audited.detail + "] where [" + prefix + " ...] was expected");
  std::size_t listed = 0;
  for (std::size_t at = audited.detail.find("plan-"); at != std::string::npos;
       at = audited.detail.find("plan-", at + 5)) {
    ++listed;
  }
  CSP_EXPECT_EQ(listed, succeeded.size());
  for (const PlanId& identity : succeeded) {
    CSP_EXPECT_MSG(audited.detail.find(identity.value()) != std::string::npos,
                   "the child's audit does not list " + identity.value());
  }
  std::printf("      multiprocess: two real processes committed concurrently, %zu succeeded\n", succeeded.size());
  std::fflush(stdout);
}

CSP_TEST(multiprocess, parent_holding_the_lock_refuses_a_real_process) {
  ScratchDirectory scratch("parent-lock");
  const std::string store = join(scratch.path(), "store");
  const std::string output = join(scratch.path(), "audit.out");

  Result<PlacementPlan> plan = make_plan("request-1", "obligation-1", 1);
  CSP_REQUIRE(plan.has_value());
  Result<PlanStore> opened = PlanStore::open(options_for(store));
  CSP_REQUIRE(opened.has_value());
  PlanStore parent_store = std::move(opened).value();
  CSP_REQUIRE(parent_store.commit(plan.value()).has_value());
  CSP_EXPECT_OK(parent_store.close());

  // The parent holds the store's own lock file exclusively, through the same adapter the
  // store uses.
  detail::FileLockOptions lock_options;
  lock_options.max_wait_ms = 5000;
  lock_options.retry_ms = 5;
  Result<detail::FileLock> held = detail::FileLock::acquire(join(store, detail::kLockFileName), lock_options);
  CSP_REQUIRE(held.has_value());

  const HelperResult refused = run_helper({"audit", store, "100"}, output);
  CSP_EXPECT_MSG(refused.exit_code == 1, "the helper exited " + std::to_string(refused.exit_code) + ": " +
                                             refused.line);
  CSP_EXPECT_EQ(refused.category, std::string("locked"));
  CSP_EXPECT_EQ(refused.code, std::string("csp.lock.timeout"));
  // The wait was bounded and it really was waited: a refusal that returned instantly
  // would not be evidence that the lock was contended.
  CSP_EXPECT_MSG(refused.elapsed_ms >= 50, "the helper returned in " + std::to_string(refused.elapsed_ms) + " ms");
  CSP_EXPECT_MSG(refused.elapsed_ms <= 5000, "the helper waited " + std::to_string(refused.elapsed_ms) + " ms");

  held.value().release();
  const HelperResult allowed = run_helper({"audit", store, "1000"}, output);
  CSP_REQUIRE_MSG(allowed.exit_code == 0, allowed.line);
  CSP_REQUIRE_MSG(allowed.ok, allowed.line);
  CSP_EXPECT_EQ(allowed.token, std::string("csp.helper.audit"));
  CSP_EXPECT_EQ(allowed.detail, std::string("1 1 1 ") + plan.value().plan.value());
}

CSP_TEST(multiprocess, a_real_process_holding_the_lock_refuses_the_parent) {
  ScratchDirectory scratch("child-lock");
  const std::string store = join(scratch.path(), "store");
  const std::string marker = join(scratch.path(), "held.marker");
  const std::string output = join(scratch.path(), "hold.out");

  Result<PlacementPlan> plan = make_plan("request-1", "obligation-1", 1);
  CSP_REQUIRE(plan.has_value());
  Result<PlanStore> opened = PlanStore::open(options_for(store));
  CSP_REQUIRE(opened.has_value());
  PlanStore parent_store = std::move(opened).value();
  CSP_REQUIRE(parent_store.commit(plan.value()).has_value());
  CSP_EXPECT_OK(parent_store.close());

  HelperResult holding;
  std::thread holder([&]() { holding = run_helper({"hold-lock", store, "1500", marker}, output); });

  // Bounded readiness wait: the marker appears once the child holds the lock. If it
  // never appears the case fails rather than passing on an untested claim.
  bool ready = false;
  for (std::size_t attempt = 0; attempt < 400 && !ready; ++attempt) {
    ready = detail::file_exists(marker);
    if (!ready) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }

  Limits limits;
  limits.store_lock_wait_ms = 100;
  limits.store_lock_retry_ms = 5;
  StoreOptions options = options_for(store);
  options.limits = limits;
  Result<PlanStore> refused = PlanStore::open(options);

  // The child is joined before anything is asserted. A required check that left the
  // case with a joinable thread would terminate the process instead of reporting.
  holder.join();

  CSP_REQUIRE_MSG(ready, "the child never reported holding the store lock");
  CSP_REQUIRE_MSG(!refused.has_value(), "the parent opened a store whose lock a real process held");
  CSP_EXPECT(refused.error().category() == ErrorCategory::Locked);
  CSP_EXPECT_EQ(refused.error().code(), std::string("csp.lock.timeout"));
  CSP_REQUIRE_MSG(holding.exit_code == 0, holding.line);
  CSP_REQUIRE_MSG(holding.ok, holding.line);
  CSP_EXPECT_EQ(holding.token, std::string("csp.helper.hold-lock"));
  CSP_EXPECT_EQ(holding.detail, std::string("1500"));

  // With the child gone the parent can open the store again, so the refusal above was
  // caused by the lock and by nothing else.
  Result<PlanStore> after = PlanStore::open(options_for(store));
  CSP_REQUIRE(after.has_value());
  Result<StoreAudit> audit = after.value().audit();
  CSP_REQUIRE(audit.has_value());
  CSP_EXPECT(audit.value().consistent);
  CSP_EXPECT_EQ(audit.value().records.size(), std::size_t{1});
  CSP_EXPECT_OK(after.value().close());
}

CSP_TEST(multiprocess, crash_boundary_between_record_and_manifest_is_not_adopted) {
  ScratchDirectory scratch("crash-boundary");
  const std::string committed_store = join(scratch.path(), "store");
  const std::string after_store = join(scratch.path(), "store-after");
  const std::string crash_store = join(scratch.path(), "store-crash");

  Result<PlacementPlan> first = make_plan("request-1", "obligation-1", 1);
  Result<PlacementPlan> second = make_plan("request-2", "obligation-2", 2);
  CSP_REQUIRE(first.has_value() && second.has_value());

  // A store holding one published plan, and its manifest copied aside.
  Result<PlanStore> opened = PlanStore::open(options_for(committed_store));
  CSP_REQUIRE(opened.has_value());
  PlanStore parent_store = std::move(opened).value();
  CSP_REQUIRE(parent_store.commit(first.value()).has_value());
  CSP_EXPECT_OK(parent_store.close());
  const std::string before_manifest = join(committed_store, detail::kManifestFileName);
  Result<std::string> manifest_bytes = detail::read_file_bounded(before_manifest, 1u << 20);
  CSP_REQUIRE(manifest_bytes.has_value());

  // A real process commits a second plan into a copy of that directory. The copy is what
  // the directory looked like after that commit's record write and manifest write.
  std::error_code copy_error;
  std::filesystem::copy(committed_store, after_store,
                        std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing,
                        copy_error);
  CSP_REQUIRE_MSG(!copy_error, "cannot copy the store directory: " + copy_error.message());
  const std::string second_document = join(scratch.path(), "second.json");
  CSP_REQUIRE(write_document(second_document, second.value()));
  const HelperResult committed =
      run_helper({"commit", after_store, second_document, "1000"}, join(scratch.path(), "commit.out"));
  CSP_REQUIRE_MSG(committed.exit_code == 0, committed.line);
  CSP_REQUIRE_MSG(committed.ok, committed.line);
  CSP_EXPECT_EQ(committed.detail, second.value().plan.value());

  // Now take the state between the two writes: the directory as the commit left it,
  // with the manifest it had before the commit. Nothing is killed; the boundary is
  // reconstructed from real artefacts.
  std::filesystem::copy(after_store, crash_store,
                        std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing,
                        copy_error);
  CSP_REQUIRE_MSG(!copy_error, "cannot copy the store directory: " + copy_error.message());
  CSP_REQUIRE(detail::write_file_durable(join(crash_store, detail::kManifestFileName), manifest_bytes.value())
                  .has_value());
  const std::string orphan_record = join(join(crash_store, detail::kRecordsDirectoryName),
                                         detail::record_file_name(second.value().plan));
  CSP_EXPECT(detail::file_exists(orphan_record));

  Result<PlanStore> recovered = PlanStore::open(options_for(crash_store));
  CSP_REQUIRE(recovered.has_value());
  PlanStore store = std::move(recovered).value();
  CSP_EXPECT_EQ(store.generation().value(), std::uint64_t{1});
  Result<StoreAudit> audit = store.audit();
  CSP_REQUIRE(audit.has_value());
  CSP_EXPECT(audit.value().consistent);
  CSP_EXPECT_EQ(audit.value().records.size(), std::size_t{1});
  CSP_EXPECT(contains(audit.value().records, first.value().plan));

  bool reported = false;
  for (const RecoveryFinding& finding : audit.value().recovery) {
    if (finding.action == RecoveryAction::RetainedAheadRecord &&
        finding.detail.find(second.value().plan.value()) != std::string::npos) {
      reported = true;
    }
  }
  CSP_EXPECT_MSG(reported, "recovery did not report the unreferenced record");

  // It was reported, not adopted: the plan is not in the store and cannot be loaded.
  Result<PlacementPlan> adopted = store.load(second.value().plan);
  CSP_EXPECT(!adopted.has_value());
  if (!adopted.has_value()) {
    CSP_EXPECT(adopted.error().category() == ErrorCategory::NotFound);
    CSP_EXPECT_EQ(adopted.error().code(), std::string("csp.store.unknown_plan"));
  }
  CSP_EXPECT(store.load(first.value().plan).has_value());

  // Compaction keeps a record newer than the committed generation, because it may be the
  // durable half of a commit that is still in flight somewhere.
  CSP_EXPECT_OK(store.compact());
  CSP_EXPECT_MSG(detail::file_exists(orphan_record),
                 "compaction removed a record newer than the committed generation");
  Result<StoreAudit> after = store.audit();
  CSP_REQUIRE(after.has_value());
  CSP_EXPECT(after.value().consistent);
  CSP_EXPECT_EQ(after.value().records.size(), std::size_t{1});
  CSP_EXPECT_OK(store.close());
}
