// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The durable plan store.
//
// Lock order, which has no inversions: a PlanStore takes its own mutex first and the
// store's lock file second. Nothing takes the lock file and then the mutex, and no user
// code runs while either is held. The mutex protects this object's in-memory copy of the
// manifest; the lock file protects the directory against another process.

#include "cross_site_placement/persistence.hpp"

#include <algorithm>
#include <cstddef>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "cross_site_placement/text.hpp"
#include "fs_atomic.hpp"
#include "sha256.hpp"
#include "store_format.hpp"

namespace csp {
namespace {

std::string join_path(const std::string& directory, const std::string& name) {
  if (directory.empty()) {
    return name;
  }
  const char last = directory.back();
  if (last == '/' || last == '\\') {
    return directory + name;
  }
  return directory + "/" + name;
}

bool is_staging_name(const std::string& name) {
  return name.find(detail::kStagingMarker) != std::string::npos;
}

bool is_record_name(const std::string& name) {
  const std::string suffix = detail::kRecordSuffix;
  return name.size() > suffix.size() && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string plan_of_record_name(const std::string& name) {
  return name.substr(0, name.size() - std::string(detail::kRecordSuffix).size());
}

}  // namespace

const char* to_string(RecoveryAction action) noexcept {
  switch (action) {
    case RecoveryAction::RemovedStagingFile:
      return "removed-staging-file";
    case RecoveryAction::RemovedOrphanRecord:
      return "removed-orphan-record";
    case RecoveryAction::RetainedAheadRecord:
      return "retained-ahead-record";
    case RecoveryAction::None:
    default:
      return "none";
  }
}

struct PlanStore::Impl {
  std::string directory;
  std::string manifest_path;
  std::string records_path;
  std::string lock_path;
  Limits limits;
  detail::FileLockOptions lock_options;
  Generation generation;
  std::vector<detail::RecordEntry> records;
  std::vector<RecoveryFinding> recovery;
  bool opened = false;
  mutable std::mutex mutex;
};

namespace {

/// Reads and verifies the manifest, then every record it references. Interior
/// corruption is an error here: the store refuses to open rather than truncating through
/// it and calling the result recovery. A record that fails its digest may be the only
/// copy of a published plan, and quietly dropping it would turn a detectable fault into
/// a silent loss.
Result<detail::Manifest> read_verified_manifest(const std::string& manifest_path, const std::string& records_path,
                                                const Limits& limits,
                                                std::vector<RecoveryFinding>& findings) {
  if (!detail::file_exists(manifest_path)) {
    return detail::Manifest{};
  }
  Result<std::string> bytes = detail::read_file_bounded(manifest_path, limits.max_document_bytes);
  if (!bytes) {
    return bytes.error();
  }
  Result<detail::Manifest> manifest = detail::decode_manifest(bytes.value());
  if (!manifest) {
    return manifest.error();
  }
  const detail::Manifest& decoded = manifest.value();
  if (decoded.records.size() > limits.max_store_records) {
    return fail(ErrorCategory::BoundExceeded, "csp.store.too_many_records",
                "the manifest references more records than the configured bound allows");
  }
  for (const detail::RecordEntry& entry : decoded.records) {
    const std::string path = join_path(records_path, detail::record_file_name(entry.plan));
    if (!detail::file_exists(path)) {
      return fail(ErrorCategory::Integrity, "csp.store.record_missing",
                  "the manifest references record " + entry.plan.value() +
                      " and the record is not present; the store is incomplete and is refused rather than "
                      "opened with a hole in it");
    }
    Result<std::string> record = detail::read_file_bounded(path, limits.max_store_record_bytes);
    if (!record) {
      return record.error();
    }
    if (record.value().size() != entry.bytes) {
      return fail(ErrorCategory::Integrity, "csp.store.record_size",
                  "record " + entry.plan.value() + " is " + std::to_string(record.value().size()) +
                      " bytes and the manifest declares " + std::to_string(entry.bytes));
    }
    if (Digest::of(record.value()) != entry.digest) {
      return fail(ErrorCategory::Integrity, "csp.store.record_digest",
                  "record " + entry.plan.value() +
                      " does not match the digest the manifest recorded for it");
    }
  }
  (void)findings;
  return decoded;
}

Status remove_staging_files(const std::string& records_path, std::vector<RecoveryFinding>& findings) {
  Result<std::vector<std::string>> names = detail::list_directory(records_path);
  if (!names) {
    return names.error();
  }
  for (const std::string& name : names.value()) {
    if (!is_staging_name(name)) {
      continue;
    }
    const Status status = detail::remove_file(join_path(records_path, name));
    if (!status) {
      return status;
    }
    RecoveryFinding finding;
    finding.action = RecoveryAction::RemovedStagingFile;
    finding.detail = "removed " + name + ", the durable half of a commit that never became visible";
    findings.push_back(std::move(finding));
  }
  return success();
}

Status note_unreferenced(const std::string& records_path, const detail::Manifest& manifest,
                         std::vector<RecoveryFinding>& findings) {
  Result<std::vector<std::string>> names = detail::list_directory(records_path);
  if (!names) {
    return names.error();
  }
  for (const std::string& name : names.value()) {
    if (!is_record_name(name)) {
      continue;
    }
    const std::string plan_name = plan_of_record_name(name);
    const bool referenced =
        std::any_of(manifest.records.begin(), manifest.records.end(),
                    [&plan_name](const detail::RecordEntry& entry) { return entry.plan.value() == plan_name; });
    if (referenced) {
      continue;
    }
    RecoveryFinding finding;
    finding.action = RecoveryAction::RetainedAheadRecord;
    finding.detail = "record " + plan_name +
                     " is present and no committed manifest references it; it is reported and kept, because it "
                     "may be the durable half of a commit that is still in flight";
    findings.push_back(std::move(finding));
  }
  return success();
}

/// True when two identities differ at most in the case of their letters. The identity
/// alphabet is ASCII, so the comparison is too.
bool same_ignoring_case(const std::string& lhs, const std::string& rhs) {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  const auto fold = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
  for (std::size_t index = 0; index < lhs.size(); ++index) {
    if (fold(lhs[index]) != fold(rhs[index])) {
      return false;
    }
  }
  return true;
}

Status find_record(const std::vector<detail::RecordEntry>& records, const PlanId& plan,
                   const detail::RecordEntry** out) {
  *out = nullptr;
  for (const detail::RecordEntry& entry : records) {
    if (entry.plan == plan) {
      *out = &entry;
      return success();
    }
  }
  return success();
}

}  // namespace

PlanStore::PlanStore() noexcept : impl_(std::make_shared<Impl>()) {}

PlanStore::~PlanStore() {
  try {
    const Status status = close();
    (void)status;
  } catch (...) {
    // A destructor that threw during unwinding would terminate the process. Closing is
    // best effort here and is reported by an explicit close() call.
  }
}

PlanStore::PlanStore(PlanStore&& other) noexcept : impl_(std::move(other.impl_)) {
  other.impl_ = std::make_shared<Impl>();
}

PlanStore& PlanStore::operator=(PlanStore&& other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
    other.impl_ = std::make_shared<Impl>();
  }
  return *this;
}

Result<PlanStore> PlanStore::open(const StoreOptions& options) {
  Status status = limits_validate(options.limits);
  if (!status) {
    return status.error();
  }
  if (options.directory.empty()) {
    return fail(ErrorCategory::Invalid, "csp.store.no_directory",
                "a store needs a directory; the empty path is not one");
  }
  PlanStore store;
  Impl& impl = *store.impl_;
  impl.directory = options.directory;
  impl.manifest_path = join_path(options.directory, detail::kManifestFileName);
  impl.records_path = join_path(options.directory, detail::kRecordsDirectoryName);
  impl.lock_path = join_path(options.directory, detail::kLockFileName);
  impl.limits = options.limits;
  impl.lock_options.max_wait_ms = options.lock_wait_ms != 0 ? options.lock_wait_ms : options.limits.store_lock_wait_ms;
  impl.lock_options.retry_ms = options.lock_retry_ms != 0 ? options.lock_retry_ms : options.limits.store_lock_retry_ms;

  status = detail::create_directories(options.directory);
  if (!status) {
    return status.error();
  }
  status = detail::create_directories(impl.records_path);
  if (!status) {
    return status.error();
  }

  Result<detail::FileLock> lock = detail::FileLock::acquire(impl.lock_path, impl.lock_options);
  if (!lock) {
    return lock.error();
  }

  std::vector<RecoveryFinding> findings;
  status = remove_staging_files(impl.records_path, findings);
  if (!status) {
    return status.error();
  }
  Result<detail::Manifest> manifest =
      read_verified_manifest(impl.manifest_path, impl.records_path, impl.limits, findings);
  if (!manifest) {
    return manifest.error();
  }
  status = note_unreferenced(impl.records_path, manifest.value(), findings);
  if (!status) {
    return status.error();
  }
  impl.generation = Generation::from_value(manifest.value().generation);
  impl.records = manifest.value().records;
  impl.recovery = std::move(findings);
  impl.opened = true;
  return store;
}

const std::string& PlanStore::directory() const noexcept { return impl_->directory; }

Generation PlanStore::generation() const noexcept {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->generation;
}

bool PlanStore::is_open() const noexcept { return impl_->opened; }

Result<PlanId> PlanStore::commit(const PlacementPlan& plan) {
  return commit_if_generation(plan, Generation{});
}

Result<PlanId> PlanStore::commit_if_generation(const PlacementPlan& plan, Generation expected) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> guard(impl.mutex);
  if (!impl.opened) {
    return fail(ErrorCategory::Invalid, "csp.store.closed", "the store has been closed");
  }

  PlacementPlan sealed = plan;
  if (sealed.digest.is_zero() || !sealed.plan.valid()) {
    plan_seal(sealed);
  }
  Status status = plan_validate(sealed, impl.limits);
  if (!status) {
    return status.error();
  }
  Result<std::string> payload = plan_to_document(sealed, false);
  if (!payload) {
    return payload.error();
  }
  // The document is read back under max_document_bytes when the plan is loaded, so a
  // document above either bound is one the store could publish and never return.
  if (payload.value().size() > impl.limits.max_store_record_bytes ||
      payload.value().size() > impl.limits.max_document_bytes) {
    return fail(ErrorCategory::BoundExceeded, "csp.store.record_too_large",
                "the plan encodes to more bytes than the configured record bound allows");
  }

  Result<detail::FileLock> lock = detail::FileLock::acquire(impl.lock_path, impl.lock_options);
  if (!lock) {
    return lock.error();
  }

  std::vector<RecoveryFinding> ignored;
  Result<detail::Manifest> manifest =
      read_verified_manifest(impl.manifest_path, impl.records_path, impl.limits, ignored);
  if (!manifest) {
    return manifest.error();
  }
  // The manifest just read under the lock is the store as it stands, so this handle's
  // own copy is brought up to it whatever the commit goes on to decide. The copy used to
  // move only when this handle published something itself: after another handle or
  // process had published, generation() kept reporting the old generation, and a commit
  // conditional on the generation the handle reported was refused as stale every time.
  impl.generation = Generation::from_value(manifest.value().generation);
  impl.records = manifest.value().records;
  const Generation current = impl.generation;
  if (expected.is_set() && current != expected) {
    return fail(ErrorCategory::Stale, "csp.store.generation_mismatch",
                "the caller expected generation " + std::to_string(expected.value()) +
                    " and the store is at " + std::to_string(current.value()) +
                    "; nothing was written");
  }

  const detail::RecordEntry* existing = nullptr;
  status = find_record(manifest.value().records, sealed.plan, &existing);
  if (!status) {
    return status.error();
  }
  if (existing != nullptr) {
    // A repeated commit of the same plan is idempotent; a repeated identity with
    // different content is a conflict, because one of the two would have to be dropped.
    // The comparison is on the decoded payload rather than on the record file, because
    // the manifest records a digest of the whole file and two encodings of one plan are
    // only equal if the plan is.
    const std::string path = join_path(impl.records_path, detail::record_file_name(sealed.plan));
    Result<std::string> bytes = detail::read_file_bounded(path, impl.limits.max_store_record_bytes);
    if (!bytes) {
      return bytes.error();
    }
    Result<detail::RecordPayload> decoded = detail::decode_record(bytes.value());
    if (!decoded) {
      return decoded.error();
    }
    if (decoded.value().payload != payload.value()) {
      return fail(ErrorCategory::Conflict, "csp.store.identity_reuse",
                  "the store already holds a plan under identity " + sealed.plan.value() +
                      " whose content differs from this one");
    }
    return sealed.plan;
  }

  // Everything below publishes a new record. The count bound is checked here, after the
  // repeat above, so that committing a plan a full store already holds is answered as
  // the repeat it is.
  if (manifest.value().records.size() >= impl.limits.max_store_records) {
    return fail(ErrorCategory::BoundExceeded, "csp.store.too_many_records",
                "the store already holds the configured maximum number of records");
  }

  // Loading verifies the plan against its digest. A plan whose content was changed
  // after it was sealed would be published as a record the store can never hand back.
  if (plan_compute_digest(sealed) != sealed.digest) {
    return fail(ErrorCategory::Integrity, "csp.store.digest_mismatch",
                "the plan's digest does not match its content; it was changed after it was sealed, and "
                "nothing was written");
  }

  // An identity is a file name. On a case-insensitive filesystem two identities that
  // differ only in case are one file, so the second record would replace the first while
  // the manifest still vouched for the first, and the store would not open again.
  for (const detail::RecordEntry& entry : manifest.value().records) {
    if (same_ignoring_case(entry.plan.value(), sealed.plan.value())) {
      return fail(ErrorCategory::Conflict, "csp.store.identity_case",
                  "the store already holds a plan under identity " + entry.plan.value() +
                      ", which differs from " + sealed.plan.value() +
                      " only in case; the two would share one record file");
    }
  }

  const Result<Generation> next = current.next();
  if (!next) {
    return next.error();
  }
  Result<std::string> record = detail::encode_record(sealed.plan, next.value(), payload.value());
  if (!record) {
    return record.error();
  }
  // Every open and every commit reads each record file, header and document together,
  // under max_store_record_bytes. Only the document used to be measured, so a document
  // within a header's length of the bound was written as a record the store refused to
  // read from then on.
  if (record.value().size() > impl.limits.max_store_record_bytes) {
    return fail(ErrorCategory::BoundExceeded, "csp.store.record_too_large",
                "the plan's record, header included, is more bytes than the configured record bound allows");
  }

  detail::Manifest updated = manifest.value();
  updated.generation = next.value().value();
  detail::RecordEntry entry;
  entry.plan = sealed.plan;
  entry.digest = Digest::of(record.value());
  entry.bytes = record.value().size();
  updated.records.push_back(std::move(entry));
  std::sort(updated.records.begin(), updated.records.end(),
            [](const detail::RecordEntry& lhs, const detail::RecordEntry& rhs) { return lhs.plan < rhs.plan; });

  Result<std::string> encoded = detail::encode_manifest(updated);
  if (!encoded) {
    return encoded.error();
  }
  // The manifest is read under max_document_bytes. One that has outgrown that bound
  // would be the last thing this store ever published.
  if (encoded.value().size() > impl.limits.max_document_bytes) {
    return fail(ErrorCategory::BoundExceeded, "csp.store.manifest_too_large",
                "the manifest with this record in it is more bytes than the configured document bound allows; "
                "nothing was written");
  }

  const std::string record_path = join_path(impl.records_path, detail::record_file_name(sealed.plan));
  status = detail::write_file_durable(record_path, record.value());
  if (!status) {
    return status.error();
  }
  // The protocol publishes a record only once it has been read back and found to be what
  // was written. Without this step a short or damaged write would be referenced by the
  // manifest and refused by every later open.
  {
    Result<std::string> stored = detail::read_file_bounded(record_path, impl.limits.max_store_record_bytes);
    if (!stored || stored.value() != record.value()) {
      (void)detail::remove_file(record_path);
      return fail(ErrorCategory::Integrity, "csp.store.record_readback",
                  "the record for plan " + sealed.plan.value() +
                      " did not read back as it was written; it was removed and nothing was published");
    }
  }

  status = detail::write_file_durable(impl.manifest_path, encoded.value());
  if (!status) {
    return status.error();
  }

  impl.generation = next.value();
  impl.records = updated.records;
  return sealed.plan;
}

Result<PlacementPlan> PlanStore::load(const PlanId& plan) const {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> guard(impl.mutex);
  if (!impl.opened) {
    return fail(ErrorCategory::Invalid, "csp.store.closed", "the store has been closed");
  }
  const detail::RecordEntry* entry = nullptr;
  const Status status = find_record(impl.records, plan, &entry);
  if (!status) {
    return status.error();
  }
  if (entry == nullptr) {
    // This handle's copy of the manifest is as old as the last time the handle read it.
    // A plan published since, through another handle or by another process, is in the
    // store, so the manifest is read again before the plan is reported as unknown.
    {
      Result<detail::FileLock> lock = detail::FileLock::acquire(impl.lock_path, impl.lock_options);
      if (!lock) {
        return lock.error();
      }
      if (detail::file_exists(impl.manifest_path)) {
        Result<std::string> manifest_bytes =
            detail::read_file_bounded(impl.manifest_path, impl.limits.max_document_bytes);
        if (!manifest_bytes) {
          return manifest_bytes.error();
        }
        Result<detail::Manifest> manifest = detail::decode_manifest(manifest_bytes.value());
        if (!manifest) {
          return manifest.error();
        }
        if (manifest.value().records.size() > impl.limits.max_store_records) {
          return fail(ErrorCategory::BoundExceeded, "csp.store.too_many_records",
                      "the manifest references more records than the configured bound allows");
        }
        impl.generation = Generation::from_value(manifest.value().generation);
        impl.records = manifest.value().records;
      }
    }
    const Status refreshed = find_record(impl.records, plan, &entry);
    if (!refreshed) {
      return refreshed.error();
    }
  }
  if (entry == nullptr) {
    return fail(ErrorCategory::NotFound, "csp.store.unknown_plan", "the store holds no plan " + plan.value());
  }
  const std::string path = join_path(impl.records_path, detail::record_file_name(plan));
  Result<std::string> bytes = detail::read_file_bounded(path, impl.limits.max_store_record_bytes);
  if (!bytes) {
    return bytes.error();
  }
  if (Digest::of(bytes.value()) != entry->digest) {
    return fail(ErrorCategory::Integrity, "csp.store.record_digest",
                "record " + plan.value() + " no longer matches the digest the manifest recorded for it");
  }
  Result<detail::RecordPayload> decoded = detail::decode_record(bytes.value());
  if (!decoded) {
    return decoded.error();
  }
  if (decoded.value().plan != plan) {
    return fail(ErrorCategory::Integrity, "csp.store.record_identity",
                "record " + plan.value() + " names a different plan inside its own header");
  }
  Result<PlacementPlan> parsed = plan_from_document(decoded.value().payload, impl.limits);
  if (!parsed) {
    return parsed.error();
  }
  if (parsed.value().plan != plan) {
    return fail(ErrorCategory::Integrity, "csp.store.record_identity",
                "record " + plan.value() + " decodes to a plan with a different identity");
  }
  return parsed.value();
}

Result<std::vector<PlanId>> PlanStore::list() const {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> guard(impl.mutex);
  if (!impl.opened) {
    return fail(ErrorCategory::Invalid, "csp.store.closed", "the store has been closed");
  }
  std::vector<PlanId> plans;
  plans.reserve(impl.records.size());
  for (const detail::RecordEntry& entry : impl.records) {
    plans.push_back(entry.plan);
  }
  return plans;
}

Result<StoreAudit> PlanStore::audit() const {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> guard(impl.mutex);
  if (!impl.opened) {
    return fail(ErrorCategory::Invalid, "csp.store.closed", "the store has been closed");
  }
  std::vector<RecoveryFinding> findings;
  Result<detail::Manifest> manifest =
      read_verified_manifest(impl.manifest_path, impl.records_path, impl.limits, findings);
  if (!manifest) {
    return manifest.error();
  }
  StoreAudit audit;
  audit.consistent = true;
  audit.generation = Generation::from_value(manifest.value().generation);
  audit.manifest_digest = manifest.value().digest;
  for (const detail::RecordEntry& entry : manifest.value().records) {
    audit.records.push_back(entry.plan);
    audit.record_bytes += static_cast<std::size_t>(entry.bytes);
  }
  audit.recovery = impl.recovery;
  return audit;
}

Status PlanStore::compact() {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> guard(impl.mutex);
  if (!impl.opened) {
    return fail(ErrorCategory::Invalid, "csp.store.closed", "the store has been closed");
  }
  Result<detail::FileLock> lock = detail::FileLock::acquire(impl.lock_path, impl.lock_options);
  if (!lock) {
    return lock.error();
  }
  std::vector<RecoveryFinding> ignored;
  Result<detail::Manifest> manifest =
      read_verified_manifest(impl.manifest_path, impl.records_path, impl.limits, ignored);
  if (!manifest) {
    return manifest.error();
  }
  Result<std::vector<std::string>> names = detail::list_directory(impl.records_path);
  if (!names) {
    return names.error();
  }
  for (const std::string& name : names.value()) {
    if (!is_record_name(name)) {
      continue;
    }
    const std::string plan_name = plan_of_record_name(name);
    const bool referenced =
        std::any_of(manifest.value().records.begin(), manifest.value().records.end(),
                    [&plan_name](const detail::RecordEntry& entry) { return entry.plan.value() == plan_name; });
    if (referenced) {
      continue;
    }
    const std::string path = join_path(impl.records_path, name);
    Result<std::string> bytes = detail::read_file_bounded(path, impl.limits.max_store_record_bytes);
    if (!bytes) {
      return bytes.error();
    }
    Result<detail::RecordPayload> decoded = detail::decode_record(bytes.value());
    if (!decoded) {
      // A record that does not decode and that no manifest references is exactly the
      // durable half of an interrupted commit, so removing it destroys nothing that was
      // ever published. A record that is newer than the committed generation is kept.
      continue;
    }
    if (decoded.value().generation.value() >= manifest.value().generation) {
      continue;
    }
    const Status status = detail::remove_file(path);
    if (!status) {
      return status;
    }
  }
  return success();
}

Status PlanStore::close() {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> guard(impl.mutex);
  impl.opened = false;
  impl.records.clear();
  impl.generation = Generation{};
  return success();
}

}  // namespace csp
