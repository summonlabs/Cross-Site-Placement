// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The durable plan store.
//
// The store exists so that a plan survives the process that made it. It is a journal of
// published plans, not a database of the world: it holds no capacity, no site, and no
// policy, and nothing in it is authoritative for anything except which plans this
// boundary has published and at which generation.
//
// The commit protocol is deliberate about what is and is not durable:
//
//   plan -> validate -> reserve nothing -> write a staging file -> flush it ->
//   read it back and decode it -> verify its digest -> replace the record atomically ->
//   write and flush a new manifest -> publish
//
// The manifest is written last and is what makes a commit visible. A crash before the
// manifest lands leaves a record that no manifest references; that record is reported by
// recovery and is never silently promoted. A crash during the manifest write leaves the
// previous manifest, which is still entirely valid, because the manifest is replaced
// atomically from a staging file of its own.
//
// Durability claim, stated exactly: on return from a successful commit, the record and
// the manifest have been handed to the operating system's flush for those files, and the
// directory entry has been flushed where the platform provides such a call. That is a
// claim about the flush boundary, not about any particular class of stable media.

#ifndef CROSS_SITE_PLACEMENT_PERSISTENCE_HPP
#define CROSS_SITE_PLACEMENT_PERSISTENCE_HPP

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "cross_site_placement/limits.hpp"
#include "cross_site_placement/plan.hpp"

namespace csp {

struct StoreOptions {
  /// Directory holding the store. Created if it does not exist.
  std::string directory;
  Limits limits;
  /// Zero means the configured limit applies.
  std::size_t lock_wait_ms = 0;
  std::size_t lock_retry_ms = 0;
};

/// What recovery did, so that an operator can see it rather than infer it.
enum class RecoveryAction : std::uint8_t {
  /// An interrupted commit's staging file was removed. The commit had not been
  /// published, so removing it restores nothing and destroys nothing.
  RemovedStagingFile = 0,
  /// A record that no committed manifest references was removed by an explicit
  /// compaction. Recovery itself does not remove these; it reports them.
  RemovedOrphanRecord = 1,
  /// A record newer than the manifest was found and kept. It may be the durable half of
  /// a commit that never became visible, and throwing it away would discard the only
  /// copy of work whose status is not yet known.
  RetainedAheadRecord = 2,
  /// No action was needed.
  None = 3,
};

const char* to_string(RecoveryAction action) noexcept;

struct RecoveryFinding {
  RecoveryAction action = RecoveryAction::None;
  std::string detail;
};

struct StoreAudit {
  /// True when the manifest verified and every record it references verified against
  /// its own digest.
  bool consistent = false;
  Generation generation;
  std::vector<PlanId> records;
  std::vector<RecoveryFinding> recovery;
  Digest manifest_digest;
  std::size_t record_bytes = 0;
};

class PlanStore {
 public:
  PlanStore() noexcept;

  /// The lock order this type maintains, which has no inversions: the object's own mutex
  /// first, the store's lock file second. No caller code runs while either is held.
  ~PlanStore();
  PlanStore(PlanStore&& other) noexcept;
  PlanStore& operator=(PlanStore&& other) noexcept;
  PlanStore(const PlanStore&) = delete;
  PlanStore& operator=(const PlanStore&) = delete;

  /// Opens the store, creating the directory if needed, taking the store lock for the
  /// duration of recovery, verifying the manifest, verifying every record it references,
  /// and removing interrupted staging files. Interior corruption is an error: the store
  /// refuses to open rather than truncating through it and calling the result recovery.
  [[nodiscard]] static Result<PlanStore> open(const StoreOptions& options);

  const std::string& directory() const noexcept;
  Generation generation() const noexcept;
  bool is_open() const noexcept;

  /// Publishes a plan, sealing it first if it has no digest yet. Returns the plan's
  /// identity. The commit takes the store lock, re-reads the manifest under it, and
  /// verifies that the generation it read is still current before replacing anything.
  [[nodiscard]] Result<PlanId> commit(const PlacementPlan& plan);

  /// Publishes a plan only if the store is still at the generation the caller saw. A
  /// mismatch is ErrorCategory::Stale naming both generations; nothing is written.
  [[nodiscard]] Result<PlanId> commit_if_generation(const PlacementPlan& plan, Generation expected);

  [[nodiscard]] Result<PlacementPlan> load(const PlanId& plan) const;
  [[nodiscard]] Result<std::vector<PlanId>> list() const;
  [[nodiscard]] Result<StoreAudit> audit() const;

  /// Removes records that no committed manifest references and that are strictly older
  /// than the committed generation, then rewrites the manifest. Records newer than the
  /// committed generation are never removed: they may be the durable half of a commit
  /// that is still in flight somewhere.
  [[nodiscard]] Status compact();

  /// Releases the handle. Idempotent, and called by the destructor. A store that is
  /// destroyed without an explicit close is still closed cleanly; there is no state left
  /// to lose, because every commit was already durable when it returned.
  Status close();

 private:
  struct Impl;
  std::shared_ptr<Impl> impl_;
};

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_PERSISTENCE_HPP
