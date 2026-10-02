// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The platform adapter for durable files and exclusive locks.
//
// Everything here is deliberately small and deliberately honest about what the
// platform actually guarantees. write_file_durable means: the bytes have been handed
// to the operating system's flush for this file before the visible name is replaced,
// and the directory entry itself has been flushed where the platform offers such a
// call. It does not mean the data has reached stable media of any particular class,
// and the public documentation says so rather than implying a stronger claim.
//
// This is the only translation unit in the library that includes a platform header.

#ifndef CSP_SRC_FS_ATOMIC_HPP
#define CSP_SRC_FS_ATOMIC_HPP

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "cross_site_placement/error.hpp"

namespace csp::detail {

struct FileLockOptions {
  /// Total time the caller is willing to spend trying to acquire the lock. The wait
  /// is always bounded: an unbounded wait turns a crashed holder into a hung process,
  /// and a bounded wait that loses is a refusal the caller can act on.
  std::size_t max_wait_ms = 5000;
  /// Gap between attempts.
  std::size_t retry_ms = 5;
};

/// An exclusive advisory lock on a path, held for the lifetime of the object.
///
/// On Windows the lock is a mandatory region lock over the whole file held by the
/// owning handle. On POSIX it is flock(LOCK_EX). Both are advisory with respect to a
/// process that chooses not to participate, which is why the store funnels every
/// mutation through this type instead of relying on the lock by itself.
class FileLock {
 public:
  FileLock() noexcept = default;
  ~FileLock();
  FileLock(FileLock&& other) noexcept;
  FileLock& operator=(FileLock&& other) noexcept;
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;

  /// Creates the lock file if needed and takes the lock. Returns
  /// ErrorCategory::Locked when the bounded wait expires, and ErrorCategory::Io when
  /// the path itself cannot be opened for a reason that will not improve by waiting.
  [[nodiscard]] static Result<FileLock> acquire(const std::string& path, const FileLockOptions& options);

  bool held() const noexcept;
  const std::string& path() const noexcept;
  void release() noexcept;

 private:
  struct Impl;
  std::shared_ptr<Impl> impl_;
};

/// Writes the bytes to the path so that a concurrent reader observes either the
/// previous contents or the complete new contents, never a mixture, and so that a
/// crash after the call has returned cannot leave the name pointing at unwritten
/// data.
///
/// Implementation shape, in order:
///   1. create a sibling staging file in the same directory, so the replace below
///      stays within one volume and is therefore atomic;
///   2. write every byte, retrying short writes rather than assuming one call is one
///      complete write;
///   3. flush the staging file to the platform durability boundary;
///   4. replace the destination with the staging file in a single atomic step;
///   5. flush the containing directory where the platform has such a call.
/// On any failure the staging file is removed and the destination is left exactly as
/// it was.
[[nodiscard]] Status write_file_durable(const std::string& path, std::string_view bytes);

/// Reads at most max_bytes. Returns ErrorCategory::BoundExceeded when the file is
/// larger than the bound, ErrorCategory::NotFound when it does not exist, and
/// ErrorCategory::Io for anything else.
[[nodiscard]] Result<std::string> read_file_bounded(const std::string& path, std::size_t max_bytes);

[[nodiscard]] bool file_exists(const std::string& path);
[[nodiscard]] bool directory_exists(const std::string& path);

/// Removes a file. A file that is already absent is a success, because every caller
/// here is cleaning up after an operation whose outcome it has already decided.
[[nodiscard]] Status remove_file(const std::string& path);

/// Creates the directory and every missing parent. An existing directory is a
/// success only if it really is a directory.
[[nodiscard]] Status create_directories(const std::string& path);

/// Removes a directory and its contents. A symbolic link or reparse point is removed
/// as a link; its target is never traversed, so a link pointing outside the tree
/// cannot cause a deletion outside the tree.
[[nodiscard]] Status remove_directory_tree(const std::string& path);

/// Names of the entries in a directory, sorted by byte order so that every caller
/// that iterates a store directory does so in a deterministic sequence. Directories
/// are included; the call does not recurse.
[[nodiscard]] Result<std::vector<std::string>> list_directory(const std::string& path);

}  // namespace csp::detail

#endif  // CSP_SRC_FS_ATOMIC_HPP
