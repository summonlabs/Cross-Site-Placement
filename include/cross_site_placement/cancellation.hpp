// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Cancellation.
//
// A cancelled operation returns ErrorCategory::Cancelled and no value. It never returns
// a partly computed plan, and it never reports success: cancelled work that later
// publishes a result is indistinguishable, to the caller that cancelled it, from work
// that ignored the cancellation.

#ifndef CROSS_SITE_PLACEMENT_CANCELLATION_HPP
#define CROSS_SITE_PLACEMENT_CANCELLATION_HPP

#include <atomic>
#include <memory>

namespace csp {

class CancellationSource;

/// A read-only view of a cancellation flag. A default-constructed token is never
/// cancelled, which is what a caller that does not care about cancellation passes.
class CancellationToken {
 public:
  CancellationToken() noexcept = default;

  bool is_cancelled() const noexcept {
    return flag_ != nullptr && flag_->load(std::memory_order_acquire);
  }
  bool can_cancel() const noexcept { return flag_ != nullptr; }

 private:
  friend class CancellationSource;
  explicit CancellationToken(std::shared_ptr<std::atomic<bool>> flag) noexcept : flag_(std::move(flag)) {}
  std::shared_ptr<std::atomic<bool>> flag_;
};

/// The writing end of a cancellation flag. Sharing the source with another thread is
/// the only supported way to cancel a planning call in flight; the flag is atomic and
/// no lock is taken on either side, so a cancellation never waits for the planner and
/// the planner never waits for a cancellation.
class CancellationSource {
 public:
  CancellationSource() : flag_(std::make_shared<std::atomic<bool>>(false)) {}

  void request_cancel() noexcept { flag_->store(true, std::memory_order_release); }
  bool is_cancelled() const noexcept { return flag_->load(std::memory_order_acquire); }
  CancellationToken token() const noexcept { return CancellationToken(flag_); }

 private:
  std::shared_ptr<std::atomic<bool>> flag_;
};

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_CANCELLATION_HPP
