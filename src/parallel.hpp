// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Bounded parallel iteration.
//
// The engine uses this for exactly one thing: evaluating a per-candidate predicate over
// a candidate list. The predicate is a pure function of the candidate and the snapshot.
// It writes only its own slot, holds no lock, and calls nothing that acquires one, so
// there is no shared mutable state for the workers to race on and no lock ordering to
// get wrong. The result is assembled by reading the slots in index order, which is why
// the answer does not depend on how many workers ran or which one finished first.

#ifndef CSP_SRC_PARALLEL_HPP
#define CSP_SRC_PARALLEL_HPP

#include <cstddef>
#include <functional>

#include "cross_site_placement/cancellation.hpp"

namespace csp::detail {

struct ParallelOptions {
  /// Zero means run on the calling thread.
  std::size_t worker_threads = 0;
  /// Below this item count the bookkeeping costs more than the work, so the calling
  /// thread does everything.
  std::size_t threshold = 512;
};

/// Calls body(index) for every index in [0, count) exactly once.
///
/// The body must not throw and must not touch state shared with another invocation.
/// Both requirements are structural rather than defensive: a throwing body would
/// terminate the process from a worker thread, and shared mutable state would make the
/// result depend on scheduling, which is the property this boundary exists to deny.
///
/// Stops early when the token is cancelled. Because a cancelled call returns no value
/// at all, a partly filled result array is never read.
void parallel_for(std::size_t count, const ParallelOptions& options, const CancellationToken& token,
                  const std::function<void(std::size_t)>& body);

}  // namespace csp::detail

#endif  // CSP_SRC_PARALLEL_HPP
