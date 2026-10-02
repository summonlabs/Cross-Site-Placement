// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "parallel.hpp"

#include <algorithm>
#include <atomic>
#include <thread>
#include <vector>

namespace csp::detail {

void parallel_for(std::size_t count, const ParallelOptions& options, const CancellationToken& token,
                  const std::function<void(std::size_t)>& body) {
  if (count == 0) {
    return;
  }

  const std::size_t requested = options.worker_threads;
  if (requested <= 1 || count < options.threshold) {
    for (std::size_t index = 0; index < count; ++index) {
      if (token.is_cancelled()) {
        return;
      }
      body(index);
    }
    return;
  }

  // One fewer worker than the bound, because the calling thread is one of them. The
  // worker count is a bound on threads, not a target: a machine with four cores asked
  // for eight workers still runs eight, which is the caller's stated budget.
  const std::size_t worker_count = std::min(requested - 1, count - 1);
  std::atomic<std::size_t> next{0};
  std::vector<std::thread> workers;
  workers.reserve(worker_count);

  for (std::size_t worker = 0; worker < worker_count; ++worker) {
    workers.emplace_back([&count, &next, &token, &body]() {
      for (;;) {
        if (token.is_cancelled()) {
          return;
        }
        const std::size_t index = next.fetch_add(1, std::memory_order_relaxed);
        if (index >= count) {
          return;
        }
        body(index);
      }
    });
  }

  for (;;) {
    if (token.is_cancelled()) {
      break;
    }
    const std::size_t index = next.fetch_add(1, std::memory_order_relaxed);
    if (index >= count) {
      break;
    }
    body(index);
  }

  // The workers are joined unconditionally, including on the cancellation path. A
  // worker is never abandoned, and nothing the caller owns is destroyed before every
  // worker has stopped touching it.
  for (std::thread& worker : workers) {
    worker.join();
  }
}

}  // namespace csp::detail
