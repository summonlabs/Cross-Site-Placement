// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Every bound this boundary enforces, in one place.
//
// The bounds are a value rather than a set of compile-time constants because a bound
// that cannot be lowered cannot be tested: the adversarial suite lowers each one until
// the limit is the thing under test. The defaults are sized for a regional fleet and
// are not a claim about what any deployment needs.

#ifndef CROSS_SITE_PLACEMENT_LIMITS_HPP
#define CROSS_SITE_PLACEMENT_LIMITS_HPP

#include <cstddef>
#include <cstdint>

#include "cross_site_placement/error.hpp"

namespace csp {

struct Limits {
  // ---- Documents -----------------------------------------------------------
  /// Largest document accepted from a file or a pipe.
  std::size_t max_document_bytes = 16u * 1024u * 1024u;
  /// Deepest nesting accepted by the document decoder.
  std::size_t max_document_depth = 48;

  // ---- Request -------------------------------------------------------------
  std::size_t max_obligations = 4096;
  /// Placements requested for one obligation, in either role.
  std::size_t max_placements_per_obligation = 64;
  std::size_t max_latency_requirements = 4096;
  std::size_t max_separation_requirements = 1024;
  /// There are exactly seven domain kinds, so a bound above seven would constrain
  /// nothing and is refused by limits_validate rather than left as a silent no-op.
  std::size_t max_separated_kinds = 7;
  std::size_t max_site_lists = 200000;
  std::size_t max_jurisdiction_lists = 4096;

  // ---- Evidence ------------------------------------------------------------
  std::size_t max_sites = 200000;
  std::size_t max_failure_domains = 500000;
  std::size_t max_domain_assignments = 2000000;
  std::size_t max_domain_aliases = 100000;
  /// Longest containment chain from a site's immediate domain to a root.
  std::size_t max_domain_depth = 64;
  /// Total resolved site-ancestry entries for one planning call. Containment is
  /// transitive, so the resolved ancestry of every site is the product of three
  /// externally supplied numbers; without this bound an adversarial snapshot could ask
  /// for an arbitrarily large one.
  std::size_t max_resolved_domains = 4000000;
  std::size_t max_capacity_evidence = 1000000;
  std::size_t max_latency_evidence = 2000000;
  std::size_t max_recovery_evidence = 500000;
  std::size_t max_compatibility_evidence = 1000000;
  std::size_t max_cost_risk_evidence = 500000;

  // ---- Output --------------------------------------------------------------
  std::size_t max_trace_entries = 200000;
  std::size_t max_residual_entries = 8192;
  std::size_t max_tie_break_entries = 8192;
  std::size_t max_plan_sites = 8192;

  // ---- Search --------------------------------------------------------------
  /// Nodes the placement search may expand before it stops. Exhausting the budget is
  /// reported as an indeterminate result, never as a refusal.
  std::uint64_t max_search_nodes = 2000000;
  /// Longest derived latency path, in evidence hops, when the policy allows a bound to
  /// be derived from a chain of maximum-statistic measurements.
  std::size_t max_derived_hops = 4;
  /// Edge relaxations the derived-latency search may perform in total.
  std::uint64_t max_derived_expansions = 200000;

  // ---- Freshness -----------------------------------------------------------
  /// Oldest evidence this boundary will use when the request does not narrow it.
  std::int64_t max_evidence_age_nanos = 86400LL * 1000000000LL;
  /// Longest validity window a plan may carry.
  std::int64_t max_plan_validity_nanos = 900LL * 1000000000LL;
  /// Slack allowed when an observation is dated slightly after the evaluation instant,
  /// because two authorities' clocks are not the same clock.
  std::int64_t max_clock_skew_nanos = 60LL * 1000000000LL;

  // ---- Concurrency ---------------------------------------------------------
  /// Worker threads used to evaluate candidate sites. Zero means the caller's thread
  /// does the work, which is the default because it is the only choice whose behaviour
  /// does not depend on how many cores the machine happens to have.
  std::size_t worker_threads = 0;
  /// Smallest number of candidate sites worth splitting across workers. Below this the
  /// bookkeeping costs more than the work.
  std::size_t parallel_threshold = 512;

  // ---- Durable store -------------------------------------------------------
  std::size_t max_store_records = 100000;
  std::size_t max_store_record_bytes = 8u * 1024u * 1024u;
  std::size_t store_lock_wait_ms = 5000;
  std::size_t store_lock_retry_ms = 5;
};

/// Checks that the bounds are internally consistent and usable. A zero bound is a
/// configuration error, not a way to ask for unlimited work: there is no unlimited.
[[nodiscard]] Status limits_validate(const Limits& limits);

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_LIMITS_HPP
