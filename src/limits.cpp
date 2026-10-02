// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "cross_site_placement/limits.hpp"

#include <string>

namespace csp {
namespace {

Status require_positive(std::size_t value, const char* field) {
  if (value == 0) {
    std::string message = field;
    message += " must be at least 1; there is no unlimited setting";
    return fail(ErrorCategory::Invalid, "csp.limits.zero", std::move(message));
  }
  return success();
}

Status require_non_negative(std::int64_t value, const char* field) {
  if (value < 0) {
    std::string message = field;
    message += " must not be negative";
    return fail(ErrorCategory::Invalid, "csp.limits.negative", std::move(message));
  }
  return success();
}

}  // namespace

Status limits_validate(const Limits& limits) {
  const auto check_size = [](std::size_t value, const char* field) { return require_positive(value, field); };

  Status status = check_size(limits.max_document_bytes, "max_document_bytes");
  if (!status) return status;
  status = check_size(limits.max_document_depth, "max_document_depth");
  if (!status) return status;
  status = check_size(limits.max_obligations, "max_obligations");
  if (!status) return status;
  status = check_size(limits.max_placements_per_obligation, "max_placements_per_obligation");
  if (!status) return status;
  status = check_size(limits.max_latency_requirements, "max_latency_requirements");
  if (!status) return status;
  status = check_size(limits.max_separation_requirements, "max_separation_requirements");
  if (!status) return status;
  status = check_size(limits.max_separated_kinds, "max_separated_kinds");
  if (!status) return status;
  status = check_size(limits.max_site_lists, "max_site_lists");
  if (!status) return status;
  status = check_size(limits.max_jurisdiction_lists, "max_jurisdiction_lists");
  if (!status) return status;
  status = check_size(limits.max_sites, "max_sites");
  if (!status) return status;
  status = check_size(limits.max_failure_domains, "max_failure_domains");
  if (!status) return status;
  status = check_size(limits.max_domain_assignments, "max_domain_assignments");
  if (!status) return status;
  status = check_size(limits.max_domain_aliases, "max_domain_aliases");
  if (!status) return status;
  status = check_size(limits.max_domain_depth, "max_domain_depth");
  if (!status) return status;
  status = check_size(limits.max_resolved_domains, "max_resolved_domains");
  if (!status) return status;
  status = check_size(limits.max_capacity_evidence, "max_capacity_evidence");
  if (!status) return status;
  status = check_size(limits.max_latency_evidence, "max_latency_evidence");
  if (!status) return status;
  status = check_size(limits.max_recovery_evidence, "max_recovery_evidence");
  if (!status) return status;
  status = check_size(limits.max_compatibility_evidence, "max_compatibility_evidence");
  if (!status) return status;
  status = check_size(limits.max_cost_risk_evidence, "max_cost_risk_evidence");
  if (!status) return status;
  status = check_size(limits.max_trace_entries, "max_trace_entries");
  if (!status) return status;
  status = check_size(limits.max_residual_entries, "max_residual_entries");
  if (!status) return status;
  status = check_size(limits.max_tie_break_entries, "max_tie_break_entries");
  if (!status) return status;
  status = check_size(limits.max_plan_sites, "max_plan_sites");
  if (!status) return status;
  status = check_size(limits.max_search_nodes, "max_search_nodes");
  if (!status) return status;
  status = check_size(limits.max_derived_hops, "max_derived_hops");
  if (!status) return status;
  status = check_size(limits.max_derived_expansions, "max_derived_expansions");
  if (!status) return status;
  status = check_size(limits.parallel_threshold, "parallel_threshold");
  if (!status) return status;
  status = check_size(limits.max_store_records, "max_store_records");
  if (!status) return status;
  status = check_size(limits.max_store_record_bytes, "max_store_record_bytes");
  if (!status) return status;
  status = check_size(limits.store_lock_wait_ms, "store_lock_wait_ms");
  if (!status) return status;
  status = check_size(limits.store_lock_retry_ms, "store_lock_retry_ms");
  if (!status) return status;

  if (limits.max_document_depth < 2) {
    return fail(ErrorCategory::Invalid, "csp.limits.document_depth",
                "max_document_depth must be at least 2 so that a top-level object can hold a value");
  }
  if (limits.max_separated_kinds > 7) {
    return fail(ErrorCategory::Invalid, "csp.limits.separated_kinds",
                "max_separated_kinds exceeds the number of domain kinds, so the bound would constrain nothing");
  }
  if (limits.worker_threads > 1024) {
    return fail(ErrorCategory::Invalid, "csp.limits.worker_threads",
                "worker_threads above 1024 is not a bounded worker set; use <= 1024 or 0 for the calling thread");
  }
  if (limits.store_lock_retry_ms > limits.store_lock_wait_ms) {
    return fail(ErrorCategory::Invalid, "csp.limits.lock_retry",
                "store_lock_retry_ms exceeds store_lock_wait_ms, so no retry can ever happen");
  }
  if (limits.max_evidence_age_nanos < 0) {
    return fail(ErrorCategory::Invalid, "csp.limits.evidence_age",
                "max_evidence_age_nanos must not be negative");
  }
  status = require_non_negative(limits.max_plan_validity_nanos, "max_plan_validity_nanos");
  if (!status) return status;
  status = require_non_negative(limits.max_clock_skew_nanos, "max_clock_skew_nanos");
  if (!status) return status;

  return success();
}

}  // namespace csp
