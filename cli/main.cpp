// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// csp-cli, the command-line boundary of the cross-site placement library.
//
// Commands:
//   version                                print the library and format versions
//   rules                                  print the planner's rule tokens in evaluation order
//   plan      --request F --evidence F --policy F [--now NANOS] [--pretty] [--out F]
//   explain   --request F --evidence F --policy F [--now NANOS] [--pretty] [--out F]
//   verify    --plan F
//   revalidate --plan F --request F --evidence F --policy F [--now NANOS]
//   store     --dir D list | load --plan PLANID | audit | commit --plan F | compact
//   gen       --sites N --seed S --classes N --out DIR [--now NANOS]
//
// Exit codes, which are part of this tool's contract:
//   0  the command succeeded and, for plan and explain, the plan outcome is planned
//   1  the planner refused: a definite proof that no arrangement exists
//   2  the planner could not decide, or a revalidation verdict was undecidable
//   3  an error: malformed input, contradictory evidence, a bound, an I/O failure, or
//      a cancelled call
//
// Every failure prints one line to standard error in the form
//   csp-cli: <category>: <code>: <message>
// and no failure prints a partial plan: output is produced only after the whole result
// exists.
//
// The clock: the library never reads one, because two runs of the same logical request
// have to agree byte for byte. This tool reads the system clock for exactly one purpose,
// to supply the evaluation instant when --now is absent. Pass --now to make a run
// reproducible. The gen command uses the same instant as the moment its generated world
// was observed at, so a generated example can be planned against the clock.

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "cross_site_placement/cross_site_placement.hpp"

namespace {

using csp::Error;
using csp::ErrorCategory;
using csp::Result;
using csp::Status;

constexpr int kExitPlaced = 0;
constexpr int kExitRefused = 1;
constexpr int kExitIndeterminate = 2;
constexpr int kExitError = 3;

/// The bounds this tool accepts on input. The library owns them; the CLI reads them
/// rather than inventing a second, silently different set.
const csp::Limits kLimits{};

// ---------------------------------------------------------------------------
// Failure handling
// ---------------------------------------------------------------------------

int report(const Error& error) {
  std::cerr << "csp-cli: " << error.render() << '\n';
  return kExitError;
}

/// Reports a defect in this program's own input and stops. Used where an identity this
/// tool authored fails to parse, which no caller can cause.
[[noreturn]] void stop_on_defect(const Error& error) {
  const int code = report(error);
  std::exit(code);
}

/// Unwraps a result this program has already established cannot fail on the values it
/// constructs itself.
template <class T>
T must(Result<T> result) {
  if (!result) {
    stop_on_defect(result.error());
  }
  return std::move(result).value();
}

template <class IdType>
IdType make_id(const std::string& text) {
  return must(IdType::parse(text));
}

// ---------------------------------------------------------------------------
// Strict flag parsing
// ---------------------------------------------------------------------------

struct FlagSpec {
  std::string_view name;
  /// A flag with no value is a switch: --pretty. Every other flag takes the next token.
  bool takes_value = false;
};

/// The parsed command line. Rejecting an unknown flag, a missing value, and a repeated
/// flag here rather than later is what keeps a typo from silently changing an answer:
/// --evidnce would otherwise leave the evidence file unset and the run looking normal.
class Arguments {
 public:
  static Result<Arguments> parse(std::string_view command, const std::vector<std::string>& tokens,
                                 const std::vector<FlagSpec>& specs, bool allow_positional) {
    Arguments parsed;
    bool terminated = false;
    std::size_t index = 0;
    while (index < tokens.size()) {
      const std::string& token = tokens[index];
      if (!terminated && token == "--") {
        terminated = true;
        ++index;
        continue;
      }
      const bool looks_like_flag = !terminated && token.size() >= 2 && token.front() == '-';
      if (looks_like_flag) {
        const std::string name = token[1] == '-' ? token.substr(2) : token.substr(1);
        const auto spec = std::find_if(specs.begin(), specs.end(),
                                       [&name](const FlagSpec& entry) { return entry.name == name; });
        if (spec == specs.end()) {
          return csp::fail(ErrorCategory::Invalid, "csp.cli.unknown_flag",
                           std::string(command) + " does not accept --" + name +
                               "; run the command with --help for the flags it does accept");
        }
        if (parsed.values_.find(name) != parsed.values_.end()) {
          return csp::fail(ErrorCategory::Invalid, "csp.cli.repeated_flag",
                           std::string(command) + " was given --" + name +
                               " more than once, which states two different things at once");
        }
        if (!spec->takes_value) {
          parsed.values_.emplace(name, std::string());
          ++index;
          continue;
        }
        if (index + 1 >= tokens.size()) {
          return csp::fail(ErrorCategory::Invalid, "csp.cli.missing_value",
                           std::string(command) + " requires a value after --" + name);
        }
        const std::string& value = tokens[index + 1];
        if (value.size() >= 2 && value.front() == '-') {
          return csp::fail(ErrorCategory::Invalid, "csp.cli.missing_value",
                           std::string(command) + " requires a value after --" + name + " but found the flag " +
                               value + "; flags take a separate value and are never empty");
        }
        parsed.values_.emplace(name, value);
        index += 2;
        continue;
      }
      if (!allow_positional) {
        return csp::fail(ErrorCategory::Invalid, "csp.cli.unexpected_argument",
                         std::string(command) + " does not accept the argument \"" + token +
                             "\"; every input is a --flag");
      }
      parsed.positionals_.push_back(token);
      ++index;
    }
    return parsed;
  }

  bool has(std::string_view name) const { return values_.find(name) != values_.end(); }

  const std::string* value(std::string_view name) const {
    const auto found = values_.find(name);
    return found == values_.end() ? nullptr : &found->second;
  }

  const std::vector<std::string>& positionals() const { return positionals_; }

  /// Every flag that was given, so a subcommand can refuse a flag addressed to another
  /// subcommand rather than ignoring it.
  std::vector<std::string> given_flags() const {
    std::vector<std::string> names;
    names.reserve(values_.size());
    for (const auto& entry : values_) {
      names.push_back(entry.first);
    }
    return names;
  }

 private:
  std::map<std::string, std::string, std::less<>> values_;
  std::vector<std::string> positionals_;
};

Result<std::string> require_value(const Arguments& arguments, std::string_view name, std::string_view command) {
  const std::string* value = arguments.value(name);
  if (value == nullptr) {
    return csp::fail(ErrorCategory::Invalid, "csp.cli.missing_flag",
                     std::string(command) + " requires --" + std::string(name));
  }
  return *value;
}

Result<std::int64_t> parse_int64(std::string_view text, std::string_view what) {
  std::int64_t value = 0;
  const char* const begin = text.data();
  const char* const end = text.data() + text.size();
  const std::from_chars_result parsed = std::from_chars(begin, end, value);
  if (parsed.ec != std::errc{} || parsed.ptr != end) {
    return csp::fail(ErrorCategory::Invalid, "csp.cli.bad_number",
                     std::string(what) + " is not a decimal integer: \"" + std::string(text) + "\"");
  }
  return value;
}

Result<std::size_t> parse_size(std::string_view text, std::string_view what) {
  const Result<std::int64_t> parsed = parse_int64(text, what);
  if (!parsed) {
    return parsed.error();
  }
  if (parsed.value() < 0) {
    return csp::fail(ErrorCategory::OutOfRange, "csp.cli.negative_number",
                     std::string(what) + " is negative: " + std::string(text));
  }
  return static_cast<std::size_t>(parsed.value());
}

Result<std::uint64_t> parse_uint64(std::string_view text, std::string_view what) {
  std::uint64_t value = 0;
  const char* const begin = text.data();
  const char* const end = text.data() + text.size();
  const std::from_chars_result parsed = std::from_chars(begin, end, value);
  if (parsed.ec != std::errc{} || parsed.ptr != end) {
    return csp::fail(ErrorCategory::Invalid, "csp.cli.bad_number",
                     std::string(what) + " is not a non-negative decimal integer: \"" + std::string(text) + "\"");
  }
  return value;
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

Result<std::string> read_file(const std::string& path, std::size_t max_bytes) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return csp::fail(ErrorCategory::Io, "csp.cli.open_failed", "cannot open " + path + " for reading");
  }
  stream.seekg(0, std::ios::end);
  const std::streamoff size = stream.tellg();
  if (size < 0) {
    return csp::fail(ErrorCategory::Io, "csp.cli.size_failed", "cannot determine the size of " + path);
  }
  const auto bytes = static_cast<std::uintmax_t>(size);
  if (bytes > max_bytes) {
    return csp::fail(ErrorCategory::BoundExceeded, "csp.cli.document_too_large",
                     path + " is " + std::to_string(bytes) + " bytes, above the document bound of " +
                         std::to_string(max_bytes) + " bytes");
  }
  stream.seekg(0, std::ios::beg);
  std::string content(static_cast<std::size_t>(bytes), '\0');
  if (!content.empty()) {
    stream.read(content.data(), static_cast<std::streamsize>(content.size()));
    if (!stream) {
      return csp::fail(ErrorCategory::Io, "csp.cli.read_failed",
                       "the read of " + path + " stopped before the end of the file");
    }
  }
  return content;
}

Status write_file(const std::string& path, std::string_view bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return csp::fail(ErrorCategory::Io, "csp.cli.open_failed", "cannot open " + path + " for writing");
  }
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  stream.flush();
  if (!stream) {
    return csp::fail(ErrorCategory::Io, "csp.cli.write_failed", "writing " + path + " failed");
  }
  return csp::success();
}

// ---------------------------------------------------------------------------
// The evaluation instant
// ---------------------------------------------------------------------------

/// --now, or the system clock when it is absent. This is the only clock read in this
/// program, and it exists because the library refuses to read one itself.
Result<csp::Instant> evaluation_instant(const Arguments& arguments) {
  const std::string* text = arguments.value("now");
  if (text == nullptr) {
    const auto now_nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
    return csp::Instant::from_nanos(static_cast<std::int64_t>(now_nanos));
  }
  const Result<std::int64_t> nanos = parse_int64(*text, "--now");
  if (!nanos) {
    return nanos.error();
  }
  if (nanos.value() <= 0) {
    return csp::fail(ErrorCategory::OutOfRange, "csp.cli.bad_now",
                     "--now must be a positive number of nanoseconds since the Unix epoch; zero is how this "
                     "library spells \"the caller asserted no instant\", which is not a useful thing to ask for");
  }
  return csp::Instant::from_nanos(nanos.value());
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

Result<csp::PlacementRequest> load_request(const std::string& path) {
  Result<std::string> text = read_file(path, kLimits.max_document_bytes);
  if (!text) {
    return text.error();
  }
  return csp::request_from_document(text.value(), kLimits);
}

Result<csp::SiteEvidenceSnapshot> load_evidence(const std::string& path) {
  Result<std::string> text = read_file(path, kLimits.max_document_bytes);
  if (!text) {
    return text.error();
  }
  return csp::snapshot_from_document(text.value(), kLimits);
}

Result<csp::PlacementPolicy> load_policy(const std::string& path) {
  Result<std::string> text = read_file(path, kLimits.max_document_bytes);
  if (!text) {
    return text.error();
  }
  return csp::policy_from_document(text.value(), kLimits);
}

Result<csp::PlacementPlan> load_plan_document(const std::string& path) {
  Result<std::string> text = read_file(path, kLimits.max_document_bytes);
  if (!text) {
    return text.error();
  }
  return csp::plan_from_document(text.value(), kLimits);
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

std::string optional_id(const csp::EvidenceId& id) {
  return id.valid() ? id.value() : std::string("<unrecorded>");
}

std::string optional_authority(const csp::AuthorityId& id) {
  return id.valid() ? id.value() : std::string("<unrecorded>");
}

std::string optional_digest(const csp::Digest& digest) {
  return digest.is_zero() ? std::string("<none>") : digest.to_hex();
}

std::string optional_instant(csp::Instant instant) {
  return instant.is_zero() ? std::string("<none>") : std::to_string(instant.nanos());
}

void print_evidence_ref(std::ostream& out, std::string_view indent, const csp::EvidenceRef& ref) {
  out << indent << "evidence " << ref.kind << ' ' << optional_id(ref.record) << " authority "
      << optional_authority(ref.authority) << " generation " << ref.authority_generation.value() << " digest "
      << optional_digest(ref.document_digest) << '\n';
}

void print_provenance(std::ostream& out, std::string_view indent, const csp::Provenance& provenance,
                       csp::Instant evaluation_instant) {
  out << indent << "record " << optional_id(provenance.source_record) << " authority "
      << optional_authority(provenance.authority) << " generation " << provenance.authority_generation.value()
      << " observed_at " << optional_instant(provenance.observed_at) << " document_digest "
      << optional_digest(provenance.document_digest);
  if (!provenance.observed_at.is_zero() && !evaluation_instant.is_zero()) {
    const csp::Result<csp::Duration> age = csp::provenance_age(provenance, evaluation_instant, kLimits);
    out << " age_ns " << (age ? std::to_string(age.value().nanos()) : std::string("undecidable"));
  }
  out << '\n';
}

std::string describe_quantity(const csp::Measurement<csp::Quantity>& measurement) {
  if (!measurement.is_known()) {
    return std::string(csp::to_string(measurement.state()));
  }
  return std::to_string(measurement.value().units());
}

std::string describe_bool(const csp::Measurement<bool>& measurement) {
  if (!measurement.is_known()) {
    return std::string(csp::to_string(measurement.state()));
  }
  return measurement.value() ? std::string("true") : std::string("false");
}

/// The records a reader should fetch to check one placement.
///
/// A plan names evidence where it relied on it, and the trace above prints exactly those
/// references. It does not restate the snapshot it was computed from, so this section
/// resolves the placement back to the records in the snapshot the caller supplied. It is
/// labelled as resolved rather than recorded for that reason.
void print_placement_evidence(std::ostream& out, const csp::PlacementRequest& request,
                              const csp::SiteEvidenceSnapshot& evidence, const csp::PlacementPlan& plan,
                              csp::Instant evaluation_instant) {
  out << "evidence behind each placement (resolved from the supplied snapshot):\n";
  for (const csp::ObligationPlacement& entry : plan.obligations) {
    const csp::Obligation* obligation = nullptr;
    for (const csp::Obligation& candidate : request.obligations) {
      if (candidate.obligation == entry.obligation) {
        obligation = &candidate;
        break;
      }
    }
    for (const csp::SitePlacement& placement : entry.placements) {
      out << "  obligation " << entry.obligation.value() << ' ' << csp::to_string(placement.role) << ' '
          << placement.index << " site " << placement.site.value() << '\n';
      for (const csp::SiteRecord& record : evidence.sites) {
        if (record.site == placement.site) {
          print_provenance(out, "    site ", record.provenance, evaluation_instant);
          break;
        }
      }
      if (obligation == nullptr) {
        continue;
      }
      for (const csp::CapacityRecord& record : evidence.capacity) {
        if (record.site != placement.site || record.service_class != obligation->service_class) {
          continue;
        }
        out << "    capacity " << record.reference.value() << " kind " << csp::to_string(record.kind)
            << " available " << describe_quantity(record.available) << '\n';
        print_provenance(out, "      ", record.provenance, evaluation_instant);
      }
      for (const csp::CompatibilityRecord& record : evidence.compatibility) {
        if (record.site != placement.site || record.service_class != obligation->service_class) {
          continue;
        }
        out << "    compatibility " << record.reference.value() << " compatible "
            << describe_bool(record.compatible) << '\n';
        print_provenance(out, "      ", record.provenance, evaluation_instant);
      }
    }
  }
}

void print_refusal(std::ostream& out, const csp::PlacementPlan& plan) {
  if (!plan.refusal.has_value()) {
    return;
  }
  const csp::Refusal& refusal = *plan.refusal;
  out << "refusal: " << csp::to_string(refusal.category) << ": " << refusal.code << ": " << refusal.detail << '\n';
  for (const csp::EvidenceRef& ref : refusal.evidence) {
    print_evidence_ref(out, "  ", ref);
  }
}

void print_residual(std::ostream& out, const csp::PlacementPlan& plan) {
  out << "residual requirements: " << plan.residual.size() << '\n';
  for (const csp::ResidualRequirement& residual : plan.residual) {
    out << "  obligation " << residual.obligation.value() << " requirement " << residual.requirement << " shortfall "
        << residual.shortfall.units() << " placements short " << residual.placements_short << '\n';
    if (!residual.detail.empty()) {
      out << "    detail: " << residual.detail << '\n';
    }
  }
}

void print_placement_detail(std::ostream& out, const csp::ObligationPlacement& entry);

void print_summary(std::ostream& out, const csp::PlacementPlan& plan) {
  std::size_t placements = 0;
  for (const csp::ObligationPlacement& entry : plan.obligations) {
    placements += entry.placements.size();
  }
  out << "plan: " << plan.plan.value() << '\n';
  out << "outcome: " << csp::to_string(plan.outcome) << '\n';
  out << "request: " << plan.request.value() << " generation " << plan.request_generation.value() << '\n';
  out << "obligations: " << plan.obligations.size() << '\n';
  out << "placements: " << placements << '\n';
  out << "nodes explored: " << plan.nodes_explored << '\n';
  out << "search exhausted: " << (plan.search_exhausted ? "true" : "false") << '\n';
  for (const csp::ObligationPlacement& entry : plan.obligations) {
    out << "obligation " << entry.obligation.value() << ": " << csp::to_string(entry.outcome);
    if (!entry.refusal_code.empty()) {
      out << " [" << entry.refusal_code << ']';
    }
    out << '\n';
    if (!entry.detail.empty()) {
      out << "  detail: " << entry.detail << '\n';
    }
    for (const csp::LatencyResolution& latency : entry.latency) {
      out << "  latency peer " << latency.peer << ' ' << csp::to_string(latency.direction) << ' '
          << csp::to_string(latency.statistic) << " measured " << latency.measured.nanos()
          << (latency.derived ? " (derived)" : " (direct)") << " chain";
      for (const csp::DependencyId& step : latency.chain) {
        out << ' ' << step.value();
      }
      out << '\n';
    }
    print_placement_detail(out, entry);
  }
  print_refusal(out, plan);
  print_residual(out, plan);
  out << "digest: " << plan.digest.to_hex() << '\n';
}

void print_placement_detail(std::ostream& out, const csp::ObligationPlacement& entry) {
  for (const csp::SitePlacement& site : entry.placements) {
    out << "  " << csp::to_string(site.role) << ' ' << site.index << ' ' << site.site.value() << " capacity "
        << site.capacity_required.units();
    if (site.jurisdiction.valid()) {
      out << " jurisdiction " << site.jurisdiction.value();
    }
    out << '\n';
    out << "    capacity basis: " << site.capacity.references.size() << " references, evidenced total "
        << site.capacity.evidenced_total.units()
        << (site.capacity.includes_offers ? ", includes offers" : ", commitments only") << '\n';
    for (const csp::CapacityRefId& reference : site.capacity.references) {
      out << "      reference " << reference.value() << '\n';
    }
    for (const csp::DomainRef& domain : site.domains) {
      out << "    domain " << domain.domain.value() << ' '
          << (domain.kind.has_value() ? csp::to_string(*domain.kind) : std::string("unclassified"))
          << " depth " << domain.depth << '\n';
    }
  }
}

void print_explanation(std::ostream& out, const csp::PlacementPlan& plan,
                        const csp::PlacementRequest& request, const csp::SiteEvidenceSnapshot& evidence,
                        csp::Instant evaluation_instant) {
  print_summary(out, plan);

  out << "constraint trace: " << plan.trace.size() << " entries\n";
  for (std::size_t index = 0; index < plan.trace.size(); ++index) {
    const csp::ConstraintTraceEntry& entry = plan.trace[index];
    out << "  [" << index << "] rule " << entry.rule << " outcome " << csp::to_string(entry.outcome);
    if (entry.obligation.has_value()) {
      out << " obligation " << entry.obligation->value();
    }
    if (entry.site.has_value()) {
      out << " site " << entry.site->value();
    }
    out << '\n';
    if (!entry.detail.empty()) {
      out << "    detail: " << entry.detail << '\n';
    }
    for (const csp::EvidenceRef& ref : entry.evidence) {
      print_evidence_ref(out, "    ", ref);
    }
  }

  out << "tie-break records: " << plan.tie_breaks.size() << '\n';
  for (const csp::TieBreakRecord& record : plan.tie_breaks) {
    out << "  criterion " << record.criterion << " applied " << csp::to_string(record.applied) << '\n';
    if (!record.detail.empty()) {
      out << "    detail: " << record.detail << '\n';
    }
    if (!record.ordered.empty()) {
      out << "    ordered:";
      for (const csp::SiteId& site : record.ordered) {
        out << ' ' << site.value();
      }
      out << '\n';
    }
  }

  out << "freshness envelope:\n";
  out << "  evaluated_at: " << optional_instant(plan.envelope.evaluated_at) << '\n';
  out << "  oldest_evidence_observed_at: " << optional_instant(plan.envelope.oldest_evidence_observed_at) << '\n';
  out << "  evidence_generation: " << plan.envelope.evidence_generation.value() << '\n';
  out << "  policy_generation: " << plan.envelope.policy_generation.value() << '\n';
  out << "  request_generation: " << plan.envelope.request_generation.value() << '\n';
  out << "  valid_until: " << optional_instant(plan.envelope.valid_until) << '\n';
  out << "  revalidate_when: " << plan.envelope.revalidate_when.size() << " conditions\n";
  for (const std::string& condition : plan.envelope.revalidate_when) {
    out << "    " << condition << '\n';
  }

  // Every record the plan named, deduplicated and in a stable order, so a reader can
  // fetch the same records from the authorities that own them.
  std::set<std::string> distinct;
  for (const csp::ConstraintTraceEntry& entry : plan.trace) {
    for (const csp::EvidenceRef& ref : entry.evidence) {
      std::ostringstream line;
      print_evidence_ref(line, std::string(), ref);
      distinct.insert(line.str());
    }
  }
  out << "evidence references recorded in the trace: " << distinct.size() << '\n';
  for (const std::string& line : distinct) {
    out << "  " << line << '\n';
  }

  print_placement_evidence(out, request, evidence, plan, evaluation_instant);
}

void print_audit(std::ostream& out, const csp::StoreAudit& audit) {
  out << "consistent: " << (audit.consistent ? "true" : "false") << '\n';
  out << "generation: " << audit.generation.value() << '\n';
  out << "records: " << audit.records.size() << '\n';
  for (const csp::PlanId& plan : audit.records) {
    out << "  " << plan.value() << '\n';
  }
  out << "manifest digest: " << optional_digest(audit.manifest_digest) << '\n';
  out << "record bytes: " << audit.record_bytes << '\n';
  out << "recovery findings: " << audit.recovery.size() << '\n';
  for (const csp::RecoveryFinding& finding : audit.recovery) {
    out << "  " << csp::to_string(finding.action);
    if (!finding.detail.empty()) {
      out << ": " << finding.detail;
    }
    out << '\n';
  }
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

void print_usage(std::ostream& out) {
  out << "csp-cli: cross-site placement planning, explanation, verification, and durable storage.\n"
      << "\n"
      << "usage: csp-cli <command> [flags]\n"
      << "\n"
      << "commands:\n"
      << "  version                      print the library and format versions\n"
      << "  rules                        print the planner's rule tokens in evaluation order\n"
      << "  plan      --request F --evidence F --policy F [--now NANOS] [--pretty] [--out F]\n"
      << "  explain   --request F --evidence F --policy F [--now NANOS] [--pretty] [--out F]\n"
      << "  verify    --plan F\n"
      << "  revalidate --plan F --request F --evidence F --policy F [--now NANOS]\n"
      << "  store     --dir D list\n"
      << "  store     --dir D load --plan PLANID\n"
      << "  store     --dir D audit\n"
      << "  store     --dir D commit --plan F\n"
      << "  store     --dir D compact\n"
      << "  gen       --sites N --seed S --classes N --out DIR [--now NANOS]\n"
      << "\n"
      << "exit codes:\n"
      << "  0  the command succeeded and, for plan and explain, the plan outcome is planned\n"
      << "  1  the planner refused: a definite proof that no arrangement exists\n"
      << "  2  the planner could not decide, or a revalidation verdict was undecidable\n"
      << "  3  an error: malformed input, contradictory evidence, a bound, an I/O failure, or cancellation\n"
      << "\n"
      << "notes:\n"
      << "  Every flag takes a separate value: --request FILE, never --request=FILE. A repeated flag,\n"
      << "  an unknown flag, and a missing value are all errors. A bare -- ends flag parsing, and the\n"
      << "  store subcommand is the only positional argument any command accepts.\n"
      << "  --pretty selects the indented encoding of the plan document that --out writes; without\n"
      << "  --out it has no effect, because what is printed is a summary rather than a document.\n"
      << "  gen writes request.json, evidence.json and policy.json, re-decodes them, plans the example,\n"
      << "  and exits with the outcome of that plan, so its exit code says whether the example is runnable.\n"
      << "  The library never reads a clock. This tool reads the system clock for one purpose only: to\n"
      << "  supply the evaluation instant when --now is absent. Pass --now NANOS (nanoseconds since the\n"
      << "  Unix epoch) to make a run reproducible. gen uses that instant as the moment its generated\n"
      << "  world was observed at.\n";
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

int command_version() {
  std::cout << csp::version_banner() << '\n';
  return kExitPlaced;
}

int command_rules() {
  for (const std::string& token : csp::Planner::rule_tokens()) {
    std::cout << token << '\n';
  }
  return kExitPlaced;
}

int exit_code_for(csp::PlanOutcome outcome) {
  switch (outcome) {
    case csp::PlanOutcome::Planned:
      return kExitPlaced;
    case csp::PlanOutcome::Refused:
      return kExitRefused;
    case csp::PlanOutcome::Indeterminate:
      return kExitIndeterminate;
  }
  return kExitError;
}

Status write_plan_document(const csp::PlacementPlan& plan, const std::string& path, bool pretty) {
  Result<std::string> document = csp::plan_to_document(plan, pretty);
  if (!document) {
    return document.error();
  }
  const Status written = write_file(path, document.value());
  if (!written) {
    return written.error();
  }
  std::cout << "wrote: " << path << " (" << document.value().size() << " bytes)\n";
  return csp::success();
}

int command_plan(const Arguments& arguments, bool explain) {
  const std::string command = explain ? "explain" : "plan";
  const Result<std::string> request_path = require_value(arguments, "request", command);
  if (!request_path) {
    return report(request_path.error());
  }
  const Result<std::string> evidence_path = require_value(arguments, "evidence", command);
  if (!evidence_path) {
    return report(evidence_path.error());
  }
  const Result<std::string> policy_path = require_value(arguments, "policy", command);
  if (!policy_path) {
    return report(policy_path.error());
  }
  const Result<csp::Instant> instant = evaluation_instant(arguments);
  if (!instant) {
    return report(instant.error());
  }

  const Result<csp::PlacementRequest> request = load_request(request_path.value());
  if (!request) {
    return report(request.error());
  }
  const Result<csp::SiteEvidenceSnapshot> evidence = load_evidence(evidence_path.value());
  if (!evidence) {
    return report(evidence.error());
  }
  const Result<csp::PlacementPolicy> policy = load_policy(policy_path.value());
  if (!policy) {
    return report(policy.error());
  }

  const csp::Planner planner;
  csp::PlanningContext context;
  context.evaluation_instant = instant.value();
  const Result<csp::PlacementPlan> planned = planner.plan(request.value(), evidence.value(), policy.value(), context);
  if (!planned) {
    return report(planned.error());
  }
  const csp::PlacementPlan& plan = planned.value();

  // The document is written only after the plan exists in full, and the summary is
  // printed only after the document write succeeded, so a failure never leaves a
  // half-reported plan behind.
  if (arguments.has("out")) {
    const std::string* path = arguments.value("out");
    const Status written = write_plan_document(plan, *path, arguments.has("pretty"));
    if (!written) {
      return report(written.error());
    }
  }

  std::ostringstream text;
  if (explain) {
    print_explanation(text, plan, request.value(), evidence.value(), instant.value());
  } else {
    print_summary(text, plan);
  }
  std::cout << text.str();
  return exit_code_for(plan.outcome);
}

int command_verify(const Arguments& arguments) {
  const Result<std::string> plan_path = require_value(arguments, "plan", "verify");
  if (!plan_path) {
    return report(plan_path.error());
  }
  // The decoder refuses a malformed document, a structurally invalid plan, and a plan
  // whose digest does not match its content. It does not re-derive the identity, which
  // is what this command checks on top of it.
  const Result<csp::PlacementPlan> decoded = load_plan_document(plan_path.value());
  if (!decoded) {
    return report(decoded.error());
  }
  const csp::PlacementPlan& plan = decoded.value();

  const Status structural = csp::plan_validate(plan, kLimits);
  if (!structural) {
    return report(structural.error());
  }
  const csp::Digest recomputed = csp::plan_compute_digest(plan);
  if (recomputed != plan.digest) {
    return report(csp::fail(ErrorCategory::Integrity, "csp.cli.digest_mismatch",
                            "the digest recomputed from the plan content differs from the digest the plan carries"));
  }
  const Result<std::string> canonical = csp::plan_canonical_bytes(plan);
  if (!canonical) {
    return report(canonical.error());
  }
  const csp::Digest canonical_digest = csp::Digest::of(canonical.value());
  if (canonical_digest != plan.digest) {
    return report(csp::fail(ErrorCategory::Integrity, "csp.cli.canonical_digest_mismatch",
                            "hashing the plan's canonical bytes does not reproduce the plan digest"));
  }
  const std::string hex = recomputed.to_hex();
  const Result<csp::PlanId> derived = csp::PlanId::parse("plan-" + hex.substr(0, csp::kPlanIdentityHexChars));
  if (!derived) {
    return report(derived.error());
  }
  if (derived.value() != plan.plan) {
    return report(csp::fail(ErrorCategory::Integrity, "csp.cli.identity_mismatch",
                            "the plan identity " + plan.plan.value() + " is not derived from its digest; the "
                            "identity derived from the digest is " + derived.value().value()));
  }

  std::cout << "plan: " << plan.plan.value() << '\n'
            << "outcome: " << csp::to_string(plan.outcome) << '\n'
            << "request: " << plan.request.value() << " generation " << plan.request_generation.value() << '\n'
            << "structural validation: ok\n"
            << "digest: " << plan.digest.to_hex() << '\n'
            << "digest recomputed: " << hex << " match\n"
            << "canonical bytes: " << canonical.value().size() << '\n'
            << "canonical digest: " << canonical_digest.to_hex() << " match\n"
            << "identity derived: " << derived.value().value() << " match\n";
  return kExitPlaced;
}

int command_revalidate(const Arguments& arguments) {
  const Result<std::string> plan_path = require_value(arguments, "plan", "revalidate");
  if (!plan_path) {
    return report(plan_path.error());
  }
  const Result<std::string> request_path = require_value(arguments, "request", "revalidate");
  if (!request_path) {
    return report(request_path.error());
  }
  const Result<std::string> evidence_path = require_value(arguments, "evidence", "revalidate");
  if (!evidence_path) {
    return report(evidence_path.error());
  }
  const Result<std::string> policy_path = require_value(arguments, "policy", "revalidate");
  if (!policy_path) {
    return report(policy_path.error());
  }
  const Result<csp::Instant> instant = evaluation_instant(arguments);
  if (!instant) {
    return report(instant.error());
  }

  const Result<csp::PlacementPlan> plan = load_plan_document(plan_path.value());
  if (!plan) {
    return report(plan.error());
  }
  const Result<csp::PlacementRequest> request = load_request(request_path.value());
  if (!request) {
    return report(request.error());
  }
  const Result<csp::SiteEvidenceSnapshot> evidence = load_evidence(evidence_path.value());
  if (!evidence) {
    return report(evidence.error());
  }
  const Result<csp::PlacementPolicy> policy = load_policy(policy_path.value());
  if (!policy) {
    return report(policy.error());
  }

  csp::PlanningContext context;
  context.evaluation_instant = instant.value();
  const Result<csp::RevalidationReport> report_result =
      csp::plan_revalidate(plan.value(), request.value(), evidence.value(), policy.value(), context);
  if (!report_result) {
    return report(report_result.error());
  }
  const csp::RevalidationReport& revalidation = report_result.value();
  std::cout << "plan: " << revalidation.plan.value() << '\n'
            << "plan digest: " << revalidation.plan_digest.to_hex() << '\n'
            << "verdict: " << csp::to_string(revalidation.verdict) << '\n'
            << "expired: " << (revalidation.expired ? "true" : "false") << '\n'
            << "evidence generation: " << revalidation.evidence_generation.value() << '\n'
            << "policy generation: " << revalidation.policy_generation.value() << '\n'
            << "findings: " << revalidation.findings.size() << '\n';
  for (const csp::RevalidationFinding& finding : revalidation.findings) {
    std::cout << "  condition " << finding.condition << " outcome " << csp::to_string(finding.outcome);
    if (finding.obligation.has_value()) {
      std::cout << " obligation " << finding.obligation->value();
    }
    if (finding.site.has_value()) {
      std::cout << " site " << finding.site->value();
    }
    std::cout << '\n';
    if (!finding.detail.empty()) {
      std::cout << "    detail: " << finding.detail << '\n';
    }
  }

  switch (revalidation.verdict) {
    case csp::RevalidationVerdict::Holds:
      return kExitPlaced;
    case csp::RevalidationVerdict::Broken:
      return kExitRefused;
    case csp::RevalidationVerdict::Undecidable:
      return kExitIndeterminate;
  }
  return kExitError;
}

int command_store(const Arguments& arguments) {
  const Result<std::string> directory = require_value(arguments, "dir", "store");
  if (!directory) {
    return report(directory.error());
  }
  if (arguments.positionals().size() != 1) {
    return report(csp::fail(ErrorCategory::Invalid, "csp.cli.store_subcommand",
                            "store requires exactly one subcommand: list, load, audit, commit, or compact"));
  }
  const std::string& subcommand = arguments.positionals().front();
  const bool needs_plan = subcommand == "load" || subcommand == "commit";

  for (const std::string& flag : arguments.given_flags()) {
    if (flag == "dir" || flag == "help") {
      continue;
    }
    if (flag == "plan" && needs_plan) {
      continue;
    }
    return report(csp::fail(ErrorCategory::Invalid, "csp.cli.misplaced_flag",
                            "store " + subcommand + " does not accept --" + flag));
  }

  csp::StoreOptions options;
  options.directory = directory.value();
  options.limits = kLimits;
  Result<csp::PlanStore> opened = csp::PlanStore::open(options);
  if (!opened) {
    return report(opened.error());
  }
  csp::PlanStore store = std::move(opened).value();

  if (subcommand == "list") {
    const Result<std::vector<csp::PlanId>> records = store.list();
    if (!records) {
      return report(records.error());
    }
    for (const csp::PlanId& plan : records.value()) {
      std::cout << plan.value() << '\n';
    }
    std::cout << "records: " << records.value().size() << " generation: " << store.generation().value() << '\n';
    return kExitPlaced;
  }

  if (subcommand == "load") {
    const Result<std::string> text = require_value(arguments, "plan", "store load");
    if (!text) {
      return report(text.error());
    }
    const Result<csp::PlanId> identity = csp::PlanId::parse(text.value());
    if (!identity) {
      return report(identity.error());
    }
    const Result<csp::PlacementPlan> plan = store.load(identity.value());
    if (!plan) {
      return report(plan.error());
    }
    const Result<std::string> document = csp::plan_to_document(plan.value(), true);
    if (!document) {
      return report(document.error());
    }
    std::cout << document.value();
    return kExitPlaced;
  }

  if (subcommand == "audit") {
    const Result<csp::StoreAudit> audit = store.audit();
    if (!audit) {
      return report(audit.error());
    }
    if (!audit.value().consistent) {
      return report(csp::fail(ErrorCategory::Integrity, "csp.cli.store_inconsistent",
                              "the store audit reports an inconsistent manifest or record set"));
    }
    print_audit(std::cout, audit.value());
    return kExitPlaced;
  }

  if (subcommand == "commit") {
    const Result<std::string> path = require_value(arguments, "plan", "store commit");
    if (!path) {
      return report(path.error());
    }
    const Result<csp::PlacementPlan> plan = load_plan_document(path.value());
    if (!plan) {
      return report(plan.error());
    }
    const Result<csp::PlanId> committed = store.commit(plan.value());
    if (!committed) {
      return report(committed.error());
    }
    std::cout << "committed: " << committed.value().value() << " generation " << store.generation().value() << '\n';
    return kExitPlaced;
  }

  if (subcommand == "compact") {
    const Status compacted = store.compact();
    if (!compacted) {
      return report(compacted.error());
    }
    const Result<std::vector<csp::PlanId>> records = store.list();
    if (!records) {
      return report(records.error());
    }
    std::cout << "compact: ok records " << records.value().size() << " generation " << store.generation().value()
              << '\n';
    return kExitPlaced;
  }

  return report(csp::fail(ErrorCategory::Invalid, "csp.cli.store_subcommand",
                          "store does not know the subcommand \"" + subcommand +
                              "\"; it accepts list, load, audit, commit, and compact"));
}

// ---------------------------------------------------------------------------
// gen
// ---------------------------------------------------------------------------

/// A deterministic generator.
///
/// std::mt19937_64's bit stream is fixed by the standard, so one seed produces one
/// sequence everywhere. The standard distribution adapters are deliberately not used:
/// their mapping from bits to values is implementation-defined, which would make the
/// generated documents differ between standard libraries for one seed.
class Generator {
 public:
  explicit Generator(std::uint64_t seed) : engine_(seed) {}

  std::uint64_t next() { return engine_(); }

  std::uint64_t below(std::uint64_t bound) { return bound == 0 ? 0 : next() % bound; }

  std::string hex(std::size_t digits) {
    static constexpr char kDigits[] = "0123456789abcdef";
    const std::uint64_t value = next();
    std::string text;
    text.reserve(digits);
    for (std::size_t index = 0; index < digits; ++index) {
      text.push_back(kDigits[(value >> (4 * (index % 16))) & 0xFU]);
    }
    return text;
  }

 private:
  std::mt19937_64 engine_;
};

struct GeneratedExample {
  csp::PlacementRequest request;
  csp::SiteEvidenceSnapshot evidence;
  csp::PlacementPolicy policy;
};

csp::Provenance make_provenance(const std::string& authority, const std::string& record, std::uint64_t generation,
                                csp::Instant observed_at) {
  csp::Provenance provenance;
  provenance.source_record = make_id<csp::EvidenceId>(record);
  provenance.authority = make_id<csp::AuthorityId>(authority);
  provenance.authority_generation = csp::Generation::from_value(generation);
  provenance.observed_at = observed_at;
  // No document digest: this generator has no upstream document, and writing a digest of
  // nothing would be a claim about a document that does not exist.
  return provenance;
}

Result<GeneratedExample> generate_example(std::size_t site_count, std::size_t class_count, std::uint64_t seed,
                                          csp::Instant observed_at) {
  if (site_count < 4) {
    return csp::fail(ErrorCategory::Invalid, "csp.cli.gen_sites",
                     "--sites must be at least 4: the generated example places two obligations with two "
                     "placements each under a power-domain separation rule, which needs at least four sites "
                     "across four power domains");
  }
  if (site_count > kLimits.max_sites) {
    return csp::fail(ErrorCategory::BoundExceeded, "csp.cli.gen_sites",
                     "--sites is above the library's bound of " + std::to_string(kLimits.max_sites));
  }
  if (class_count == 0 || class_count > 64) {
    return csp::fail(ErrorCategory::OutOfRange, "csp.cli.gen_classes",
                     "--classes must lie between 1 and 64; each class adds a capacity, compatibility, recovery, "
                     "and cost record per site");
  }

  Generator generator(seed);
  GeneratedExample example;

  // Identities are drawn from the seeded generator and are never derived from a clock or
  // an address. The index suffix is what makes them unique by construction rather than
  // by a collision probability.
  const std::string request_text = "request-" + generator.hex(8);
  const std::string policy_text = "policy-" + generator.hex(8);
  const std::string jurisdiction_text = "jurisdiction-" + generator.hex(8);

  example.policy.policy = make_id<csp::PolicyId>(policy_text);
  example.policy.generation = csp::Generation::from_value(1 + generator.below(1000));
  example.policy.allow_degraded_sites = false;
  example.policy.allow_unknown_maintenance_state = false;
  example.policy.allow_unknown_jurisdiction = false;
  // The generated capacity records are commitments, so the generated policy asks for
  // commitments only. Setting one flag without the other would be the contradiction
  // policy_validate refuses.
  example.policy.allow_offer_capacity = false;
  example.policy.require_commitment_capacity = true;
  example.policy.allow_derived_latency_bounds = true;
  example.policy.max_derived_hops = 0;
  example.policy.allow_recovery_on_primary_site = false;

  example.request.request = make_id<csp::RequestId>(request_text);
  example.request.generation = csp::Generation::from_value(1 + generator.below(1000));
  example.request.policy.policy = example.policy.policy;
  example.request.policy.generation = example.policy.generation;
  example.request.preferences.objectives = {csp::Preferences::Objective::MinimiseCost,
                                            csp::Preferences::Objective::MinimiseRisk};

  const csp::JurisdictionId jurisdiction = make_id<csp::JurisdictionId>(jurisdiction_text);

  std::vector<csp::ServiceClassId> classes;
  classes.reserve(class_count);
  for (std::size_t index = 0; index < class_count; ++index) {
    classes.push_back(make_id<csp::ServiceClassId>("class-" + generator.hex(6) + "-" + std::to_string(index)));
  }

  std::vector<csp::SiteId> sites;
  sites.reserve(site_count);
  const std::size_t power_domain_count = std::min<std::size_t>(4, site_count);
  const std::size_t geography_domain_count = std::min<std::size_t>(8, site_count);
  const std::uint64_t site_generation = 1 + generator.below(1000);
  const std::uint64_t fabric_generation = 1 + generator.below(1000);
  const std::uint64_t registry_generation = 1 + generator.below(1000);

  example.evidence.generation = csp::Generation::from_value(1 + generator.below(1000));
  example.evidence.captured_at = observed_at;

  for (std::size_t index = 0; index < site_count; ++index) {
    const std::string site_text = "site-" + generator.hex(8) + "-" + std::to_string(index);
    sites.push_back(make_id<csp::SiteId>(site_text));
    csp::SiteRecord record;
    record.site = sites.back();
    record.jurisdiction = jurisdiction;
    record.maintenance = csp::Measurement<csp::MaintenanceState>::known(csp::MaintenanceState::Operational);
    record.provenance = make_provenance("site-registry", "site-observation-" + site_text, site_generation,
                                        observed_at);
    example.evidence.sites.push_back(std::move(record));
  }

  std::vector<csp::FailureDomainId> power_domains;
  std::vector<csp::FailureDomainId> geography_domains;
  for (std::size_t index = 0; index < power_domain_count; ++index) {
    const std::string text = "power-" + generator.hex(6) + "-" + std::to_string(index);
    power_domains.push_back(make_id<csp::FailureDomainId>(text));
    csp::FailureDomainRecord record;
    record.domain = power_domains.back();
    record.kind = csp::DomainKind::Power;
    record.provenance = make_provenance("failure-domain-registry", "domain-observation-" + text,
                                        registry_generation, observed_at);
    example.evidence.failure_domains.push_back(std::move(record));
  }
  for (std::size_t index = 0; index < geography_domain_count; ++index) {
    const std::string text = "geography-" + generator.hex(6) + "-" + std::to_string(index);
    geography_domains.push_back(make_id<csp::FailureDomainId>(text));
    csp::FailureDomainRecord record;
    record.domain = geography_domains.back();
    record.kind = csp::DomainKind::Geography;
    record.provenance = make_provenance("failure-domain-registry", "domain-observation-" + text,
                                        registry_generation, observed_at);
    example.evidence.failure_domains.push_back(std::move(record));
  }
  for (std::size_t index = 0; index < site_count; ++index) {
    const csp::FailureDomainId power = power_domains[index % power_domain_count];
    const csp::FailureDomainId geography = geography_domains[index % geography_domain_count];
    csp::DomainAssignment power_assignment;
    power_assignment.site = sites[index];
    power_assignment.domain = power;
    power_assignment.provenance =
        make_provenance("failure-domain-registry", "membership-power-" + sites[index].value(),
                        registry_generation, observed_at);
    example.evidence.domain_assignments.push_back(std::move(power_assignment));
    csp::DomainAssignment geography_assignment;
    geography_assignment.site = sites[index];
    geography_assignment.domain = geography;
    geography_assignment.provenance =
        make_provenance("failure-domain-registry", "membership-geography-" + sites[index].value(),
                        registry_generation, observed_at);
    example.evidence.domain_assignments.push_back(std::move(geography_assignment));
  }

  for (std::size_t site_index = 0; site_index < site_count; ++site_index) {
    for (std::size_t class_index = 0; class_index < class_count; ++class_index) {
      const std::string suffix = std::to_string(site_index) + "-" + std::to_string(class_index);

      csp::CapacityRecord capacity;
      capacity.reference = make_id<csp::CapacityRefId>("capacity-" + generator.hex(6) + "-" + suffix);
      capacity.site = sites[site_index];
      capacity.service_class = classes[class_index];
      capacity.kind = csp::CapacityKind::Commitment;
      capacity.available = csp::Measurement<csp::Quantity>::known(csp::Quantity::from_units(100));
      capacity.provenance = make_provenance("capacity-authority", "capacity-observation-" + suffix,
                                            site_generation, observed_at);
      example.evidence.capacity.push_back(std::move(capacity));

      csp::CompatibilityRecord compatibility;
      compatibility.reference = make_id<csp::EvidenceId>("compatibility-" + generator.hex(6) + "-" + suffix);
      compatibility.site = sites[site_index];
      compatibility.service_class = classes[class_index];
      compatibility.compatible = csp::Measurement<bool>::known(true);
      compatibility.provenance = make_provenance("compatibility-registry", "compatibility-observation-" + suffix,
                                                 registry_generation, observed_at);
      example.evidence.compatibility.push_back(std::move(compatibility));

      csp::RecoveryRecord recovery;
      recovery.reference = make_id<csp::RecoveryRefId>("recovery-" + generator.hex(6) + "-" + suffix);
      recovery.site = sites[site_index];
      recovery.service_class = classes[class_index];
      recovery.can_host_recovery = csp::Measurement<bool>::known(true);
      recovery.achievable_rto =
          csp::Measurement<csp::Duration>::known(must(csp::Duration::from_seconds(300)));
      recovery.achievable_rpo =
          csp::Measurement<csp::Duration>::known(must(csp::Duration::from_seconds(60)));
      recovery.provenance = make_provenance("recovery-authority", "recovery-observation-" + suffix,
                                            registry_generation, observed_at);
      example.evidence.recovery.push_back(std::move(recovery));

      csp::CostRiskRecord cost;
      cost.reference = make_id<csp::EvidenceId>("cost-" + generator.hex(6) + "-" + suffix);
      cost.site = sites[site_index];
      cost.service_class = classes[class_index];
      cost.cost_per_unit =
          csp::Measurement<csp::Quantity>::known(csp::Quantity::from_units(
              static_cast<std::int64_t>(10 + generator.below(90))));
      cost.risk_per_mille = csp::Measurement<std::int64_t>::known(
          static_cast<std::int64_t>(generator.below(1001)));
      cost.provenance = make_provenance("cost-ledger", "cost-observation-" + suffix, site_generation,
                                        observed_at);
      example.evidence.cost_risk.push_back(std::move(cost));
    }
  }

  // One directed path measurement around the ring of sites, in both directions, so the
  // example carries real fabric evidence even though the generated request states no
  // latency bound.
  for (std::size_t index = 0; index < site_count; ++index) {
    const std::size_t next = (index + 1) % site_count;
    const std::pair<std::size_t, std::size_t> pairs[2] = {{index, next}, {next, index}};
    for (const std::pair<std::size_t, std::size_t>& pair : pairs) {
      csp::LatencyRecord record;
      record.reference = make_id<csp::DependencyId>("path-" + generator.hex(6) + "-" + std::to_string(pair.first) +
                                                    "-" + std::to_string(pair.second));
      record.from_site = sites[pair.first];
      record.to_site = sites[pair.second];
      record.statistic = csp::LatencyStatistic::Max;
      record.latency = csp::Measurement<csp::Duration>::known(must(csp::Duration::from_millis(5)));
      record.provenance = make_provenance("fabric-authority",
                                          "path-observation-" + std::to_string(pair.first) + "-" +
                                              std::to_string(pair.second),
                                          fabric_generation, observed_at);
      example.evidence.latency.push_back(std::move(record));
    }
  }

  for (std::size_t index = 0; index < 2; ++index) {
    csp::Obligation obligation;
    obligation.obligation =
        make_id<csp::ObligationId>("obligation-" + generator.hex(6) + "-" + std::to_string(index));
    obligation.service_class = classes[index < classes.size() ? index : 0];
    obligation.required_capacity = csp::Quantity::from_units(10);
    obligation.primary_placements = 2;
    csp::SeparationRequirement separation;
    separation.group = csp::SeparationGroup::All;
    separation.separated_kinds.push_back(csp::DomainKind::Power);
    if (index == 1) {
      separation.separated_kinds.push_back(csp::DomainKind::Geography);
    }
    obligation.separations.push_back(std::move(separation));
    example.request.obligations.push_back(std::move(obligation));
  }

  return example;
}

int command_gen(const Arguments& arguments) {
  const Result<std::string> site_text = require_value(arguments, "sites", "gen");
  if (!site_text) {
    return report(site_text.error());
  }
  const Result<std::string> seed_text = require_value(arguments, "seed", "gen");
  if (!seed_text) {
    return report(seed_text.error());
  }
  const Result<std::string> class_text = require_value(arguments, "classes", "gen");
  if (!class_text) {
    return report(class_text.error());
  }
  const Result<std::string> directory = require_value(arguments, "out", "gen");
  if (!directory) {
    return report(directory.error());
  }
  const Result<std::size_t> sites = parse_size(site_text.value(), "--sites");
  if (!sites) {
    return report(sites.error());
  }
  const Result<std::uint64_t> seed = parse_uint64(seed_text.value(), "--seed");
  if (!seed) {
    return report(seed.error());
  }
  const Result<std::size_t> classes = parse_size(class_text.value(), "--classes");
  if (!classes) {
    return report(classes.error());
  }
  const Result<csp::Instant> instant = evaluation_instant(arguments);
  if (!instant) {
    return report(instant.error());
  }

  const Result<GeneratedExample> example = generate_example(sites.value(), classes.value(), seed.value(),
                                                            instant.value());
  if (!example) {
    return report(example.error());
  }

  std::error_code code;
  std::filesystem::create_directories(directory.value(), code);
  if (code) {
    return report(csp::fail(ErrorCategory::Io, "csp.cli.mkdir_failed",
                            "cannot create " + directory.value() + ": " + code.message()));
  }

  const Result<std::string> request_document = csp::request_to_document(example.value().request, true);
  if (!request_document) {
    return report(request_document.error());
  }
  const Result<std::string> evidence_document = csp::snapshot_to_document(example.value().evidence, true);
  if (!evidence_document) {
    return report(evidence_document.error());
  }
  const Result<std::string> policy_document = csp::policy_to_document(example.value().policy, true);
  if (!policy_document) {
    return report(policy_document.error());
  }

  const std::filesystem::path root(directory.value());
  const std::string request_path = (root / "request.json").string();
  const std::string evidence_path = (root / "evidence.json").string();
  const std::string policy_path = (root / "policy.json").string();
  Status written = write_file(request_path, request_document.value());
  if (!written) {
    return report(written.error());
  }
  std::cout << "wrote: " << request_path << " (" << request_document.value().size() << " bytes)\n";
  written = write_file(evidence_path, evidence_document.value());
  if (!written) {
    return report(written.error());
  }
  std::cout << "wrote: " << evidence_path << " (" << evidence_document.value().size() << " bytes)\n";
  written = write_file(policy_path, policy_document.value());
  if (!written) {
    return report(written.error());
  }
  std::cout << "wrote: " << policy_path << " (" << policy_document.value().size() << " bytes)\n";

  // The self-check reads the three files back through the same decoders a caller will
  // use. Checking the in-memory values would prove nothing about what was written.
  const Result<csp::PlacementRequest> reloaded_request = load_request(request_path);
  if (!reloaded_request) {
    return report(reloaded_request.error());
  }
  const Result<csp::SiteEvidenceSnapshot> reloaded_evidence = load_evidence(evidence_path);
  if (!reloaded_evidence) {
    return report(reloaded_evidence.error());
  }
  const Result<csp::PlacementPolicy> reloaded_policy = load_policy(policy_path);
  if (!reloaded_policy) {
    return report(reloaded_policy.error());
  }

  const csp::Planner planner;
  csp::PlanningContext context;
  context.evaluation_instant = instant.value();
  const Result<csp::PlacementPlan> planned =
      planner.plan(reloaded_request.value(), reloaded_evidence.value(), reloaded_policy.value(), context);
  if (!planned) {
    return report(planned.error());
  }
  const csp::PlacementPlan& plan = planned.value();
  std::size_t placements = 0;
  for (const csp::ObligationPlacement& entry : plan.obligations) {
    placements += entry.placements.size();
  }
  std::cout << "self-check: outcome " << csp::to_string(plan.outcome) << " plan " << plan.plan.value() << " digest "
            << plan.digest.to_hex() << " placements " << placements << " nodes " << plan.nodes_explored << '\n';
  print_refusal(std::cout, plan);
  print_residual(std::cout, plan);
  return exit_code_for(plan.outcome);
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

const std::vector<FlagSpec>& flag_specs_for(const std::string& command) {
  static const std::vector<FlagSpec> kNone{{"help", false}};
  static const std::vector<FlagSpec> kPlan{{"request", true}, {"evidence", true}, {"policy", true},
                                           {"now", true},     {"pretty", false}, {"out", true},
                                           {"help", false}};
  static const std::vector<FlagSpec> kVerify{{"plan", true}, {"help", false}};
  static const std::vector<FlagSpec> kRevalidate{{"plan", true}, {"request", true}, {"evidence", true},
                                                 {"policy", true}, {"now", true},  {"help", false}};
  static const std::vector<FlagSpec> kStore{{"dir", true}, {"plan", true}, {"help", false}};
  static const std::vector<FlagSpec> kGen{{"sites", true}, {"seed", true}, {"classes", true}, {"out", true},
                                          {"now", true},   {"help", false}};
  if (command == "version" || command == "rules") {
    return kNone;
  }
  if (command == "plan" || command == "explain") {
    return kPlan;
  }
  if (command == "verify") {
    return kVerify;
  }
  if (command == "revalidate") {
    return kRevalidate;
  }
  if (command == "store") {
    return kStore;
  }
  if (command == "gen") {
    return kGen;
  }
  return kNone;
}

int run_command(const std::string& command, const std::vector<std::string>& tokens) {
  if (command == "help") {
    print_usage(std::cout);
    return kExitPlaced;
  }
  const std::vector<std::string> known{"version", "rules",   "plan",  "explain", "verify",
                                       "revalidate", "store", "gen",   "help"};
  if (std::find(known.begin(), known.end(), command) == known.end()) {
    return report(csp::fail(ErrorCategory::Invalid, "csp.cli.unknown_command",
                            "csp-cli does not know the command \"" + command + "\"; run it with --help"));
  }

  const bool allow_positional = command == "store";
  const Result<Arguments> arguments =
      Arguments::parse(command, tokens, flag_specs_for(command), allow_positional);
  if (!arguments) {
    return report(arguments.error());
  }
  if (arguments.value().has("help")) {
    print_usage(std::cout);
    return kExitPlaced;
  }

  if (command == "version") {
    return command_version();
  }
  if (command == "rules") {
    return command_rules();
  }
  if (command == "plan" || command == "explain") {
    return command_plan(arguments.value(), command == "explain");
  }
  if (command == "verify") {
    return command_verify(arguments.value());
  }
  if (command == "revalidate") {
    return command_revalidate(arguments.value());
  }
  if (command == "store") {
    return command_store(arguments.value());
  }
  return command_gen(arguments.value());
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> tokens;
  tokens.reserve(argc > 0 ? static_cast<std::size_t>(argc) : 0);
  for (int index = 1; index < argc; ++index) {
    tokens.emplace_back(argv[index]);
  }
  if (tokens.empty()) {
    print_usage(std::cerr);
    return kExitError;
  }
  if (tokens.front() == "--help" || tokens.front() == "-h") {
    print_usage(std::cout);
    return kExitPlaced;
  }
  const std::string command = tokens.front();
  tokens.erase(tokens.begin());
  return run_command(command, tokens);
}
