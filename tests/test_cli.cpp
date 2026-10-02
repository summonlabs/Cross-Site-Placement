// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The command-line tool, driven as a real child process.
//
// Every case in this file is inside #if defined(CSP_CLI_PATH), because tests/CMakeLists.txt
// only defines that macro when the tool was built. A build without the tool still has to
// compile this translation unit: a case that cannot run is not evidence, and a file that
// does not compile would take the evidence of every other file down with it.
//
// The interface driven here is the one cli/main.cpp publishes:
//
//   csp-cli --help
//   csp-cli version
//   csp-cli rules
//   csp-cli gen   --sites N --seed S --classes N --out DIR --now NANOS
//   csp-cli plan  --request F --evidence F --policy F --now NANOS [--out F]
//   csp-cli store --dir D commit --plan F
//   csp-cli store --dir D load   --plan PLANID
//   csp-cli store --dir D audit
//   csp-cli store --dir D list
//
// Exit codes are part of the tool's contract: 0 planned, 1 refused, 2 indeterminate,
// 3 an error. A failure prints one line to stderr as
// "csp-cli: <category>: <code>: <message>". Every case reports the command line, the
// exit code and both streams when it fails, so a mismatch is a diagnosis rather than a
// puzzle.

#include "test_harness.hpp"

#if defined(CSP_CLI_PATH)

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
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

using namespace csp;

/// A required check that names the command line, the exit code and both streams before
/// it stops the case. A CLI case that failed without saying what the tool printed would
/// be a puzzle rather than a diagnosis.
#define CSP_REQUIRE_MSG(condition, detail)                                                          do {                                                                                                if (!csp_test::check((condition), #condition, __FILE__, __LINE__, (detail))) {                      csp_test::abort_case();                                                                         }                                                                                               } while (false)

namespace {

/// An instant far enough from the epoch that every generated observation is inside the
/// configured freshness window, and fixed so that two runs of a command agree.
constexpr std::int64_t kNow = 1700000000000000000LL;

constexpr const char* kRequestFile = "request.json";
constexpr const char* kEvidenceFile = "evidence.json";
constexpr const char* kPolicyFile = "policy.json";

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
    path_ = std::string(base) + "/csp-cli-" + tag + "-" + std::to_string(process_id()) + "-" +
            std::to_string(counter.fetch_add(1));
    if (detail::directory_exists(path_)) {
      (void)detail::remove_directory_tree(path_);
    }
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

std::string system_command(const std::string& command) {
#if defined(_WIN32)
  // cmd.exe strips the outer pair of quotes from a command line that begins with one, and
  // every command here begins with the quoted path of the tool.
  if (!command.empty() && command.front() == '"') {
    return "\"" + command + "\"";
  }
#endif
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

std::string read_text(const std::string& path) {
  Result<std::string> bytes = detail::read_file_bounded(path, 8u * 1024u * 1024u);
  return bytes.has_value() ? bytes.value() : std::string();
}

bool write_text(const std::string& path, const std::string& text) {
  return detail::write_file_durable(path, text).has_value();
}

struct CliResult {
  int exit_code = -1;
  std::string out;
  std::string err;
  std::string command;
};

CliResult run_cli(const std::string& scratch, const std::string& tag, const std::string& arguments) {
  const std::string out_path = join(scratch, tag + ".out");
  const std::string err_path = join(scratch, tag + ".err");
  const std::string command =
      system_command(quote(CSP_CLI_PATH) + " " + arguments + " > " + quote(out_path) + " 2> " + quote(err_path));
  CliResult result;
  result.command = command;
  result.exit_code = exit_code_of(std::system(command.c_str()));
  result.out = read_text(out_path);
  result.err = read_text(err_path);
  return result;
}

std::string describe(const CliResult& result) {
  std::string text = "command: " + result.command;
  text += "\nexit: " + std::to_string(result.exit_code);
  text += "\nstdout: " + result.out;
  text += "\nstderr: " + result.err;
  return text;
}

bool contains(const std::string& text, const std::string& token) {
  return text.find(token) != std::string::npos;
}

bool is_hex(char value) {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F');
}

/// Every standalone 64-hex-character run in the text: the digests a human-facing summary
/// might carry, wherever in the line they were placed.
std::vector<std::string> hex_digests(const std::string& text) {
  std::vector<std::string> found;
  std::size_t index = 0;
  while (index + 64 <= text.size()) {
    bool candidate = true;
    for (std::size_t offset = 0; offset < 64; ++offset) {
      if (!is_hex(text[index + offset])) {
        candidate = false;
        break;
      }
    }
    const bool before = index > 0 && is_hex(text[index - 1]);
    const bool after = index + 64 < text.size() && is_hex(text[index + 64]);
    if (candidate && !before && !after) {
      found.push_back(text.substr(index, 64));
      index += 64;
      continue;
    }
    ++index;
  }
  return found;
}

/// The flags that name one generated document set.
std::string document_flags(const std::string& directory) {
  return std::string("--request ") + quote(join(directory, kRequestFile)) + " --evidence " +
         quote(join(directory, kEvidenceFile)) + " --policy " + quote(join(directory, kPolicyFile));
}

CliResult run_gen(const std::string& scratch, const std::string& tag, const std::string& directory) {
  return run_cli(scratch, tag, std::string("gen --sites 8 --seed 11 --classes 2 --out ") + quote(directory) +
                                   " --now " + std::to_string(kNow));
}

CliResult run_plan(const std::string& scratch, const std::string& tag, const std::string& directory,
                   const std::string& extra) {
  return run_cli(scratch, tag, std::string("plan ") + document_flags(directory) + " --now " +
                                   std::to_string(kNow) + extra);
}

bool same_bytes(const std::string& lhs, const std::string& rhs) { return lhs == rhs; }

}  // namespace

CSP_TEST(cli, version_prints_the_banner) {
  ScratchDirectory scratch("version");
  const CliResult result = run_cli(scratch.path(), "version", "version");
  CSP_EXPECT_MSG(result.exit_code == 0, describe(result));
  CSP_EXPECT_MSG(contains(result.out, version_banner()), describe(result));
  CSP_EXPECT_MSG(contains(result.out, kVersionString), describe(result));
}

CSP_TEST(cli, rules_prints_the_rule_tokens_in_order) {
  ScratchDirectory scratch("rules");
  const CliResult result = run_cli(scratch.path(), "rules", "rules");
  CSP_EXPECT_MSG(result.exit_code == 0, describe(result));
  std::size_t cursor = 0;
  for (const std::string& token : Planner::rule_tokens()) {
    const std::size_t at = result.out.find(token, cursor);
    CSP_EXPECT_MSG(at != std::string::npos,
                   "rule token " + token + " is missing or out of order:\n" + describe(result));
    if (at == std::string::npos) {
      break;
    }
    cursor = at + token.size();
  }
  CSP_EXPECT_EQ(Planner::rule_tokens().size(), std::size_t{19});
}

CSP_TEST(cli, help_exits_zero_and_prints_usage) {
  ScratchDirectory scratch("help");
  const CliResult result = run_cli(scratch.path(), "help", "--help");
  CSP_EXPECT_MSG(result.exit_code == 0, describe(result));
  CSP_EXPECT_MSG(contains(result.out, "usage: csp-cli"), describe(result));
  CSP_EXPECT_MSG(contains(result.out, "exit codes"), describe(result));
}

CSP_TEST(cli, gen_writes_a_self_consistent_document_set) {
  ScratchDirectory scratch("gen");
  const std::string first = join(scratch.path(), "first");
  const std::string second = join(scratch.path(), "second");
  const CliResult generated = run_gen(scratch.path(), "gen", first);
  CSP_EXPECT_MSG(generated.exit_code == 0, describe(generated));

  const std::string request_path = join(first, kRequestFile);
  const std::string evidence_path = join(first, kEvidenceFile);
  const std::string policy_path = join(first, kPolicyFile);
  CSP_EXPECT_MSG(detail::file_exists(request_path), describe(generated));
  CSP_EXPECT_MSG(detail::file_exists(evidence_path), describe(generated));
  CSP_EXPECT_MSG(detail::file_exists(policy_path), describe(generated));
  CSP_REQUIRE(detail::file_exists(request_path) && detail::file_exists(evidence_path) &&
              detail::file_exists(policy_path));

  // It re-reads what it wrote and plans it, and says so: the exit code is the outcome of
  // that plan, so a zero here is the tool's own statement that the set is usable.
  CSP_EXPECT_MSG(contains(generated.out, "self-check: outcome planned"), describe(generated));

  const Limits limits;
  Result<PlacementRequest> request = request_from_document(read_text(request_path), limits);
  CSP_REQUIRE_MSG(request.has_value(), "the generated request does not decode: " + request.error().render());
  Result<SiteEvidenceSnapshot> evidence = snapshot_from_document(read_text(evidence_path), limits);
  CSP_REQUIRE_MSG(evidence.has_value(), "the generated evidence does not decode: " + evidence.error().render());
  Result<PlacementPolicy> policy = policy_from_document(read_text(policy_path), limits);
  CSP_REQUIRE_MSG(policy.has_value(), "the generated policy does not decode: " + policy.error().render());

  // The evidence describes every site the request names, and the request names the
  // policy the policy document carries.
  CSP_EXPECT_EQ(policy.value().policy.value(), request.value().policy.policy.value());
  CSP_EXPECT_EQ(policy.value().generation.value(), request.value().policy.generation.value());
  CSP_EXPECT(!evidence.value().sites.empty());
  for (const SiteRecord& site : evidence.value().sites) {
    bool has_capacity = false;
    for (const CapacityRecord& capacity : evidence.value().capacity) {
      has_capacity = has_capacity || capacity.site == site.site;
    }
    CSP_EXPECT_MSG(has_capacity, "the generated evidence has no capacity for " + site.site.value());
  }

  // Deterministic: one seed and one instant produce one set of bytes.
  const CliResult again = run_gen(scratch.path(), "gen-again", second);
  CSP_EXPECT_MSG(again.exit_code == 0, describe(again));
  CSP_EXPECT_MSG(same_bytes(read_text(join(second, kRequestFile)), read_text(request_path)),
                 "two runs of gen with one seed produced different requests");
  CSP_EXPECT_MSG(same_bytes(read_text(join(second, kEvidenceFile)), read_text(evidence_path)),
                 "two runs of gen with one seed produced different evidence");
}

CSP_TEST(cli, plan_matches_an_independently_computed_digest) {
  ScratchDirectory scratch("plan");
  const std::string directory = join(scratch.path(), "example");
  const CliResult generated = run_gen(scratch.path(), "gen", directory);
  CSP_REQUIRE_MSG(generated.exit_code == 0, describe(generated));

  const CliResult planned = run_plan(scratch.path(), "plan", directory, "");
  CSP_EXPECT_MSG(planned.exit_code == 0, describe(planned));

  const Limits limits;
  Result<PlacementRequest> request = request_from_document(read_text(join(directory, kRequestFile)), limits);
  CSP_REQUIRE(request.has_value());
  Result<SiteEvidenceSnapshot> evidence = snapshot_from_document(read_text(join(directory, kEvidenceFile)), limits);
  CSP_REQUIRE(evidence.has_value());
  Result<PlacementPolicy> policy = policy_from_document(read_text(join(directory, kPolicyFile)), limits);
  CSP_REQUIRE(policy.has_value());

  PlanningContext context;
  context.evaluation_instant = Instant::from_nanos(kNow);
  const Planner planner;
  Result<PlacementPlan> mine = planner.plan(request.value(), evidence.value(), policy.value(), context);
  CSP_REQUIRE_MSG(mine.has_value(), "the same inputs cannot be planned here: " + mine.error().render());
  CSP_REQUIRE_MSG(mine.value().outcome == PlanOutcome::Planned,
                  std::string("the generated example is not plannable: ") + to_string(mine.value().outcome));

  bool digest_printed = false;
  for (const std::string& digest : hex_digests(planned.out)) {
    if (digest == mine.value().digest.to_hex()) {
      digest_printed = true;
    }
  }
  CSP_EXPECT_MSG(digest_printed, "the printed digest is not the digest of the plan for these documents:\nexpected " +
                                     mine.value().digest.to_hex() + "\n" + describe(planned));
  CSP_EXPECT_MSG(contains(planned.out, mine.value().plan.value()), describe(planned));

  // The document form, written by the tool itself, carries the same plan.
  const std::string plan_path = join(scratch.path(), "plan.json");
  const CliResult written = run_plan(scratch.path(), "plan-out", directory, " --out " + quote(plan_path));
  CSP_EXPECT_MSG(written.exit_code == 0, describe(written));
  CSP_REQUIRE(detail::file_exists(plan_path));
  Result<PlacementPlan> document = plan_from_document(read_text(plan_path), limits);
  CSP_REQUIRE_MSG(document.has_value(), "the written plan document does not decode: " + document.error().render());
  Result<std::string> expected_bytes = plan_canonical_bytes(mine.value());
  Result<std::string> written_bytes = plan_canonical_bytes(document.value());
  CSP_REQUIRE(expected_bytes.has_value() && written_bytes.has_value());
  CSP_EXPECT_MSG(expected_bytes.value() == written_bytes.value(),
                 "the written plan is not the plan those documents produce");

  // Two runs of one command agree, so a digest comparison is not comparing two drifts.
  const CliResult repeated = run_plan(scratch.path(), "plan-again", directory, "");
  CSP_EXPECT_MSG(repeated.exit_code == 0, describe(repeated));
  CSP_EXPECT_MSG(repeated.out == planned.out, "two runs of the same command disagree:\n" + describe(repeated));
}

CSP_TEST(cli, unsatisfiable_documents_exit_one_with_a_refusal) {
  ScratchDirectory scratch("refusal");
  const std::string directory = join(scratch.path(), "example");
  const CliResult generated = run_gen(scratch.path(), "gen", directory);
  CSP_REQUIRE_MSG(generated.exit_code == 0, describe(generated));

  const Limits limits;
  Result<PlacementRequest> request = request_from_document(read_text(join(directory, kRequestFile)), limits);
  CSP_REQUIRE(request.has_value());
  Result<SiteEvidenceSnapshot> evidence = snapshot_from_document(read_text(join(directory, kEvidenceFile)), limits);
  CSP_REQUIRE(evidence.has_value());

  // Every site the evidence describes is forbidden to the request, so no arrangement
  // exists and the answer is a refusal rather than a failure to read the input.
  PlacementRequest unsatisfiable = request.value();
  for (const SiteRecord& site : evidence.value().sites) {
    unsatisfiable.forbidden_sites.push_back(site.site);
  }
  const std::string refused_path = join(directory, "request-refused.json");
  Result<std::string> document = request_to_document(unsatisfiable, false);
  CSP_REQUIRE(document.has_value());
  CSP_REQUIRE(write_text(refused_path, document.value()));

  const CliResult refused = run_cli(scratch.path(), "refused",
                                    std::string("plan --request ") + quote(refused_path) + " --evidence " +
                                        quote(join(directory, kEvidenceFile)) + " --policy " +
                                        quote(join(directory, kPolicyFile)) + " --now " + std::to_string(kNow));
  CSP_EXPECT_MSG(refused.exit_code == 1, describe(refused));
  CSP_EXPECT_MSG(contains(refused.out, "refused") || contains(refused.out, "refusal"), describe(refused));
}

CSP_TEST(cli, malformed_documents_exit_three_with_category_code_and_message) {
  ScratchDirectory scratch("malformed");
  const std::string directory = join(scratch.path(), "example");
  const CliResult generated = run_gen(scratch.path(), "gen", directory);
  CSP_REQUIRE_MSG(generated.exit_code == 0, describe(generated));

  const std::string broken_path = join(directory, "request-broken.json");
  CSP_REQUIRE(write_text(broken_path, "this is not a document at all\n"));

  const CliResult broken = run_cli(scratch.path(), "broken",
                                   std::string("plan --request ") + quote(broken_path) + " --evidence " +
                                       quote(join(directory, kEvidenceFile)) + " --policy " +
                                       quote(join(directory, kPolicyFile)) + " --now " + std::to_string(kNow));
  CSP_EXPECT_MSG(broken.exit_code == 3, describe(broken));
  // The category, the code, and a message that says something, on stderr.
  CSP_EXPECT_MSG(contains(broken.err, "csp-cli: "), describe(broken));
  CSP_EXPECT_MSG(contains(broken.err, to_string(ErrorCategory::Malformed)), describe(broken));
  CSP_EXPECT_MSG(contains(broken.err, "csp."), describe(broken));
  bool says_something = false;
  for (const char* candidate : {"not", "document", "expected", "byte", "malformed", "json"}) {
    if (contains(broken.err, candidate)) {
      says_something = true;
    }
  }
  CSP_EXPECT_MSG(says_something, "the message names nothing about the defect:\n" + describe(broken));
  CSP_EXPECT_MSG(broken.out.empty(), "a failed command printed something on stdout:\n" + describe(broken));
}

CSP_TEST(cli, store_commit_then_load_round_trips_a_plan) {
  ScratchDirectory scratch("store");
  const std::string directory = join(scratch.path(), "example");
  const std::string store = join(scratch.path(), "store");

  // The plan comes out of the tool itself, which is what makes this a round trip through
  // the real command line rather than through the library twice.
  const CliResult generated = run_gen(scratch.path(), "gen", directory);
  CSP_REQUIRE_MSG(generated.exit_code == 0, describe(generated));
  const std::string plan_path = join(scratch.path(), "plan.json");
  const CliResult planned = run_plan(scratch.path(), "plan", directory, " --out " + quote(plan_path));
  CSP_REQUIRE_MSG(planned.exit_code == 0, describe(planned));
  CSP_REQUIRE(detail::file_exists(plan_path));

  const Limits limits;
  Result<PlacementPlan> printed = plan_from_document(read_text(plan_path), limits);
  CSP_REQUIRE_MSG(printed.has_value(), "the written plan does not decode: " + printed.error().render());

  const CliResult committed =
      run_cli(scratch.path(), "commit",
              std::string("store --dir ") + quote(store) + " commit --plan " + quote(plan_path));
  CSP_EXPECT_MSG(committed.exit_code == 0, describe(committed));
  CSP_EXPECT_MSG(contains(committed.out, printed.value().plan.value()), describe(committed));
  CSP_EXPECT_MSG(contains(committed.out, "generation 1"), describe(committed));

  const CliResult loaded =
      run_cli(scratch.path(), "load", std::string("store --dir ") + quote(store) + " load --plan " +
                                             quote(printed.value().plan.value()));
  CSP_EXPECT_MSG(loaded.exit_code == 0, describe(loaded));
  Result<PlacementPlan> reloaded = plan_from_document(loaded.out, limits);
  CSP_REQUIRE_MSG(reloaded.has_value(), "the loaded plan does not decode: " + reloaded.error().render());
  CSP_EXPECT_MSG(reloaded.value().plan.value() == printed.value().plan.value(), describe(loaded));
  Result<std::string> before_bytes = plan_canonical_bytes(printed.value());
  Result<std::string> after_bytes = plan_canonical_bytes(reloaded.value());
  CSP_REQUIRE(before_bytes.has_value() && after_bytes.has_value());
  CSP_EXPECT_MSG(before_bytes.value() == after_bytes.value(), "the plan changed on its way through the store");

  const CliResult audited =
      run_cli(scratch.path(), "audit", std::string("store --dir ") + quote(store) + " audit");
  CSP_EXPECT_MSG(audited.exit_code == 0, describe(audited));
  CSP_EXPECT_MSG(contains(audited.out, "consistent: true"), describe(audited));
  CSP_EXPECT_MSG(contains(audited.out, printed.value().plan.value()), describe(audited));

  const CliResult listed = run_cli(scratch.path(), "list", std::string("store --dir ") + quote(store) + " list");
  CSP_EXPECT_MSG(listed.exit_code == 0, describe(listed));
  CSP_EXPECT_MSG(contains(listed.out, printed.value().plan.value()), describe(listed));

  // Loading an identity the store does not hold is an error, not an empty success.
  const CliResult missing = run_cli(scratch.path(), "missing",
                                    std::string("store --dir ") + quote(store) +
                                        " load --plan plan-0000000000000000000000000000dead");
  CSP_EXPECT_MSG(missing.exit_code == 3, describe(missing));
  CSP_EXPECT_MSG(contains(missing.err, "not_found"), describe(missing));
  CSP_EXPECT_MSG(contains(missing.err, "csp.store.unknown_plan"), describe(missing));
}

#endif  // CSP_CLI_PATH
