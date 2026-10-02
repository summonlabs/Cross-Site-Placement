// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "test_harness.hpp"

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <utility>
#include <vector>

#include "cross_site_placement/error.hpp"

namespace csp_test {
namespace {

std::size_t g_checks = 0;
std::size_t g_failures = 0;
std::vector<std::string> g_current_failures;

}  // namespace

Registry& Registry::instance() {
  static Registry registry;
  return registry;
}

void Registry::add(std::string name, Body body) { cases_.emplace_back(std::move(name), std::move(body)); }

bool check(bool condition, const char* expression, const char* file, int line, const std::string& detail) {
  ++g_checks;
  if (condition) {
    return true;
  }
  ++g_failures;
  std::string message = std::string(file) + ":" + std::to_string(line) + ": " + expression;
  if (!detail.empty()) {
    message += "\n      " + detail;
  }
  g_current_failures.push_back(std::move(message));
  return false;
}

void abort_case() { throw CaseAbort{}; }

std::uint64_t SeededRandom::next_u64() noexcept {
  state_ += 0x9E3779B97F4A7C15ULL;
  std::uint64_t value = state_;
  value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ULL;
  value = (value ^ (value >> 27)) * 0x94D049BB133111EBULL;
  return value ^ (value >> 31);
}

std::uint64_t SeededRandom::below(std::uint64_t bound) noexcept {
  if (bound == 0) {
    return 0;
  }
  // Rejection sampling, so the result is uniform rather than merely small.
  const std::uint64_t limit = UINT64_MAX - (UINT64_MAX % bound);
  for (;;) {
    const std::uint64_t value = next_u64();
    if (value < limit) {
      return value % bound;
    }
  }
}

std::int64_t SeededRandom::between(std::int64_t low, std::int64_t high) noexcept {
  if (high <= low) {
    return low;
  }
  const std::uint64_t span = static_cast<std::uint64_t>(high - low) + 1U;
  return low + static_cast<std::int64_t>(below(span));
}

bool SeededRandom::one_in(std::uint64_t denominator) noexcept {
  if (denominator <= 1) {
    return true;
  }
  return below(denominator) == 0;
}

int run_all(int argc, char** argv) {
  std::vector<std::string> filters;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--list") {
      for (const auto& entry : Registry::instance().cases()) {
        std::printf("%s\n", entry.first.c_str());
      }
      return 0;
    }
    filters.push_back(argument);
  }

  std::size_t passed = 0;
  std::size_t failed = 0;
  for (const auto& entry : Registry::instance().cases()) {
    if (!filters.empty()) {
      bool matched = false;
      for (const std::string& filter : filters) {
        if (entry.first.find(filter) != std::string::npos) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        continue;
      }
    }
    g_current_failures.clear();
    const std::size_t checks_before = g_checks;
    bool crashed = false;
    std::string crash;
    try {
      entry.second();
    } catch (const CaseAbort&) {
      // A required check failed and the case stopped early. The failure is already
      // recorded, so this is not a second one.
    } catch (const std::exception& error) {
      crashed = true;
      crash = error.what();
    } catch (...) {
      crashed = true;
      crash = "an unknown exception escaped the case";
    }
    const bool ok = !crashed && g_current_failures.empty();
    if (crashed) {
      ++g_failures;
      g_current_failures.push_back("the case threw: " + crash);
    }
    if (ok) {
      ++passed;
      std::printf("PASS %-52s (%zu checks)\n", entry.first.c_str(), g_checks - checks_before);
    } else {
      ++failed;
      std::printf("FAIL %s\n", entry.first.c_str());
      for (const std::string& failure : g_current_failures) {
        std::printf("     %s\n", failure.c_str());
      }
    }
    std::fflush(stdout);
  }

  std::printf("\ncases: %zu passed, %zu failed; checks: %zu, failures: %zu\n", passed, failed, g_checks,
              g_failures);
  std::fflush(stdout);
  return g_failures == 0 ? 0 : 1;
}

}  // namespace csp_test
