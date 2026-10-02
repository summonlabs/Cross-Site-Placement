// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// A small test harness, owned by this repository so the suite has no dependency.
//
// Two properties are deliberate. There is no timeout and no watchdog anywhere: a test
// that hangs is a defect to diagnose, and a harness that kills it would convert that
// defect into a passing run. And every randomized case takes its randomness from a named
// seed that is printed when it fails, so a failure is reproducible from the seed alone
// rather than from the machine that produced it.

#ifndef CSP_TESTS_TEST_HARNESS_HPP
#define CSP_TESTS_TEST_HARNESS_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace csp_test {

using Body = std::function<void()>;

class Registry {
 public:
  static Registry& instance();
  void add(std::string name, Body body);
  const std::vector<std::pair<std::string, Body>>& cases() const noexcept { return cases_; }

 private:
  std::vector<std::pair<std::string, Body>> cases_;
};

struct Registration {
  Registration(const char* name, Body body) { Registry::instance().add(name, std::move(body)); }
};

/// Thrown by CSP_REQUIRE to leave the current case without running the rest of it.
struct CaseAbort {};

/// Records one check. Returns whether it held, so a caller can branch on it.
bool check(bool condition, const char* expression, const char* file, int line, const std::string& detail);

/// Leaves the current case immediately. Used by CSP_REQUIRE, where continuing would
/// dereference a value the case has already established is absent.
[[noreturn]] void abort_case();

/// splitmix64, chosen because it is short, has no state beyond one word, and is exactly
/// reproducible across platforms and standard libraries.
class SeededRandom {
 public:
  explicit SeededRandom(std::uint64_t seed) noexcept : state_(seed), seed_(seed) {}

  std::uint64_t next_u64() noexcept;
  /// Uniform in [0, bound); bound must be positive.
  std::uint64_t below(std::uint64_t bound) noexcept;
  /// Uniform in [low, high].
  std::int64_t between(std::int64_t low, std::int64_t high) noexcept;
  bool one_in(std::uint64_t denominator) noexcept;
  std::uint64_t seed() const noexcept { return seed_; }

 private:
  std::uint64_t state_;
  std::uint64_t seed_;
};

/// Runs every registered case in registration order and prints one line per case plus a
/// final count. Returns zero only when every check held.
int run_all(int argc, char** argv);

}  // namespace csp_test

#define CSP_TEST(suite, name)                                            \
  static void csp_test_body_##suite##_##name();                          \
  static const csp_test::Registration csp_test_registration_##suite##_##name( \
      #suite "." #name, &csp_test_body_##suite##_##name);                \
  static void csp_test_body_##suite##_##name()

#define CSP_EXPECT(condition) \
  (void)csp_test::check((condition), #condition, __FILE__, __LINE__, std::string())

#define CSP_EXPECT_MSG(condition, detail) \
  (void)csp_test::check((condition), #condition, __FILE__, __LINE__, (detail))

#define CSP_EXPECT_EQ(lhs, rhs) \
  (void)csp_test::check((lhs) == (rhs), #lhs " == " #rhs, __FILE__, __LINE__, std::string())

#define CSP_REQUIRE(condition)                                                    \
  do {                                                                            \
    if (!csp_test::check((condition), #condition, __FILE__, __LINE__, std::string())) { \
      csp_test::abort_case();                                                     \
    }                                                                             \
  } while (false)

/// Asserts that an expression returning csp::Result<T> or csp::Status succeeded, and
/// reports the error when it did not.
#define CSP_EXPECT_OK(expression)                                                  \
  do {                                                                             \
    auto csp_test_result = (expression);                                           \
    (void)csp_test::check(csp_test_result.has_value(), #expression, __FILE__, __LINE__, \
                          csp_test_result.has_value() ? std::string()                  \
                                                      : csp_test_result.error().render()); \
  } while (false)

/// Asserts that an expression returning csp::Result<T> or csp::Status failed, and
/// reports the value when it did not.
#define CSP_EXPECT_ERROR(expression)                                            \
  do {                                                                          \
    auto csp_test_result = (expression);                                        \
    (void)csp_test::check(!csp_test_result.has_value(), #expression " fails", __FILE__, __LINE__, \
                          std::string());                                       \
  } while (false)

/// Asserts that an expression failed with a specific error category. The parameter is
/// named so that it cannot be substituted into a member call of its own name.
#define CSP_EXPECT_CATEGORY(expression, wanted_category)                                \
  do {                                                                                  \
    auto csp_test_result = (expression);                                                \
    (void)csp_test::check(!csp_test_result.has_value() &&                                \
                              csp_test_result.error().category() == (wanted_category),   \
                          #expression " fails with " #wanted_category, __FILE__, __LINE__, \
                          csp_test_result.has_value() ? std::string("it succeeded")      \
                                                      : csp_test_result.error().render()); \
  } while (false)

#endif  // CSP_TESTS_TEST_HARNESS_HPP
