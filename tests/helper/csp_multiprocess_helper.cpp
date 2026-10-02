// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// A second operating-system process for the multiprocess cases.
//
// It performs exactly one store operation and prints exactly one machine-readable line
// on stdout: "ok <token> ..." when the operation completed and "error <category> <code>"
// when the library refused it. Everything a human might want to read goes to stderr, so
// a parent that parses stdout never has to guess which line is the answer.
//
// It links only the public library: the store lock it holds in "hold-lock" mode is taken
// through the platform's own exclusive-lock call on the same file the store locks, which
// is the only honest way for a second process to hold a lock this library does not
// expose.

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

#include "cross_site_placement/cross_site_placement.hpp"

namespace {

using namespace csp;

std::string join_path(const std::string& directory, const std::string& name) {
  if (!directory.empty() && (directory.back() == '/' || directory.back() == '\\')) {
    return directory + name;
  }
  return directory + "/" + name;
}

int report_error(const Error& error) {
  std::printf("error %s %s\n", to_string(error.category()), error.code().c_str());
  std::fflush(stdout);
  return 1;
}

int report_usage(const char* detail) {
  std::printf("error invalid csp.helper.usage\n");
  std::fflush(stdout);
  std::fprintf(stderr, "csp-multiprocess-helper: %s\n", detail);
  return 2;
}

Error helper_error(const char* condition, std::string detail) {
  return fail(ErrorCategory::Invalid, std::string("csp.helper.") + condition, std::move(detail));
}

std::size_t parse_wait(const char* text, bool& ok) {
  char* end = nullptr;
  const unsigned long long parsed = std::strtoull(text, &end, 10);
  ok = end != nullptr && *end == '\0';
  return static_cast<std::size_t>(parsed);
}

bool read_file(const std::string& path, std::string& out) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return false;
  }
  std::string contents((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
  out = std::move(contents);
  return true;
}

bool write_marker(const std::string& path) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return false;
  }
  stream << "held\n";
  stream.flush();
  return stream.good();
}

StoreOptions options_for(const std::string& directory, std::size_t wait_ms) {
  StoreOptions options;
  options.directory = directory;
  options.lock_wait_ms = wait_ms;
  options.lock_retry_ms = 5;
  return options;
}

#if defined(_WIN32)

std::wstring to_wide(const std::string& text) {
  if (text.empty()) {
    return std::wstring();
  }
  const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
  if (size <= 0) {
    return std::wstring();
  }
  std::wstring wide(static_cast<std::size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), size);
  return wide;
}

int hold_lock(const std::string& directory, std::size_t milliseconds, const std::string& marker) {
  const std::wstring wide = to_wide(join_path(directory, "store.lock"));
  if (wide.empty()) {
    return report_error(helper_error("path", "the lock path is not valid UTF-8"));
  }
  HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return report_error(fail(ErrorCategory::Io, "csp.helper.lock_open",
                             "cannot open the store lock file for an exclusive hold"));
  }
  OVERLAPPED overlapped{};
  const DWORD low = 0xFFFFFFFFUL;
  const DWORD high = 0xFFFFFFFFUL;
  if (LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, low, high, &overlapped) == 0) {
    CloseHandle(handle);
    return report_error(fail(ErrorCategory::Locked, "csp.helper.lock_acquire",
                             "cannot take the exclusive lock on the store lock file"));
  }
  if (!write_marker(marker)) {
    UnlockFileEx(handle, 0, low, high, &overlapped);
    CloseHandle(handle);
    return report_error(fail(ErrorCategory::Io, "csp.helper.marker",
                             "the lock was taken and the ready marker could not be written"));
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<std::int64_t>(milliseconds)));
  UnlockFileEx(handle, 0, low, high, &overlapped);
  CloseHandle(handle);
  return 0;
}

#else

int hold_lock(const std::string& directory, std::size_t milliseconds, const std::string& marker) {
  const std::string path = join_path(directory, "store.lock");
  const int descriptor = ::open(path.c_str(), O_RDWR | O_CREAT, 0666);
  if (descriptor < 0) {
    return report_error(fail(ErrorCategory::Io, "csp.helper.lock_open",
                             "cannot open the store lock file for an exclusive hold"));
  }
  if (flock(descriptor, LOCK_EX) != 0) {
    ::close(descriptor);
    return report_error(fail(ErrorCategory::Locked, "csp.helper.lock_acquire",
                             "cannot take the exclusive lock on the store lock file"));
  }
  if (!write_marker(marker)) {
    flock(descriptor, LOCK_UN);
    ::close(descriptor);
    return report_error(fail(ErrorCategory::Io, "csp.helper.marker",
                             "the lock was taken and the ready marker could not be written"));
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<std::int64_t>(milliseconds)));
  flock(descriptor, LOCK_UN);
  ::close(descriptor);
  return 0;
}

#endif

int run_commit(const std::string& directory, const std::string& document_path, std::size_t wait_ms) {
  std::string document;
  if (!read_file(document_path, document)) {
    return report_error(fail(ErrorCategory::NotFound, "csp.helper.document",
                             "the plan document could not be read"));
  }
  const Limits limits;
  Result<PlacementPlan> plan = plan_from_document(document, limits);
  if (!plan) {
    return report_error(plan.error());
  }
  Result<PlanStore> store = PlanStore::open(options_for(directory, wait_ms));
  if (!store) {
    return report_error(store.error());
  }
  Result<PlanId> committed = store.value().commit(plan.value());
  if (!committed) {
    return report_error(committed.error());
  }
  const Status closed = store.value().close();
  if (!closed) {
    return report_error(closed.error());
  }
  std::printf("ok csp.helper.commit %s\n", committed.value().value().c_str());
  std::fflush(stdout);
  return 0;
}

int run_load(const std::string& directory, const std::string& identity, std::size_t wait_ms) {
  Result<PlanId> plan_id = PlanId::parse(identity);
  if (!plan_id) {
    return report_error(plan_id.error());
  }
  Result<PlanStore> store = PlanStore::open(options_for(directory, wait_ms));
  if (!store) {
    return report_error(store.error());
  }
  Result<PlacementPlan> loaded = store.value().load(plan_id.value());
  if (!loaded) {
    return report_error(loaded.error());
  }
  std::printf("ok csp.helper.load %s %s\n", loaded.value().plan.value().c_str(),
              loaded.value().digest.to_hex().c_str());
  std::fflush(stdout);
  return 0;
}

int run_audit(const std::string& directory, std::size_t wait_ms) {
  Result<PlanStore> store = PlanStore::open(options_for(directory, wait_ms));
  if (!store) {
    return report_error(store.error());
  }
  Result<StoreAudit> audit = store.value().audit();
  if (!audit) {
    return report_error(audit.error());
  }
  std::string line = "ok csp.helper.audit ";
  line += audit.value().consistent ? "1" : "0";
  line += " ";
  line += std::to_string(audit.value().generation.value());
  line += " ";
  line += std::to_string(audit.value().records.size());
  for (const PlanId& record : audit.value().records) {
    line += " ";
    line += record.value();
  }
  std::printf("%s\n", line.c_str());
  std::fflush(stdout);
  const Status closed = store.value().close();
  if (!closed) {
    return report_error(closed.error());
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    return report_usage("usage: csp-multiprocess-helper <commit|load|audit|hold-lock> <directory> [args]");
  }
  const std::string mode = argv[1];
  const std::string directory = argv[2];
  if (directory.empty()) {
    return report_usage("the store directory must not be empty");
  }
  bool ok = true;

  if (mode == "commit") {
    if (argc < 4) {
      return report_usage("commit needs a plan document path");
    }
    const std::size_t wait_ms = argc >= 5 ? parse_wait(argv[4], ok) : 5000;
    if (!ok) {
      return report_usage("the lock wait must be a decimal integer");
    }
    return run_commit(directory, argv[3], wait_ms);
  }
  if (mode == "load") {
    if (argc < 4) {
      return report_usage("load needs a plan identity");
    }
    const std::size_t wait_ms = argc >= 5 ? parse_wait(argv[4], ok) : 5000;
    if (!ok) {
      return report_usage("the lock wait must be a decimal integer");
    }
    return run_load(directory, argv[3], wait_ms);
  }
  if (mode == "audit") {
    const std::size_t wait_ms = argc >= 4 ? parse_wait(argv[3], ok) : 5000;
    if (!ok) {
      return report_usage("the lock wait must be a decimal integer");
    }
    return run_audit(directory, wait_ms);
  }
  if (mode == "hold-lock") {
    if (argc < 5) {
      return report_usage("hold-lock needs a duration in milliseconds and a ready marker path");
    }
    const std::size_t milliseconds = parse_wait(argv[3], ok);
    if (!ok) {
      return report_usage("the hold duration must be a decimal integer");
    }
    const int status = hold_lock(directory, milliseconds, argv[4]);
    if (status != 0) {
      return status;
    }
    std::printf("ok csp.helper.hold-lock %zu\n", milliseconds);
    std::fflush(stdout);
    return 0;
  }
  return report_usage("unknown mode");
}
