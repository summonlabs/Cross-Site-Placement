// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The platform adapter for durable files and exclusive locks.
//
// This is the only translation unit in the library that includes a platform
// header, so every platform difference the library has is visible here and
// nowhere else. Each operation is written once per platform on purpose: the
// sequence of platform calls is the thing under review, and hiding it behind one
// more abstraction would make the stated guarantees harder to check against the
// platform manual rather than easier.
//
// Every path at this boundary is UTF-8. On Windows a path is converted with
// MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, ...) so input that is not
// valid UTF-8 is reported instead of silently substituted. On POSIX the bytes
// are handed to the kernel unchanged, because there a file name is a byte string
// and re-encoding it would corrupt names this process did not create.
//
// Nothing here throws: every failure is a csp::Error.

#include "fs_atomic.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#else

#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#endif

namespace csp::detail {
namespace {

/// Number of distinct staging names tried before giving up. Each retry uses a
/// fresh counter value, so this only runs out if a concurrent writer managed to
/// consume that many names inside one call.
constexpr int kStagingAttempts = 16;

/// Write granularity. One MiB is far below any platform limit on a single write
/// (the Windows parameter is a DWORD, the POSIX one a ssize_t) and large enough
/// that a multi-megabyte payload is not a syscall per kilobyte.
constexpr std::size_t kWriteChunk = 1U << 20U;

/// Read granularity for read_file_bounded. Small enough to keep the buffer on
/// the stack budget of a caller that reads many small files, large enough that a
/// big file is not a syscall per page.
constexpr std::size_t kReadChunk = 1U << 16U;

/// Ceiling for any duration derived from caller input, so deadline arithmetic
/// cannot overflow the clock's representation. One hundred years is not a budget
/// any caller has.
constexpr std::int64_t kLongestWaitMs = 100LL * 365LL * 24LL * 60LL * 60LL * 1000LL;

std::string quoted(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 2);
  out.push_back('"');
  out += value;
  out.push_back('"');
  return out;
}

/// Builds an error with a "csp.fs.<condition>" code, a message that names the
/// paths involved, and the platform's own error text last.
Error fs_error(ErrorCategory category, std::string condition, std::string detail, std::string platform_detail) {
  if (!platform_detail.empty()) {
    detail += ": ";
    detail += platform_detail;
  }
  std::string code = "csp.fs.";
  code += condition;
  return fail(category, std::move(code), std::move(detail));
}

/// Unsigned byte order, spelled out rather than relying on char being unsigned.
bool byte_less(const std::string& lhs, const std::string& rhs) {
  return std::lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(),
                                      [](char left, char right) {
                                        return static_cast<unsigned char>(left) < static_cast<unsigned char>(right);
                                      });
}

std::chrono::milliseconds clamp_wait(std::size_t requested) {
  const std::size_t ceiling = static_cast<std::size_t>(kLongestWaitMs);
  const std::size_t bounded = requested > ceiling ? ceiling : requested;
  return std::chrono::milliseconds(static_cast<std::int64_t>(bounded));
}

#if defined(_WIN32)

bool is_separator(char value) { return value == '\\' || value == '/'; }
bool is_wide_separator(wchar_t value) { return value == L'\\' || value == L'/'; }

std::string platform_error_text(unsigned long code) {
  std::string text = "win32 error ";
  text += std::to_string(code);
  const std::error_code platform(static_cast<int>(code), std::system_category());
  const std::string description = platform.message();
  if (!description.empty()) {
    text += " (";
    text += description;
    text += ")";
  }
  return text;
}

/// UTF-8 to UTF-16. Returns false for input that is not valid UTF-8, for input
/// carrying an embedded NUL (which the wide API would read as a terminator), and
/// for input too long for the API's int parameter.
bool to_wide(std::string_view utf8, std::wstring& out) {
  out.clear();
  if (utf8.empty()) {
    return true;
  }
  if (utf8.size() > static_cast<std::size_t>(INT_MAX) || utf8.find('\0') != std::string_view::npos) {
    return false;
  }
  const int length = static_cast<int>(utf8.size());
  const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), length, nullptr, 0);
  if (needed <= 0) {
    return false;
  }
  out.resize(static_cast<std::size_t>(needed));
  const int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), length, out.data(), needed);
  if (written != needed) {
    out.clear();
    return false;
  }
  return true;
}

/// UTF-16 to UTF-8. WC_ERR_INVALID_CHARS refuses to substitute, so a name that
/// cannot round-trip is reported rather than turned into a different name.
bool to_utf8(std::wstring_view wide, std::string& out) {
  out.clear();
  if (wide.empty()) {
    return true;
  }
  if (wide.size() > static_cast<std::size_t>(INT_MAX) || wide.find(L'\0') != std::wstring_view::npos) {
    return false;
  }
  const int length = static_cast<int>(wide.size());
  const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), length, nullptr, 0, nullptr, nullptr);
  if (needed <= 0) {
    return false;
  }
  out.resize(static_cast<std::size_t>(needed));
  const int written =
      WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), length, out.data(), needed, nullptr, nullptr);
  if (written != needed) {
    out.clear();
    return false;
  }
  return true;
}

/// Printable form of a wide path for an error message.
std::string show(const std::wstring& wide) {
  std::string narrow;
  if (to_utf8(wide, narrow)) {
    return narrow;
  }
  return "<path that is not valid UTF-16>";
}

/// Splits a path at its last separator. directory keeps the separator and is
/// empty when the path is a bare name, which places a staging file beside the
/// destination in both cases and therefore inside one volume.
void split_path(const std::string& path, std::string& directory, std::string& name) {
  std::size_t cut = std::string::npos;
  for (std::size_t i = path.size(); i > 0; --i) {
    if (is_separator(path[i - 1])) {
      cut = i;
      break;
    }
  }
  if (cut == std::string::npos) {
    directory.clear();
    name = path;
  } else {
    directory = path.substr(0, cut);
    name = path.substr(cut);
  }
}

unsigned long process_id() { return static_cast<unsigned long>(GetCurrentProcessId()); }

enum class EntryKind { Missing, File, Directory, Other, Failure };

struct EntryAttributes {
  EntryKind kind = EntryKind::Failure;
  unsigned long attributes = 0;
  unsigned long error = 0;
};

bool is_missing_error(unsigned long code) {
  return code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND || code == ERROR_INVALID_NAME ||
         code == ERROR_BAD_PATHNAME;
}

/// Attributes of the entry itself (follow == false, a reparse point stays a
/// reparse point) or of what it resolves to (follow == true). Opening with
/// FILE_FLAG_BACKUP_SEMANTICS is what makes the same call work for files and
/// directories. Querying attributes is not traversal: nothing below the named
/// entry is visited.
EntryAttributes probe_attributes(const std::wstring& wide, bool follow) {
  EntryAttributes result;
  DWORD flags = FILE_FLAG_BACKUP_SEMANTICS;
  if (!follow) {
    flags |= FILE_FLAG_OPEN_REPARSE_POINT;
  }
  HANDLE handle = CreateFileW(wide.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, flags, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    result.error = static_cast<unsigned long>(GetLastError());
    if (is_missing_error(result.error)) {
      result.kind = EntryKind::Missing;
    }
    return result;
  }
  BY_HANDLE_FILE_INFORMATION info{};
  if (GetFileInformationByHandle(handle, &info) == 0) {
    result.error = static_cast<unsigned long>(GetLastError());
    CloseHandle(handle);
    return result;
  }
  CloseHandle(handle);
  result.attributes = static_cast<unsigned long>(info.dwFileAttributes);
  if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
    result.kind = EntryKind::Directory;
  } else if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
    result.kind = EntryKind::Other;
  } else {
    result.kind = EntryKind::File;
  }
  return result;
}

/// Closes a handle exactly once. Handles are the one resource here whose leak is
/// both silent and unbounded, so no early return is left to remember a close.
class UniqueHandle {
 public:
  UniqueHandle() = default;
  explicit UniqueHandle(HANDLE handle) : handle_(handle) {}
  ~UniqueHandle() { reset(); }
  UniqueHandle(const UniqueHandle&) = delete;
  UniqueHandle& operator=(const UniqueHandle&) = delete;

  HANDLE get() const { return handle_; }
  bool valid() const { return handle_ != INVALID_HANDLE_VALUE; }
  void reset() {
    if (handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(handle_);
      handle_ = INVALID_HANDLE_VALUE;
    }
  }

 private:
  HANDLE handle_ = INVALID_HANDLE_VALUE;
};

/// Deletes a file, clearing a read-only attribute first if that is the only
/// thing standing in the way. remove_directory_tree was asked for the tree.
bool delete_file_wide(const std::wstring& wide, unsigned long& failure) {
  if (DeleteFileW(wide.c_str()) != 0) {
    return true;
  }
  failure = static_cast<unsigned long>(GetLastError());
  if (failure == ERROR_ACCESS_DENIED) {
    const DWORD attributes = GetFileAttributesW(wide.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY) != 0) {
      if (SetFileAttributesW(wide.c_str(), attributes & ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY)) != 0) {
        if (DeleteFileW(wide.c_str()) != 0) {
          return true;
        }
        failure = static_cast<unsigned long>(GetLastError());
      }
    }
  }
  return false;
}

/// Removes one entry that is a reparse point, as a link: RemoveDirectoryW
/// unlinks a directory link (and a junction) without touching the target, and
/// DeleteFileW unlinks a file link.
bool remove_link_wide(const std::wstring& wide, unsigned long attributes, unsigned long& failure) {
  if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
    if (RemoveDirectoryW(wide.c_str()) != 0) {
      return true;
    }
    failure = static_cast<unsigned long>(GetLastError());
    return false;
  }
  return delete_file_wide(wide, failure);
}

Status remove_tree_wide(const std::wstring& target) {
  const EntryAttributes self = probe_attributes(target, false);
  if (self.kind == EntryKind::Missing) {
    return success();
  }
  if (self.kind == EntryKind::Failure) {
    return fs_error(ErrorCategory::Io, "remove_tree", "cannot read the attributes of " + quoted(show(target)),
                    platform_error_text(self.error));
  }
  if ((self.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    unsigned long failure = 0;
    if (!remove_link_wide(target, self.attributes, failure)) {
      return fs_error(ErrorCategory::Io, "remove_tree", "cannot remove the link " + quoted(show(target)),
                      platform_error_text(failure));
    }
    return success();
  }
  if (self.kind != EntryKind::Directory) {
    unsigned long failure = 0;
    if (!delete_file_wide(target, failure)) {
      return fs_error(ErrorCategory::Io, "remove_tree", "cannot remove the file " + quoted(show(target)),
                      platform_error_text(failure));
    }
    return success();
  }

  std::wstring pattern = target;
  if (!pattern.empty() && !is_wide_separator(pattern.back())) {
    pattern.push_back(L'\\');
  }
  pattern.push_back(L'*');

  WIN32_FIND_DATAW found{};
  HANDLE search = FindFirstFileW(pattern.c_str(), &found);
  if (search == INVALID_HANDLE_VALUE) {
    const unsigned long code = static_cast<unsigned long>(GetLastError());
    // An empty directory can surface here as "no files", which is not an error.
    if (code != ERROR_FILE_NOT_FOUND) {
      return fs_error(ErrorCategory::Io, "remove_tree", "cannot enumerate " + quoted(show(target)),
                      platform_error_text(code));
    }
  } else {
    for (;;) {
      const std::wstring name(found.cFileName);
      if (name != L"." && name != L"..") {
        std::wstring child = target;
        if (!child.empty() && !is_wide_separator(child.back())) {
          child.push_back(L'\\');
        }
        child += name;
        // FindFirstFileW reports the attributes of the link itself, and the
        // recursive step rechecks them anyway, so a junction is never descended
        // into and the recursion cannot cycle.
        const Status status = remove_tree_wide(child);
        if (!status) {
          FindClose(search);
          return status;
        }
      }
      if (FindNextFileW(search, &found) == 0) {
        const unsigned long code = static_cast<unsigned long>(GetLastError());
        FindClose(search);
        if (code != ERROR_NO_MORE_FILES) {
          return fs_error(ErrorCategory::Io, "remove_tree", "cannot enumerate " + quoted(show(target)),
                          platform_error_text(code));
        }
        break;
      }
    }
  }

  if (RemoveDirectoryW(target.c_str()) == 0) {
    return fs_error(ErrorCategory::Io, "remove_tree", "cannot remove the directory " + quoted(show(target)),
                    platform_error_text(static_cast<unsigned long>(GetLastError())));
  }
  return success();
}

/// Creates exactly one directory component; an existing directory is a success
/// and an existing non-directory is a Conflict, because that distinction is
/// something the caller can act on.
Status create_one_directory(const std::wstring& prefix, const std::string& destination) {
  if (CreateDirectoryW(prefix.c_str(), nullptr) != 0) {
    return success();
  }
  const unsigned long code = static_cast<unsigned long>(GetLastError());
  if (code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS) {
    const EntryAttributes existing = probe_attributes(prefix, true);
    if (existing.kind == EntryKind::Directory) {
      return success();
    }
    if (existing.kind == EntryKind::File || existing.kind == EntryKind::Other) {
      return fs_error(ErrorCategory::Conflict, "conflict",
                      "cannot create the directory " + quoted(show(prefix)) + " on the way to " + quoted(destination),
                      "an entry that is not a directory already exists at that name");
    }
  }
  return fs_error(ErrorCategory::Io, "mkdir",
                  "cannot create the directory " + quoted(show(prefix)) + " on the way to " + quoted(destination),
                  platform_error_text(code));
}

#else  // POSIX

constexpr char kSeparator = '/';

std::string platform_error_text(int code) {
  std::string text = "errno ";
  text += std::to_string(code);
  const std::error_code platform(code, std::system_category());
  const std::string description = platform.message();
  if (!description.empty()) {
    text += " (";
    text += description;
    text += ")";
  }
  return text;
}

void split_path(const std::string& path, std::string& directory, std::string& name) {
  const std::size_t cut = path.rfind(kSeparator);
  if (cut == std::string::npos) {
    directory.clear();
    name = path;
  } else {
    directory = path.substr(0, cut + 1);
    name = path.substr(cut + 1);
  }
}

long process_id() { return static_cast<long>(getpid()); }

/// Closes a descriptor exactly once.
class UniqueFd {
 public:
  UniqueFd() = default;
  explicit UniqueFd(int descriptor) : descriptor_(descriptor) {}
  ~UniqueFd() { reset(); }
  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;

  int get() const { return descriptor_; }
  bool valid() const { return descriptor_ >= 0; }
  void reset() {
    if (descriptor_ >= 0) {
      ::close(descriptor_);
      descriptor_ = -1;
    }
  }

 private:
  int descriptor_ = -1;
};

Status remove_tree_path(const std::string& target) {
  struct stat info {};
  if (lstat(target.c_str(), &info) != 0) {
    const int code = errno;
    if (code == ENOENT || code == ENOTDIR) {
      return success();
    }
    return fs_error(ErrorCategory::Io, "remove_tree", "cannot read the attributes of " + quoted(target),
                    platform_error_text(code));
  }
  if (S_ISLNK(info.st_mode) || (!S_ISDIR(info.st_mode) && !S_ISREG(info.st_mode))) {
    // A symbolic link is removed as a link; its target is never visited.
    if (unlink(target.c_str()) != 0) {
      return fs_error(ErrorCategory::Io, "remove_tree", "cannot remove the link " + quoted(target),
                      platform_error_text(errno));
    }
    return success();
  }
  if (!S_ISDIR(info.st_mode)) {
    if (unlink(target.c_str()) != 0) {
      return fs_error(ErrorCategory::Io, "remove_tree", "cannot remove the file " + quoted(target),
                      platform_error_text(errno));
    }
    return success();
  }

  DIR* directory = opendir(target.c_str());
  if (directory == nullptr) {
    return fs_error(ErrorCategory::Io, "remove_tree", "cannot enumerate " + quoted(target), platform_error_text(errno));
  }
  for (;;) {
    errno = 0;
    dirent* entry = readdir(directory);
    if (entry == nullptr) {
      break;
    }
    const std::string name(entry->d_name);
    if (name == "." || name == "..") {
      continue;
    }
    std::string child = target;
    if (child.empty() || child.back() != kSeparator) {
      child.push_back(kSeparator);
    }
    child += name;
    const Status status = remove_tree_path(child);
    if (!status) {
      closedir(directory);
      return status;
    }
  }
  const int read_error = errno;
  closedir(directory);
  if (read_error != 0) {
    return fs_error(ErrorCategory::Io, "remove_tree", "cannot enumerate " + quoted(target),
                    platform_error_text(read_error));
  }
  if (rmdir(target.c_str()) != 0) {
    return fs_error(ErrorCategory::Io, "remove_tree", "cannot remove the directory " + quoted(target),
                    platform_error_text(errno));
  }
  return success();
}

Status create_one_directory(const std::string& prefix, const std::string& destination) {
  if (mkdir(prefix.c_str(), 0777) == 0) {
    return success();
  }
  const int code = errno;
  if (code == EEXIST) {
    struct stat info {};
    if (stat(prefix.c_str(), &info) == 0) {
      if (S_ISDIR(info.st_mode)) {
        return success();
      }
      if (S_ISREG(info.st_mode) || S_ISLNK(info.st_mode)) {
        return fs_error(ErrorCategory::Conflict, "conflict",
                        "cannot create the directory " + quoted(prefix) + " on the way to " + quoted(destination),
                        "an entry that is not a directory already exists at that name");
      }
    }
  }
  return fs_error(ErrorCategory::Io, "mkdir",
                  "cannot create the directory " + quoted(prefix) + " on the way to " + quoted(destination),
                  platform_error_text(code));
}

#endif

/// Unique per process and per call, so two writers racing on the same
/// destination never pick the same staging name.
std::string staging_token() {
  static std::atomic<unsigned long long> counter{0};
  const unsigned long long sequence = counter.fetch_add(1, std::memory_order_relaxed);
  std::string token = ".staging.";
  token += std::to_string(process_id());
  token.push_back('.');
  token += std::to_string(sequence);
  return token;
}

}  // namespace

struct FileLock::Impl {
  explicit Impl(std::string lock_path) : path(std::move(lock_path)) {}
  ~Impl() { unlock_and_close(); }

  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  bool held() const noexcept { return locked_.load(std::memory_order_acquire); }

  /// Unlocks and closes at most once, whichever of release() and the destructor
  /// arrives first.
  void unlock_and_close() noexcept {
    if (closed_.exchange(true, std::memory_order_acq_rel)) {
      return;
    }
#if defined(_WIN32)
    if (handle != INVALID_HANDLE_VALUE) {
      if (locked_.load(std::memory_order_acquire)) {
        OVERLAPPED overlapped{};
        UnlockFileEx(handle, 0, kWholeFileLow, kWholeFileHigh, &overlapped);
      }
      CloseHandle(handle);
      handle = INVALID_HANDLE_VALUE;
    }
#else
    if (descriptor >= 0) {
      if (locked_.load(std::memory_order_acquire)) {
        flock(descriptor, LOCK_UN);
      }
      ::close(descriptor);
      descriptor = -1;
    }
#endif
    locked_.store(false, std::memory_order_release);
  }

  std::string path;

#if defined(_WIN32)
  // The whole file, as a byte range: LockFileEx cannot express "to the end of
  // the file", and a range that starts at zero and runs to 2^64-1 covers every
  // file this process will ever be given.
  static constexpr DWORD kWholeFileLow = 0xFFFFFFFFUL;
  static constexpr DWORD kWholeFileHigh = 0xFFFFFFFFUL;

  HANDLE handle = INVALID_HANDLE_VALUE;

  enum class Attempt { Acquired, Busy, Failed };

  Attempt try_lock_once(unsigned long& failure) noexcept {
    OVERLAPPED overlapped{};
    if (LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, kWholeFileLow, kWholeFileHigh,
                   &overlapped) != 0) {
      locked_.store(true, std::memory_order_release);
      return Attempt::Acquired;
    }
    failure = static_cast<unsigned long>(GetLastError());
    if (failure == ERROR_LOCK_VIOLATION || failure == ERROR_SHARING_VIOLATION) {
      return Attempt::Busy;
    }
    return Attempt::Failed;
  }
#else
  int descriptor = -1;

  enum class Attempt { Acquired, Busy, Failed };

  Attempt try_lock_once(int& failure) noexcept {
    if (flock(descriptor, LOCK_EX | LOCK_NB) == 0) {
      locked_.store(true, std::memory_order_release);
      return Attempt::Acquired;
    }
    failure = errno;
    if (failure == EWOULDBLOCK || failure == EAGAIN || failure == EINTR) {
      return Attempt::Busy;
    }
    return Attempt::Failed;
  }
#endif

  std::atomic<bool> locked_{false};
  std::atomic<bool> closed_{false};
};

FileLock::~FileLock() = default;

FileLock::FileLock(FileLock&& other) noexcept : impl_(std::move(other.impl_)) {}

FileLock& FileLock::operator=(FileLock&& other) noexcept {
  if (this != &other) {
    // Assigning over a held lock releases it: the shared_ptr's last reference
    // runs the Impl destructor, which unlocks and closes exactly once.
    impl_ = std::move(other.impl_);
  }
  return *this;
}

Result<FileLock> FileLock::acquire(const std::string& path, const FileLockOptions& options) {
  if (path.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot lock " + quoted(path), "the path is empty");
  }

  auto impl = std::make_shared<Impl>(path);

#if defined(_WIN32)
  std::wstring wide;
  if (!to_wide(path, wide)) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot lock " + quoted(path), "the path is not valid UTF-8");
  }
  // Read and write sharing lets other processes open the lock file while this
  // one holds the region lock; withholding FILE_SHARE_DELETE keeps the name
  // itself from disappearing underneath a holder.
  impl->handle = CreateFileW(wide.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (impl->handle == INVALID_HANDLE_VALUE) {
    const unsigned long failure = static_cast<unsigned long>(GetLastError());
    return fs_error(ErrorCategory::Io, "lock.open", "cannot open the lock file " + quoted(path),
                    platform_error_text(failure));
  }
  unsigned long failure = 0;
#else
  impl->descriptor = ::open(path.c_str(), O_RDWR | O_CREAT, 0666);
  if (impl->descriptor < 0) {
    const int failure = errno;
    return fs_error(ErrorCategory::Io, "lock.open", "cannot open the lock file " + quoted(path),
                    platform_error_text(failure));
  }
  int failure = 0;
#endif

  const std::chrono::milliseconds budget = clamp_wait(options.max_wait_ms);
  const auto start = std::chrono::steady_clock::now();
  const auto deadline = start + budget;

  for (;;) {
    const Impl::Attempt attempt = impl->try_lock_once(failure);
    if (attempt == Impl::Attempt::Acquired) {
      FileLock lock;
      lock.impl_ = std::move(impl);
      return Result<FileLock>(std::move(lock));
    }
    if (attempt == Impl::Attempt::Failed) {
      return fs_error(ErrorCategory::Io, "lock.acquire", "cannot lock " + quoted(path),
                      platform_error_text(failure));
    }

    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
      std::string detail = "waited ";
      detail += std::to_string(waited);
      detail += " ms of a ";
      detail += std::to_string(budget.count());
      detail += " ms budget for the exclusive lock on ";
      detail += quoted(path);
      return fail(ErrorCategory::Locked, "csp.lock.timeout", std::move(detail));
    }

    // The wait is bounded twice over: by the deadline and by this step. A caller
    // that asks for a zero retry gap still yields instead of spinning.
    const std::size_t requested_step = options.retry_ms == 0 ? 1 : options.retry_ms;
    const std::size_t ceiling = static_cast<std::size_t>(kLongestWaitMs);
    std::chrono::milliseconds step(static_cast<std::int64_t>(requested_step > ceiling ? ceiling : requested_step));
    const std::chrono::milliseconds remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    if (step > remaining) {
      step = remaining;
    }
    if (step > std::chrono::milliseconds::zero()) {
      std::this_thread::sleep_for(step);
    }
  }
}

bool FileLock::held() const noexcept { return impl_ != nullptr && impl_->held(); }

const std::string& FileLock::path() const noexcept {
  static const std::string kNoPath;
  return impl_ != nullptr ? impl_->path : kNoPath;
}

void FileLock::release() noexcept {
  if (impl_ != nullptr) {
    impl_->unlock_and_close();
  }
}

Status write_file_durable(const std::string& path, std::string_view bytes) {
  if (path.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot write " + quoted(path), "the path is empty");
  }

#if defined(_WIN32)
  std::wstring wide_destination;
  if (!to_wide(path, wide_destination)) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot write " + quoted(path), "the path is not valid UTF-8");
  }
#else
  const std::string& wide_destination = path;
#endif

  std::string directory;
  std::string name;
  split_path(path, directory, name);
  if (name.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot write " + quoted(path),
                    "the path names a directory, not a file");
  }

#if defined(_WIN32)

  // The staging file lives in the destination's own directory, so the replace
  // below stays inside one volume and is therefore atomic. Staging in a system
  // temporary directory would make the final step a copy, not a rename.
  struct StagingFile {
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::wstring wide_path;
    bool committed = false;

    StagingFile() = default;
    StagingFile(const StagingFile&) = delete;
    StagingFile& operator=(const StagingFile&) = delete;
    ~StagingFile() {
      if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
      }
      if (!committed && !wide_path.empty()) {
        DeleteFileW(wide_path.c_str());
      }
    }
  };

  StagingFile staging;
  unsigned long failure = 0;
  for (int attempt = 0; attempt < kStagingAttempts; ++attempt) {
    const std::string candidate = directory + name + staging_token();
    std::wstring wide_candidate;
    if (!to_wide(candidate, wide_candidate)) {
      return fs_error(ErrorCategory::Invalid, "path", "cannot stage a write of " + quoted(path),
                      "the staging path is not valid UTF-8");
    }
    staging.handle = CreateFileW(wide_candidate.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (staging.handle != INVALID_HANDLE_VALUE) {
      staging.wide_path = std::move(wide_candidate);
      break;
    }
    failure = static_cast<unsigned long>(GetLastError());
    if (failure != ERROR_FILE_EXISTS && failure != ERROR_ALREADY_EXISTS) {
      return fs_error(ErrorCategory::Io, "staging_create", "cannot create a staging file for " + quoted(path),
                      platform_error_text(failure));
    }
    // That name was taken; the counter moved on, so the next candidate differs.
  }
  if (staging.handle == INVALID_HANDLE_VALUE) {
    return fs_error(ErrorCategory::Io, "staging_create",
                    "cannot create a unique staging file for " + quoted(path) + " in " +
                        std::to_string(kStagingAttempts) + " attempts",
                    platform_error_text(failure));
  }

  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const std::size_t remaining = bytes.size() - offset;
    const std::size_t chunk = remaining < kWriteChunk ? remaining : kWriteChunk;
    DWORD written = 0;
    if (WriteFile(staging.handle, bytes.data() + offset, static_cast<DWORD>(chunk), &written, nullptr) == 0) {
      return fs_error(ErrorCategory::Io, "write",
                      "cannot write byte " + std::to_string(offset) + " of " + std::to_string(bytes.size()) +
                          " to the staging file for " + quoted(path),
                      platform_error_text(static_cast<unsigned long>(GetLastError())));
    }
    if (written == 0) {
      return fs_error(ErrorCategory::Io, "write_stalled",
                      "a write to the staging file for " + quoted(path) + " reported success but stored no bytes, with " +
                          std::to_string(remaining) + " bytes still to write",
                      "the platform made no progress");
    }
    offset += static_cast<std::size_t>(written);
  }

  if (FlushFileBuffers(staging.handle) == 0) {
    return fs_error(ErrorCategory::Io, "flush", "cannot flush the staging file for " + quoted(path),
                    platform_error_text(static_cast<unsigned long>(GetLastError())));
  }
  if (CloseHandle(staging.handle) == 0) {
    const unsigned long code = static_cast<unsigned long>(GetLastError());
    staging.handle = INVALID_HANDLE_VALUE;
    return fs_error(ErrorCategory::Io, "close", "cannot close the staging file for " + quoted(path),
                    platform_error_text(code));
  }
  staging.handle = INVALID_HANDLE_VALUE;

  // MOVEFILE_WRITE_THROUGH makes this call return only once the name change has
  // been flushed, which is the Windows counterpart of the directory fsync the
  // POSIX branch performs after its rename; there is no separate "flush the
  // directory" call on Windows to make here.
  if (MoveFileExW(staging.wide_path.c_str(), wide_destination.c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    return fs_error(ErrorCategory::Io, "replace",
                    "cannot replace " + quoted(path) + " with its staging file " + quoted(show(staging.wide_path)),
                    platform_error_text(static_cast<unsigned long>(GetLastError())));
  }
  staging.committed = true;
  return success();

#else  // POSIX

  struct StagingFile {
    int descriptor = -1;
    std::string path;
    bool committed = false;

    StagingFile() = default;
    StagingFile(const StagingFile&) = delete;
    StagingFile& operator=(const StagingFile&) = delete;
    ~StagingFile() {
      if (descriptor >= 0) {
        ::close(descriptor);
      }
      if (!committed && !path.empty()) {
        unlink(path.c_str());
      }
    }
  };

  StagingFile staging;
  int failure = 0;
  for (int attempt = 0; attempt < kStagingAttempts; ++attempt) {
    staging.path = directory + name + staging_token();
    staging.descriptor = ::open(staging.path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (staging.descriptor >= 0) {
      break;
    }
    failure = errno;
    if (failure != EEXIST) {
      return fs_error(ErrorCategory::Io, "staging_create", "cannot create a staging file for " + quoted(path),
                      platform_error_text(failure));
    }
  }
  if (staging.descriptor < 0) {
    return fs_error(ErrorCategory::Io, "staging_create",
                    "cannot create a unique staging file for " + quoted(path) + " in " +
                        std::to_string(kStagingAttempts) + " attempts",
                    platform_error_text(failure));
  }

  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const std::size_t remaining = bytes.size() - offset;
    const std::size_t chunk = remaining < kWriteChunk ? remaining : kWriteChunk;
    const ssize_t written = ::write(staging.descriptor, bytes.data() + offset, chunk);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return fs_error(ErrorCategory::Io, "write",
                      "cannot write byte " + std::to_string(offset) + " of " + std::to_string(bytes.size()) +
                          " to the staging file for " + quoted(path),
                      platform_error_text(errno));
    }
    if (written == 0) {
      return fs_error(ErrorCategory::Io, "write_stalled",
                      "a write to the staging file for " + quoted(path) + " returned zero, with " +
                          std::to_string(remaining) + " bytes still to write",
                      "the platform made no progress");
    }
    offset += static_cast<std::size_t>(written);
  }

  if (fsync(staging.descriptor) != 0) {
    return fs_error(ErrorCategory::Io, "flush", "cannot flush the staging file for " + quoted(path),
                    platform_error_text(errno));
  }
  if (::close(staging.descriptor) != 0) {
    const int code = errno;
    staging.descriptor = -1;
    return fs_error(ErrorCategory::Io, "close", "cannot close the staging file for " + quoted(path),
                    platform_error_text(code));
  }
  staging.descriptor = -1;

  if (rename(staging.path.c_str(), wide_destination.c_str()) != 0) {
    return fs_error(ErrorCategory::Io, "replace",
                    "cannot replace " + quoted(path) + " with its staging file " + quoted(staging.path),
                    platform_error_text(errno));
  }
  staging.committed = true;

  // rename(2) has no write-through flag, so the directory entry itself is
  // flushed here. A filesystem that does not support fsync on a directory
  // reports EINVAL or ENOTSUP and is not an error; anything else is. This runs
  // after the replace has already happened, so a failure here is reported while
  // the destination keeps its new contents: the staging file no longer exists
  // and there is nothing left to roll back to.
  const std::string directory_path = directory.empty() ? std::string(".") : directory;
  UniqueFd directory_fd(::open(directory_path.c_str(), O_RDONLY));
  if (!directory_fd.valid()) {
    return fs_error(ErrorCategory::Io, "sync_directory",
                    "cannot open the directory " + quoted(directory_path) + " of " + quoted(path) +
                        " to flush the rename",
                    platform_error_text(errno));
  }
  if (fsync(directory_fd.get()) != 0) {
    const int code = errno;
    if (code != EINVAL && code != ENOTSUP) {
      return fs_error(ErrorCategory::Io, "sync_directory",
                      "cannot flush the directory " + quoted(directory_path) + " of " + quoted(path),
                      platform_error_text(code));
    }
  }
  return success();

#endif
}

Result<std::string> read_file_bounded(const std::string& path, std::size_t max_bytes) {
  if (path.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot read " + quoted(path), "the path is empty");
  }

#if defined(_WIN32)

  std::wstring wide;
  if (!to_wide(path, wide)) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot read " + quoted(path), "the path is not valid UTF-8");
  }
  UniqueHandle file(CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!file.valid()) {
    const unsigned long failure = static_cast<unsigned long>(GetLastError());
    if (is_missing_error(failure)) {
      return fs_error(ErrorCategory::NotFound, "not_found", "no such file " + quoted(path),
                      platform_error_text(failure));
    }
    return fs_error(ErrorCategory::Io, "open", "cannot open " + quoted(path) + " for reading",
                    platform_error_text(failure));
  }

  LARGE_INTEGER size{};
  if (GetFileSizeEx(file.get(), &size) == 0) {
    return fs_error(ErrorCategory::Io, "stat", "cannot size " + quoted(path),
                    platform_error_text(static_cast<unsigned long>(GetLastError())));
  }
  if (size.QuadPart < 0) {
    return fs_error(ErrorCategory::Io, "stat", "cannot size " + quoted(path), "the platform reported a negative size");
  }
  const unsigned long long declared = static_cast<unsigned long long>(size.QuadPart);
  if (declared > max_bytes) {
    return fs_error(ErrorCategory::BoundExceeded, "bound_exceeded",
                    "the file " + quoted(path) + " is " + std::to_string(declared) + " bytes, above the " +
                        std::to_string(max_bytes) + " byte bound",
                    "refused before allocating");
  }

  std::string contents;
  // Only as much as the file actually is: a small file must not cost the bound.
  contents.reserve(static_cast<std::size_t>(declared));
  std::vector<char> buffer(kReadChunk);
  for (;;) {
    DWORD read = 0;
    if (ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) == 0) {
      return fs_error(ErrorCategory::Io, "read", "cannot read " + quoted(path),
                      platform_error_text(static_cast<unsigned long>(GetLastError())));
    }
    if (read == 0) {
      break;
    }
    contents.append(buffer.data(), static_cast<std::size_t>(read));
    if (contents.size() > max_bytes) {
      // The file grew between the size check and the read; the bound still wins.
      return fs_error(ErrorCategory::BoundExceeded, "bound_exceeded",
                      "the file " + quoted(path) + " grew past the " + std::to_string(max_bytes) +
                          " byte bound while it was being read",
                      "refused after " + std::to_string(contents.size()) + " bytes");
    }
  }
  return contents;

#else

  UniqueFd file(::open(path.c_str(), O_RDONLY));
  if (!file.valid()) {
    const int failure = errno;
    if (failure == ENOENT || failure == ENOTDIR) {
      return fs_error(ErrorCategory::NotFound, "not_found", "no such file " + quoted(path),
                      platform_error_text(failure));
    }
    return fs_error(ErrorCategory::Io, "open", "cannot open " + quoted(path) + " for reading",
                    platform_error_text(failure));
  }

  struct stat info {};
  if (fstat(file.get(), &info) != 0) {
    return fs_error(ErrorCategory::Io, "stat", "cannot size " + quoted(path), platform_error_text(errno));
  }
  if (S_ISDIR(info.st_mode)) {
    return fs_error(ErrorCategory::Io, "read", "cannot read " + quoted(path), "the path is a directory");
  }
  const unsigned long long declared = static_cast<unsigned long long>(info.st_size);
  if (declared > max_bytes) {
    return fs_error(ErrorCategory::BoundExceeded, "bound_exceeded",
                    "the file " + quoted(path) + " is " + std::to_string(declared) + " bytes, above the " +
                        std::to_string(max_bytes) + " byte bound",
                    "refused before allocating");
  }

  std::string contents;
  contents.reserve(static_cast<std::size_t>(declared));
  std::vector<char> buffer(kReadChunk);
  for (;;) {
    const ssize_t read = ::read(file.get(), buffer.data(), buffer.size());
    if (read < 0) {
      if (errno == EINTR) {
        continue;
      }
      return fs_error(ErrorCategory::Io, "read", "cannot read " + quoted(path), platform_error_text(errno));
    }
    if (read == 0) {
      break;
    }
    contents.append(buffer.data(), static_cast<std::size_t>(read));
    if (contents.size() > max_bytes) {
      return fs_error(ErrorCategory::BoundExceeded, "bound_exceeded",
                      "the file " + quoted(path) + " grew past the " + std::to_string(max_bytes) +
                          " byte bound while it was being read",
                      "refused after " + std::to_string(contents.size()) + " bytes");
    }
  }
  return contents;

#endif
}

bool file_exists(const std::string& path) {
  if (path.empty()) {
    return false;
  }
#if defined(_WIN32)
  std::wstring wide;
  if (!to_wide(path, wide)) {
    return false;
  }
  return probe_attributes(wide, true).kind == EntryKind::File;
#else
  struct stat info {};
  if (stat(path.c_str(), &info) != 0) {
    return false;
  }
  return S_ISREG(info.st_mode) != 0;
#endif
}

bool directory_exists(const std::string& path) {
  if (path.empty()) {
    return false;
  }
#if defined(_WIN32)
  std::wstring wide;
  if (!to_wide(path, wide)) {
    return false;
  }
  return probe_attributes(wide, true).kind == EntryKind::Directory;
#else
  struct stat info {};
  if (stat(path.c_str(), &info) != 0) {
    return false;
  }
  return S_ISDIR(info.st_mode) != 0;
#endif
}

Status remove_file(const std::string& path) {
  if (path.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot remove " + quoted(path), "the path is empty");
  }
#if defined(_WIN32)
  std::wstring wide;
  if (!to_wide(path, wide)) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot remove " + quoted(path), "the path is not valid UTF-8");
  }
  if (DeleteFileW(wide.c_str()) != 0) {
    return success();
  }
  const unsigned long failure = static_cast<unsigned long>(GetLastError());
  if (is_missing_error(failure)) {
    return success();
  }
  return fs_error(ErrorCategory::Io, "remove", "cannot remove " + quoted(path), platform_error_text(failure));
#else
  if (unlink(path.c_str()) == 0) {
    return success();
  }
  const int failure = errno;
  if (failure == ENOENT || failure == ENOTDIR) {
    return success();
  }
  return fs_error(ErrorCategory::Io, "remove", "cannot remove " + quoted(path), platform_error_text(failure));
#endif
}

Status create_directories(const std::string& path) {
  if (path.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot create " + quoted(path), "the path is empty");
  }

#if defined(_WIN32)

  std::wstring wide;
  if (!to_wide(path, wide)) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot create " + quoted(path), "the path is not valid UTF-8");
  }
  if (wide.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot create " + quoted(path), "the path is empty");
  }

  // The common case is that it already exists, and that case must not depend on
  // the prefix walk agreeing with the platform about what a component is.
  const EntryAttributes existing = probe_attributes(wide, true);
  if (existing.kind == EntryKind::Directory) {
    return success();
  }
  if (existing.kind == EntryKind::File || existing.kind == EntryKind::Other) {
    return fs_error(ErrorCategory::Conflict, "conflict", "cannot create the directory " + quoted(path),
                    "an entry that is not a directory already exists at that name");
  }

  // Start after whatever prefix names a volume: "C:\" or "\\server\share\".
  std::size_t start = 1;
  if (wide.size() >= 2 && is_wide_separator(wide[0]) && is_wide_separator(wide[1])) {
    std::size_t position = 2;
    int components = 0;
    while (position < wide.size() && components < 2) {
      if (is_wide_separator(wide[position])) {
        ++components;
        while (position < wide.size() && is_wide_separator(wide[position])) {
          ++position;
        }
      } else {
        ++position;
      }
    }
    start = position;
  } else if (wide.size() >= 2 && wide[1] == L':') {
    start = (wide.size() >= 3 && is_wide_separator(wide[2])) ? 3 : 2;
  }

  for (std::size_t i = start; i < wide.size(); ++i) {
    if (is_wide_separator(wide[i]) && !is_wide_separator(wide[i - 1])) {
      const Status status = create_one_directory(wide.substr(0, i), path);
      if (!status) {
        return status;
      }
    }
  }
  return create_one_directory(wide, path);

#else

  // Trailing separators would otherwise produce a component that names nothing.
  std::size_t end = path.size();
  while (end > 1 && path[end - 1] == kSeparator) {
    --end;
  }
  const std::string target = path.substr(0, end);

  if (directory_exists(target)) {
    return success();
  }
  if (file_exists(target)) {
    return fs_error(ErrorCategory::Conflict, "conflict", "cannot create the directory " + quoted(path),
                    "an entry that is not a directory already exists at that name");
  }

  for (std::size_t i = 1; i < target.size(); ++i) {
    if (target[i] == kSeparator && target[i - 1] != kSeparator) {
      const Status status = create_one_directory(target.substr(0, i), path);
      if (!status) {
        return status;
      }
    }
  }
  return create_one_directory(target, path);

#endif
}

Status remove_directory_tree(const std::string& path) {
  if (path.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot remove " + quoted(path), "the path is empty");
  }
#if defined(_WIN32)
  std::wstring wide;
  if (!to_wide(path, wide)) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot remove " + quoted(path), "the path is not valid UTF-8");
  }
  if (wide.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot remove " + quoted(path), "the path is empty");
  }
  return remove_tree_wide(wide);
#else
  return remove_tree_path(path);
#endif
}

Result<std::vector<std::string>> list_directory(const std::string& path) {
  if (path.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot list " + quoted(path), "the path is empty");
  }

  std::vector<std::string> names;

#if defined(_WIN32)

  std::wstring wide;
  if (!to_wide(path, wide)) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot list " + quoted(path), "the path is not valid UTF-8");
  }
  if (wide.empty()) {
    return fs_error(ErrorCategory::Invalid, "path", "cannot list " + quoted(path), "the path is empty");
  }

  std::wstring pattern = wide;
  if (!is_wide_separator(pattern.back())) {
    pattern.push_back(L'\\');
  }
  pattern.push_back(L'*');

  WIN32_FIND_DATAW found{};
  HANDLE search = FindFirstFileW(pattern.c_str(), &found);
  if (search == INVALID_HANDLE_VALUE) {
    const unsigned long failure = static_cast<unsigned long>(GetLastError());
    if (is_missing_error(failure) || failure == ERROR_DIRECTORY) {
      return fs_error(ErrorCategory::NotFound, "not_found", "no such directory " + quoted(path),
                      platform_error_text(failure));
    }
    return fs_error(ErrorCategory::Io, "list", "cannot list " + quoted(path), platform_error_text(failure));
  }

  for (;;) {
    const std::wstring entry(found.cFileName);
    if (entry != L"." && entry != L"..") {
      std::string name;
      if (!to_utf8(entry, name)) {
        FindClose(search);
        return fs_error(ErrorCategory::Io, "name_encoding",
                        "cannot list " + quoted(path) + " because the entry " + quoted(show(entry)) +
                            " is not valid UTF-16",
                        "reported instead of substituted");
      }
      names.push_back(std::move(name));
    }
    if (FindNextFileW(search, &found) == 0) {
      const unsigned long failure = static_cast<unsigned long>(GetLastError());
      FindClose(search);
      if (failure != ERROR_NO_MORE_FILES) {
        return fs_error(ErrorCategory::Io, "list", "cannot list " + quoted(path), platform_error_text(failure));
      }
      break;
    }
  }

#else

  DIR* directory = opendir(path.c_str());
  if (directory == nullptr) {
    const int failure = errno;
    if (failure == ENOENT || failure == ENOTDIR) {
      return fs_error(ErrorCategory::NotFound, "not_found", "no such directory " + quoted(path),
                      platform_error_text(failure));
    }
    return fs_error(ErrorCategory::Io, "list", "cannot list " + quoted(path), platform_error_text(failure));
  }
  for (;;) {
    errno = 0;
    dirent* entry = readdir(directory);
    if (entry == nullptr) {
      break;
    }
    const std::string name(entry->d_name);
    if (name != "." && name != "..") {
      // Names are bytes on POSIX; passing them through unchanged is what makes
      // this the inverse of the path handling everywhere else in this file.
      names.push_back(name);
    }
  }
  const int read_error = errno;
  closedir(directory);
  if (read_error != 0) {
    return fs_error(ErrorCategory::Io, "list", "cannot list " + quoted(path), platform_error_text(read_error));
  }

#endif

  std::sort(names.begin(), names.end(), byte_less);
  return names;
}

}  // namespace csp::detail
