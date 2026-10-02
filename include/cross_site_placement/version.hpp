// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Version and format identity.
//
// Three version numbers are tracked separately on purpose. A library release can fix
// a defect without changing any byte on disk, and a format can be extended without
// the library losing the ability to read what it already wrote. Collapsing them into
// one number would make every upgrade look like a format break.

#ifndef CROSS_SITE_PLACEMENT_VERSION_HPP
#define CROSS_SITE_PLACEMENT_VERSION_HPP

#include <string>

namespace csp {

inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 1;
inline constexpr const char* kVersionString = "1.0.1";

/// Format of the textual documents this boundary reads and writes (requests,
/// evidence snapshots, policies, plans). A reader accepts exactly the versions it
/// knows and refuses the rest rather than guessing at unknown fields.
inline constexpr int kDocumentFormatVersion = 1;

/// Format of the durable plan store. Independent of the document version because the
/// store frames documents rather than being one.
inline constexpr int kStoreFormatVersion = 1;

/// The smallest and largest document format version this build can read. A document
/// outside the range is refused with ErrorCategory::Unsupported.
inline constexpr int kMinReadableDocumentVersion = 1;
inline constexpr int kMaxReadableDocumentVersion = 1;

/// "cross-site-placement 1.0.1"
const char* library_version() noexcept;

/// "cross-site-placement 1.0.1 (document format 1, store format 1)"
std::string version_banner();

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_VERSION_HPP
