// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The byte-level format of the durable store.
//
// The store is a directory holding a manifest and one record per published plan. Both
// are line-oriented text with an explicit length and an explicit digest, so a partial
// write is detectable at the byte level rather than inferred from a parse failure, and
// so a person debugging a store can read it without a tool.
//
// The manifest is what makes a commit visible. A record written without a manifest entry
// is a commit that did not happen, and recovery reports it as such instead of adopting
// it.

#ifndef CSP_SRC_STORE_FORMAT_HPP
#define CSP_SRC_STORE_FORMAT_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "cross_site_placement/error.hpp"
#include "cross_site_placement/strong_types.hpp"

namespace csp::detail {

inline constexpr const char* kManifestMagic = "CSPHEAD";
inline constexpr const char* kRecordMagic = "CSPREC";
inline constexpr const char* kManifestFileName = "HEAD";
inline constexpr const char* kRecordsDirectoryName = "records";
inline constexpr const char* kLockFileName = "store.lock";
inline constexpr const char* kRecordSuffix = ".plan";
inline constexpr const char* kStagingMarker = ".staging.";

/// Format version of the container. A store whose container version this build does not
/// implement is refused rather than guessed at.
inline constexpr int kStoreContainerVersion = 1;

struct RecordEntry {
  PlanId plan;
  /// SHA-256 of the whole record file, so a corrupted record is caught before it is
  /// parsed and before anything is concluded from it.
  Digest digest;
  std::uint64_t bytes = 0;
};

struct Manifest {
  std::uint64_t generation = 0;
  std::vector<RecordEntry> records;
  /// SHA-256 over the encoded manifest up to and including the newline before the digest
  /// line. A manifest whose digest does not match is refused, never truncated.
  Digest digest;
};

/// Encodes the manifest and computes its digest from the encoding, so a manifest value
/// and its encoded form always agree.
[[nodiscard]] Result<std::string> encode_manifest(const Manifest& manifest);

/// Decodes and verifies. Reports ErrorCategory::Integrity when the digest does not match
/// and ErrorCategory::Malformed when the framing does not parse.
[[nodiscard]] Result<Manifest> decode_manifest(std::string_view text);

/// The file name a plan's record lives under.
[[nodiscard]] std::string record_file_name(const PlanId& plan);

/// Encodes a record. The payload is the canonical plan document.
[[nodiscard]] Result<std::string> encode_record(const PlanId& plan, Generation generation,
                                                std::string_view payload);

struct RecordPayload {
  PlanId plan;
  Generation generation;
  std::string payload;
};

/// Decodes and verifies a record: framing, declared length, CRC-32, and SHA-256.
[[nodiscard]] Result<RecordPayload> decode_record(std::string_view text);

}  // namespace csp::detail

#endif  // CSP_SRC_STORE_FORMAT_HPP
