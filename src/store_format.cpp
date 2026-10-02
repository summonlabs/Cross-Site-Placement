// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "store_format.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "checked.hpp"
#include "crc32.hpp"
#include "sha256.hpp"

namespace csp::detail {
namespace {

// Returns an Error rather than a Status so that one helper serves every function
// below, whatever value type it returns on success.
Error malformed(const std::string& detail) {
  return fail(ErrorCategory::Malformed, "csp.store.malformed", detail);
}

/// Reads one line, leaving the rest after it. A file that ends without a newline is
/// malformed rather than implicitly terminated: a cut-off last line is exactly the shape
/// a torn write leaves behind, and reading it as a complete line would adopt it.
bool take_line(std::string_view& rest, std::string_view& line) {
  const std::size_t position = rest.find('\n');
  if (position == std::string_view::npos) {
    return false;
  }
  line = rest.substr(0, position);
  rest.remove_prefix(position + 1);
  return true;
}

void split_tokens(std::string_view line, std::vector<std::string_view>& tokens) {
  tokens.clear();
  std::size_t position = 0;
  while (position < line.size()) {
    while (position < line.size() && line[position] == ' ') {
      ++position;
    }
    if (position >= line.size()) {
      break;
    }
    const std::size_t start = position;
    while (position < line.size() && line[position] != ' ') {
      ++position;
    }
    tokens.push_back(line.substr(start, position - start));
  }
}

bool parse_hex_u32(std::string_view text, std::uint32_t& out) {
  if (text.size() != 8) {
    return false;
  }
  std::uint32_t value = 0;
  for (const char c : text) {
    value <<= 4U;
    if (c >= '0' && c <= '9') {
      value |= static_cast<std::uint32_t>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      value |= static_cast<std::uint32_t>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      value |= static_cast<std::uint32_t>(c - 'A' + 10);
    } else {
      return false;
    }
  }
  out = value;
  return true;
}

std::string lowercase_hex(std::uint32_t value) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(8);
  for (int shift = 28; shift >= 0; shift -= 4) {
    out.push_back(kHex[(value >> shift) & 0x0FU]);
  }
  return out;
}

}  // namespace

std::string record_file_name(const PlanId& plan) { return plan.value() + kRecordSuffix; }

Result<std::string> encode_manifest(const Manifest& manifest) {
  std::string body;
  body += kManifestMagic;
  body += " ";
  body += std::to_string(kStoreContainerVersion);
  body += "\n";
  body += "generation ";
  body += std::to_string(manifest.generation);
  body += "\n";
  body += "count ";
  body += std::to_string(manifest.records.size());
  body += "\n";
  for (const RecordEntry& entry : manifest.records) {
    body += "record ";
    body += entry.plan.value();
    body += " ";
    body += entry.digest.to_hex();
    body += " ";
    body += std::to_string(entry.bytes);
    body += "\n";
  }

  std::string text = body;
  text += "digest ";
  text += Digest::of(body).to_hex();
  text += "\n";
  return text;
}

Result<Manifest> decode_manifest(std::string_view text) {
  std::string_view rest = text;
  std::string_view line;
  std::vector<std::string_view> tokens;
  if (!take_line(rest, line)) {
    return malformed("the manifest has no first line");
  }
  split_tokens(line, tokens);
  if (tokens.size() != 2 || tokens[0] != kManifestMagic) {
    return malformed("the manifest does not begin with its magic and container version");
  }
  std::uint64_t version = 0;
  if (!parse_u64(tokens[1], version) || version != static_cast<std::uint64_t>(kStoreContainerVersion)) {
    return fail(ErrorCategory::Unsupported, "csp.store.container_version",
                "the store declares container version " + std::string(tokens[1]) +
                    ", which this build does not implement");
  }

  Manifest manifest;
  if (!take_line(rest, line)) {
    return malformed("the manifest has no generation line");
  }
  split_tokens(line, tokens);
  if (tokens.size() != 2 || tokens[0] != "generation") {
    return malformed("the manifest has no generation line");
  }
  if (!parse_u64(tokens[1], manifest.generation)) {
    return malformed("the manifest generation is not a decimal integer");
  }

  if (!take_line(rest, line)) {
    return malformed("the manifest has no record count line");
  }
  split_tokens(line, tokens);
  if (tokens.size() != 2 || tokens[0] != "count") {
    return malformed("the manifest has no record count line");
  }
  std::uint64_t count = 0;
  if (!parse_u64(tokens[1], count)) {
    return malformed("the manifest record count is not a decimal integer");
  }

  for (std::uint64_t index = 0; index < count; ++index) {
    if (!take_line(rest, line)) {
      return malformed("the manifest ends before its declared record count was read");
    }
    split_tokens(line, tokens);
    if (tokens.size() != 4 || tokens[0] != "record") {
      return malformed("a manifest record entry is not a record line");
    }
    RecordEntry entry;
    Result<PlanId> plan = PlanId::parse(tokens[1]);
    if (!plan) {
      return malformed("a manifest record entry names an identity this boundary does not accept");
    }
    entry.plan = plan.value();
    Result<Digest> digest = Digest::parse_hex(tokens[2]);
    if (!digest) {
      return malformed("a manifest record entry carries a digest that is not 64 hexadecimal characters");
    }
    entry.digest = digest.value();
    if (!parse_u64(tokens[3], entry.bytes)) {
      return malformed("a manifest record entry carries a length that is not a decimal integer");
    }
    manifest.records.push_back(std::move(entry));
  }

  // The digest line is the first thing left once the declared number of records has been
  // read, and it covers every byte before it. Both facts are checked rather than assumed:
  // a manifest with trailing material after its digest line is not the manifest this
  // build writes, and adopting it would silently accept a document from something else.
  const std::size_t consumed = static_cast<std::size_t>(text.size() - rest.size());
  if (rest.find("digest ") != 0 || rest.back() != '\n') {
    return malformed("the manifest does not end with exactly one digest line after its records");
  }
  const std::string_view covered = text.substr(0, consumed);
  const std::string_view digest_field = rest.substr(0, 71);
  if (digest_field.size() < 71 || digest_field.substr(0, 7) != "digest ") {
    return malformed("the manifest digest line is truncated");
  }
  Result<Digest> claimed = Digest::parse_hex(digest_field.substr(7, 64));
  if (!claimed) {
    return malformed("the manifest digest line does not carry 64 hexadecimal characters");
  }
  manifest.digest = claimed.value();
  if (Digest::of(covered) != manifest.digest) {
    return fail(ErrorCategory::Integrity, "csp.store.manifest_digest",
                "the manifest digest does not match its own contents; the store is not usable as it stands");
  }
  return manifest;
}

Result<std::string> encode_record(const PlanId& plan, Generation generation, std::string_view payload) {
  Sha256 hasher;
  hasher.update(payload);
  const std::string raw_digest = hasher.finish();

  std::string record;
  record += kRecordMagic;
  record += " ";
  record += std::to_string(kStoreContainerVersion);
  record += "\n";
  record += "plan ";
  record += plan.value();
  record += "\n";
  record += "generation ";
  record += std::to_string(generation.value());
  record += "\n";
  record += "length ";
  record += std::to_string(payload.size());
  record += "\n";
  record += "crc32 ";
  record += lowercase_hex(crc32(payload));
  record += "\n";
  record += "sha256 ";
  record += to_hex(raw_digest);
  record += "\n\n";
  record += payload;
  return record;
}

Result<RecordPayload> decode_record(std::string_view text) {
  std::string_view rest = text;
  std::string_view line;
  std::vector<std::string_view> tokens;
  if (!take_line(rest, line)) {
    return malformed("the record has no first line");
  }
  split_tokens(line, tokens);
  if (tokens.size() != 2 || tokens[0] != kRecordMagic) {
    return malformed("the record does not begin with its magic and container version");
  }
  std::uint64_t version = 0;
  if (!parse_u64(tokens[1], version) || version != static_cast<std::uint64_t>(kStoreContainerVersion)) {
    return fail(ErrorCategory::Unsupported, "csp.store.container_version",
                "the record declares a container version this build does not implement");
  }

  RecordPayload payload;
  if (!take_line(rest, line)) {
    return malformed("the record has no plan line");
  }
  split_tokens(line, tokens);
  if (tokens.size() != 2 || tokens[0] != "plan") {
    return malformed("the record has no plan line");
  }
  Result<PlanId> plan = PlanId::parse(tokens[1]);
  if (!plan) {
    return malformed("the record names an identity this boundary does not accept");
  }
  payload.plan = plan.value();

  if (!take_line(rest, line)) {
    return malformed("the record has no generation line");
  }
  split_tokens(line, tokens);
  std::uint64_t generation = 0;
  if (tokens.size() != 2 || tokens[0] != "generation" || !parse_u64(tokens[1], generation)) {
    return malformed("the record has no usable generation line");
  }
  payload.generation = Generation::from_value(generation);

  if (!take_line(rest, line)) {
    return malformed("the record has no length line");
  }
  split_tokens(line, tokens);
  std::uint64_t declared = 0;
  if (tokens.size() != 2 || tokens[0] != "length" || !parse_u64(tokens[1], declared)) {
    return malformed("the record has no usable length line");
  }

  if (!take_line(rest, line)) {
    return malformed("the record has no checksum line");
  }
  split_tokens(line, tokens);
  std::string_view checksum_token;
  if (tokens.size() != 2 || tokens[0] != "crc32" || tokens[1].size() != 8) {
    return malformed("the record has no usable checksum line");
  }
  checksum_token = tokens[1];

  if (!take_line(rest, line)) {
    return malformed("the record has no digest line");
  }
  split_tokens(line, tokens);
  if (tokens.size() != 2 || tokens[0] != "sha256") {
    return malformed("the record has no digest line");
  }
  Result<Digest> declared_digest = Digest::parse_hex(tokens[1]);
  if (!declared_digest) {
    return malformed("the record digest is not 64 hexadecimal characters");
  }

  if (!take_line(rest, line) || !line.empty()) {
    return malformed("the record header is not followed by an empty separator line");
  }

  if (declared != rest.size()) {
    return fail(ErrorCategory::Integrity, "csp.store.record_length",
                "the record declares " + std::to_string(declared) + " payload bytes and carries " +
                    std::to_string(rest.size()) +
                    "; a torn write is not a record, and this one is discarded rather than completed");
  }
  std::uint32_t expected_checksum = 0;
  if (!parse_hex_u32(checksum_token, expected_checksum) || crc32(rest) != expected_checksum) {
    return fail(ErrorCategory::Integrity, "csp.store.record_checksum",
                "the record payload does not match its checksum");
  }
  if (Digest::of(rest) != declared_digest.value()) {
    return fail(ErrorCategory::Integrity, "csp.store.record_digest",
                "the record payload does not match its digest");
  }
  payload.payload = std::string(rest);
  return payload;
}

}  // namespace csp::detail
