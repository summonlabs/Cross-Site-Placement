// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// FIPS 180-4 SHA-256: streaming, first-party, no allocation on the update path.
//
// The message is compressed block by block as it arrives, so the object only ever holds
// the 64-byte partial block and the running chain value. finish() appends the 0x80 byte,
// pads with zeros to the length field, appends the message length in bits as a 64-bit
// big-endian integer, and returns the 32 raw digest bytes.

#include "sha256.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "cross_site_placement/error.hpp"

namespace csp::detail {
namespace {

constexpr std::size_t kBlockBytes = 64;
constexpr std::size_t kDigestBytes = 32;
/// The padding byte and the length field must fit after the buffered bytes; the length
/// field occupies the final eight bytes of the final block.
constexpr std::size_t kLengthFieldBytes = 8;
constexpr std::size_t kMaxPaddingStart = kBlockBytes - kLengthFieldBytes;

constexpr std::array<std::uint32_t, 64> kRoundConstants{{
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u,
}};

constexpr std::array<std::uint32_t, 8> kInitialState{{
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
}};

constexpr std::uint32_t rotr(std::uint32_t value, unsigned shift) noexcept {
  return (value >> shift) | (value << (32u - shift));
}

constexpr int hex_value(char ch) noexcept {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  }
  if (ch >= 'A' && ch <= 'F') {
    return ch - 'A' + 10;
  }
  return -1;
}

}  // namespace

Sha256::Sha256() noexcept
    : state_(kInitialState), buffer_{}, buffered_(0), total_bytes_(0), finished_(false) {}

void Sha256::update(std::string_view bytes) noexcept { update(bytes.data(), bytes.size()); }

void Sha256::update(const void* data, std::size_t size) noexcept {
  if (finished_ || size == 0) {
    return;
  }
  const auto* input = static_cast<const std::uint8_t*>(data);
  total_bytes_ += size;
  std::size_t consumed = 0;
  if (buffered_ > 0) {
    const std::size_t missing = kBlockBytes - buffered_;
    const std::size_t taken = (size < missing) ? size : missing;
    for (std::size_t index = 0; index < taken; ++index) {
      buffer_[buffered_ + index] = input[index];
    }
    buffered_ += taken;
    consumed = taken;
    if (buffered_ == kBlockBytes) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }
  while (size - consumed >= kBlockBytes) {
    compress(input + consumed);
    consumed += kBlockBytes;
  }
  if (consumed < size) {
    const std::size_t remaining = size - consumed;
    for (std::size_t index = 0; index < remaining; ++index) {
      buffer_[index] = input[consumed + index];
    }
    buffered_ = remaining;
  }
}

std::string Sha256::finish() noexcept {
  if (!finished_) {
    const std::uint64_t bit_length = total_bytes_ * 8u;
    std::size_t index = buffered_;
    buffer_[index] = 0x80u;
    ++index;
    if (index > kMaxPaddingStart) {
      while (index < kBlockBytes) {
        buffer_[index] = 0u;
        ++index;
      }
      compress(buffer_.data());
      index = 0;
    }
    while (index < kMaxPaddingStart) {
      buffer_[index] = 0u;
      ++index;
    }
    for (std::size_t byte = 0; byte < kLengthFieldBytes; ++byte) {
      buffer_[kMaxPaddingStart + byte] =
          static_cast<std::uint8_t>((bit_length >> (56u - 8u * static_cast<unsigned>(byte))) & 0xFFu);
    }
    compress(buffer_.data());
    buffered_ = 0;
    finished_ = true;
  }
  std::string digest(kDigestBytes, '\0');
  for (std::size_t word = 0; word < state_.size(); ++word) {
    const std::uint32_t value = state_[word];
    digest[word * 4 + 0] = static_cast<char>((value >> 24u) & 0xFFu);
    digest[word * 4 + 1] = static_cast<char>((value >> 16u) & 0xFFu);
    digest[word * 4 + 2] = static_cast<char>((value >> 8u) & 0xFFu);
    digest[word * 4 + 3] = static_cast<char>(value & 0xFFu);
  }
  return digest;
}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::array<std::uint32_t, 64> schedule{};
  for (std::size_t index = 0; index < 16; ++index) {
    const std::size_t base = index * 4;
    schedule[index] = (static_cast<std::uint32_t>(block[base]) << 24u) |
                      (static_cast<std::uint32_t>(block[base + 1]) << 16u) |
                      (static_cast<std::uint32_t>(block[base + 2]) << 8u) |
                      static_cast<std::uint32_t>(block[base + 3]);
  }
  for (std::size_t index = 16; index < schedule.size(); ++index) {
    const std::uint32_t previous = schedule[index - 15];
    const std::uint32_t recent = schedule[index - 2];
    const std::uint32_t sigma0 = rotr(previous, 7) ^ rotr(previous, 18) ^ (previous >> 3u);
    const std::uint32_t sigma1 = rotr(recent, 17) ^ rotr(recent, 19) ^ (recent >> 10u);
    schedule[index] = schedule[index - 16] + sigma0 + schedule[index - 7] + sigma1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t index = 0; index < schedule.size(); ++index) {
    const std::uint32_t big_sigma1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t choose = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + big_sigma1 + choose + kRoundConstants[index] + schedule[index];
    const std::uint32_t big_sigma0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = big_sigma0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

std::string to_hex(std::string_view bytes) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const char ch : bytes) {
    const auto byte = static_cast<std::uint8_t>(ch);
    out.push_back(kDigits[byte >> 4u]);
    out.push_back(kDigits[byte & 0x0Fu]);
  }
  return out;
}

Result<std::string> from_hex(std::string_view hex) {
  if (hex.empty()) {
    return fail(ErrorCategory::Malformed, "csp.hex.empty", "hexadecimal input is empty");
  }
  if ((hex.size() % 2u) != 0u) {
    return fail(ErrorCategory::Malformed, "csp.hex.odd_length",
                "hexadecimal input has an odd number of characters: " + std::to_string(hex.size()));
  }
  std::string out;
  out.reserve(hex.size() / 2);
  for (std::size_t index = 0; index < hex.size(); index += 2) {
    const int high = hex_value(hex[index]);
    const int low = hex_value(hex[index + 1]);
    if (high < 0 || low < 0) {
      const std::size_t bad = (high < 0) ? index : index + 1;
      return fail(ErrorCategory::Malformed, "csp.hex.invalid",
                  "hexadecimal input has a non-hex character at offset " + std::to_string(bad));
    }
    out.push_back(static_cast<char>((high << 4) | low));
  }
  return out;
}

}  // namespace csp::detail
