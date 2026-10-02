// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Enumerations shared by the request, the plan, and the explanation.

#ifndef CROSS_SITE_PLACEMENT_CORE_HPP
#define CROSS_SITE_PLACEMENT_CORE_HPP

#include <cstdint>
#include <optional>
#include <string_view>

namespace csp {

/// Which set of placements of an obligation a rule is about. Primary placements carry
/// the service; recovery placements are the alternatives that a recovery objective
/// requires to exist.
enum class PlacementRole : std::uint8_t {
  Primary = 0,
  Recovery = 1,
};

const char* to_string(PlacementRole role) noexcept;
std::optional<PlacementRole> placement_role_from_string(std::string_view token) noexcept;

/// Which placements a separation rule constrains.
enum class SeparationGroup : std::uint8_t {
  /// Every pair of placements of the obligation, primary against primary, primary
  /// against recovery, and recovery against recovery.
  All = 0,
  /// Every pair of primary placements, and separately every pair of recovery
  /// placements. A primary and a recovery placement may share a domain.
  WithinRole = 1,
  /// Every primary-to-recovery pair. Primary placements may share with each other.
  AcrossRoles = 2,
};

const char* to_string(SeparationGroup group) noexcept;
std::optional<SeparationGroup> separation_group_from_string(std::string_view token) noexcept;

/// Which way round a latency requirement is measured.
///
/// A path is directed. The time from here to there is not the time from there to here,
/// and this boundary has no way to compute one from the other, so a requirement that
/// needs both must say so twice.
enum class LatencyDirection : std::uint8_t {
  /// Measured from the placement under consideration to the peer.
  FromPlacement = 0,
  /// Measured from the peer to the placement under consideration.
  ToPlacement = 1,
};

const char* to_string(LatencyDirection direction) noexcept;
std::optional<LatencyDirection> latency_direction_from_string(std::string_view token) noexcept;

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_CORE_HPP
