// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "cross_site_placement/core.hpp"

#include "cross_site_placement/measurement.hpp"

#include <array>

namespace csp {
namespace {

template <class Enum, std::size_t N>
std::optional<Enum> lookup(const std::array<std::pair<Enum, const char*>, N>& table, std::string_view token) {
  for (const auto& entry : table) {
    if (token == entry.second) {
      return entry.first;
    }
  }
  return std::nullopt;
}

constexpr std::array<std::pair<PlacementRole, const char*>, 2> kRoles{{
    {PlacementRole::Primary, "primary"},
    {PlacementRole::Recovery, "recovery"},
}};

constexpr std::array<std::pair<SeparationGroup, const char*>, 3> kSeparationGroups{{
    {SeparationGroup::All, "all"},
    {SeparationGroup::WithinRole, "within-role"},
    {SeparationGroup::AcrossRoles, "across-roles"},
}};

constexpr std::array<std::pair<LatencyDirection, const char*>, 2> kDirections{{
    {LatencyDirection::FromPlacement, "from-placement"},
    {LatencyDirection::ToPlacement, "to-placement"},
}};

constexpr std::array<std::pair<Tri, const char*>, 3> kTri{{
    {Tri::Violated, "violated"},
    {Tri::Indeterminate, "indeterminate"},
    {Tri::Satisfied, "satisfied"},
}};

constexpr std::array<std::pair<MeasurementState, const char*>, 4> kMeasurementStates{{
    {MeasurementState::Unknown, "unknown"},
    {MeasurementState::Known, "known"},
    {MeasurementState::Unsupported, "unsupported"},
    {MeasurementState::Unavailable, "unavailable"},
}};

}  // namespace

const char* to_string(PlacementRole role) noexcept {
  return role == PlacementRole::Recovery ? "recovery" : "primary";
}
const char* to_string(SeparationGroup group) noexcept {
  switch (group) {
    case SeparationGroup::WithinRole:
      return "within-role";
    case SeparationGroup::AcrossRoles:
      return "across-roles";
    case SeparationGroup::All:
    default:
      return "all";
  }
}
const char* to_string(LatencyDirection direction) noexcept {
  return direction == LatencyDirection::ToPlacement ? "to-placement" : "from-placement";
}

std::optional<PlacementRole> placement_role_from_string(std::string_view token) noexcept {
  return lookup(kRoles, token);
}
std::optional<SeparationGroup> separation_group_from_string(std::string_view token) noexcept {
  return lookup(kSeparationGroups, token);
}
std::optional<LatencyDirection> latency_direction_from_string(std::string_view token) noexcept {
  return lookup(kDirections, token);
}

const char* to_string(Tri value) noexcept {
  switch (value) {
    case Tri::Satisfied:
      return "satisfied";
    case Tri::Violated:
      return "violated";
    case Tri::Indeterminate:
    default:
      return "indeterminate";
  }
}

std::optional<Tri> tri_from_string(std::string_view token) noexcept { return lookup(kTri, token); }

const char* to_string(MeasurementState state) noexcept {
  switch (state) {
    case MeasurementState::Known:
      return "known";
    case MeasurementState::Unsupported:
      return "unsupported";
    case MeasurementState::Unavailable:
      return "unavailable";
    case MeasurementState::Unknown:
    default:
      return "unknown";
  }
}

std::optional<MeasurementState> measurement_state_from_string(std::string_view token) noexcept {
  return lookup(kMeasurementStates, token);
}

}  // namespace csp
