// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Three-valued logic and measured quantities.
//
// This boundary answers questions about the physical world using evidence that other
// authorities produced, and that evidence is routinely incomplete. The central rule of
// this header is that incompleteness has its own answer. A constraint is satisfied, or
// it is violated, or it cannot be decided. Collapsing the third case into either of the
// other two is the defect this type exists to prevent: read as satisfied it fabricates
// a placement, and read as violated it hides one.
//
// A default-constructed measurement is Unknown, never zero.

#ifndef CROSS_SITE_PLACEMENT_MEASUREMENT_HPP
#define CROSS_SITE_PLACEMENT_MEASUREMENT_HPP

#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

namespace csp {

/// Three-valued truth under Kleene logic. The enumerators are deliberately ordered so
/// that conjunction is minimum and disjunction is maximum, which makes the lattice
/// laws properties of the representation rather than of a hand-written table.
enum class Tri : std::uint8_t {
  Violated = 0,
  Indeterminate = 1,
  Satisfied = 2,
};

constexpr Tri tri_conjunction(Tri lhs, Tri rhs) noexcept { return lhs < rhs ? lhs : rhs; }
constexpr Tri tri_disjunction(Tri lhs, Tri rhs) noexcept { return lhs < rhs ? rhs : lhs; }
constexpr Tri tri_negation(Tri value) noexcept {
  return value == Tri::Satisfied ? Tri::Violated : (value == Tri::Violated ? Tri::Satisfied : Tri::Indeterminate);
}
constexpr bool tri_is_definite(Tri value) noexcept { return value != Tri::Indeterminate; }

const char* to_string(Tri value) noexcept;
std::optional<Tri> tri_from_string(std::string_view token) noexcept;

/// Why a quantity has no value. The four states are not decoration. Unsupported means
/// the authority was asked and said the quantity does not apply to this subject;
/// Unavailable means the authority was asked and could not answer; Unknown means
/// nothing was supplied at all. A caller that has to report why a placement was
/// refused needs to tell those apart, and a planner that treats any of them as zero
/// will place an obligation on a site with no capacity.
enum class MeasurementState : std::uint8_t {
  Unknown = 0,
  Known = 1,
  Unsupported = 2,
  Unavailable = 3,
};

const char* to_string(MeasurementState state) noexcept;
std::optional<MeasurementState> measurement_state_from_string(std::string_view token) noexcept;

/// A quantity as reported by the authority that owns it.
template <class T>
class Measurement {
 public:
  using State = MeasurementState;

  constexpr Measurement() noexcept : state_(MeasurementState::Unknown), value_() {}

  static constexpr Measurement known(T value) noexcept {
    Measurement measurement;
    measurement.state_ = MeasurementState::Known;
    measurement.value_ = std::move(value);
    return measurement;
  }
  static constexpr Measurement unknown() noexcept { return Measurement(); }
  static constexpr Measurement unsupported() noexcept {
    Measurement measurement;
    measurement.state_ = MeasurementState::Unsupported;
    return measurement;
  }
  static constexpr Measurement unavailable() noexcept {
    Measurement measurement;
    measurement.state_ = MeasurementState::Unavailable;
    return measurement;
  }

  constexpr MeasurementState state() const noexcept { return state_; }
  constexpr bool is_known() const noexcept { return state_ == MeasurementState::Known; }
  constexpr bool is_unknown() const noexcept { return state_ == MeasurementState::Unknown; }
  constexpr bool is_unsupported() const noexcept { return state_ == MeasurementState::Unsupported; }
  constexpr bool is_unavailable() const noexcept { return state_ == MeasurementState::Unavailable; }

  /// Precondition: is_known(). Calling this on a measurement without a value is a
  /// defect in this library rather than in caller input, so it does not throw: it
  /// returns the default-constructed value, and the test suite is what catches the
  /// defect. Every call site in this library checks is_known() first.
  constexpr const T& value() const noexcept { return value_; }

  /// The measurement as a truth value for the question "is this usable?".
  /// Unsupported and Unavailable are definite negatives; Unknown is not.
  constexpr Tri usability() const noexcept {
    return state_ == MeasurementState::Known
               ? Tri::Satisfied
               : (state_ == MeasurementState::Unknown ? Tri::Indeterminate : Tri::Violated);
  }

  friend constexpr bool operator==(const Measurement& lhs, const Measurement& rhs) noexcept {
    if (lhs.state_ != rhs.state_) {
      return false;
    }
    return lhs.state_ != MeasurementState::Known || lhs.value_ == rhs.value_;
  }
  friend constexpr bool operator!=(const Measurement& lhs, const Measurement& rhs) noexcept {
    return !(lhs == rhs);
  }

 private:
  MeasurementState state_;
  T value_{};
};

}  // namespace csp

#endif  // CROSS_SITE_PLACEMENT_MEASUREMENT_HPP
