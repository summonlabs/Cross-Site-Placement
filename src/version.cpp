// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "cross_site_placement/version.hpp"

#include <string>

namespace csp {

const char* library_version() noexcept { return kVersionString; }

std::string version_banner() {
  std::string banner = "cross-site-placement ";
  banner += kVersionString;
  banner += " (document format ";
  banner += std::to_string(kDocumentFormatVersion);
  banner += ", store format ";
  banner += std::to_string(kStoreFormatVersion);
  banner += ")";
  return banner;
}

}  // namespace csp
