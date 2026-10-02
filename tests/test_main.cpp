// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The test entry point. Cases register themselves before main runs, so adding a case
// never means editing this file.

#include "test_harness.hpp"

int main(int argc, char** argv) { return csp_test::run_all(argc, argv); }
