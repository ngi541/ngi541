/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_TESTS_DIFFERENTIAL_TEST_UTIL_H
#define NGI541_TESTS_DIFFERENTIAL_TEST_UTIL_H

#include <stddef.h>
#include <stdint.h>


size_t ngi541_diff_first_mismatch (
  const uint8_t *expected,
  const uint8_t *actual,
  size_t length);


#endif