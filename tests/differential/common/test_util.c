/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "test_util.h"


size_t
ngi541_diff_first_mismatch (
  const uint8_t *expected,
  const uint8_t *actual,
  size_t length)
{
  size_t index;

  for (index = 0;
       index < length;
       index++)
    {
      if (expected[index] !=
          actual[index])
        return index;
    }

  return length;
}