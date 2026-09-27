/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "corpus.h"


static uint64_t
ngi541_diff_mix64 (
  uint64_t value)
{
  value +=
    UINT64_C (0x9e3779b97f4a7c15);

  value =
    (value ^ (value >> 30)) *
    UINT64_C (0xbf58476d1ce4e5b9);

  value =
    (value ^ (value >> 27)) *
    UINT64_C (0x94d049bb133111eb);

  return value ^ (value >> 31);
}


uint64_t
ngi541_diff_case_seed (
  uint64_t base_seed,
  ngi541_diff_family_t family,
  uint32_t variant,
  uint64_t case_index)
{
  uint64_t value;

  value = base_seed;

  value ^=
    ((uint64_t) family << 56);

  value ^=
    ((uint64_t) variant << 32);

  value ^=
    case_index;

  return ngi541_diff_mix64 (
    value);
}