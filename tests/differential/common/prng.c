/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "prng.h"


void
ngi541_diff_prng_init (
  ngi541_diff_prng_t *prng,
  uint64_t seed)
{
  prng->state = seed;
}


uint64_t
ngi541_diff_prng_next_u64 (
  ngi541_diff_prng_t *prng)
{
  uint64_t value;

  prng->state +=
    UINT64_C (0x9e3779b97f4a7c15);

  value = prng->state;

  value =
    (value ^ (value >> 30)) *
    UINT64_C (0xbf58476d1ce4e5b9);

  value =
    (value ^ (value >> 27)) *
    UINT64_C (0x94d049bb133111eb);

  return value ^ (value >> 31);
}


uint64_t
ngi541_diff_prng_bounded (
  ngi541_diff_prng_t *prng,
  uint64_t bound)
{
  uint64_t value;
  uint64_t threshold;

  if (bound == 0)
    return 0;

  /*
   * Rejection sampling avoids modulo bias while keeping generation
   * deterministic for a given PRNG state.
   */
  threshold =
    (UINT64_C (0) - bound) % bound;

  do
    {
      value =
        ngi541_diff_prng_next_u64 (
          prng);
    }
  while (value < threshold);

  return value % bound;
}


void
ngi541_diff_prng_fill (
  ngi541_diff_prng_t *prng,
  uint8_t *buffer,
  size_t length)
{
  uint64_t value;
  unsigned int available;

  value = 0;
  available = 0;

  while (length != 0)
    {
      if (available == 0)
        {
          value =
            ngi541_diff_prng_next_u64 (
              prng);

          available = 8;
        }

      *buffer++ =
        (uint8_t) value;

      value >>= 8;
      available--;
      length--;
    }
}