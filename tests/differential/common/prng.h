/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_TESTS_DIFFERENTIAL_PRNG_H
#define NGI541_TESTS_DIFFERENTIAL_PRNG_H

#include <stddef.h>
#include <stdint.h>


typedef struct
{
  uint64_t state;
} ngi541_diff_prng_t;


void ngi541_diff_prng_init (
  ngi541_diff_prng_t *prng,
  uint64_t seed);

uint64_t ngi541_diff_prng_next_u64 (
  ngi541_diff_prng_t *prng);

uint64_t ngi541_diff_prng_bounded (
  ngi541_diff_prng_t *prng,
  uint64_t bound);

void ngi541_diff_prng_fill (
  ngi541_diff_prng_t *prng,
  uint8_t *buffer,
  size_t length);


#endif