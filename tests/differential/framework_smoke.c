/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "common/corpus.h"
#include "common/prng.h"
#include "reference/openssl_ref.h"

#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>


int
main (void)
{
  static const uint64_t base_seed =
    NGI541_DIFF_BASE_SEED;

  ngi541_diff_prng_t prng_a;
  ngi541_diff_prng_t prng_b;
  ngi541_diff_prng_t prng_c;

  ngi541_diff_reference_info_t reference;

  uint8_t bytes_a[64];
  uint8_t bytes_b[64];
  uint8_t bytes_c[64];

  uint64_t seed_a;
  uint64_t seed_b;

  ngi541_status_t status;


  /*
   * Same case identity must always derive the same seed.
   */
  seed_a =
    ngi541_diff_case_seed (
      base_seed,
      NGI541_DIFF_FAMILY_AES_CBC,
      128,
      0);

  seed_b =
    ngi541_diff_case_seed (
      base_seed,
      NGI541_DIFF_FAMILY_AES_CBC,
      128,
      0);

  if (seed_a != seed_b)
    {
      fprintf (
        stderr,
        "differential case seed is not deterministic\n");

      return 1;
    }


  /*
   * A different case index must derive independent input data.
   */
  ngi541_diff_prng_init (
    &prng_a,
    seed_a);

  ngi541_diff_prng_init (
    &prng_b,
    seed_b);

  ngi541_diff_prng_fill (
    &prng_a,
    bytes_a,
    sizeof (bytes_a));

  ngi541_diff_prng_fill (
    &prng_b,
    bytes_b,
    sizeof (bytes_b));

  if (memcmp (
        bytes_a,
        bytes_b,
        sizeof (bytes_a)) != 0)
    {
      fprintf (
        stderr,
        "same differential seed generated different bytes\n");

      return 2;
    }


  seed_b =
    ngi541_diff_case_seed (
      base_seed,
      NGI541_DIFF_FAMILY_AES_CBC,
      128,
      1);

  ngi541_diff_prng_init (
    &prng_c,
    seed_b);

  ngi541_diff_prng_fill (
    &prng_c,
    bytes_c,
    sizeof (bytes_c));

  if (memcmp (
        bytes_a,
        bytes_c,
        sizeof (bytes_a)) == 0)
    {
      fprintf (
        stderr,
        "different differential cases generated identical data\n");

      return 3;
    }


  /*
   * Verify that the mandatory reference implementation is linked
   * and can report its identity.
   */
  if (ngi541_diff_openssl_reference_info (
        &reference) != 0)
    {
      fprintf (
        stderr,
        "OpenSSL differential reference unavailable\n");

      return 4;
    }

  if (reference.id !=
      NGI541_DIFF_REFERENCE_OPENSSL)
    return 5;

  if (reference.name == NULL ||
      reference.version == NULL)
    return 6;


  /*
   * Differential tests exercise the public NGI541 engine boundary,
   * never internal execution/provider APIs.
   */
  status =
    ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "NGI541 engine initialization failed: %d\n",
        (int) status);

      return 7;
    }


  printf (
    "Differential framework ready\n"
    "reference: %s\n"
    "version: %s\n"
    "base_seed: 0x%016llx\n",
    reference.name,
    reference.version,
    (unsigned long long) base_seed);

  return 0;
}