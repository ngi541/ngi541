/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "common/corpus.h"
#include "common/prng.h"
#include "common/test_util.h"
#include "reference/reference.h"

#include <ngi541/crypto.h>
#include <ngi541/engine.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define NGI541_DIFF_SHA2_RANDOM_CASES 2048U
#define NGI541_DIFF_SHA2_MAX_MESSAGE 65536U

#define NGI541_DIFF_SHA224_DIGEST_LEN 28U
#define NGI541_DIFF_SHA256_DIGEST_LEN 32U

#define NGI541_DIFF_BOUNDARY_CASE_BASE \
  UINT64_C (0x8000000000000000)


static const size_t
ngi541_diff_sha2_boundaries[] =
{
  0,
  1,

  55,
  56,
  57,

  63,
  64,
  65,

  119,
  120,
  121,

  127,
  128,
  129,

  255,
  256,
  257,

  4095,
  4096,
  4097,

  65535,
  65536,
};


static size_t
ngi541_diff_sha2_random_message_length (
  ngi541_diff_prng_t *prng)
{
  uint64_t bucket;


  bucket =
    ngi541_diff_prng_bounded (
      prng,
      100);


  /*
   * Most cases intentionally stay around short and
   * packet-sized messages while still maintaining
   * coverage of larger multi-block inputs.
   */
  if (bucket < 70)
    {
      return
        (size_t)
        ngi541_diff_prng_bounded (
          prng,
          257);
    }


  if (bucket < 95)
    {
      return
        257U +
        (size_t)
        ngi541_diff_prng_bounded (
          prng,
          3840);
    }


  return
    4097U +
    (size_t)
    ngi541_diff_prng_bounded (
      prng,
      61440);
}


static int
ngi541_diff_sha2_parameters (
  unsigned int digest_bits,
  ngi541_hash_algorithm_t *algorithm,
  size_t *digest_len)
{
  if (algorithm == NULL ||
      digest_len == NULL)
    return 1;


  switch (digest_bits)
    {
    case 224:
      *algorithm =
        NGI541_HASH_SHA2_224;

      *digest_len =
        NGI541_DIFF_SHA224_DIGEST_LEN;

      return 0;


    case 256:
      *algorithm =
        NGI541_HASH_SHA2_256;

      *digest_len =
        NGI541_DIFF_SHA256_DIGEST_LEN;

      return 0;


    default:
      return 1;
    }
}


static int
ngi541_diff_sha2_report_mismatch (
  unsigned int digest_bits,
  uint64_t case_index,
  uint64_t case_seed,
  size_t message_len,
  const uint8_t *expected,
  const uint8_t *actual,
  size_t digest_len)
{
  size_t offset;


  offset =
    ngi541_diff_first_mismatch (
      expected,
      actual,
      digest_len);


  fprintf (
    stderr,
    "SHA-%u differential mismatch\n"
    "case_index:   %" PRIu64 "\n"
    "base_seed:    0x%016" PRIx64 "\n"
    "case_seed:    0x%016" PRIx64 "\n"
    "message_len:  %zu\n",
    digest_bits,
    case_index,
    (uint64_t) NGI541_DIFF_BASE_SEED,
    case_seed,
    message_len);


  if (offset < digest_len)
    {
      fprintf (
        stderr,
        "offset:       %zu\n"
        "expected:     %02x\n"
        "actual:       %02x\n",
        offset,
        (unsigned int) expected[offset],
        (unsigned int) actual[offset]);
    }


  return 1;
}


static int
ngi541_diff_sha2_run_case (
  unsigned int digest_bits,
  uint64_t case_index,
  uint64_t case_seed,
  size_t message_len,
  uint8_t *message)
{
  ngi541_diff_prng_t prng;

  ngi541_hash_algorithm_t algorithm;
  ngi541_hash_request_t request;

  ngi541_status_t status;

  uint8_t reference_digest[NGI541_DIFF_SHA256_DIGEST_LEN];
  uint8_t ngi541_digest[NGI541_DIFF_SHA256_DIGEST_LEN];

  size_t expected_digest_len;
  size_t reference_digest_len;


  if (ngi541_diff_sha2_parameters (
        digest_bits,
        &algorithm,
        &expected_digest_len) != 0)
    {
      fprintf (
        stderr,
        "Unsupported SHA differential variant: %u\n",
        digest_bits);

      return 1;
    }


  ngi541_diff_prng_init (
    &prng,
    case_seed);


  if (message_len != 0)
    {
      ngi541_diff_prng_fill (
        &prng,
        message,
        message_len);
    }


  memset (
    reference_digest,
    0,
    sizeof (reference_digest));

  memset (
    ngi541_digest,
    0,
    sizeof (ngi541_digest));


  /*
   * Independent OpenSSL EVP oracle.
   */
  reference_digest_len = 0;

  if (ngi541_diff_reference_sha2_compute (
        digest_bits,
        message_len != 0
          ? message
          : NULL,
        message_len,
        reference_digest,
        sizeof (reference_digest),
        &reference_digest_len) != 0)
    {
      fprintf (
        stderr,
        "OpenSSL SHA-%u failed: "
        "case=%" PRIu64
        " seed=0x%016" PRIx64
        " message_len=%zu\n",
        digest_bits,
        case_index,
        case_seed,
        message_len);

      return 1;
    }


  if (reference_digest_len !=
      expected_digest_len)
    {
      fprintf (
        stderr,
        "OpenSSL SHA-%u returned unexpected digest length: "
        "case=%" PRIu64
        " seed=0x%016" PRIx64
        " expected=%zu actual=%zu\n",
        digest_bits,
        case_index,
        case_seed,
        expected_digest_len,
        reference_digest_len);

      return 1;
    }


  /*
   * NGI541 IUT.
   *
   * Important: only the public NGI541 API is exercised.
   */
  memset (
    &request,
    0,
    sizeof (request));

  request.struct_size =
    sizeof (request);

  request.algorithm =
    algorithm;

  request.message =
    message_len != 0
      ? message
      : NULL;

  request.message_len =
    message_len;

  request.digest =
    ngi541_digest;

  request.digest_capacity =
    sizeof (ngi541_digest);


  status =
    ngi541_crypto_hash_compute (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "NGI541 SHA-%u failed: "
        "status=%d "
        "case=%" PRIu64
        " seed=0x%016" PRIx64
        " message_len=%zu\n",
        digest_bits,
        (int) status,
        case_index,
        case_seed,
        message_len);

      return 1;
    }


  if (memcmp (
        reference_digest,
        ngi541_digest,
        expected_digest_len) != 0)
    {
      return
        ngi541_diff_sha2_report_mismatch (
          digest_bits,
          case_index,
          case_seed,
          message_len,
          reference_digest,
          ngi541_digest,
          expected_digest_len);
    }


  return 0;
}


static int
ngi541_diff_sha2_run_boundaries (
  unsigned int digest_bits,
  uint8_t *message,
  uint64_t *case_count)
{
  size_t i;


  for (i = 0;
       i <
         sizeof (ngi541_diff_sha2_boundaries) /
         sizeof (ngi541_diff_sha2_boundaries[0]);
       i++)
    {
      uint64_t case_index;
      uint64_t case_seed;

      size_t message_len;


      case_index =
        NGI541_DIFF_BOUNDARY_CASE_BASE +
        (uint64_t) i;

      message_len =
        ngi541_diff_sha2_boundaries[i];


      case_seed =
        ngi541_diff_case_seed (
          NGI541_DIFF_BASE_SEED,
          NGI541_DIFF_FAMILY_SHA2,
          digest_bits,
          case_index);


      if (ngi541_diff_sha2_run_case (
            digest_bits,
            case_index,
            case_seed,
            message_len,
            message) != 0)
        return 1;


      (*case_count)++;
    }


  return 0;
}


static int
ngi541_diff_sha2_run_random (
  unsigned int digest_bits,
  uint8_t *message,
  uint64_t *case_count)
{
  uint64_t case_index;


  for (case_index = 0;
       case_index <
         NGI541_DIFF_SHA2_RANDOM_CASES;
       case_index++)
    {
      ngi541_diff_prng_t length_prng;

      uint64_t case_seed;
      size_t message_len;


      case_seed =
        ngi541_diff_case_seed (
          NGI541_DIFF_BASE_SEED,
          NGI541_DIFF_FAMILY_SHA2,
          digest_bits,
          case_index);


      ngi541_diff_prng_init (
        &length_prng,
        case_seed);


      message_len =
        ngi541_diff_sha2_random_message_length (
          &length_prng);


      if (ngi541_diff_sha2_run_case (
            digest_bits,
            case_index,
            case_seed,
            message_len,
            message) != 0)
        return 1;


      (*case_count)++;
    }


  return 0;
}


int
main (void)
{
  static const unsigned int
  variants[] =
  {
    224,
    256,
  };

  ngi541_status_t status;

  uint8_t *message;

  uint64_t randomized_cases;
  uint64_t boundary_cases;

  size_t variant_index;


  status =
    ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "NGI541 engine initialization failed: %d\n",
        (int) status);

      return 1;
    }


  message =
    malloc (
      NGI541_DIFF_SHA2_MAX_MESSAGE);

  if (message == NULL)
    {
      fprintf (
        stderr,
        "Unable to allocate SHA-2 differential message buffer\n");

      return 1;
    }


  randomized_cases = 0;
  boundary_cases = 0;


  for (variant_index = 0;
       variant_index <
         sizeof (variants) /
         sizeof (variants[0]);
       variant_index++)
    {
      unsigned int digest_bits;


      digest_bits =
        variants[variant_index];


      if (ngi541_diff_sha2_run_boundaries (
            digest_bits,
            message,
            &boundary_cases) != 0)
        {
          free (
            message);

          return 1;
        }


      if (ngi541_diff_sha2_run_random (
            digest_bits,
            message,
            &randomized_cases) != 0)
        {
          free (
            message);

          return 1;
        }
    }


  free (
    message);


  printf (
    "SHA-2 differential passed\n"
    "randomized_cases: %" PRIu64 "\n"
    "boundary_cases:   %" PRIu64 "\n"
    "total_cases:      %" PRIu64 "\n"
    "base_seed:        0x%016" PRIx64 "\n",
    randomized_cases,
    boundary_cases,
    randomized_cases + boundary_cases,
    (uint64_t) NGI541_DIFF_BASE_SEED);


  return 0;
}