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


#define NGI541_DIFF_CBC_RANDOM_CASES 1024U
#define NGI541_DIFF_CBC_MAX_LENGTH 65536U


static const size_t ngi541_diff_cbc_boundary_lengths[] =
{
  0,
  16,
  32,
  48,
  64,
  80,
  128,
  256,
  512,
  1024,
  4096,
  16384,
  65536,
};


static size_t
ngi541_diff_cbc_random_length (
  ngi541_diff_prng_t *prng)
{
  uint64_t bucket;
  uint64_t blocks;

  bucket =
    ngi541_diff_prng_bounded (
      prng,
      100);

  /*
   * 70%: 0..256 bytes
   * 25%: 272..4096 bytes
   *  5%: 4112..65536 bytes
   *
   * All values remain AES block aligned.
   */
  if (bucket < 70)
    {
      blocks =
        ngi541_diff_prng_bounded (
          prng,
          17);
    }
  else if (bucket < 95)
    {
      blocks =
        17 +
        ngi541_diff_prng_bounded (
          prng,
          240);
    }
  else
    {
      blocks =
        257 +
        ngi541_diff_prng_bounded (
          prng,
          3840);
    }

  return (size_t) blocks * 16;
}


static int
ngi541_diff_cbc_report_mismatch (
  const char *operation,
  unsigned int key_bits,
  uint64_t case_index,
  uint64_t case_seed,
  size_t input_len,
  const uint8_t *expected,
  const uint8_t *actual)
{
  size_t offset;

  offset =
    ngi541_diff_first_mismatch (
      expected,
      actual,
      input_len);

  fprintf (
    stderr,
    "AES-CBC differential mismatch\n"
    "operation:   %s\n"
    "key_bits:    %u\n"
    "case_index:  %" PRIu64 "\n"
    "base_seed:   0x%016" PRIx64 "\n"
    "case_seed:   0x%016" PRIx64 "\n"
    "input_len:   %zu\n",
    operation,
    key_bits,
    case_index,
    (uint64_t) NGI541_DIFF_BASE_SEED,
    case_seed,
    input_len);

  if (offset < input_len)
    {
      fprintf (
        stderr,
        "offset:      %zu\n"
        "expected:    %02x\n"
        "actual:      %02x\n",
        offset,
        (unsigned int) expected[offset],
        (unsigned int) actual[offset]);
    }

  return 1;
}


static int
ngi541_diff_cbc_run_case (
  unsigned int key_bits,
  uint64_t case_index,
  uint64_t case_seed,
  size_t input_len,
  uint8_t *plaintext,
  uint8_t *reference_ciphertext,
  uint8_t *ngi541_ciphertext,
  uint8_t *reference_plaintext,
  uint8_t *ngi541_plaintext)
{
  ngi541_diff_prng_t prng;

  ngi541_cipher_request_t request;
  ngi541_status_t status;

  uint8_t key[32];
  uint8_t iv[16];

  size_t key_len;
  size_t reference_ciphertext_len;
  size_t reference_plaintext_len;


  key_len =
    (size_t) key_bits / 8U;

  ngi541_diff_prng_init (
    &prng,
    case_seed);

  ngi541_diff_prng_fill (
    &prng,
    key,
    key_len);

  ngi541_diff_prng_fill (
    &prng,
    iv,
    sizeof (iv));

  if (input_len != 0)
    {
      ngi541_diff_prng_fill (
        &prng,
        plaintext,
        input_len);
    }


  /*
   * Independent reference encryption.
   */
  reference_ciphertext_len = 0;

  if (ngi541_diff_reference_aes_cbc_encrypt (
        key,
        key_len,
        iv,
        plaintext,
        input_len,
        reference_ciphertext,
        NGI541_DIFF_CBC_MAX_LENGTH,
        &reference_ciphertext_len) != 0)
    {
      fprintf (
        stderr,
        "OpenSSL AES-CBC encrypt failed: "
        "key_bits=%u case=%" PRIu64
        " seed=0x%016" PRIx64
        " len=%zu\n",
        key_bits,
        case_index,
        case_seed,
        input_len);

      return 1;
    }

  if (reference_ciphertext_len !=
      input_len)
    {
      fprintf (
        stderr,
        "OpenSSL AES-CBC ciphertext length mismatch: "
        "expected=%zu actual=%zu\n",
        input_len,
        reference_ciphertext_len);

      return 1;
    }


  /*
   * NGI541 encryption through the public execution API.
   */
  request =
    (ngi541_cipher_request_t) {
      .struct_size =
        sizeof (ngi541_cipher_request_t),

      .algorithm =
        NGI541_CIPHER_AES_CBC,

      .key = key,
      .key_len = key_len,

      .iv = iv,
      .iv_len = sizeof (iv),

      .input =
        input_len != 0
          ? plaintext
          : NULL,

      .input_len =
        input_len,

      .output =
        input_len != 0
          ? ngi541_ciphertext
          : NULL,

      .output_capacity =
        input_len,
    };

  status =
    ngi541_crypto_cipher_encrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "NGI541 AES-CBC encrypt failed: "
        "status=%d key_bits=%u case=%" PRIu64
        " seed=0x%016" PRIx64
        " len=%zu\n",
        (int) status,
        key_bits,
        case_index,
        case_seed,
        input_len);

      return 1;
    }


  if (memcmp (
        reference_ciphertext,
        ngi541_ciphertext,
        input_len) != 0)
    {
      return ngi541_diff_cbc_report_mismatch (
        "encrypt",
        key_bits,
        case_index,
        case_seed,
        input_len,
        reference_ciphertext,
        ngi541_ciphertext);
    }


  /*
   * Both decrypt implementations consume the independently
   * generated reference ciphertext. This avoids relying on an
   * NGI541-produced ciphertext when validating NGI541 decrypt.
   */
  reference_plaintext_len = 0;

  if (ngi541_diff_reference_aes_cbc_decrypt (
        key,
        key_len,
        iv,
        reference_ciphertext,
        reference_ciphertext_len,
        reference_plaintext,
        NGI541_DIFF_CBC_MAX_LENGTH,
        &reference_plaintext_len) != 0)
    {
      fprintf (
        stderr,
        "OpenSSL AES-CBC decrypt failed: "
        "key_bits=%u case=%" PRIu64
        " seed=0x%016" PRIx64
        " len=%zu\n",
        key_bits,
        case_index,
        case_seed,
        input_len);

      return 1;
    }

  if (reference_plaintext_len !=
      input_len)
    return 1;


  request =
    (ngi541_cipher_request_t) {
      .struct_size =
        sizeof (ngi541_cipher_request_t),

      .algorithm =
        NGI541_CIPHER_AES_CBC,

      .key = key,
      .key_len = key_len,

      .iv = iv,
      .iv_len = sizeof (iv),

      .input =
        input_len != 0
          ? reference_ciphertext
          : NULL,

      .input_len =
        input_len,

      .output =
        input_len != 0
          ? ngi541_plaintext
          : NULL,

      .output_capacity =
        input_len,
    };

  status =
    ngi541_crypto_cipher_decrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "NGI541 AES-CBC decrypt failed: "
        "status=%d key_bits=%u case=%" PRIu64
        " seed=0x%016" PRIx64
        " len=%zu\n",
        (int) status,
        key_bits,
        case_index,
        case_seed,
        input_len);

      return 1;
    }


  if (memcmp (
        plaintext,
        reference_plaintext,
        input_len) != 0)
    {
      return ngi541_diff_cbc_report_mismatch (
        "reference-decrypt",
        key_bits,
        case_index,
        case_seed,
        input_len,
        plaintext,
        reference_plaintext);
    }


  if (memcmp (
        plaintext,
        ngi541_plaintext,
        input_len) != 0)
    {
      return ngi541_diff_cbc_report_mismatch (
        "decrypt",
        key_bits,
        case_index,
        case_seed,
        input_len,
        plaintext,
        ngi541_plaintext);
    }


  return 0;
}


int
main (void)
{
  static const unsigned int key_bits_list[] =
  {
    128,
    192,
    256,
  };

  const size_t boundary_count =
    sizeof (ngi541_diff_cbc_boundary_lengths) /
    sizeof (ngi541_diff_cbc_boundary_lengths[0]);

  uint8_t *plaintext;
  uint8_t *reference_ciphertext;
  uint8_t *ngi541_ciphertext;
  uint8_t *reference_plaintext;
  uint8_t *ngi541_plaintext;

  ngi541_diff_prng_t length_prng;

  ngi541_status_t status;

  uint64_t case_seed;
  uint64_t case_index;

  size_t key_index;
  size_t boundary_index;
  size_t input_len;

  unsigned int key_bits;


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


  plaintext =
    malloc (
      NGI541_DIFF_CBC_MAX_LENGTH);

  reference_ciphertext =
    malloc (
      NGI541_DIFF_CBC_MAX_LENGTH);

  ngi541_ciphertext =
    malloc (
      NGI541_DIFF_CBC_MAX_LENGTH);

  reference_plaintext =
    malloc (
      NGI541_DIFF_CBC_MAX_LENGTH);

  ngi541_plaintext =
    malloc (
      NGI541_DIFF_CBC_MAX_LENGTH);

  if (plaintext == NULL ||
      reference_ciphertext == NULL ||
      ngi541_ciphertext == NULL ||
      reference_plaintext == NULL ||
      ngi541_plaintext == NULL)
    {
      fprintf (
        stderr,
        "unable to allocate AES-CBC differential buffers\n");

      free (ngi541_plaintext);
      free (reference_plaintext);
      free (ngi541_ciphertext);
      free (reference_ciphertext);
      free (plaintext);

      return 1;
    }


  for (key_index = 0;
       key_index <
         sizeof (key_bits_list) /
         sizeof (key_bits_list[0]);
       key_index++)
    {
      key_bits =
        key_bits_list[key_index];


      /*
       * Permanent boundary corpus.
       *
       * Use a disjoint case-index range so boundary vectors never
       * overlap with randomized case identities.
       */
      for (boundary_index = 0;
           boundary_index < boundary_count;
           boundary_index++)
        {
          case_index =
            UINT64_C (0x8000000000000000) +
            boundary_index;

          case_seed =
            ngi541_diff_case_seed (
              NGI541_DIFF_BASE_SEED,
              NGI541_DIFF_FAMILY_AES_CBC,
              key_bits,
              case_index);

          input_len =
            ngi541_diff_cbc_boundary_lengths[
              boundary_index];

          if (ngi541_diff_cbc_run_case (
                key_bits,
                case_index,
                case_seed,
                input_len,
                plaintext,
                reference_ciphertext,
                ngi541_ciphertext,
                reference_plaintext,
                ngi541_plaintext) != 0)
            goto fail;
        }


      /*
       * Randomized corpus.
       */
      for (case_index = 0;
           case_index <
             NGI541_DIFF_CBC_RANDOM_CASES;
           case_index++)
        {
          case_seed =
            ngi541_diff_case_seed (
              NGI541_DIFF_BASE_SEED,
              NGI541_DIFF_FAMILY_AES_CBC,
              key_bits,
              case_index);

          /*
           * Derive length from the same case seed, but use an
           * independent local generator. The actual case data starts
           * again from case_seed inside run_case(), so adding/changing
           * length-generation logic does not shift key/IV/plaintext
           * generation.
           */
          ngi541_diff_prng_init (
            &length_prng,
            case_seed ^
            UINT64_C (0x4c454e4754483531));

          input_len =
            ngi541_diff_cbc_random_length (
              &length_prng);

          if (ngi541_diff_cbc_run_case (
                key_bits,
                case_index,
                case_seed,
                input_len,
                plaintext,
                reference_ciphertext,
                ngi541_ciphertext,
                reference_plaintext,
                ngi541_plaintext) != 0)
            goto fail;
        }
    }


  printf (
    "AES-CBC differential passed\n"
    "randomized_cases: %u\n"
    "boundary_cases: %zu\n"
    "total_cases: %zu\n"
    "base_seed: 0x%016" PRIx64 "\n",
    3U * NGI541_DIFF_CBC_RANDOM_CASES,
    3U * boundary_count,
    3U *
      ((size_t) NGI541_DIFF_CBC_RANDOM_CASES +
       boundary_count),
    (uint64_t) NGI541_DIFF_BASE_SEED);


  free (ngi541_plaintext);
  free (reference_plaintext);
  free (ngi541_ciphertext);
  free (reference_ciphertext);
  free (plaintext);

  return 0;


fail:
  free (ngi541_plaintext);
  free (reference_plaintext);
  free (ngi541_ciphertext);
  free (reference_ciphertext);
  free (plaintext);

  return 1;
}