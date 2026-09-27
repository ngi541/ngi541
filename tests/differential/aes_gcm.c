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


#define NGI541_DIFF_GCM_RANDOM_CASES 1024U

#define NGI541_DIFF_GCM_MAX_PAYLOAD 65536U
#define NGI541_DIFF_GCM_MAX_AAD 8192U

#define NGI541_DIFF_GCM_IV_LEN 12U
#define NGI541_DIFF_GCM_TAG_LEN 16U


typedef struct
{
  size_t payload_len;
  size_t aad_len;
} ngi541_diff_gcm_boundary_t;


static const ngi541_diff_gcm_boundary_t
ngi541_diff_gcm_boundaries[] =
{
  { 0,     0 },
  { 0,     1 },
  { 0,     7 },
  { 0,     8 },
  { 0,     9 },
  { 0,    11 },
  { 0,    12 },
  { 0,    13 },

  { 1,     0 },
  { 15,    0 },
  { 16,    0 },
  { 17,    0 },

  { 1,     8 },
  { 2,     8 },
  { 15,    8 },
  { 16,    8 },
  { 17,    8 },
  { 18,    8 },
  { 34,    8 },
  { 50,    8 },

  { 1,    12 },
  { 15,   12 },
  { 16,   12 },
  { 17,   12 },

  { 31,   13 },
  { 32,   16 },
  { 33,   17 },

  { 63,   31 },
  { 64,   32 },
  { 65,   33 },

  { 255, 255 },

  { 4096, 1024 },

  { 65536, 8192 },
};


static size_t
ngi541_diff_gcm_random_payload_length (
  ngi541_diff_prng_t *prng)
{
  uint64_t bucket;

  bucket =
    ngi541_diff_prng_bounded (
      prng,
      100);

  if (bucket < 70)
    {
      return (size_t)
        ngi541_diff_prng_bounded (
          prng,
          257);
    }

  if (bucket < 95)
    {
      return 257U +
        (size_t)
        ngi541_diff_prng_bounded (
          prng,
          3840);
    }

  return 4097U +
    (size_t)
    ngi541_diff_prng_bounded (
      prng,
      61440);
}


static size_t
ngi541_diff_gcm_random_aad_length (
  ngi541_diff_prng_t *prng)
{
  uint64_t bucket;

  bucket =
    ngi541_diff_prng_bounded (
      prng,
      100);

  /*
   * Explicitly stress the optimized NGI541 AAD paths.
   */
  if (bucket < 10)
    return 8;

  if (bucket < 20)
    return 12;

  if (bucket < 75)
    {
      return (size_t)
        ngi541_diff_prng_bounded (
          prng,
          65);
    }

  if (bucket < 95)
    {
      return 65U +
        (size_t)
        ngi541_diff_prng_bounded (
          prng,
          960);
    }

  return 1025U +
    (size_t)
    ngi541_diff_prng_bounded (
      prng,
      7168);
}


static int
ngi541_diff_gcm_report_mismatch (
  const char *operation,
  unsigned int key_bits,
  uint64_t case_index,
  uint64_t case_seed,
  size_t payload_len,
  size_t aad_len,
  const uint8_t *expected,
  const uint8_t *actual,
  size_t compare_len)
{
  size_t offset;

  offset =
    ngi541_diff_first_mismatch (
      expected,
      actual,
      compare_len);

  fprintf (
    stderr,
    "AES-GCM differential mismatch\n"
    "operation:    %s\n"
    "key_bits:     %u\n"
    "case_index:   %" PRIu64 "\n"
    "base_seed:    0x%016" PRIx64 "\n"
    "case_seed:    0x%016" PRIx64 "\n"
    "payload_len:  %zu\n"
    "aad_len:      %zu\n",
    operation,
    key_bits,
    case_index,
    (uint64_t) NGI541_DIFF_BASE_SEED,
    case_seed,
    payload_len,
    aad_len);

  if (offset < compare_len)
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
ngi541_diff_gcm_run_case (
  unsigned int key_bits,
  uint64_t case_index,
  uint64_t case_seed,
  size_t payload_len,
  size_t aad_len,
  uint8_t *aad,
  uint8_t *plaintext,
  uint8_t *reference_ciphertext,
  uint8_t *ngi541_ciphertext,
  uint8_t *reference_plaintext,
  uint8_t *ngi541_plaintext,
  uint8_t *ngi541_bad_plaintext)
{
  ngi541_diff_prng_t prng;

  ngi541_aead_encrypt_request_t encrypt_request;
  ngi541_aead_decrypt_request_t decrypt_request;

  ngi541_diff_reference_result_t reference_result;
  ngi541_status_t status;

  uint8_t key[32];
  uint8_t iv[NGI541_DIFF_GCM_IV_LEN];

  uint8_t reference_tag[NGI541_DIFF_GCM_TAG_LEN];
  uint8_t ngi541_tag[NGI541_DIFF_GCM_TAG_LEN];
  uint8_t bad_tag[NGI541_DIFF_GCM_TAG_LEN];

  size_t key_len;
  size_t reference_ciphertext_len;
  size_t reference_plaintext_len;
  size_t reference_tag_len;

  size_t bad_tag_offset;
  unsigned int bad_tag_bit;


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

  if (aad_len != 0)
    {
      ngi541_diff_prng_fill (
        &prng,
        aad,
        aad_len);
    }

  if (payload_len != 0)
    {
      ngi541_diff_prng_fill (
        &prng,
        plaintext,
        payload_len);
    }


  /*
   * Independent OpenSSL encryption.
   */
  reference_ciphertext_len = 0;
  reference_tag_len = 0;

  if (ngi541_diff_reference_aes_gcm_encrypt (
        key,
        key_len,
        iv,
        sizeof (iv),
        aad_len != 0 ? aad : NULL,
        aad_len,
        payload_len != 0 ? plaintext : NULL,
        payload_len,
        payload_len != 0
          ? reference_ciphertext
          : NULL,
        payload_len,
        &reference_ciphertext_len,
        reference_tag,
        sizeof (reference_tag),
        &reference_tag_len) != 0)
    {
      fprintf (
        stderr,
        "OpenSSL AES-GCM encrypt failed: "
        "key_bits=%u case=%" PRIu64
        " seed=0x%016" PRIx64
        " payload=%zu aad=%zu\n",
        key_bits,
        case_index,
        case_seed,
        payload_len,
        aad_len);

      return 1;
    }


  if (reference_ciphertext_len !=
        payload_len ||
      reference_tag_len !=
        NGI541_DIFF_GCM_TAG_LEN)
    {
      fprintf (
        stderr,
        "OpenSSL AES-GCM output length mismatch\n");

      return 1;
    }


  /*
   * NGI541 encryption through the public API.
   */
  encrypt_request =
    (ngi541_aead_encrypt_request_t) {
      .struct_size =
        sizeof (ngi541_aead_encrypt_request_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = key,
      .key_len = key_len,

      .iv = iv,
      .iv_len = sizeof (iv),

      .aad =
        aad_len != 0
          ? aad
          : NULL,

      .aad_len =
        aad_len,

      .plaintext =
        payload_len != 0
          ? plaintext
          : NULL,

      .plaintext_len =
        payload_len,

      .ciphertext =
        payload_len != 0
          ? ngi541_ciphertext
          : NULL,

      .ciphertext_capacity =
        payload_len,

      .tag =
        ngi541_tag,

      .tag_len =
        sizeof (ngi541_tag),
    };


  status =
    ngi541_crypto_aead_encrypt (
      &encrypt_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "NGI541 AES-GCM encrypt failed: "
        "status=%d key_bits=%u case=%" PRIu64
        " seed=0x%016" PRIx64
        " payload=%zu aad=%zu\n",
        (int) status,
        key_bits,
        case_index,
        case_seed,
        payload_len,
        aad_len);

      return 1;
    }


  if (memcmp (
        reference_ciphertext,
        ngi541_ciphertext,
        payload_len) != 0)
    {
      return ngi541_diff_gcm_report_mismatch (
        "encrypt-ciphertext",
        key_bits,
        case_index,
        case_seed,
        payload_len,
        aad_len,
        reference_ciphertext,
        ngi541_ciphertext,
        payload_len);
    }


  if (memcmp (
        reference_tag,
        ngi541_tag,
        sizeof (reference_tag)) != 0)
    {
      return ngi541_diff_gcm_report_mismatch (
        "encrypt-tag",
        key_bits,
        case_index,
        case_seed,
        payload_len,
        aad_len,
        reference_tag,
        ngi541_tag,
        sizeof (reference_tag));
    }

    /*
    * Diagnostic: zero bytes immediately following the valid
    * ciphertext. These bytes are outside ciphertext_len and
    * must have no influence on AES-GCM authentication.
    */
    if (payload_len <
        NGI541_DIFF_GCM_MAX_PAYLOAD)
    {
        size_t tail_len =
        NGI541_DIFF_GCM_MAX_PAYLOAD -
        payload_len;

        if (tail_len > 16)
        tail_len = 16;

        memset (
        reference_ciphertext +
            payload_len,
        0,
        tail_len);
    }

  /*
   * Positive reference decrypt.
   */
  reference_plaintext_len = 0;

  reference_result =
    ngi541_diff_reference_aes_gcm_decrypt (
      key,
      key_len,
      iv,
      sizeof (iv),
      aad_len != 0 ? aad : NULL,
      aad_len,
      payload_len != 0
        ? reference_ciphertext
        : NULL,
      payload_len,
      reference_tag,
      sizeof (reference_tag),
      payload_len != 0
        ? reference_plaintext
        : NULL,
      payload_len,
      &reference_plaintext_len);


  if (reference_result !=
        NGI541_DIFF_REFERENCE_RESULT_OK ||
      reference_plaintext_len !=
        payload_len)
    {
      fprintf (
        stderr,
        "OpenSSL AES-GCM valid decrypt failed\n");

      return 1;
    }


  if (memcmp (
        plaintext,
        reference_plaintext,
        payload_len) != 0)
    {
      return ngi541_diff_gcm_report_mismatch (
        "reference-decrypt",
        key_bits,
        case_index,
        case_seed,
        payload_len,
        aad_len,
        plaintext,
        reference_plaintext,
        payload_len);
    }


  /*
   * NGI541 positive decrypt consumes the independent OpenSSL
   * ciphertext and authentication tag.
   */
  decrypt_request =
    (ngi541_aead_decrypt_request_t) {
      .struct_size =
        sizeof (ngi541_aead_decrypt_request_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = key,
      .key_len = key_len,

      .iv = iv,
      .iv_len = sizeof (iv),

      .aad =
        aad_len != 0
          ? aad
          : NULL,

      .aad_len =
        aad_len,

      .ciphertext =
        payload_len != 0
          ? reference_ciphertext
          : NULL,

      .ciphertext_len =
        payload_len,

      .tag =
        reference_tag,

      .tag_len =
        sizeof (reference_tag),

      .plaintext =
        payload_len != 0
          ? ngi541_plaintext
          : NULL,

      .plaintext_capacity =
        payload_len,
    };


  status =
    ngi541_crypto_aead_decrypt (
      &decrypt_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "NGI541 AES-GCM valid decrypt failed: "
        "status=%d key_bits=%u case=%" PRIu64
        " seed=0x%016" PRIx64
        " payload=%zu aad=%zu\n",
        (int) status,
        key_bits,
        case_index,
        case_seed,
        payload_len,
        aad_len);

      return 1;
    }


  if (memcmp (
        plaintext,
        ngi541_plaintext,
        payload_len) != 0)
    {
      return ngi541_diff_gcm_report_mismatch (
        "decrypt",
        key_bits,
        case_index,
        case_seed,
        payload_len,
        aad_len,
        plaintext,
        ngi541_plaintext,
        payload_len);
    }


  /*
   * Deterministically corrupt exactly one tag bit.
   */
  memcpy (
    bad_tag,
    reference_tag,
    sizeof (bad_tag));

  bad_tag_offset =
    (size_t)
    (case_seed %
     NGI541_DIFF_GCM_TAG_LEN);

  bad_tag_bit =
    (unsigned int)
    ((case_seed >> 8) & 7U);

  bad_tag[bad_tag_offset] ^=
    (uint8_t)
    (1U << bad_tag_bit);


  /*
   * First establish that the independent reference rejects
   * exactly the same corrupted authentication input.
   */
  reference_plaintext_len = 0;

  reference_result =
    ngi541_diff_reference_aes_gcm_decrypt (
      key,
      key_len,
      iv,
      sizeof (iv),
      aad_len != 0 ? aad : NULL,
      aad_len,
      payload_len != 0
        ? reference_ciphertext
        : NULL,
      payload_len,
      bad_tag,
      sizeof (bad_tag),
      payload_len != 0
        ? reference_plaintext
        : NULL,
      payload_len,
      &reference_plaintext_len);


  if (reference_result !=
      NGI541_DIFF_REFERENCE_RESULT_AUTH_FAILED)
    {
      fprintf (
        stderr,
        "OpenSSL AES-GCM accepted corrupted tag: "
        "key_bits=%u case=%" PRIu64
        " seed=0x%016" PRIx64 "\n",
        key_bits,
        case_index,
        case_seed);

      return 1;
    }


  /*
   * NGI541 must reject the corrupted tag and scrub any plaintext
   * produced before authentication completed.
   */
  if (payload_len != 0)
    {
      memset (
        ngi541_bad_plaintext,
        0xa5,
        payload_len);
    }


  decrypt_request.tag =
    bad_tag;

  decrypt_request.plaintext =
    payload_len != 0
      ? ngi541_bad_plaintext
      : NULL;


  status =
    ngi541_crypto_aead_decrypt (
      &decrypt_request);

  if (status != NGI541_STATUS_AUTH_FAILED)
    {
      fprintf (
        stderr,
        "NGI541 AES-GCM corrupted-tag result mismatch: "
        "status=%d key_bits=%u case=%" PRIu64
        " seed=0x%016" PRIx64 "\n",
        (int) status,
        key_bits,
        case_index,
        case_seed);

      return 1;
    }


  if (payload_len != 0 &&
      !ngi541_diff_buffer_is_zero (
        ngi541_bad_plaintext,
        payload_len))
    {
      fprintf (
        stderr,
        "NGI541 AES-GCM authentication failure "
        "did not scrub plaintext: "
        "key_bits=%u case=%" PRIu64
        " seed=0x%016" PRIx64
        " payload=%zu aad=%zu\n",
        key_bits,
        case_index,
        case_seed,
        payload_len,
        aad_len);

      return 1;
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
    sizeof (ngi541_diff_gcm_boundaries) /
    sizeof (ngi541_diff_gcm_boundaries[0]);

  uint8_t *aad;
  uint8_t *plaintext;
  uint8_t *reference_ciphertext;
  uint8_t *ngi541_ciphertext;
  uint8_t *reference_plaintext;
  uint8_t *ngi541_plaintext;
  uint8_t *ngi541_bad_plaintext;

  ngi541_diff_prng_t payload_length_prng;
  ngi541_diff_prng_t aad_length_prng;

  ngi541_status_t status;

  uint64_t case_index;
  uint64_t case_seed;

  size_t key_index;
  size_t boundary_index;

  size_t payload_len;
  size_t aad_len;

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


  aad =
    malloc (
      NGI541_DIFF_GCM_MAX_AAD);

  plaintext =
    malloc (
      NGI541_DIFF_GCM_MAX_PAYLOAD);

  reference_ciphertext =
    malloc (
      NGI541_DIFF_GCM_MAX_PAYLOAD);

  ngi541_ciphertext =
    malloc (
      NGI541_DIFF_GCM_MAX_PAYLOAD);

  reference_plaintext =
    malloc (
      NGI541_DIFF_GCM_MAX_PAYLOAD);

  ngi541_plaintext =
    malloc (
      NGI541_DIFF_GCM_MAX_PAYLOAD);

  ngi541_bad_plaintext =
    malloc (
      NGI541_DIFF_GCM_MAX_PAYLOAD);


  if (aad == NULL ||
      plaintext == NULL ||
      reference_ciphertext == NULL ||
      ngi541_ciphertext == NULL ||
      reference_plaintext == NULL ||
      ngi541_plaintext == NULL ||
      ngi541_bad_plaintext == NULL)
    {
      fprintf (
        stderr,
        "unable to allocate AES-GCM differential buffers\n");

      goto allocation_fail;
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
              NGI541_DIFF_FAMILY_AES_GCM,
              key_bits,
              case_index);

          payload_len =
            ngi541_diff_gcm_boundaries[
              boundary_index].payload_len;

          aad_len =
            ngi541_diff_gcm_boundaries[
              boundary_index].aad_len;


          if (ngi541_diff_gcm_run_case (
                key_bits,
                case_index,
                case_seed,
                payload_len,
                aad_len,
                aad,
                plaintext,
                reference_ciphertext,
                ngi541_ciphertext,
                reference_plaintext,
                ngi541_plaintext,
                ngi541_bad_plaintext) != 0)
            goto fail;
        }


      /*
       * Randomized corpus.
       */
      for (case_index = 0;
           case_index <
             NGI541_DIFF_GCM_RANDOM_CASES;
           case_index++)
        {
          case_seed =
            ngi541_diff_case_seed (
              NGI541_DIFF_BASE_SEED,
              NGI541_DIFF_FAMILY_AES_GCM,
              key_bits,
              case_index);


          ngi541_diff_prng_init (
            &payload_length_prng,
            case_seed ^
            UINT64_C (0x5041594c4f414435));

          payload_len =
            ngi541_diff_gcm_random_payload_length (
              &payload_length_prng);


          ngi541_diff_prng_init (
            &aad_length_prng,
            case_seed ^
            UINT64_C (0x4141444c454e3531));

          aad_len =
            ngi541_diff_gcm_random_aad_length (
              &aad_length_prng);


          if (ngi541_diff_gcm_run_case (
                key_bits,
                case_index,
                case_seed,
                payload_len,
                aad_len,
                aad,
                plaintext,
                reference_ciphertext,
                ngi541_ciphertext,
                reference_plaintext,
                ngi541_plaintext,
                ngi541_bad_plaintext) != 0)
            goto fail;
        }
    }


  printf (
    "AES-GCM differential passed\n"
    "randomized_cases: %u\n"
    "boundary_cases: %zu\n"
    "total_cases: %zu\n"
    "bad_tag_cases: %zu\n"
    "base_seed: 0x%016" PRIx64 "\n",
    3U * NGI541_DIFF_GCM_RANDOM_CASES,
    3U * boundary_count,
    3U *
      ((size_t) NGI541_DIFF_GCM_RANDOM_CASES +
       boundary_count),
    3U *
      ((size_t) NGI541_DIFF_GCM_RANDOM_CASES +
       boundary_count),
    (uint64_t) NGI541_DIFF_BASE_SEED);


  free (ngi541_bad_plaintext);
  free (ngi541_plaintext);
  free (reference_plaintext);
  free (ngi541_ciphertext);
  free (reference_ciphertext);
  free (plaintext);
  free (aad);

  return 0;


fail:
  free (ngi541_bad_plaintext);
  free (ngi541_plaintext);
  free (reference_plaintext);
  free (ngi541_ciphertext);
  free (reference_ciphertext);
  free (plaintext);
  free (aad);

  return 1;


allocation_fail:
  free (ngi541_bad_plaintext);
  free (ngi541_plaintext);
  free (reference_plaintext);
  free (ngi541_ciphertext);
  free (reference_ciphertext);
  free (plaintext);
  free (aad);

  return 1;
}