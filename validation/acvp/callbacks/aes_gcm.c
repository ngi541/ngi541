/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "callbacks/aes_gcm.h"

#include <ngi541/crypto.h>

#include <stddef.h>

static int
ngi541_acvp_gcm_key_bits_to_bytes (
  unsigned int bits,
  size_t *bytes)
{
  if (bytes == NULL)
    return 0;

  if ((bits & 7U) != 0)
    return 0;

  *bytes = (size_t) bits / 8U;

  return 1;
}

int
ngi541_acvp_aes_gcm_handler (
  ACVP_TEST_CASE *test_case)
{
  ACVP_SYM_CIPHER_TC *tc;
  ngi541_status_t status;

  size_t key_len;
  size_t iv_len;
  size_t aad_len;
  size_t tag_len;

  if (test_case == NULL)
    return 1;

  tc = test_case->tc.symmetric;

  if (tc == NULL)
    return 1;

  if (tc->cipher != ACVP_AES_GCM)
    return 1;

  if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT)
    return 1;

  if (tc->key == NULL || tc->iv == NULL || tc->tag == NULL)
    return 1;

  if (!ngi541_acvp_gcm_key_bits_to_bytes (
        tc->key_len,
        &key_len))
    return 1;

  /*
   * libacvp exposes symmetric payload, IV, AAD and tag
   * lengths to the crypto callback in bytes.
   */
  iv_len = (size_t) tc->iv_len;
  aad_len = (size_t) tc->aad_len;
  tag_len = (size_t) tc->tag_len;

  /*
   * Current NGI541 public AES-GCM contract:
   *
   *   key: 128 / 192 / 256 bits
   *   IV:  96 bits
   *   tag: 128 bits
   */
  if (key_len != 16 &&
      key_len != 24 &&
      key_len != 32)
    return 1;

  if (iv_len != 12)
    return 1;

  if (tag_len != 16)
    return 1;

  if (aad_len != 0 && tc->aad == NULL)
    return 1;

  switch (tc->direction)
    {
    case ACVP_SYM_CIPH_DIR_ENCRYPT:
      {
        size_t plaintext_len =
          (size_t) tc->pt_len;

        if (plaintext_len != 0 &&
            (tc->pt == NULL || tc->ct == NULL))
          return 1;

        ngi541_aead_encrypt_request_t request = {
          .struct_size =
            sizeof (ngi541_aead_encrypt_request_t),

          .algorithm =
            NGI541_AEAD_AES_GCM,

          .key = tc->key,
          .key_len = key_len,

          .iv = tc->iv,
          .iv_len = iv_len,

          .aad = tc->aad,
          .aad_len = aad_len,

          .plaintext = tc->pt,
          .plaintext_len = plaintext_len,

          .ciphertext = tc->ct,
          .ciphertext_capacity = plaintext_len,

          .tag = tc->tag,
          .tag_len = tag_len,
        };

        status =
          ngi541_crypto_aead_encrypt (&request);

        if (status != NGI541_STATUS_OK)
          return 1;

        tc->ct_len = tc->pt_len;

        return 0;
      }

    case ACVP_SYM_CIPH_DIR_DECRYPT:
      {
        size_t ciphertext_len =
          (size_t) tc->ct_len;

        if (ciphertext_len != 0 &&
            (tc->ct == NULL || tc->pt == NULL))
          return 1;

        ngi541_aead_decrypt_request_t request = {
          .struct_size =
            sizeof (ngi541_aead_decrypt_request_t),

          .algorithm =
            NGI541_AEAD_AES_GCM,

          .key = tc->key,
          .key_len = key_len,

          .iv = tc->iv,
          .iv_len = iv_len,

          .aad = tc->aad,
          .aad_len = aad_len,

          .ciphertext = tc->ct,
          .ciphertext_len = ciphertext_len,

          .tag = tc->tag,
          .tag_len = tag_len,

          .plaintext = tc->pt,
          .plaintext_capacity = ciphertext_len,
        };

        status =
          ngi541_crypto_aead_decrypt (&request);

        /*
         * For authenticated decrypt, libacvp interprets a
         * non-zero crypto-handler return as testPassed=false.
         *
         * NGI541 AUTH_FAILED is therefore a valid ACVP
         * verification result, not successful plaintext output.
         */
        if (status == NGI541_STATUS_AUTH_FAILED)
          {
            tc->pt_len = 0;
            return 1;
          }

        if (status != NGI541_STATUS_OK)
          return 1;

        tc->pt_len = tc->ct_len;

        return 0;
      }

    default:
      return 1;
    }
}