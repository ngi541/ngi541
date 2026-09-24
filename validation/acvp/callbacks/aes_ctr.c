/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "callbacks/aes_ctr.h"

#include <ngi541/crypto.h>

#include <stddef.h>

static int
ngi541_acvp_ctr_bits_to_bytes (
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
ngi541_acvp_aes_ctr_handler (
  ACVP_TEST_CASE *test_case)
{
  ACVP_SYM_CIPHER_TC *tc;
  ngi541_cipher_request_t request;
  ngi541_status_t status;

  size_t key_len;
  size_t iv_len;
  size_t input_len;

  if (test_case == NULL)
    return 1;

  tc = test_case->tc.symmetric;

  if (tc == NULL)
    return 1;

  if (tc->cipher != ACVP_AES_CTR)
    return 1;

  /*
   * MCT requires protocol-level orchestration outside the
   * one-shot public NGI541 execution contract.
   */
  if (tc->test_type == ACVP_SYM_TEST_TYPE_MCT)
    return 1;

  if (tc->key == NULL || tc->iv == NULL)
    return 1;

  if (!ngi541_acvp_ctr_bits_to_bytes (
        tc->key_len,
        &key_len))
    return 1;

  if (!ngi541_acvp_ctr_bits_to_bytes (
        tc->iv_len,
        &iv_len))
    return 1;

  if (key_len != 16 &&
      key_len != 24 &&
      key_len != 32)
    return 1;

  /*
   * Current NGI541 public CTR contract uses a complete
   * 128-bit initial counter block.
   */
  if (iv_len != 16)
    return 1;

  switch (tc->direction)
    {
    case ACVP_SYM_CIPH_DIR_ENCRYPT:
      if (tc->pt == NULL || tc->ct == NULL)
        return 1;

      if (!ngi541_acvp_ctr_bits_to_bytes (
            tc->pt_len,
            &input_len))
        return 1;

      request = (ngi541_cipher_request_t) {
        .struct_size =
          sizeof (ngi541_cipher_request_t),

        .algorithm =
          NGI541_CIPHER_AES_CTR,

        .key = tc->key,
        .key_len = key_len,

        .iv = tc->iv,
        .iv_len = iv_len,

        .input = tc->pt,
        .input_len = input_len,

        .output = tc->ct,
        .output_capacity = input_len,
      };

      status =
        ngi541_crypto_cipher_encrypt (&request);

      if (status != NGI541_STATUS_OK)
        return 1;

      tc->ct_len = tc->pt_len;

      return 0;

    case ACVP_SYM_CIPH_DIR_DECRYPT:
      if (tc->ct == NULL || tc->pt == NULL)
        return 1;

      if (!ngi541_acvp_ctr_bits_to_bytes (
            tc->ct_len,
            &input_len))
        return 1;

      request = (ngi541_cipher_request_t) {
        .struct_size =
          sizeof (ngi541_cipher_request_t),

        .algorithm =
          NGI541_CIPHER_AES_CTR,

        .key = tc->key,
        .key_len = key_len,

        .iv = tc->iv,
        .iv_len = iv_len,

        .input = tc->ct,
        .input_len = input_len,

        .output = tc->pt,
        .output_capacity = input_len,
      };

      status =
        ngi541_crypto_cipher_decrypt (&request);

      if (status != NGI541_STATUS_OK)
        return 1;

      tc->pt_len = tc->ct_len;

      return 0;

    default:
      return 1;
    }
}