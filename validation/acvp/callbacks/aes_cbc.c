/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "callbacks/aes_cbc.h"

#include <ngi541/crypto.h>

#include <stddef.h>
#include <string.h>


#define NGI541_ACVP_AES_BLOCK_SIZE 16U


/*
 * libacvp performs the AES Monte Carlo protocol orchestration itself:
 *
 *   - 100 outer iterations
 *   - 1000 inner cipher operations
 *   - pt/ct/iv mutation between inner iterations
 *   - key derivation between outer iterations
 *
 * The crypto callback, however, is expected to preserve the CBC cipher
 * chaining state across the 1000 inner operations.
 *
 * NGI541 intentionally exposes a stateless one-shot public cipher API.
 * Therefore the chaining value required by ACVP MCT is maintained here,
 * inside the validation adapter only.
 *
 * This state is not part of the NGI541 production API or engine ABI.
 */
typedef struct
{
  int active;

  unsigned int tc_id;
  ACVP_SYM_CIPH_DIR direction;
  size_t key_len;

  unsigned char chaining_value[
    NGI541_ACVP_AES_BLOCK_SIZE];
} ngi541_acvp_aes_cbc_mct_state_t;


static ngi541_acvp_aes_cbc_mct_state_t
  ngi541_acvp_aes_cbc_mct_state;


static void
ngi541_acvp_aes_cbc_mct_reset (void)
{
  memset (
    &ngi541_acvp_aes_cbc_mct_state,
    0,
    sizeof (ngi541_acvp_aes_cbc_mct_state));
}


static int
ngi541_acvp_key_bits_to_bytes (
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


static int
ngi541_acvp_aes_cbc_prepare_iv (
  ACVP_SYM_CIPHER_TC *tc,
  size_t key_len,
  size_t input_len,
  const unsigned char **operation_iv)
{
  if (tc == NULL || operation_iv == NULL)
    return 0;

  /*
   * Ordinary AFT processing uses the IV supplied directly
   * by libacvp.
   */
  if (tc->test_type != ACVP_SYM_TEST_TYPE_MCT)
    {
      *operation_iv = tc->iv;
      return 1;
    }

  /*
   * AES-CBC MCT operates one AES block at a time.
   */
  if (input_len != NGI541_ACVP_AES_BLOCK_SIZE)
    return 0;

  if (tc->mct_index >= ACVP_AES_MCT_INNER)
    return 0;

  /*
   * mct_index == 0 starts a new inner MCT sequence.
   *
   * This happens once for every outer iteration, after libacvp
   * has prepared the new key, IV and input.
   */
  if (tc->mct_index == 0)
    {
      ngi541_acvp_aes_cbc_mct_reset ();

      memcpy (
        ngi541_acvp_aes_cbc_mct_state.chaining_value,
        tc->iv,
        NGI541_ACVP_AES_BLOCK_SIZE);

      ngi541_acvp_aes_cbc_mct_state.active = 1;
      ngi541_acvp_aes_cbc_mct_state.tc_id = tc->tc_id;
      ngi541_acvp_aes_cbc_mct_state.direction =
        tc->direction;
      ngi541_acvp_aes_cbc_mct_state.key_len =
        key_len;
    }
  else
    {
      /*
       * An inner MCT operation must follow an initialized
       * mct_index == 0 operation from the same test case.
       */
      if (!ngi541_acvp_aes_cbc_mct_state.active)
        return 0;

      if (ngi541_acvp_aes_cbc_mct_state.tc_id !=
          tc->tc_id)
        return 0;

      if (ngi541_acvp_aes_cbc_mct_state.direction !=
          tc->direction)
        return 0;

      if (ngi541_acvp_aes_cbc_mct_state.key_len !=
          key_len)
        return 0;
    }

  *operation_iv =
    ngi541_acvp_aes_cbc_mct_state.chaining_value;

  return 1;
}


static void
ngi541_acvp_aes_cbc_finish_mct (
  ACVP_SYM_CIPHER_TC *tc,
  const unsigned char *ciphertext,
  size_t ciphertext_len)
{
  if (tc == NULL)
    return;

  if (tc->test_type != ACVP_SYM_TEST_TYPE_MCT)
    return;

  /*
   * For both CBC encryption and decryption, the chaining value
   * for the next cipher operation is the final ciphertext block:
   *
   *   encrypt: ciphertext produced by this operation
   *   decrypt: ciphertext consumed by this operation
   */
  memcpy (
    ngi541_acvp_aes_cbc_mct_state.chaining_value,
    ciphertext + ciphertext_len -
      NGI541_ACVP_AES_BLOCK_SIZE,
    NGI541_ACVP_AES_BLOCK_SIZE);

  /*
   * libacvp starts the next outer iteration with mct_index == 0.
   * Discard validation-only chaining state after the final inner
   * operation.
   */
  if (tc->mct_index == ACVP_AES_MCT_INNER - 1U)
    ngi541_acvp_aes_cbc_mct_reset ();
}


int
ngi541_acvp_aes_cbc_handler (
  ACVP_TEST_CASE *test_case)
{
  ACVP_SYM_CIPHER_TC *tc;
  ngi541_cipher_request_t request;
  ngi541_status_t status;

  const unsigned char *operation_iv;

  size_t key_len;
  size_t iv_len;
  size_t input_len;

  if (test_case == NULL)
    return 1;

  tc = test_case->tc.symmetric;

  if (tc == NULL)
    return 1;

  if (tc->cipher != ACVP_AES_CBC)
    return 1;

  if (tc->test_type != ACVP_SYM_TEST_TYPE_AFT &&
      tc->test_type != ACVP_SYM_TEST_TYPE_MCT)
    return 1;

  if (tc->key == NULL || tc->iv == NULL)
    return 1;

  /*
   * libacvp exposes AES key length in bits.
   */
  if (!ngi541_acvp_key_bits_to_bytes (
        tc->key_len,
        &key_len))
    return 1;

  /*
   * libacvp exposes IV and payload lengths to the callback
   * in bytes.
   */
  iv_len = (size_t) tc->iv_len;

  if (key_len != 16 &&
      key_len != 24 &&
      key_len != 32)
    return 1;

  if (iv_len != NGI541_ACVP_AES_BLOCK_SIZE)
    return 1;

  switch (tc->direction)
    {
    case ACVP_SYM_CIPH_DIR_ENCRYPT:
      if (tc->pt == NULL || tc->ct == NULL)
        return 1;

      input_len = (size_t) tc->pt_len;

      if (input_len == 0 ||
          (input_len % NGI541_ACVP_AES_BLOCK_SIZE) != 0)
        return 1;

      if (!ngi541_acvp_aes_cbc_prepare_iv (
            tc,
            key_len,
            input_len,
            &operation_iv))
        return 1;

      request = (ngi541_cipher_request_t) {
        .struct_size =
          sizeof (ngi541_cipher_request_t),

        .algorithm =
          NGI541_CIPHER_AES_CBC,

        .key = tc->key,
        .key_len = key_len,

        .iv = operation_iv,
        .iv_len = iv_len,

        .input = tc->pt,
        .input_len = input_len,

        .output = tc->ct,
        .output_capacity = input_len,
      };

      status =
        ngi541_crypto_cipher_encrypt (&request);

      if (status != NGI541_STATUS_OK)
        {
          if (tc->test_type ==
              ACVP_SYM_TEST_TYPE_MCT)
            ngi541_acvp_aes_cbc_mct_reset ();

          return 1;
        }

      tc->ct_len = tc->pt_len;

      ngi541_acvp_aes_cbc_finish_mct (
        tc,
        tc->ct,
        input_len);

      return 0;

    case ACVP_SYM_CIPH_DIR_DECRYPT:
      if (tc->ct == NULL || tc->pt == NULL)
        return 1;

      input_len = (size_t) tc->ct_len;

      if (input_len == 0 ||
          (input_len % NGI541_ACVP_AES_BLOCK_SIZE) != 0)
        return 1;

      if (!ngi541_acvp_aes_cbc_prepare_iv (
            tc,
            key_len,
            input_len,
            &operation_iv))
        return 1;

      request = (ngi541_cipher_request_t) {
        .struct_size =
          sizeof (ngi541_cipher_request_t),

        .algorithm =
          NGI541_CIPHER_AES_CBC,

        .key = tc->key,
        .key_len = key_len,

        .iv = operation_iv,
        .iv_len = iv_len,

        .input = tc->ct,
        .input_len = input_len,

        .output = tc->pt,
        .output_capacity = input_len,
      };

      status =
        ngi541_crypto_cipher_decrypt (&request);

      if (status != NGI541_STATUS_OK)
        {
          if (tc->test_type ==
              ACVP_SYM_TEST_TYPE_MCT)
            ngi541_acvp_aes_cbc_mct_reset ();

          return 1;
        }

      tc->pt_len = tc->ct_len;

      /*
       * CBC decryption chaining uses the ciphertext input,
       * not the produced plaintext.
       */
      ngi541_acvp_aes_cbc_finish_mct (
        tc,
        tc->ct,
        input_len);

      return 0;

    default:
      return 1;
    }
}