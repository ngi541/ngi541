/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <stdint.h>

int
main (void)
{
  uint8_t key[32] = { 0 };
  uint8_t iv[16] = { 0 };
  uint8_t input[16] = { 0 };
  uint8_t output[16] = { 0 };
  uint8_t digest[32] = { 0 };
  uint8_t tag[16] = { 0 };

  ngi541_hash_request_t hash_request = {
    .struct_size = sizeof (ngi541_hash_request_t),
    .algorithm = NGI541_HASH_SHA2_256,
    .message = input,
    .message_len = sizeof (input),
    .digest = digest,
    .digest_capacity = sizeof (digest),
  };

  /*
   * Explicit initialization is part of the public API contract.
   */
  if (ngi541_crypto_hash_compute (&hash_request) !=
      NGI541_STATUS_NOT_INITIALIZED)
    return 1;

  if (ngi541_engine_init () != NGI541_STATUS_OK)
    return 2;

  /*
   * Initialization is idempotent.
   */
  if (ngi541_engine_init () != NGI541_STATUS_OK)
    return 3;

  if (ngi541_crypto_hash_compute (NULL) !=
      NGI541_STATUS_INVALID_ARGUMENT)
    return 4;

  hash_request.struct_size =
    sizeof (ngi541_hash_request_t) - 1;

  if (ngi541_crypto_hash_compute (&hash_request) !=
      NGI541_STATUS_INVALID_ARGUMENT)
    return 5;

  hash_request.struct_size =
    sizeof (ngi541_hash_request_t);

  hash_request.algorithm =
    (ngi541_hash_algorithm_t) UINT32_MAX;

  if (ngi541_crypto_hash_compute (&hash_request) !=
      NGI541_STATUS_UNSUPPORTED)
    return 6;

  hash_request.algorithm =
    NGI541_HASH_SHA2_256;

  hash_request.digest_capacity = 31;

  if (ngi541_crypto_hash_compute (&hash_request) !=
      NGI541_STATUS_BUFFER_TOO_SMALL)
    return 7;

  {
    ngi541_cipher_request_t cipher_request = {
      .struct_size =
        sizeof (ngi541_cipher_request_t),
      .algorithm =
        NGI541_CIPHER_AES_CBC,
      .key = key,
      .key_len = 16,
      .iv = iv,
      .iv_len = 16,
      .input = input,
      .input_len = 1,
      .output = output,
      .output_capacity = sizeof (output),
    };

    if (ngi541_crypto_cipher_encrypt (
          &cipher_request) !=
        NGI541_STATUS_INVALID_ARGUMENT)
      return 8;
  }

  {
    ngi541_aead_encrypt_request_t request = {
      .struct_size =
        sizeof (ngi541_aead_encrypt_request_t),
      .algorithm =
        NGI541_AEAD_AES_GCM,
      .key = key,
      .key_len = 16,
      .iv = iv,
      .iv_len = 12,
      .aad = NULL,
      .aad_len = 0,
      .plaintext = input,
      .plaintext_len = sizeof (input),
      .ciphertext = output,
      .ciphertext_capacity = sizeof (output),
      .tag = tag,

      /*
       * Current v1 implementation intentionally supports
       * 16-byte GCM authentication tags only.
       */
      .tag_len = 12,
    };

    if (ngi541_crypto_aead_encrypt (&request) !=
        NGI541_STATUS_UNSUPPORTED)
      return 9;
  }

  return 0;
}