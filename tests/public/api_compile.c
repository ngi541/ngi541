/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/api.h>
#include <ngi541/crypto.h>
#include <ngi541/engine.h>

#include <stddef.h>
#include <stdint.h>

_Static_assert (
  sizeof (ngi541_status_t) == sizeof (int32_t),
  "ngi541_status_t must be 32-bit");

_Static_assert (
  sizeof (ngi541_cipher_algorithm_t) == sizeof (uint32_t),
  "cipher algorithm ID must be 32-bit");

_Static_assert (
  sizeof (ngi541_aead_algorithm_t) == sizeof (uint32_t),
  "AEAD algorithm ID must be 32-bit");

_Static_assert (
  sizeof (ngi541_hash_algorithm_t) == sizeof (uint32_t),
  "hash algorithm ID must be 32-bit");

int
main (void)
{
  uint8_t key[32] = { 0 };
  uint8_t iv[16] = { 0 };

  uint8_t input[16] = { 0 };
  uint8_t output[16] = { 0 };

  uint8_t aad[16] = { 0 };
  uint8_t tag[16] = { 0 };

  uint8_t digest[32] = { 0 };

  ngi541_cipher_request_t cipher_request = {
    .struct_size = sizeof (ngi541_cipher_request_t),
    .algorithm = NGI541_CIPHER_AES_CBC,
    .key = key,
    .key_len = 16,
    .iv = iv,
    .iv_len = 16,
    .input = input,
    .input_len = sizeof (input),
    .output = output,
    .output_capacity = sizeof (output),
  };

  ngi541_aead_encrypt_request_t aead_encrypt_request = {
    .struct_size = sizeof (ngi541_aead_encrypt_request_t),
    .algorithm = NGI541_AEAD_AES_GCM,
    .key = key,
    .key_len = 16,
    .iv = iv,
    .iv_len = 12,
    .aad = aad,
    .aad_len = sizeof (aad),
    .plaintext = input,
    .plaintext_len = sizeof (input),
    .ciphertext = output,
    .ciphertext_capacity = sizeof (output),
    .tag = tag,
    .tag_len = sizeof (tag),
  };

  ngi541_aead_decrypt_request_t aead_decrypt_request = {
    .struct_size = sizeof (ngi541_aead_decrypt_request_t),
    .algorithm = NGI541_AEAD_AES_GCM,
    .key = key,
    .key_len = 16,
    .iv = iv,
    .iv_len = 12,
    .aad = aad,
    .aad_len = sizeof (aad),
    .ciphertext = input,
    .ciphertext_len = sizeof (input),
    .tag = tag,
    .tag_len = sizeof (tag),
    .plaintext = output,
    .plaintext_capacity = sizeof (output),
  };

  ngi541_hash_request_t hash_request = {
    .struct_size = sizeof (ngi541_hash_request_t),
    .algorithm = NGI541_HASH_SHA2_256,
    .message = input,
    .message_len = sizeof (input),
    .digest = digest,
    .digest_capacity = sizeof (digest),
  };

  /*
   * Make the objects observable so this remains a real compile-time
   * consumer of the public request structures.
   */
  if (cipher_request.struct_size == 0 ||
      aead_encrypt_request.struct_size == 0 ||
      aead_decrypt_request.struct_size == 0 ||
      hash_request.struct_size == 0)
    return 1;

  return 0;
}