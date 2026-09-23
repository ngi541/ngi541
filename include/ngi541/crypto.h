/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_CRYPTO_H
#define NGI541_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include <ngi541/api.h>

NGI541_BEGIN_DECLS

typedef enum
{
  NGI541_STATUS_OK = 0,

  /*
   * The operation completed correctly, but authenticated
   * verification failed.
   */
  NGI541_STATUS_AUTH_FAILED = 1,

  NGI541_STATUS_INVALID_ARGUMENT = 2,

  /*
   * The requested algorithm or parameter combination is not
   * supported by the NGI541 public API.
   */
  NGI541_STATUS_UNSUPPORTED = 3,

  /*
   * The operation is supported by the API, but no implementation
   * is available in the current build / execution environment.
   */
  NGI541_STATUS_UNAVAILABLE = 4,

  NGI541_STATUS_NOT_INITIALIZED = 5,

  NGI541_STATUS_INTERNAL_ERROR = 6,
} ngi541_status_t;

typedef enum
{
  NGI541_CIPHER_AES_CBC = 1,
  NGI541_CIPHER_AES_CTR = 2,
} ngi541_cipher_algorithm_t;

typedef enum
{
  NGI541_AEAD_AES_GCM = 1,
} ngi541_aead_algorithm_t;

typedef enum
{
  NGI541_HASH_SHA2_224 = 1,
  NGI541_HASH_SHA2_256 = 2,
} ngi541_hash_algorithm_t;

typedef struct
{
  /*
   * Size of this structure as provided by the caller.
   * Must be set to sizeof (ngi541_cipher_request_t).
   */
  uint32_t struct_size;

  ngi541_cipher_algorithm_t algorithm;

  const uint8_t *key;
  size_t key_len;

  const uint8_t *iv;
  size_t iv_len;

  const uint8_t *input;
  size_t input_len;

  uint8_t *output;
  size_t output_capacity;
} ngi541_cipher_request_t;

typedef struct
{
  uint32_t struct_size;

  ngi541_aead_algorithm_t algorithm;

  const uint8_t *key;
  size_t key_len;

  const uint8_t *iv;
  size_t iv_len;

  const uint8_t *aad;
  size_t aad_len;

  const uint8_t *plaintext;
  size_t plaintext_len;

  uint8_t *ciphertext;
  size_t ciphertext_capacity;

  uint8_t *tag;
  size_t tag_len;
} ngi541_aead_encrypt_request_t;

typedef struct
{
  uint32_t struct_size;

  ngi541_aead_algorithm_t algorithm;

  const uint8_t *key;
  size_t key_len;

  const uint8_t *iv;
  size_t iv_len;

  const uint8_t *aad;
  size_t aad_len;

  const uint8_t *ciphertext;
  size_t ciphertext_len;

  const uint8_t *tag;
  size_t tag_len;

  uint8_t *plaintext;
  size_t plaintext_capacity;
} ngi541_aead_decrypt_request_t;

typedef struct
{
  uint32_t struct_size;

  ngi541_hash_algorithm_t algorithm;

  const uint8_t *message;
  size_t message_len;

  uint8_t *digest;
  size_t digest_capacity;
} ngi541_hash_request_t;

NGI541_API ngi541_status_t
ngi541_crypto_cipher_encrypt (
  const ngi541_cipher_request_t *request);

NGI541_API ngi541_status_t
ngi541_crypto_cipher_decrypt (
  const ngi541_cipher_request_t *request);

NGI541_API ngi541_status_t
ngi541_crypto_aead_encrypt (
  const ngi541_aead_encrypt_request_t *request);

NGI541_API ngi541_status_t
ngi541_crypto_aead_decrypt (
  const ngi541_aead_decrypt_request_t *request);

NGI541_API ngi541_status_t
ngi541_crypto_hash_compute (
  const ngi541_hash_request_t *request);

NGI541_END_DECLS

#endif /* NGI541_CRYPTO_H */