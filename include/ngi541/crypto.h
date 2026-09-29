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

/*
 * Public operation status.
 *
 * Authentication failure is a valid cryptographic result and is
 * intentionally distinct from execution or argument errors.
 */
typedef int32_t ngi541_status_t;

enum
{
  NGI541_STATUS_OK = 0,

  NGI541_STATUS_AUTH_FAILED = 1,

  NGI541_STATUS_INVALID_ARGUMENT = 2,
  NGI541_STATUS_BUFFER_TOO_SMALL = 3,

  /*
   * The requested algorithm or parameter combination is not
   * supported by this API implementation.
   */
  NGI541_STATUS_UNSUPPORTED = 4,

  /*
   * The operation is supported by the API, but no usable
   * implementation is available in the current environment.
   */
  NGI541_STATUS_UNAVAILABLE = 5,

  NGI541_STATUS_NOT_INITIALIZED = 6,
  NGI541_STATUS_INTERNAL_ERROR = 7,
};


/*
 * Public cipher algorithms.
 *
 * AES key size is determined by key_len:
 *
 *   16 bytes -> AES-128
 *   24 bytes -> AES-192
 *   32 bytes -> AES-256
 */
typedef uint32_t ngi541_cipher_algorithm_t;

enum
{
  NGI541_CIPHER_AES_CBC = 1,
  NGI541_CIPHER_AES_CTR = 2,
};


/*
 * Public AEAD algorithms.
 */
typedef uint32_t ngi541_aead_algorithm_t;

enum
{
  NGI541_AEAD_AES_GCM = 1,
};


/*
 * Public hash algorithms.
 *
 * Only algorithms backed by the current NGI541 native provider
 * are exposed here.
 */
typedef uint32_t ngi541_hash_algorithm_t;

enum
{
  NGI541_HASH_SHA2_224 = 1,
  NGI541_HASH_SHA2_256 = 2,
};


/*
 * Symmetric cipher request.
 *
 * All lengths are expressed in bytes.
 *
 * input and output must refer to valid buffers for input_len bytes.
 * output_capacity must be at least input_len.
 *
 * AES-CTR supports exact in-place operation when input == output.
 *
 * For AES-CTR, distinct input and output buffers must not partially
 * overlap over the input_len-byte operation region. Partial overlap
 * is rejected with NGI541_STATUS_INVALID_ARGUMENT.
 *
 * No in-place or overlap guarantee is currently made for other
 * cipher algorithms.
 *
 * The request structure is caller-owned and is not retained by NGI541.
 */
typedef struct
{
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


/*
 * AEAD encryption request.
 *
 * All lengths are expressed in bytes.
 *
 * The caller owns all input and output buffers. NGI541 does not retain
 * pointers after the operation returns.
 */
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


/*
 * AEAD decryption request.
 *
 * NGI541_STATUS_AUTH_FAILED means that the operation completed but
 * authentication of the supplied tag failed.
 *
 * The plaintext buffer must not be treated as valid when
 * NGI541_STATUS_AUTH_FAILED is returned.
 */
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


/*
 * One-shot hash request.
 *
 * message may be NULL only when message_len is zero.
 *
 * digest_capacity must be large enough for the selected algorithm.
 */
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