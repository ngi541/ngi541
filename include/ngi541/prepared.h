/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_PREPARED_H
#define NGI541_PREPARED_H

#include <stddef.h>
#include <stdint.h>

#include <ngi541/crypto.h>

NGI541_BEGIN_DECLS


/*
 * Opaque immutable prepared-key objects.
 *
 * A prepared key owns provider-specific expanded key material.
 * The implementation does not retain the caller's raw-key pointer.
 *
 * After creation, prepared-key objects are immutable.
 *
 * The same prepared key may be used concurrently by multiple
 * execution calls. The caller must ensure that the object remains
 * alive for the full duration of every execution using it.
 *
 * Destruction must not run concurrently with execution using the
 * same prepared key.
 */
typedef struct ngi541_cipher_key ngi541_cipher_key_t;
typedef struct ngi541_aead_key ngi541_aead_key_t;


/*
 * Parameters used to create a prepared cipher key.
 *
 * key is consumed synchronously during creation and is not retained.
 */
typedef struct
{
  uint32_t struct_size;

  ngi541_cipher_algorithm_t algorithm;

  const uint8_t *key;
  size_t key_len;
} ngi541_cipher_key_params_t;


/*
 * Parameters used to create a prepared AEAD key.
 *
 * key is consumed synchronously during creation and is not retained.
 */
typedef struct
{
  uint32_t struct_size;

  ngi541_aead_algorithm_t algorithm;

  const uint8_t *key;
  size_t key_len;
} ngi541_aead_key_params_t;


/*
 * Cipher execution request using an already prepared key.
 *
 * All lengths are expressed in bytes.
 *
 * input and output must refer to valid buffers for input_len bytes.
 * output_capacity must be at least input_len.
 *
 * AES-CTR supports exact in-place operation when input == output.
 * Distinct AES-CTR input and output buffers must not partially
 * overlap over the input_len-byte operation region.
 *
 * The request structure and all buffers are caller-owned and are
 * not retained after the operation returns.
 */
typedef struct
{
  uint32_t struct_size;

  const uint8_t *iv;
  size_t iv_len;

  const uint8_t *input;
  size_t input_len;

  uint8_t *output;
  size_t output_capacity;
} ngi541_cipher_exec_request_t;


/*
 * AEAD encryption request using an already prepared key.
 *
 * The prepared key contains only key-dependent state.
 * IV/nonce, AAD, payload and authentication tag remain
 * operation-local state.
 */
typedef struct
{
  uint32_t struct_size;

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
} ngi541_aead_encrypt_exec_request_t;


/*
 * AEAD decryption request using an already prepared key.
 *
 * Authentication failure is reported as
 * NGI541_STATUS_AUTH_FAILED.
 *
 * The plaintext buffer must not be treated as valid after an
 * authentication failure.
 */
typedef struct
{
  uint32_t struct_size;

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
} ngi541_aead_decrypt_exec_request_t;

/*
 * Create an immutable prepared cipher key.
 *
 * Raw key material is consumed synchronously and is not retained.
 * On success, *prepared_key receives an engine-owned object.
 */
NGI541_API ngi541_status_t
ngi541_crypto_cipher_key_create (
  const ngi541_cipher_key_params_t *params,
  ngi541_cipher_key_t **prepared_key);

NGI541_API void
ngi541_crypto_cipher_key_destroy (
  ngi541_cipher_key_t *prepared_key);


/*
 * Create an immutable prepared AEAD key.
 */
NGI541_API ngi541_status_t
ngi541_crypto_aead_key_create (
  const ngi541_aead_key_params_t *params,
  ngi541_aead_key_t **prepared_key);

NGI541_API void
ngi541_crypto_aead_key_destroy (
  ngi541_aead_key_t *prepared_key);


/*
 * Execute using an already prepared cipher key.
 *
 * No key expansion or memory allocation is performed by this call.
 */
NGI541_API ngi541_status_t
ngi541_crypto_cipher_encrypt_prepared (
  const ngi541_cipher_key_t *prepared_key,
  const ngi541_cipher_exec_request_t *request);

NGI541_API ngi541_status_t
ngi541_crypto_cipher_decrypt_prepared (
  const ngi541_cipher_key_t *prepared_key,
  const ngi541_cipher_exec_request_t *request);


/*
 * Execute using an already prepared AEAD key.
 *
 * No key expansion or memory allocation is performed by these calls.
 */
NGI541_API ngi541_status_t
ngi541_crypto_aead_encrypt_prepared (
  const ngi541_aead_key_t *prepared_key,
  const ngi541_aead_encrypt_exec_request_t *request);

NGI541_API ngi541_status_t
ngi541_crypto_aead_decrypt_prepared (
  const ngi541_aead_key_t *prepared_key,
  const ngi541_aead_decrypt_exec_request_t *request);

NGI541_END_DECLS

#endif /* NGI541_PREPARED_H */