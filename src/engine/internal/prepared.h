/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_INTERNAL_PREPARED_H
#define NGI541_INTERNAL_PREPARED_H

#include <ngi541/engine.h>

#include <stddef.h>
#include <stdint.h>

/*
 * Direct prepared execution ABI.
 *
 * This layer deliberately does not use:
 *
 *   ngi541_crypto_op_t
 *   ngi541_crypto_op_id_t
 *   provider handler tables
 *
 * Algorithm/backend/ISA selection belongs to control-plane setup.
 * The data path receives already prepared key material and a direct
 * execution function.
 */

typedef ngi541_status_t
(ngi541_prepared_key_init_fn_t) (
  void *key_data,
  const uint8_t *key,
  size_t key_len);

typedef void
(ngi541_prepared_key_cleanup_fn_t) (
  void *key_data);

/*
 * Internal AEAD execution contract.
 *
 * IV and tag are mutable here only because the current AES-GCM core ABI
 * is not fully const-qualified. Public API const semantics remain
 * enforced by execute.c.
 *
 * Length validation is performed before entering this layer.
 */
typedef ngi541_status_t
(ngi541_prepared_aead_encrypt_fn_t) (
  const void *key_data,
  uint8_t *iv,
  const uint8_t *aad,
  uint16_t aad_len,
  const uint8_t *src,
  uint8_t *dst,
  uint32_t len,
  uint8_t *tag);

typedef ngi541_status_t
(ngi541_prepared_aead_decrypt_fn_t) (
  const void *key_data,
  uint8_t *iv,
  const uint8_t *aad,
  uint16_t aad_len,
  const uint8_t *src,
  uint8_t *dst,
  uint32_t len,
  uint8_t *tag);

typedef struct
{
  size_t key_data_size;

  ngi541_prepared_key_init_fn_t *key_init;
  ngi541_prepared_key_cleanup_fn_t *key_cleanup;

  ngi541_prepared_aead_encrypt_fn_t *encrypt;
  ngi541_prepared_aead_decrypt_fn_t *decrypt;
} ngi541_prepared_aead_impl_t;


/*
 * Direct prepared cipher ABI.
 *
 * AES-CTR uses the same prepared execution model as AEAD:
 * implementation and key setup are resolved before entering
 * the data path.
 */
typedef ngi541_status_t
(ngi541_prepared_cipher_fn_t) (
  const void *key_data,
  uint8_t *iv,
  const uint8_t *src,
  uint8_t *dst,
  uint32_t len);

typedef struct
{
  size_t key_data_size;

  ngi541_prepared_key_init_fn_t *key_init;
  ngi541_prepared_key_cleanup_fn_t *key_cleanup;

  ngi541_prepared_cipher_fn_t *encrypt;
  ngi541_prepared_cipher_fn_t *decrypt;
} ngi541_prepared_cipher_impl_t;


/*
 * Control-plane selectors.
 *
 * These functions may perform CPU capability checks and key-size
 * selection. They are never part of the packet data path.
 */
const ngi541_prepared_aead_impl_t *
ngi541_native_prepared_aes_gcm_get (
  size_t key_len);

const ngi541_prepared_cipher_impl_t *
ngi541_native_prepared_aes_ctr_get (
  size_t key_len);

#endif /* NGI541_INTERNAL_PREPARED_H */
