/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 *
 * Modified for NGI541: source layout and include paths.
 */

#ifndef NGI541_INTERNAL_CRYPTO_TYPES_H
#define NGI541_INTERNAL_CRYPTO_TYPES_H

#include <compat/assert.h>
#include <compat/base.h>
#include <vppinfra/cache.h>
#include <vppinfra/string.h>

/* CRYPTO_ID, PRETTY_NAME, ARGS*/
#define NGI541_FOREACH_CRYPTO_CIPHER_ALG                               \
  _ (AES_128_CBC, "aes-128-cbc", .key_length = 16)                     \
  _ (AES_192_CBC, "aes-192-cbc", .key_length = 24)                     \
  _ (AES_256_CBC, "aes-256-cbc", .key_length = 32)                     \
  _ (AES_128_CTR, "aes-128-ctr", .key_length = 16)                     \
  _ (AES_192_CTR, "aes-192-ctr", .key_length = 24)                     \
  _ (AES_256_CTR, "aes-256-ctr", .key_length = 32)

#define NGI541_FOREACH_CRYPTO_HASH_ALG                                 \
  _ (SHA224, "sha-224")                                                \
  _ (SHA256, "sha-256")


#define NGI541_FOREACH_CRYPTO_OP_STATUS \
  _(COMPLETED, "completed")             \
  _(FAIL_BAD_HMAC, "bad-hmac")


#define NGI541_FOREACH_CRYPTO_AEAD_ALG                                 \
  _ (AES_128_GCM, "aes-128-gcm", .is_aead = 1, .key_length = 16)       \
  _ (AES_192_GCM, "aes-192-gcm", .is_aead = 1, .key_length = 24)       \
  _ (AES_256_GCM, "aes-256-gcm", .is_aead = 1, .key_length = 32)

/* CRYPTO_ID, PRETTY_NAME, KEY_LENGTH_IN_BYTES, TAG_LEN, AAD_LEN */
#define NGI541_FOREACH_CRYPTO_AEAD_VARIANT_ALG                         \
  _ (AES_128_GCM, "aes-128-gcm-aad8", 16, 16, 8)                       \
  _ (AES_128_GCM, "aes-128-gcm-aad12", 16, 16, 12)                     \
  _ (AES_192_GCM, "aes-192-gcm-aad8", 24, 16, 8)                       \
  _ (AES_192_GCM, "aes-192-gcm-aad12", 24, 16, 12)                     \
  _ (AES_256_GCM, "aes-256-gcm-aad8", 32, 16, 8)                       \
  _ (AES_256_GCM, "aes-256-gcm-aad12", 32, 16, 12)

/* CRYPTO_ID, INTEG_ID, PRETTY_NAME, KEY_LENGTH_IN_BYTES, DIGEST_LEN */
#define NGI541_FOREACH_CRYPTO_LINK_ALG                                 \
  _ (AES_128_CBC, SHA224, "aes-128-cbc-hmac-sha-224", 16, 14)          \
  _ (AES_192_CBC, SHA224, "aes-192-cbc-hmac-sha-224", 24, 14)          \
  _ (AES_256_CBC, SHA224, "aes-256-cbc-hmac-sha-224", 32, 14)          \
                                                                       \
  _ (AES_128_CBC, SHA256, "aes-128-cbc-hmac-sha-256", 16, 16)          \
  _ (AES_192_CBC, SHA256, "aes-192-cbc-hmac-sha-256", 24, 16)          \
  _ (AES_256_CBC, SHA256, "aes-256-cbc-hmac-sha-256", 32, 16)          \
                                                                       \
  _ (AES_128_CTR, SHA256, "aes-128-ctr-hmac-sha-256", 16, 16)          \
  _ (AES_192_CTR, SHA256, "aes-192-ctr-hmac-sha-256", 24, 16)          \
  _ (AES_256_CTR, SHA256, "aes-256-ctr-hmac-sha-256", 32, 16)

typedef enum
{
  NGI541_CRYPTO_KEY_OP_ADD,
  NGI541_CRYPTO_KEY_OP_DEL,
  NGI541_CRYPTO_KEY_OP_MODIFY,
} ngi541_crypto_key_op_t;

typedef enum
{
#define _(n, s) NGI541_CRYPTO_OP_STATUS_##n,
  NGI541_FOREACH_CRYPTO_OP_STATUS
#undef _
    NGI541_CRYPTO_OP_N_STATUS,
} ngi541_crypto_op_status_t;

typedef enum
{
  NGI541_CRYPTO_ALG_NONE = 0,
#define _(n, s, ...) NGI541_CRYPTO_ALG_##n,
  NGI541_FOREACH_CRYPTO_CIPHER_ALG NGI541_FOREACH_CRYPTO_AEAD_ALG
#undef _
#define _(n, s) NGI541_CRYPTO_ALG_HASH_##n, NGI541_CRYPTO_ALG_HMAC_##n,
    NGI541_FOREACH_CRYPTO_HASH_ALG
#undef _
#define _(n, s, k, t, a) \
  NGI541_CRYPTO_ALG_##n##_TAG##t##_AAD##a,
      NGI541_FOREACH_CRYPTO_AEAD_VARIANT_ALG
#undef _
#define _(c, h, s, k ,d) \
  NGI541_CRYPTO_ALG_##c##_##h##_TAG##d,
	NGI541_FOREACH_CRYPTO_LINK_ALG
#undef _
	  NGI541_CRYPTO_N_ALGS,
} ngi541_crypto_alg_t;

typedef enum
{
  NGI541_CRYPTO_OP_NONE = 0,
#define _(n, s, ...) NGI541_CRYPTO_OP_##n##_ENC, NGI541_CRYPTO_OP_##n##_DEC,
  NGI541_FOREACH_CRYPTO_CIPHER_ALG NGI541_FOREACH_CRYPTO_AEAD_ALG
#undef _
#define _(n, s) NGI541_CRYPTO_OP_##n##_HASH, NGI541_CRYPTO_OP_##n##_HMAC,
    NGI541_FOREACH_CRYPTO_HASH_ALG
#undef _
#define _(n, s, k, t, a)                                                      \
  NGI541_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC,                                 \
    NGI541_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,
      NGI541_FOREACH_CRYPTO_AEAD_VARIANT_ALG
#undef _
#define _(c, h, s, k, d)                                                      \
  NGI541_CRYPTO_OP_##c##_##h##_TAG##d##_ENC,                                    \
    NGI541_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,
	NGI541_FOREACH_CRYPTO_LINK_ALG
#undef _
	  NGI541_CRYPTO_N_OP_IDS,
} __clib_packed ngi541_crypto_op_id_t;


typedef struct
{
  u8 *src;
  u8 *dst;
  u32 len;
} ngi541_crypto_op_chunk_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  union
  {
    struct
    {
      u8 *src;
      u8 *dst;
    };

    /* valid if NGI541_CRYPTO_OP_FLAG_CHAINED_BUFFERS is set */
    struct
    {
      u32 chunk_index;
      u32 integ_chunk_index;
    };
  };

  u8 *iv;

  union
  {
    u8 *integ_src;
    u8 *aad;
  };

  union
  {
    u8 *tag;
    u8 *digest;
  };

  void *key_data;

  union
  {
    u32 len;

    /* valid if NGI541_CRYPTO_OP_FLAG_CHAINED_BUFFERS is set */
    u16 n_chunks;
  };

  ngi541_crypto_op_id_t op;
  ngi541_crypto_op_status_t status : 8;
  u8 flags;
#define NGI541_CRYPTO_OP_FLAG_HMAC_CHECK	    (1 << 0)
#define NGI541_CRYPTO_OP_FLAG_CHAINED_BUFFERS (1 << 1)

  union
  {
    u8 digest_len;
    u8 tag_len;
  };

  union
  {
    u16 integ_len;
    u16 integ_n_chunks;
    u16 aad_len;
  };
} ngi541_crypto_op_t;

STATIC_ASSERT_SIZEOF (ngi541_crypto_op_t, CLIB_CACHE_LINE_BYTES);

typedef struct
{
  ngi541_crypto_alg_t alg;
  void *key_data;
  const u8 *key;
  u16 key_length;
} ngi541_crypto_key_handler_args_t;

typedef u32 (ngi541_crypto_chained_op_fn_t) (ngi541_crypto_op_t *ops[], ngi541_crypto_op_chunk_t *chunks,
					   u32 n_ops);

typedef u32 (ngi541_crypto_simple_op_fn_t) (ngi541_crypto_op_t *ops[], u32 n_ops);

typedef void (ngi541_crypto_key_fn_t) (ngi541_crypto_key_op_t kop, ngi541_crypto_key_handler_args_t a);


#endif /* NGI541_INTERNAL_CRYPTO_TYPES_H */
