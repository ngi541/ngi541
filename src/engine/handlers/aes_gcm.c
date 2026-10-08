/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 *
 * Modified for NGI541: source layout and include paths.
 */

#include "support/compat/cpu.h"

#include "engine/internal/crypto_types.h"
#include "engine/internal/native.h"
#include "engine/internal/prepared.h"
#include "core/aes/aes_gcm.h"

#if __GNUC__ > 4 && !__clang__ && CLIB_DEBUG == 0
#pragma GCC optimize("O3")
#endif

static_always_inline u32
aes_ops_enc_aes_gcm (ngi541_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
		     u32 fixed, u32 aad_len)
{
  ngi541_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;

next:
  kd = (aes_gcm_key_data_t *) op->key_data;
  aes_gcm (op->src, op->dst, op->aad, (u8 *) op->iv, op->tag, op->len,
	   fixed ? aad_len : op->aad_len, fixed ? 16 : op->tag_len, kd,
	   AES_KEY_ROUNDS (ks), AES_GCM_OP_ENCRYPT);
  op->status = NGI541_CRYPTO_OP_STATUS_COMPLETED;

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline u32
aes_ops_dec_aes_gcm (ngi541_crypto_op_t *ops[], u32 n_ops, aes_key_size_t ks,
		     u32 fixed, u32 aad_len)
{
  ngi541_crypto_op_t *op = ops[0];
  aes_gcm_key_data_t *kd;
  u32 n_left = n_ops;
  int rv;

next:
  kd = (aes_gcm_key_data_t *) op->key_data;
  rv = aes_gcm (op->src, op->dst, op->aad, (u8 *) op->iv, op->tag, op->len,
		fixed ? aad_len : op->aad_len, fixed ? 16 : op->tag_len, kd,
		AES_KEY_ROUNDS (ks), AES_GCM_OP_DECRYPT);

  if (rv)
    {
      op->status = NGI541_CRYPTO_OP_STATUS_COMPLETED;
    }
  else
    {
      op->status = NGI541_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
      n_ops--;
    }

  if (--n_left)
    {
      op += 1;
      goto next;
    }

  return n_ops;
}

static_always_inline void
aes_gcm_key_exp (ngi541_crypto_key_op_t kop, aes_gcm_key_data_t *key_data, const u8 *data,
		 aes_key_size_t ks)
{
  if (kop == NGI541_CRYPTO_KEY_OP_ADD || kop == NGI541_CRYPTO_KEY_OP_MODIFY)
    {
      clib_aes_gcm_key_expand (key_data, data, ks);
    }
}

/*
 * -------------------------------------------------------------------------
 * Direct prepared AES-GCM execution
 * -------------------------------------------------------------------------
 *
 * This path bypasses the generic ngi541_crypto_op_t/provider execution
 * envelope. The prepared key object will bind one of the key-size-specific
 * executors once during key creation.
 */

static_always_inline ngi541_status_t
aes_gcm_prepared_encrypt (
  const void *key_data,
  uint8_t *iv,
  const uint8_t *aad,
  uint16_t aad_len,
  const uint8_t *src,
  uint8_t *dst,
  uint32_t len,
  uint8_t *tag,
  aes_key_size_t ks)
{
  const aes_gcm_key_data_t *kd =
    (const aes_gcm_key_data_t *) key_data;

  /*
   * Preserve the existing AAD8/AAD12 specialization without performing
   * runtime operation mapping or handler lookup.
   *
   * The only runtime decision here depends on packet-local AAD length.
   */
  if (aad_len == 8)
    {
      aes_gcm (
        (u8 *) src,
        dst,
        (u8 *) aad,
        iv,
        tag,
        len,
        8,
        16,
        kd,
        AES_KEY_ROUNDS (ks),
        AES_GCM_OP_ENCRYPT);
    }
  else if (aad_len == 12)
    {
      aes_gcm (
        (u8 *) src,
        dst,
        (u8 *) aad,
        iv,
        tag,
        len,
        12,
        16,
        kd,
        AES_KEY_ROUNDS (ks),
        AES_GCM_OP_ENCRYPT);
    }
  else
    {
      aes_gcm (
        (u8 *) src,
        dst,
        (u8 *) aad,
        iv,
        tag,
        len,
        aad_len,
        16,
        kd,
        AES_KEY_ROUNDS (ks),
        AES_GCM_OP_ENCRYPT);
    }

  return NGI541_STATUS_OK;
}


static_always_inline ngi541_status_t
aes_gcm_prepared_decrypt (
  const void *key_data,
  uint8_t *iv,
  const uint8_t *aad,
  uint16_t aad_len,
  const uint8_t *src,
  uint8_t *dst,
  uint32_t len,
  uint8_t *tag,
  aes_key_size_t ks)
{
  const aes_gcm_key_data_t *kd =
    (const aes_gcm_key_data_t *) key_data;

  int rv;

  if (aad_len == 8)
    {
      rv = aes_gcm (
        (u8 *) src,
        dst,
        (u8 *) aad,
        iv,
        tag,
        len,
        8,
        16,
        kd,
        AES_KEY_ROUNDS (ks),
        AES_GCM_OP_DECRYPT);
    }
  else if (aad_len == 12)
    {
      rv = aes_gcm (
        (u8 *) src,
        dst,
        (u8 *) aad,
        iv,
        tag,
        len,
        12,
        16,
        kd,
        AES_KEY_ROUNDS (ks),
        AES_GCM_OP_DECRYPT);
    }
  else
    {
      rv = aes_gcm (
        (u8 *) src,
        dst,
        (u8 *) aad,
        iv,
        tag,
        len,
        aad_len,
        16,
        kd,
        AES_KEY_ROUNDS (ks),
        AES_GCM_OP_DECRYPT);
    }

  return rv
    ? NGI541_STATUS_OK
    : NGI541_STATUS_AUTH_FAILED;
}


#define NGI541_DEFINE_PREPARED_AES_GCM(bits, ks)                         \
  static ngi541_status_t                                                  \
  aes##bits##_gcm_prepared_key_init (                                    \
    void *key_data,                                                       \
    const uint8_t *key,                                                   \
    size_t key_len)                                                       \
  {                                                                       \
    if (key_data == NULL ||                                               \
        key == NULL ||                                                    \
        key_len != AES_KEY_BYTES (ks))                                    \
      return NGI541_STATUS_INTERNAL_ERROR;                                \
                                                                          \
    clib_memset (                                                         \
      key_data,                                                           \
      0,                                                                  \
      sizeof (aes_gcm_key_data_t));                                       \
                                                                          \
    clib_aes_gcm_key_expand (                                             \
      (aes_gcm_key_data_t *) key_data,                                    \
      key,                                                                \
      ks);                                                                \
                                                                          \
    return NGI541_STATUS_OK;                                              \
  }                                                                       \
                                                                          \
  static ngi541_status_t                                                  \
  aes##bits##_gcm_prepared_encrypt (                                      \
    const void *key_data,                                                 \
    uint8_t *iv,                                                          \
    const uint8_t *aad,                                                   \
    uint16_t aad_len,                                                     \
    const uint8_t *src,                                                   \
    uint8_t *dst,                                                         \
    uint32_t len,                                                         \
    uint8_t *tag)                                                         \
  {                                                                       \
    return aes_gcm_prepared_encrypt (                                     \
      key_data, iv, aad, aad_len, src, dst, len, tag, ks);                \
  }                                                                       \
                                                                          \
  static ngi541_status_t                                                  \
  aes##bits##_gcm_prepared_decrypt (                                      \
    const void *key_data,                                                 \
    uint8_t *iv,                                                          \
    const uint8_t *aad,                                                   \
    uint16_t aad_len,                                                     \
    const uint8_t *src,                                                   \
    uint8_t *dst,                                                         \
    uint32_t len,                                                         \
    uint8_t *tag)                                                         \
  {                                                                       \
    return aes_gcm_prepared_decrypt (                                     \
      key_data, iv, aad, aad_len, src, dst, len, tag, ks);                \
  }

NGI541_DEFINE_PREPARED_AES_GCM (128, AES_KEY_128)
NGI541_DEFINE_PREPARED_AES_GCM (192, AES_KEY_192)
NGI541_DEFINE_PREPARED_AES_GCM (256, AES_KEY_256)

#undef NGI541_DEFINE_PREPARED_AES_GCM

#define _(x)                                                                                       \
  static u32 aes_ops_dec_aes_gcm_##x (ngi541_crypto_op_t *ops[], u32 n_ops)                          \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, 0, 0);                                    \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x (ngi541_crypto_op_t *ops[], u32 n_ops)                          \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, 0, 0);                                    \
  }                                                                                                \
  static u32 aes_ops_dec_aes_gcm_##x##_tag16_aad8 (ngi541_crypto_op_t *ops[], u32 n_ops)             \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, 1, 8);                                    \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x##_tag16_aad8 (ngi541_crypto_op_t *ops[], u32 n_ops)             \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, 1, 8);                                    \
  }                                                                                                \
  static u32 aes_ops_dec_aes_gcm_##x##_tag16_aad12 (ngi541_crypto_op_t *ops[], u32 n_ops)            \
  {                                                                                                \
    return aes_ops_dec_aes_gcm (ops, n_ops, AES_KEY_##x, 1, 12);                                   \
  }                                                                                                \
  static u32 aes_ops_enc_aes_gcm_##x##_tag16_aad12 (ngi541_crypto_op_t *ops[], u32 n_ops)            \
  {                                                                                                \
    return aes_ops_enc_aes_gcm (ops, n_ops, AES_KEY_##x, 1, 12);                                   \
  }                                                                                                \
  static void aes_gcm_key_exp_##x (ngi541_crypto_key_op_t kop, ngi541_crypto_key_handler_args_t a)     \
  {                                                                                                \
    return aes_gcm_key_exp (kop, a.key_data, a.key, AES_KEY_##x);                       \
  }

_ (128)
_ (192)
_ (256)

#undef _

static int
probe (void)
{
#if defined(__VAES__) && defined(__AVX512F__)
  if (clib_cpu_supports_vpclmulqdq () && clib_cpu_supports_vaes () &&
      clib_cpu_supports_avx512f ())
    return 50;
#elif defined(__VAES__)
  if (clib_cpu_supports_vpclmulqdq () && clib_cpu_supports_vaes ())
    return 40;
#elif defined(__AVX512F__)
  if (clib_cpu_supports_pclmulqdq () && clib_cpu_supports_avx512f ())
    return 30;
#elif defined(__AVX2__)
  if (clib_cpu_supports_pclmulqdq () && clib_cpu_supports_avx2 ())
    return 20;
#elif __AES__
  if (clib_cpu_supports_pclmulqdq () && clib_cpu_supports_aes ())
    return 10;
#elif __aarch64__
  if (clib_cpu_supports_aarch64_aes ())
    return 10;
#endif
  return -1;
}

/*
 * Compile-time-defined prepared implementations.
 *
 * CPU support is checked only when an implementation is requested during
 * key creation. No probe or implementation selection occurs in the data
 * path.
 */

static const ngi541_prepared_aead_impl_t
aes128_gcm_prepared_impl = {
  .key_data_size = sizeof (aes_gcm_key_data_t),
  .key_init = aes128_gcm_prepared_key_init,
  .key_cleanup = NULL,
  .encrypt = aes128_gcm_prepared_encrypt,
  .decrypt = aes128_gcm_prepared_decrypt,
};

static const ngi541_prepared_aead_impl_t
aes192_gcm_prepared_impl = {
  .key_data_size = sizeof (aes_gcm_key_data_t),
  .key_init = aes192_gcm_prepared_key_init,
  .key_cleanup = NULL,
  .encrypt = aes192_gcm_prepared_encrypt,
  .decrypt = aes192_gcm_prepared_decrypt,
};

static const ngi541_prepared_aead_impl_t
aes256_gcm_prepared_impl = {
  .key_data_size = sizeof (aes_gcm_key_data_t),
  .key_init = aes256_gcm_prepared_key_init,
  .key_cleanup = NULL,
  .encrypt = aes256_gcm_prepared_encrypt,
  .decrypt = aes256_gcm_prepared_decrypt,
};


const ngi541_prepared_aead_impl_t *
ngi541_native_prepared_aes_gcm_get (
  size_t key_len)
{
  /*
   * CPU/ISA selection is control-plane work.
   *
   * This probe happens when the prepared key is created, never when a
   * packet is encrypted or decrypted.
   */
  if (probe () < 0)
    return NULL;

  switch (key_len)
    {
    case 16:
      return &aes128_gcm_prepared_impl;

    case 24:
      return &aes192_gcm_prepared_impl;

    case 32:
      return &aes256_gcm_prepared_impl;

    default:
      return NULL;
    }
}

#define _(b)                                                                                       \
  NGI541_NATIVE_OP_HANDLER (aes_##b##_gcm_enc) = {                                                 \
    .op_id = NGI541_CRYPTO_OP_AES_##b##_GCM_ENC,                                                     \
    .fn = aes_ops_enc_aes_gcm_##b,                                                                 \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  NGI541_NATIVE_OP_HANDLER (aes_##b##_gcm_dec) = {                                                 \
    .op_id = NGI541_CRYPTO_OP_AES_##b##_GCM_DEC,                                                     \
    .fn = aes_ops_dec_aes_gcm_##b,                                                                 \
    .probe = probe,                                                                                \
  };                                                                                               \
  NGI541_NATIVE_OP_HANDLER (aes_##b##_gcm_enc_tag16_aad8) = {                                      \
    .op_id = NGI541_CRYPTO_OP_AES_##b##_GCM_TAG16_AAD8_ENC,                                          \
    .fn = aes_ops_enc_aes_gcm_##b##_tag16_aad8,                                                    \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  NGI541_NATIVE_OP_HANDLER (aes_##b##_gcm_dec_tag16_aad8) = {                                      \
    .op_id = NGI541_CRYPTO_OP_AES_##b##_GCM_TAG16_AAD8_DEC,                                          \
    .fn = aes_ops_dec_aes_gcm_##b##_tag16_aad8,                                                    \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  NGI541_NATIVE_OP_HANDLER (aes_##b##_gcm_enc_tag16_aad12) = {                                     \
    .op_id = NGI541_CRYPTO_OP_AES_##b##_GCM_TAG16_AAD12_ENC,                                         \
    .fn = aes_ops_enc_aes_gcm_##b##_tag16_aad12,                                                   \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  NGI541_NATIVE_OP_HANDLER (aes_##b##_gcm_dec_tag16_aad12) = {                                     \
    .op_id = NGI541_CRYPTO_OP_AES_##b##_GCM_TAG16_AAD12_DEC,                                         \
    .fn = aes_ops_dec_aes_gcm_##b##_tag16_aad12,                                                   \
    .probe = probe,                                                                                \
  };                                                                                               \
                                                                                                   \
  NGI541_NATIVE_KEY_HANDLER (aes_##b##_gcm) = {                                                    \
    .alg_id = NGI541_CRYPTO_ALG_AES_##b##_GCM,                                                       \
    .key_fn = aes_gcm_key_exp_##b,                                                                 \
    .probe = probe,                                                                                \
    .key_data_size = sizeof (aes_gcm_key_data_t),                                                    \
  };

_ (128) _ (192) _ (256)
#undef _

void
ngi541_native_link_aes_gcm_handlers (void)
{
}