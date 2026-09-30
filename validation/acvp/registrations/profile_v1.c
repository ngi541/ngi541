/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "registrations/profile_v1.h"

#include "callbacks/aes_cbc.h"
#include "callbacks/aes_ctr.h"
#include "callbacks/aes_gcm.h"
#include "callbacks/sha2.h"

ACVP_RESULT
ngi541_acvp_register_profile_v1 (
  ACVP_CTX *ctx)
{
  return
    ngi541_acvp_register_profile_v1_selected (
      ctx,
      NGI541_ACVP_PROFILE_V1_ALL);
}


ACVP_RESULT
ngi541_acvp_register_profile_v1_selected (
  ACVP_CTX *ctx,
  unsigned int profile_mask)
{
  ACVP_RESULT result;

  if (profile_mask & NGI541_ACVP_PROFILE_AES_CBC)
  {

        result =
            acvp_cap_sym_cipher_enable (
            ctx,
            ACVP_AES_CBC,
            ngi541_acvp_aes_cbc_handler);

        if (result != ACVP_SUCCESS)
            return result;

        result =
            acvp_cap_sym_cipher_set_parm (
            ctx,
            ACVP_AES_CBC,
            ACVP_SYM_CIPH_PARM_DIR,
            ACVP_SYM_CIPH_DIR_BOTH);

        if (result != ACVP_SUCCESS)
            return result;

        result =
            acvp_cap_sym_cipher_set_parm (
            ctx,
            ACVP_AES_CBC,
            ACVP_SYM_CIPH_PARM_IVGEN_SRC,
            ACVP_SYM_CIPH_IVGEN_SRC_NA);

        if (result != ACVP_SUCCESS)
            return result;

        result =
            acvp_cap_sym_cipher_set_parm (
            ctx,
            ACVP_AES_CBC,
            ACVP_SYM_CIPH_PARM_IVGEN_MODE,
            ACVP_SYM_CIPH_IVGEN_MODE_NA);

        if (result != ACVP_SUCCESS)
            return result;

        result =
            acvp_cap_sym_cipher_set_parm (
            ctx,
            ACVP_AES_CBC,
            ACVP_SYM_CIPH_KEYLEN,
            128);

        if (result != ACVP_SUCCESS)
            return result;

        result =
            acvp_cap_sym_cipher_set_parm (
            ctx,
            ACVP_AES_CBC,
            ACVP_SYM_CIPH_KEYLEN,
            192);

        if (result != ACVP_SUCCESS)
            return result;

        result =
            acvp_cap_sym_cipher_set_parm (
            ctx,
            ACVP_AES_CBC,
            ACVP_SYM_CIPH_KEYLEN,
            256);

        if (result != ACVP_SUCCESS)
            return result;
    }

  /*
   * AES-CTR
   *
   * NGI541 uses an incrementing 128-bit counter block.
   * Counter overflow support is intentionally not advertised.
   */

if (profile_mask & NGI541_ACVP_PROFILE_AES_CTR)
  {

  result =
    acvp_cap_sym_cipher_enable (
      ctx,
      ACVP_AES_CTR,
      ngi541_acvp_aes_ctr_handler);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_CTR,
      ACVP_SYM_CIPH_PARM_DIR,
      ACVP_SYM_CIPH_DIR_BOTH);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_CTR,
      ACVP_SYM_CIPH_PARM_PERFORM_CTR,
      1);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_CTR,
      ACVP_SYM_CIPH_PARM_CTR_INCR,
      1);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_CTR,
      ACVP_SYM_CIPH_PARM_CTR_OVRFLW,
      0);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_CTR,
      ACVP_SYM_CIPH_KEYLEN,
      128);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_CTR,
      ACVP_SYM_CIPH_KEYLEN,
      192);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_CTR,
      ACVP_SYM_CIPH_KEYLEN,
      256);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_domain (
      ctx,
      ACVP_AES_CTR,
      ACVP_SYM_CIPH_DOMAIN_PTLEN,
      8,
      128,
      8);

  if (result != ACVP_SUCCESS)
    return result;
  }

  /*
   * AES-GCM
   *
   * NGI541 ACVP profile v1 intentionally advertises only the
   * subset supported by the current public NGI541 API:
   *
   *   key:     128 / 192 / 256 bits
   *   IV:      96 bits
   *   tag:     128 bits
   *   payload: byte-aligned
   *   AAD:     byte-aligned
   *
   * IV generation is external. NGI541 consumes the IV supplied
   * by the ACVP test case and does not generate GCM IVs.
   */

if (profile_mask & NGI541_ACVP_PROFILE_AES_GCM)
  {

  result =
    acvp_cap_sym_cipher_enable (
      ctx,
      ACVP_AES_GCM,
      ngi541_acvp_aes_gcm_handler);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_GCM,
      ACVP_SYM_CIPH_PARM_DIR,
      ACVP_SYM_CIPH_DIR_BOTH);

  if (result != ACVP_SUCCESS)
    return result;

/*
 * NGI541 does not internally generate GCM IVs.
 * The ACVP test vector supplies the IV to the callback.
 *
 * libacvp represents AES-GCM IV source/mode combinations through
 * iv_mode_matrix. Therefore GCM registration must use
 * acvp_cap_sym_cipher_set_iv_modes() rather than setting IVGEN_SRC
 * independently.
 *
 * Profile v1 advertises externally supplied IVs using the
 * deterministic construction method defined by SP 800-38D 8.2.1.
 */
result =
  acvp_cap_sym_cipher_set_iv_modes (
    ctx,
    ACVP_AES_GCM,
    ACVP_SYM_CIPH_IVGEN_MODE_821,
    ACVP_SYM_CIPH_IVGEN_SRC_EXT);

if (result != ACVP_SUCCESS)
  return result;

  /*
   * AES key sizes supported by the public NGI541 GCM API.
   */
  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_GCM,
      ACVP_SYM_CIPH_KEYLEN,
      128);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_GCM,
      ACVP_SYM_CIPH_KEYLEN,
      192);

  if (result != ACVP_SUCCESS)
    return result;

  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_GCM,
      ACVP_SYM_CIPH_KEYLEN,
      256);

  if (result != ACVP_SUCCESS)
    return result;

  /*
   * Current NGI541 GCM implementation supports a 96-bit IV only.
   *
   * Registration domains are expressed in bits.
   */
  result =
  acvp_cap_sym_cipher_set_parm (
    ctx,
    ACVP_AES_GCM,
    ACVP_SYM_CIPH_IVLEN,
    96);

  if (result != ACVP_SUCCESS)
    return result;

  /*
   * Current NGI541 public GCM contract supports a 128-bit tag only.
   */
  result =
    acvp_cap_sym_cipher_set_parm (
      ctx,
      ACVP_AES_GCM,
      ACVP_SYM_CIPH_TAGLEN,
      128);

  if (result != ACVP_SUCCESS)
    return result;

  /*
   * Advertise byte-aligned payload lengths.
   *
   * The ACVP capability domain is expressed in bits; the callback
   * receives the parsed payload length in bytes.
   */
  result =
    acvp_cap_sym_cipher_set_domain (
      ctx,
      ACVP_AES_GCM,
      ACVP_SYM_CIPH_DOMAIN_PTLEN,
      0,
      65536,
      8);

  if (result != ACVP_SUCCESS)
    return result;

  /*
   * Advertise byte-aligned AAD lengths.
   */
  result =
    acvp_cap_sym_cipher_set_domain (
      ctx,
      ACVP_AES_GCM,
      ACVP_SYM_CIPH_DOMAIN_AADLEN,
      0,
      65536,
      8);

  if (result != ACVP_SUCCESS)
    return result;

  }

  /*
   * SHA2-256
   *
   * NGI541 profile v1 currently exposes byte-aligned one-shot
   * SHA-256 messages through the public hash API.
   *
   * ACVP registration domains are expressed in bits.
   */
  if (profile_mask & NGI541_ACVP_PROFILE_SHA2_256)
    {
      result =
        acvp_cap_hash_enable (
          ctx,
          ACVP_HASH_SHA256,
          ngi541_acvp_sha2_handler);

      if (result != ACVP_SUCCESS)
        return result;

      result =
        acvp_cap_hash_set_domain (
          ctx,
          ACVP_HASH_SHA256,
          ACVP_HASH_MESSAGE_LEN,
          0,
          65536,
          8);

      if (result != ACVP_SUCCESS)
        return result;
    }

  /*
   * SHA2-224
   *
   * NGI541 profile v1 exposes byte-aligned one-shot SHA-224
   * messages through the public hash API.
   *
   * ACVP registration domains are expressed in bits.
   */
  if (profile_mask & NGI541_ACVP_PROFILE_SHA2_224)
    {
      result =
        acvp_cap_hash_enable (
          ctx,
          ACVP_HASH_SHA224,
          ngi541_acvp_sha2_handler);

      if (result != ACVP_SUCCESS)
        return result;

      result =
        acvp_cap_hash_set_domain (
          ctx,
          ACVP_HASH_SHA224,
          ACVP_HASH_MESSAGE_LEN,
          0,
          65536,
          8);

      if (result != ACVP_SUCCESS)
        return result;
    }

  return ACVP_SUCCESS;
}