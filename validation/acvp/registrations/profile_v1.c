/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "registrations/profile_v1.h"

#include "callbacks/aes_cbc.h"

ACVP_RESULT
ngi541_acvp_register_profile_v1 (
  ACVP_CTX *ctx)
{
  ACVP_RESULT result;

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

  return ACVP_SUCCESS;
}