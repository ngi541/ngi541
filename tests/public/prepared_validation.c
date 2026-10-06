/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


static int
expect_status (
  const char *name,
  ngi541_status_t actual,
  ngi541_status_t expected)
{
  if (actual == expected)
    return 0;

  fprintf (
    stderr,
    "%s: expected status=%d actual=%d\n",
    name,
    (int) expected,
    (int) actual);

  return 1;
}


static int
expect_null_handle (
  const char *name,
  const void *handle)
{
  if (handle == NULL)
    return 0;

  fprintf (
    stderr,
    "%s: output handle was not cleared\n",
    name);

  return 1;
}


static int
test_cipher_key_creation_validation (void)
{
  static const uint8_t key_material[32] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f,
  };

  ngi541_cipher_key_params_t params;
  ngi541_cipher_key_t *prepared_key;
  ngi541_status_t status;


  /*
   * NULL output slot.
   */
  params =
    (ngi541_cipher_key_params_t)
    {
      .struct_size =
        sizeof (ngi541_cipher_key_params_t),

      .algorithm =
        NGI541_CIPHER_AES_CTR,

      .key = key_material,
      .key_len = 16,
    };

  if (expect_status (
        "cipher create: NULL output",
        ngi541_crypto_cipher_key_create (
          &params,
          NULL),
        NGI541_STATUS_INVALID_ARGUMENT))
    return 1;


  /*
   * NULL params must clear the caller's output slot.
   */
  prepared_key =
    (ngi541_cipher_key_t *) (uintptr_t) 1;

  status =
    ngi541_crypto_cipher_key_create (
      NULL,
      &prepared_key);

  if (expect_status (
        "cipher create: NULL params",
        status,
        NGI541_STATUS_INVALID_ARGUMENT) ||
      expect_null_handle (
        "cipher create: NULL params",
        prepared_key))
    return 1;


  /*
   * Truncated public structure.
   */
  params =
    (ngi541_cipher_key_params_t)
    {
      .struct_size =
        sizeof (ngi541_cipher_key_params_t) - 1,

      .algorithm =
        NGI541_CIPHER_AES_CTR,

      .key = key_material,
      .key_len = 16,
    };

  prepared_key =
    (ngi541_cipher_key_t *) (uintptr_t) 1;

  status =
    ngi541_crypto_cipher_key_create (
      &params,
      &prepared_key);

  if (expect_status (
        "cipher create: truncated struct",
        status,
        NGI541_STATUS_INVALID_ARGUMENT) ||
      expect_null_handle (
        "cipher create: truncated struct",
        prepared_key))
    return 1;


  /*
   * Missing raw key.
   */
  params.struct_size =
    sizeof (ngi541_cipher_key_params_t);

  params.key = NULL;

  prepared_key =
    (ngi541_cipher_key_t *) (uintptr_t) 1;

  status =
    ngi541_crypto_cipher_key_create (
      &params,
      &prepared_key);

  if (expect_status (
        "cipher create: NULL key",
        status,
        NGI541_STATUS_INVALID_ARGUMENT) ||
      expect_null_handle (
        "cipher create: NULL key",
        prepared_key))
    return 1;


  /*
   * Unsupported public algorithm.
   */
  params.key = key_material;

  params.algorithm =
    (ngi541_cipher_algorithm_t) UINT32_MAX;

  prepared_key =
    (ngi541_cipher_key_t *) (uintptr_t) 1;

  status =
    ngi541_crypto_cipher_key_create (
      &params,
      &prepared_key);

  if (expect_status (
        "cipher create: unsupported algorithm",
        status,
        NGI541_STATUS_UNSUPPORTED) ||
      expect_null_handle (
        "cipher create: unsupported algorithm",
        prepared_key))
    return 1;


  /*
   * AES public API supports 16/24/32-byte keys only.
   */
  params.algorithm =
    NGI541_CIPHER_AES_CTR;

  params.key_len = 15;

  prepared_key =
    (ngi541_cipher_key_t *) (uintptr_t) 1;

  status =
    ngi541_crypto_cipher_key_create (
      &params,
      &prepared_key);

  if (expect_status (
        "cipher create: unsupported key length",
        status,
        NGI541_STATUS_UNSUPPORTED) ||
      expect_null_handle (
        "cipher create: unsupported key length",
        prepared_key))
    return 1;


  /*
   * destroy(NULL) is explicitly harmless.
   */
  ngi541_crypto_cipher_key_destroy (NULL);

  return 0;
}


static int
test_cipher_execution_validation (void)
{
  static const uint8_t key_material[16] = {
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f,
  };

  uint8_t iv[16] = { 0 };

  uint8_t input[64] = { 0 };
  uint8_t output[64] = { 0 };

  ngi541_cipher_key_params_t params;

  ngi541_cipher_key_t *ctr_key = NULL;
  ngi541_cipher_key_t *cbc_key = NULL;

  ngi541_cipher_exec_request_t request;

  ngi541_status_t status;


  params =
    (ngi541_cipher_key_params_t)
    {
      .struct_size =
        sizeof (ngi541_cipher_key_params_t),

      .algorithm =
        NGI541_CIPHER_AES_CTR,

      .key = key_material,
      .key_len = sizeof (key_material),
    };


  status =
    ngi541_crypto_cipher_key_create (
      &params,
      &ctr_key);

  if (expect_status (
        "CTR prepared key creation",
        status,
        NGI541_STATUS_OK))
    return 1;


  request =
    (ngi541_cipher_exec_request_t)
    {
      .struct_size =
        sizeof (ngi541_cipher_exec_request_t),

      .iv = iv,
      .iv_len = sizeof (iv),

      .input = input,
      .input_len = 16,

      .output = output,
      .output_capacity = sizeof (output),
    };


  if (expect_status (
        "cipher execute: NULL prepared key",
        ngi541_crypto_cipher_encrypt_prepared (
          NULL,
          &request),
        NGI541_STATUS_INVALID_ARGUMENT))
    goto fail;


  if (expect_status (
        "cipher execute: NULL request",
        ngi541_crypto_cipher_encrypt_prepared (
          ctr_key,
          NULL),
        NGI541_STATUS_INVALID_ARGUMENT))
    goto fail;


  {
    ngi541_cipher_exec_request_t invalid =
      request;

    invalid.struct_size =
      sizeof (invalid) - 1;

    if (expect_status (
          "cipher execute: truncated struct",
          ngi541_crypto_cipher_encrypt_prepared (
            ctr_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_cipher_exec_request_t invalid =
      request;

    invalid.iv = NULL;

    if (expect_status (
          "cipher execute: NULL IV",
          ngi541_crypto_cipher_encrypt_prepared (
            ctr_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_cipher_exec_request_t invalid =
      request;

    invalid.iv_len = 15;

    if (expect_status (
          "cipher execute: invalid IV length",
          ngi541_crypto_cipher_encrypt_prepared (
            ctr_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_cipher_exec_request_t invalid =
      request;

    invalid.input = NULL;
    invalid.input_len = 1;

    if (expect_status (
          "cipher execute: NULL input",
          ngi541_crypto_cipher_encrypt_prepared (
            ctr_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_cipher_exec_request_t invalid =
      request;

    invalid.output_capacity = 15;

    if (expect_status (
          "cipher execute: output too small",
          ngi541_crypto_cipher_encrypt_prepared (
            ctr_key,
            &invalid),
          NGI541_STATUS_BUFFER_TOO_SMALL))
      goto fail;
  }


  {
    ngi541_cipher_exec_request_t invalid =
      request;

    invalid.output = NULL;
    invalid.output_capacity = 16;

    if (expect_status (
          "cipher execute: NULL output",
          ngi541_crypto_cipher_encrypt_prepared (
            ctr_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  /*
   * Exact input == output is legal for CTR, but partial overlap is not.
   */
  {
    ngi541_cipher_exec_request_t invalid =
      request;

    invalid.input = input;
    invalid.input_len = 16;

    invalid.output =
      input + 1;

    invalid.output_capacity = 16;

    if (expect_status (
          "CTR execute: partial overlap",
          ngi541_crypto_cipher_encrypt_prepared (
            ctr_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


#if SIZE_MAX > UINT32_MAX
  /*
   * Validate the public/internal u32 operation-size boundary without
   * allowing the implementation to dereference the tiny test buffers.
   */
  {
    ngi541_cipher_exec_request_t invalid =
      request;

    invalid.input_len =
      (size_t) UINT32_MAX + 1u;

    invalid.output_capacity =
      invalid.input_len;

    if (expect_status (
          "cipher execute: length above UINT32_MAX",
          ngi541_crypto_cipher_encrypt_prepared (
            ctr_key,
            &invalid),
          NGI541_STATUS_UNSUPPORTED))
      goto fail;
  }
#endif


  /*
   * Zero-length CTR is a valid boundary operation. NULL data buffers
   * are allowed because no payload bytes are read or written.
   */
  {
    ngi541_cipher_exec_request_t zero =
      request;

    zero.input = NULL;
    zero.input_len = 0;

    zero.output = NULL;
    zero.output_capacity = 0;

    if (expect_status (
          "CTR execute: zero length",
          ngi541_crypto_cipher_encrypt_prepared (
            ctr_key,
            &zero),
          NGI541_STATUS_OK))
      goto fail;
  }


  /*
   * CBC has a separate block-alignment contract.
   */
  params.algorithm =
    NGI541_CIPHER_AES_CBC;

  status =
    ngi541_crypto_cipher_key_create (
      &params,
      &cbc_key);

  if (expect_status (
        "CBC prepared key creation",
        status,
        NGI541_STATUS_OK))
    goto fail;


  {
    ngi541_cipher_exec_request_t invalid =
      request;

    invalid.input_len = 15;
    invalid.output_capacity = 15;

    if (expect_status (
          "CBC execute: non-block length",
          ngi541_crypto_cipher_encrypt_prepared (
            cbc_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  ngi541_crypto_cipher_key_destroy (
    cbc_key);

  ngi541_crypto_cipher_key_destroy (
    ctr_key);

  return 0;


fail:

  ngi541_crypto_cipher_key_destroy (
    cbc_key);

  ngi541_crypto_cipher_key_destroy (
    ctr_key);

  return 1;
}


static int
test_aead_key_creation_validation (void)
{
  static const uint8_t key_material[32] = {
    0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x3e, 0x3f,
  };

  ngi541_aead_key_params_t params;
  ngi541_aead_key_t *prepared_key;
  ngi541_status_t status;


  params =
    (ngi541_aead_key_params_t)
    {
      .struct_size =
        sizeof (ngi541_aead_key_params_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = key_material,
      .key_len = 16,
    };


  if (expect_status (
        "AEAD create: NULL output",
        ngi541_crypto_aead_key_create (
          &params,
          NULL),
        NGI541_STATUS_INVALID_ARGUMENT))
    return 1;


  prepared_key =
    (ngi541_aead_key_t *) (uintptr_t) 1;

  status =
    ngi541_crypto_aead_key_create (
      NULL,
      &prepared_key);

  if (expect_status (
        "AEAD create: NULL params",
        status,
        NGI541_STATUS_INVALID_ARGUMENT) ||
      expect_null_handle (
        "AEAD create: NULL params",
        prepared_key))
    return 1;


  params.struct_size =
    sizeof (ngi541_aead_key_params_t) - 1;

  prepared_key =
    (ngi541_aead_key_t *) (uintptr_t) 1;

  status =
    ngi541_crypto_aead_key_create (
      &params,
      &prepared_key);

  if (expect_status (
        "AEAD create: truncated struct",
        status,
        NGI541_STATUS_INVALID_ARGUMENT) ||
      expect_null_handle (
        "AEAD create: truncated struct",
        prepared_key))
    return 1;


  params.struct_size =
    sizeof (ngi541_aead_key_params_t);

  params.key = NULL;

  prepared_key =
    (ngi541_aead_key_t *) (uintptr_t) 1;

  status =
    ngi541_crypto_aead_key_create (
      &params,
      &prepared_key);

  if (expect_status (
        "AEAD create: NULL key",
        status,
        NGI541_STATUS_INVALID_ARGUMENT) ||
      expect_null_handle (
        "AEAD create: NULL key",
        prepared_key))
    return 1;


  params.key = key_material;

  params.algorithm =
    (ngi541_aead_algorithm_t) UINT32_MAX;

  prepared_key =
    (ngi541_aead_key_t *) (uintptr_t) 1;

  status =
    ngi541_crypto_aead_key_create (
      &params,
      &prepared_key);

  if (expect_status (
        "AEAD create: unsupported algorithm",
        status,
        NGI541_STATUS_UNSUPPORTED) ||
      expect_null_handle (
        "AEAD create: unsupported algorithm",
        prepared_key))
    return 1;


  params.algorithm =
    NGI541_AEAD_AES_GCM;

  params.key_len = 15;

  prepared_key =
    (ngi541_aead_key_t *) (uintptr_t) 1;

  status =
    ngi541_crypto_aead_key_create (
      &params,
      &prepared_key);

  if (expect_status (
        "AEAD create: unsupported key length",
        status,
        NGI541_STATUS_UNSUPPORTED) ||
      expect_null_handle (
        "AEAD create: unsupported key length",
        prepared_key))
    return 1;


  ngi541_crypto_aead_key_destroy (NULL);

  return 0;
}


static int
test_aead_execution_validation (void)
{
  static const uint8_t key_material[16] = {
    0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b,
    0x4c, 0x4d, 0x4e, 0x4f,
  };

  uint8_t iv[12] = { 0 };
  uint8_t aad[32] = { 0 };

  uint8_t plaintext[64] = { 0 };
  uint8_t ciphertext[64] = { 0 };

  uint8_t tag[16] = { 0 };

  ngi541_aead_key_params_t params;
  ngi541_aead_key_t *prepared_key = NULL;

  ngi541_aead_encrypt_exec_request_t encrypt_request;
  ngi541_aead_decrypt_exec_request_t decrypt_request;

  ngi541_status_t status;


  params =
    (ngi541_aead_key_params_t)
    {
      .struct_size =
        sizeof (ngi541_aead_key_params_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = key_material,
      .key_len = sizeof (key_material),
    };


  status =
    ngi541_crypto_aead_key_create (
      &params,
      &prepared_key);

  if (expect_status (
        "AEAD prepared key creation",
        status,
        NGI541_STATUS_OK))
    return 1;


  encrypt_request =
    (ngi541_aead_encrypt_exec_request_t)
    {
      .struct_size =
        sizeof (
          ngi541_aead_encrypt_exec_request_t),

      .iv = iv,
      .iv_len = sizeof (iv),

      .aad = aad,
      .aad_len = 8,

      .plaintext = plaintext,
      .plaintext_len = 32,

      .ciphertext = ciphertext,
      .ciphertext_capacity =
        sizeof (ciphertext),

      .tag = tag,
      .tag_len = sizeof (tag),
    };


  if (expect_status (
        "AEAD encrypt: NULL prepared key",
        ngi541_crypto_aead_encrypt_prepared (
          NULL,
          &encrypt_request),
        NGI541_STATUS_INVALID_ARGUMENT))
    goto fail;


  if (expect_status (
        "AEAD encrypt: NULL request",
        ngi541_crypto_aead_encrypt_prepared (
          prepared_key,
          NULL),
        NGI541_STATUS_INVALID_ARGUMENT))
    goto fail;


  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.struct_size =
      sizeof (invalid) - 1;

    if (expect_status (
          "AEAD encrypt: truncated struct",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.iv = NULL;

    if (expect_status (
          "AEAD encrypt: NULL IV",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.tag = NULL;

    if (expect_status (
          "AEAD encrypt: NULL tag",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.aad = NULL;
    invalid.aad_len = 8;

    if (expect_status (
          "AEAD encrypt: NULL AAD",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.plaintext = NULL;
    invalid.plaintext_len = 1;

    if (expect_status (
          "AEAD encrypt: NULL plaintext",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.ciphertext_capacity = 31;

    if (expect_status (
          "AEAD encrypt: output too small",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_BUFFER_TOO_SMALL))
      goto fail;
  }


  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.ciphertext = NULL;
    invalid.ciphertext_capacity = 32;

    if (expect_status (
          "AEAD encrypt: NULL ciphertext",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.iv_len = 11;

    if (expect_status (
          "AEAD encrypt: unsupported IV length",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_UNSUPPORTED))
      goto fail;
  }


  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.tag_len = 12;

    if (expect_status (
          "AEAD encrypt: unsupported tag length",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_UNSUPPORTED))
      goto fail;
  }


  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.aad_len =
      (size_t) UINT16_MAX + 1u;

    if (expect_status (
          "AEAD encrypt: AAD above UINT16_MAX",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_UNSUPPORTED))
      goto fail;
  }


#if SIZE_MAX > UINT32_MAX
  {
    ngi541_aead_encrypt_exec_request_t invalid =
      encrypt_request;

    invalid.plaintext_len =
      (size_t) UINT32_MAX + 1u;

    invalid.ciphertext_capacity =
      invalid.plaintext_len;

    if (expect_status (
          "AEAD encrypt: payload above UINT32_MAX",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_UNSUPPORTED))
      goto fail;
  }
#endif


  /*
   * Zero-length GCM payload is valid. A tag is still generated.
   */
  {
    ngi541_aead_encrypt_exec_request_t zero =
      encrypt_request;

    zero.aad = NULL;
    zero.aad_len = 0;

    zero.plaintext = NULL;
    zero.plaintext_len = 0;

    zero.ciphertext = NULL;
    zero.ciphertext_capacity = 0;

    if (expect_status (
          "AEAD encrypt: zero payload",
          ngi541_crypto_aead_encrypt_prepared (
            prepared_key,
            &zero),
          NGI541_STATUS_OK))
      goto fail;
  }


  /*
   * Produce a valid ciphertext/tag for decrypt validation.
   */
  status =
    ngi541_crypto_aead_encrypt_prepared (
      prepared_key,
      &encrypt_request);

  if (expect_status (
        "AEAD encrypt setup for decrypt validation",
        status,
        NGI541_STATUS_OK))
    goto fail;


  decrypt_request =
    (ngi541_aead_decrypt_exec_request_t)
    {
      .struct_size =
        sizeof (
          ngi541_aead_decrypt_exec_request_t),

      .iv = iv,
      .iv_len = sizeof (iv),

      .aad = aad,
      .aad_len = 8,

      .ciphertext = ciphertext,
      .ciphertext_len = 32,

      .tag = tag,
      .tag_len = sizeof (tag),

      .plaintext = plaintext,
      .plaintext_capacity =
        sizeof (plaintext),
    };


  if (expect_status (
        "AEAD decrypt: NULL prepared key",
        ngi541_crypto_aead_decrypt_prepared (
          NULL,
          &decrypt_request),
        NGI541_STATUS_INVALID_ARGUMENT))
    goto fail;


  if (expect_status (
        "AEAD decrypt: NULL request",
        ngi541_crypto_aead_decrypt_prepared (
          prepared_key,
          NULL),
        NGI541_STATUS_INVALID_ARGUMENT))
    goto fail;


  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.struct_size =
      sizeof (invalid) - 1;

    if (expect_status (
          "AEAD decrypt: truncated struct",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.iv = NULL;

    if (expect_status (
          "AEAD decrypt: NULL IV",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.tag = NULL;

    if (expect_status (
          "AEAD decrypt: NULL tag",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.aad = NULL;
    invalid.aad_len = 8;

    if (expect_status (
          "AEAD decrypt: NULL AAD",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.ciphertext = NULL;
    invalid.ciphertext_len = 1;

    if (expect_status (
          "AEAD decrypt: NULL ciphertext",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.plaintext_capacity = 31;

    if (expect_status (
          "AEAD decrypt: plaintext too small",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_BUFFER_TOO_SMALL))
      goto fail;
  }


  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.plaintext = NULL;
    invalid.plaintext_capacity = 32;

    if (expect_status (
          "AEAD decrypt: NULL plaintext",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_INVALID_ARGUMENT))
      goto fail;
  }


  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.iv_len = 11;

    if (expect_status (
          "AEAD decrypt: unsupported IV length",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_UNSUPPORTED))
      goto fail;
  }


  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.tag_len = 12;

    if (expect_status (
          "AEAD decrypt: unsupported tag length",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_UNSUPPORTED))
      goto fail;
  }


  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.aad_len =
      (size_t) UINT16_MAX + 1u;

    if (expect_status (
          "AEAD decrypt: AAD above UINT16_MAX",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_UNSUPPORTED))
      goto fail;
  }


#if SIZE_MAX > UINT32_MAX
  {
    ngi541_aead_decrypt_exec_request_t invalid =
      decrypt_request;

    invalid.ciphertext_len =
      (size_t) UINT32_MAX + 1u;

    invalid.plaintext_capacity =
      invalid.ciphertext_len;

    if (expect_status (
          "AEAD decrypt: payload above UINT32_MAX",
          ngi541_crypto_aead_decrypt_prepared (
            prepared_key,
            &invalid),
          NGI541_STATUS_UNSUPPORTED))
      goto fail;
  }
#endif


  ngi541_crypto_aead_key_destroy (
    prepared_key);

  return 0;


fail:

  ngi541_crypto_aead_key_destroy (
    prepared_key);

  return 1;
}


int
main (void)
{
  ngi541_status_t status;


  status =
    ngi541_engine_init ();

  if (expect_status (
        "engine init",
        status,
        NGI541_STATUS_OK))
    return 1;


  if (test_cipher_key_creation_validation () != 0)
    return 1;


  if (test_cipher_execution_validation () != 0)
    return 1;


  if (test_aead_key_creation_validation () != 0)
    return 1;


  if (test_aead_execution_validation () != 0)
    return 1;


  return 0;
}