/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "openssl_ref.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <limits.h>
#include <string.h>

int
ngi541_diff_openssl_reference_info (
  ngi541_diff_reference_info_t *info)
{
  if (info == NULL)
    return 1;

  info->id =
    NGI541_DIFF_REFERENCE_OPENSSL;

  info->name =
    "OpenSSL";

  info->version =
    OpenSSL_version (
      OPENSSL_VERSION);

  return 0;
}

static const EVP_CIPHER *
ngi541_diff_openssl_aes_cbc_cipher (
  size_t key_len)
{
  switch (key_len)
    {
    case 16:
      return EVP_aes_128_cbc ();

    case 24:
      return EVP_aes_192_cbc ();

    case 32:
      return EVP_aes_256_cbc ();

    default:
      return NULL;
    }
}


static int
ngi541_diff_openssl_aes_cbc_crypt (
  int encrypt,
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *input,
  size_t input_len,
  uint8_t *output,
  size_t output_capacity,
  size_t *output_len)
{
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *ctx;

  int update_len;
  int final_len;
  int result;

  uint8_t empty_input = 0;
  uint8_t empty_output = 0;


  if (key == NULL ||
      iv == NULL ||
      output_len == NULL)
    return 1;

  if (input_len != 0 &&
      input == NULL)
    return 1;

  if (output_capacity < input_len)
    return 1;

  if (input_len != 0 &&
      output == NULL)
    return 1;

  if ((input_len % 16) != 0)
    return 1;

  if (input_len > INT_MAX)
    return 1;


  cipher =
    ngi541_diff_openssl_aes_cbc_cipher (
      key_len);

  if (cipher == NULL)
    return 1;


  ctx =
    EVP_CIPHER_CTX_new ();

  if (ctx == NULL)
    return 1;


  result = 1;
  update_len = 0;
  final_len = 0;

  if (encrypt)
    {
      if (EVP_EncryptInit_ex (
            ctx,
            cipher,
            NULL,
            key,
            iv) != 1)
        goto out;

      if (EVP_CIPHER_CTX_set_padding (
            ctx,
            0) != 1)
        goto out;

      if (EVP_EncryptUpdate (
            ctx,
            output != NULL
              ? output
              : &empty_output,
            &update_len,
            input != NULL
              ? input
              : &empty_input,
            (int) input_len) != 1)
        goto out;

      if (EVP_EncryptFinal_ex (
            ctx,
            (output != NULL
               ? output
               : &empty_output) + update_len,
            &final_len) != 1)
        goto out;
    }
  else
    {
      if (EVP_DecryptInit_ex (
            ctx,
            cipher,
            NULL,
            key,
            iv) != 1)
        goto out;

      if (EVP_CIPHER_CTX_set_padding (
            ctx,
            0) != 1)
        goto out;

      if (EVP_DecryptUpdate (
            ctx,
            output != NULL
              ? output
              : &empty_output,
            &update_len,
            input != NULL
              ? input
              : &empty_input,
            (int) input_len) != 1)
        goto out;

      if (EVP_DecryptFinal_ex (
            ctx,
            (output != NULL
               ? output
               : &empty_output) + update_len,
            &final_len) != 1)
        goto out;
    }


  if ((size_t) update_len +
      (size_t) final_len != input_len)
    goto out;

  *output_len =
    (size_t) update_len +
    (size_t) final_len;

  result = 0;


out:
  EVP_CIPHER_CTX_free (
    ctx);

  return result;
}


int
ngi541_diff_openssl_aes_cbc_encrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *plaintext,
  size_t plaintext_len,
  uint8_t *ciphertext,
  size_t ciphertext_capacity,
  size_t *ciphertext_len)
{
  return ngi541_diff_openssl_aes_cbc_crypt (
    1,
    key,
    key_len,
    iv,
    plaintext,
    plaintext_len,
    ciphertext,
    ciphertext_capacity,
    ciphertext_len);
}


int
ngi541_diff_openssl_aes_cbc_decrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *ciphertext,
  size_t ciphertext_len,
  uint8_t *plaintext,
  size_t plaintext_capacity,
  size_t *plaintext_len)
{
  return ngi541_diff_openssl_aes_cbc_crypt (
    0,
    key,
    key_len,
    iv,
    ciphertext,
    ciphertext_len,
    plaintext,
    plaintext_capacity,
    plaintext_len);
}


static const EVP_CIPHER *
ngi541_diff_openssl_aes_ctr_cipher (
  size_t key_len)
{
  switch (key_len)
    {
    case 16:
      return EVP_aes_128_ctr ();

    case 24:
      return EVP_aes_192_ctr ();

    case 32:
      return EVP_aes_256_ctr ();

    default:
      return NULL;
    }
}


static int
ngi541_diff_openssl_aes_ctr_crypt (
  int encrypt,
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *input,
  size_t input_len,
  uint8_t *output,
  size_t output_capacity,
  size_t *output_len)
{
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *ctx;

  int update_len;
  int final_len;
  int result;

  uint8_t empty_input = 0;
  uint8_t empty_output = 0;


  if (key == NULL ||
      iv == NULL ||
      output_len == NULL)
    return 1;

  if (input_len != 0 &&
      input == NULL)
    return 1;

  if (output_capacity < input_len)
    return 1;

  if (input_len != 0 &&
      output == NULL)
    return 1;

  if (input_len > INT_MAX)
    return 1;


  cipher =
    ngi541_diff_openssl_aes_ctr_cipher (
      key_len);

  if (cipher == NULL)
    return 1;


  ctx =
    EVP_CIPHER_CTX_new ();

  if (ctx == NULL)
    return 1;


  result = 1;
  update_len = 0;
  final_len = 0;

  if (encrypt)
    {
      if (EVP_EncryptInit_ex (
            ctx,
            cipher,
            NULL,
            key,
            iv) != 1)
        goto out;

      if (EVP_EncryptUpdate (
            ctx,
            output != NULL
              ? output
              : &empty_output,
            &update_len,
            input != NULL
              ? input
              : &empty_input,
            (int) input_len) != 1)
        goto out;

      if (EVP_EncryptFinal_ex (
            ctx,
            (output != NULL
               ? output
               : &empty_output) + update_len,
            &final_len) != 1)
        goto out;
    }
  else
    {
      if (EVP_DecryptInit_ex (
            ctx,
            cipher,
            NULL,
            key,
            iv) != 1)
        goto out;

      if (EVP_DecryptUpdate (
            ctx,
            output != NULL
              ? output
              : &empty_output,
            &update_len,
            input != NULL
              ? input
              : &empty_input,
            (int) input_len) != 1)
        goto out;

      if (EVP_DecryptFinal_ex (
            ctx,
            (output != NULL
               ? output
               : &empty_output) + update_len,
            &final_len) != 1)
        goto out;
    }


  if ((size_t) update_len +
      (size_t) final_len != input_len)
    goto out;

  *output_len =
    (size_t) update_len +
    (size_t) final_len;

  result = 0;


out:
  EVP_CIPHER_CTX_free (
    ctx);

  return result;
}


int
ngi541_diff_openssl_aes_ctr_encrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *plaintext,
  size_t plaintext_len,
  uint8_t *ciphertext,
  size_t ciphertext_capacity,
  size_t *ciphertext_len)
{
  return ngi541_diff_openssl_aes_ctr_crypt (
    1,
    key,
    key_len,
    iv,
    plaintext,
    plaintext_len,
    ciphertext,
    ciphertext_capacity,
    ciphertext_len);
}


int
ngi541_diff_openssl_aes_ctr_decrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *ciphertext,
  size_t ciphertext_len,
  uint8_t *plaintext,
  size_t plaintext_capacity,
  size_t *plaintext_len)
{
  return ngi541_diff_openssl_aes_ctr_crypt (
    0,
    key,
    key_len,
    iv,
    ciphertext,
    ciphertext_len,
    plaintext,
    plaintext_capacity,
    plaintext_len);
}

static const EVP_CIPHER *
ngi541_diff_openssl_aes_gcm_cipher (
  size_t key_len)
{
  switch (key_len)
    {
    case 16:
      return EVP_aes_128_gcm ();

    case 24:
      return EVP_aes_192_gcm ();

    case 32:
      return EVP_aes_256_gcm ();

    default:
      return NULL;
    }
}


int
ngi541_diff_openssl_aes_gcm_encrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  size_t iv_len,
  const uint8_t *aad,
  size_t aad_len,
  const uint8_t *plaintext,
  size_t plaintext_len,
  uint8_t *ciphertext,
  size_t ciphertext_capacity,
  size_t *ciphertext_len,
  uint8_t *tag,
  size_t tag_capacity,
  size_t *tag_len)
{
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *ctx;

  uint8_t empty_output = 0;

  int aad_out_len;
  int update_len;
  int final_len;
  int result;


  if (key == NULL ||
      iv == NULL ||
      tag == NULL ||
      ciphertext_len == NULL ||
      tag_len == NULL)
    return 1;

  if (iv_len != 12 ||
      tag_capacity < 16)
    return 1;

  if (aad_len != 0 &&
      aad == NULL)
    return 1;

  if (plaintext_len != 0 &&
      plaintext == NULL)
    return 1;

  if (plaintext_len != 0 &&
      ciphertext == NULL)
    return 1;

  if (ciphertext_capacity <
      plaintext_len)
    return 1;

  if (aad_len > INT_MAX ||
      plaintext_len > INT_MAX)
    return 1;


  cipher =
    ngi541_diff_openssl_aes_gcm_cipher (
      key_len);

  if (cipher == NULL)
    return 1;


  ctx =
    EVP_CIPHER_CTX_new ();

  if (ctx == NULL)
    return 1;


  result = 1;
  aad_out_len = 0;
  update_len = 0;
  final_len = 0;

  if (EVP_EncryptInit_ex (
        ctx,
        cipher,
        NULL,
        NULL,
        NULL) != 1)
    goto out;

  if (EVP_CIPHER_CTX_ctrl (
        ctx,
        EVP_CTRL_GCM_SET_IVLEN,
        (int) iv_len,
        NULL) != 1)
    goto out;

  if (EVP_EncryptInit_ex (
        ctx,
        NULL,
        NULL,
        key,
        iv) != 1)
    goto out;


  if (aad_len != 0)
    {
      if (EVP_EncryptUpdate (
            ctx,
            NULL,
            &aad_out_len,
            aad,
            (int) aad_len) != 1)
        goto out;
    }


  if (plaintext_len != 0)
    {
      if (EVP_EncryptUpdate (
            ctx,
            ciphertext,
            &update_len,
            plaintext,
            (int) plaintext_len) != 1)
        goto out;
    }


  if (EVP_EncryptFinal_ex (
        ctx,
        ciphertext != NULL
          ? ciphertext + update_len
          : &empty_output,
        &final_len) != 1)
    goto out;


  if ((size_t) update_len +
      (size_t) final_len !=
      plaintext_len)
    goto out;


  if (EVP_CIPHER_CTX_ctrl (
        ctx,
        EVP_CTRL_GCM_GET_TAG,
        16,
        tag) != 1)
    goto out;


  *ciphertext_len =
    (size_t) update_len +
    (size_t) final_len;

  *tag_len = 16;

  result = 0;


out:
  EVP_CIPHER_CTX_free (
    ctx);

  return result;
}


ngi541_diff_reference_result_t
ngi541_diff_openssl_aes_gcm_decrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  size_t iv_len,
  const uint8_t *aad,
  size_t aad_len,
  const uint8_t *ciphertext,
  size_t ciphertext_len,
  const uint8_t *tag,
  size_t tag_len,
  uint8_t *plaintext,
  size_t plaintext_capacity,
  size_t *plaintext_len)
{
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *ctx;

  ngi541_diff_reference_result_t result;

  uint8_t tag_copy[16];
  uint8_t empty_output = 0;

  int aad_out_len;
  int update_len;
  int final_len;
  int final_result;


  if (plaintext_len == NULL)
    return NGI541_DIFF_REFERENCE_RESULT_ERROR;

  *plaintext_len = 0;


  if (key == NULL ||
      iv == NULL ||
      tag == NULL)
    return NGI541_DIFF_REFERENCE_RESULT_ERROR;

  if (iv_len != 12 ||
      tag_len != 16)
    return NGI541_DIFF_REFERENCE_RESULT_ERROR;

  if (aad_len != 0 &&
      aad == NULL)
    return NGI541_DIFF_REFERENCE_RESULT_ERROR;

  if (ciphertext_len != 0 &&
      ciphertext == NULL)
    return NGI541_DIFF_REFERENCE_RESULT_ERROR;

  if (ciphertext_len != 0 &&
      plaintext == NULL)
    return NGI541_DIFF_REFERENCE_RESULT_ERROR;

  if (plaintext_capacity <
      ciphertext_len)
    return NGI541_DIFF_REFERENCE_RESULT_ERROR;

  if (aad_len > INT_MAX ||
      ciphertext_len > INT_MAX)
    return NGI541_DIFF_REFERENCE_RESULT_ERROR;


  cipher =
    ngi541_diff_openssl_aes_gcm_cipher (
      key_len);

  if (cipher == NULL)
    return NGI541_DIFF_REFERENCE_RESULT_ERROR;


  ctx =
    EVP_CIPHER_CTX_new ();

  if (ctx == NULL)
    return NGI541_DIFF_REFERENCE_RESULT_ERROR;


  result =
    NGI541_DIFF_REFERENCE_RESULT_ERROR;

  aad_out_len = 0;
  update_len = 0;
  final_len = 0;


  if (EVP_DecryptInit_ex (
        ctx,
        cipher,
        NULL,
        NULL,
        NULL) != 1)
    goto out;

  if (EVP_CIPHER_CTX_ctrl (
        ctx,
        EVP_CTRL_GCM_SET_IVLEN,
        (int) iv_len,
        NULL) != 1)
    goto out;

  if (EVP_DecryptInit_ex (
        ctx,
        NULL,
        NULL,
        key,
        iv) != 1)
    goto out;


  if (aad_len != 0)
    {
      if (EVP_DecryptUpdate (
            ctx,
            NULL,
            &aad_out_len,
            aad,
            (int) aad_len) != 1)
        goto out;
    }


  if (ciphertext_len != 0)
    {
      if (EVP_DecryptUpdate (
            ctx,
            plaintext,
            &update_len,
            ciphertext,
            (int) ciphertext_len) != 1)
        goto out;
    }


  memcpy (
    tag_copy,
    tag,
    sizeof (tag_copy));

  if (EVP_CIPHER_CTX_ctrl (
        ctx,
        EVP_CTRL_GCM_SET_TAG,
        16,
        tag_copy) != 1)
    goto out;


  final_result =
    EVP_DecryptFinal_ex (
      ctx,
      plaintext != NULL
        ? plaintext + update_len
        : &empty_output,
      &final_len);

  if (final_result != 1)
    {
      result =
        NGI541_DIFF_REFERENCE_RESULT_AUTH_FAILED;

      goto out;
    }


  if ((size_t) update_len +
      (size_t) final_len !=
      ciphertext_len)
    goto out;


  *plaintext_len =
    (size_t) update_len +
    (size_t) final_len;

  result =
    NGI541_DIFF_REFERENCE_RESULT_OK;


out:
  EVP_CIPHER_CTX_free (
    ctx);

  return result;
}