/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "openssl_ref.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <limits.h>

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