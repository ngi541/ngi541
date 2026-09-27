/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "reference.h"
#include "openssl_ref.h"


int
ngi541_diff_reference_aes_cbc_encrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *plaintext,
  size_t plaintext_len,
  uint8_t *ciphertext,
  size_t ciphertext_capacity,
  size_t *ciphertext_len)
{
  return ngi541_diff_openssl_aes_cbc_encrypt (
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
ngi541_diff_reference_aes_cbc_decrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *ciphertext,
  size_t ciphertext_len,
  uint8_t *plaintext,
  size_t plaintext_capacity,
  size_t *plaintext_len)
{
  return ngi541_diff_openssl_aes_cbc_decrypt (
    key,
    key_len,
    iv,
    ciphertext,
    ciphertext_len,
    plaintext,
    plaintext_capacity,
    plaintext_len);
}

int
ngi541_diff_reference_aes_ctr_encrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *plaintext,
  size_t plaintext_len,
  uint8_t *ciphertext,
  size_t ciphertext_capacity,
  size_t *ciphertext_len)
{
  return ngi541_diff_openssl_aes_ctr_encrypt (
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
ngi541_diff_reference_aes_ctr_decrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *ciphertext,
  size_t ciphertext_len,
  uint8_t *plaintext,
  size_t plaintext_capacity,
  size_t *plaintext_len)
{
  return ngi541_diff_openssl_aes_ctr_decrypt (
    key,
    key_len,
    iv,
    ciphertext,
    ciphertext_len,
    plaintext,
    plaintext_capacity,
    plaintext_len);
}

int
ngi541_diff_reference_aes_gcm_encrypt (
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
  return ngi541_diff_openssl_aes_gcm_encrypt (
    key,
    key_len,
    iv,
    iv_len,
    aad,
    aad_len,
    plaintext,
    plaintext_len,
    ciphertext,
    ciphertext_capacity,
    ciphertext_len,
    tag,
    tag_capacity,
    tag_len);
}


ngi541_diff_reference_result_t
ngi541_diff_reference_aes_gcm_decrypt (
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
  return ngi541_diff_openssl_aes_gcm_decrypt (
    key,
    key_len,
    iv,
    iv_len,
    aad,
    aad_len,
    ciphertext,
    ciphertext_len,
    tag,
    tag_len,
    plaintext,
    plaintext_capacity,
    plaintext_len);
}

int
ngi541_diff_reference_sha2_compute (
  unsigned int digest_bits,
  const uint8_t *message,
  size_t message_len,
  uint8_t *digest,
  size_t digest_capacity,
  size_t *digest_len)
{
  return ngi541_diff_openssl_sha2_compute (
    digest_bits,
    message,
    message_len,
    digest,
    digest_capacity,
    digest_len);
}