/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_TESTS_DIFFERENTIAL_REFERENCE_H
#define NGI541_TESTS_DIFFERENTIAL_REFERENCE_H

#include <stddef.h>
#include <stdint.h>


typedef enum
{
  NGI541_DIFF_REFERENCE_OPENSSL = 1,
  NGI541_DIFF_REFERENCE_IPSEC_MB = 2,
} ngi541_diff_reference_id_t;

typedef enum
{
  NGI541_DIFF_REFERENCE_RESULT_OK = 0,
  NGI541_DIFF_REFERENCE_RESULT_AUTH_FAILED,
  NGI541_DIFF_REFERENCE_RESULT_ERROR,
} ngi541_diff_reference_result_t;

typedef struct
{
  ngi541_diff_reference_id_t id;
  const char *name;
  const char *version;
} ngi541_diff_reference_info_t;


int ngi541_diff_reference_aes_cbc_encrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *plaintext,
  size_t plaintext_len,
  uint8_t *ciphertext,
  size_t ciphertext_capacity,
  size_t *ciphertext_len);

int ngi541_diff_reference_aes_cbc_decrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *ciphertext,
  size_t ciphertext_len,
  uint8_t *plaintext,
  size_t plaintext_capacity,
  size_t *plaintext_len);

int ngi541_diff_reference_aes_ctr_encrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *plaintext,
  size_t plaintext_len,
  uint8_t *ciphertext,
  size_t ciphertext_capacity,
  size_t *ciphertext_len);

int ngi541_diff_reference_aes_ctr_decrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *ciphertext,
  size_t ciphertext_len,
  uint8_t *plaintext,
  size_t plaintext_capacity,
  size_t *plaintext_len);

int ngi541_diff_reference_aes_gcm_encrypt (
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
  size_t *tag_len);

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
  size_t *plaintext_len);

#endif