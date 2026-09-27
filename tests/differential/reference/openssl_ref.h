/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_TESTS_DIFFERENTIAL_OPENSSL_REF_H
#define NGI541_TESTS_DIFFERENTIAL_OPENSSL_REF_H

#include "reference.h"

#include <stddef.h>
#include <stdint.h>


int ngi541_diff_openssl_reference_info (
  ngi541_diff_reference_info_t *info);

int ngi541_diff_openssl_aes_cbc_encrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *plaintext,
  size_t plaintext_len,
  uint8_t *ciphertext,
  size_t ciphertext_capacity,
  size_t *ciphertext_len);

int ngi541_diff_openssl_aes_cbc_decrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *ciphertext,
  size_t ciphertext_len,
  uint8_t *plaintext,
  size_t plaintext_capacity,
  size_t *plaintext_len);

int ngi541_diff_openssl_aes_ctr_encrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *plaintext,
  size_t plaintext_len,
  uint8_t *ciphertext,
  size_t ciphertext_capacity,
  size_t *ciphertext_len);

int ngi541_diff_openssl_aes_ctr_decrypt (
  const uint8_t *key,
  size_t key_len,
  const uint8_t *iv,
  const uint8_t *ciphertext,
  size_t ciphertext_len,
  uint8_t *plaintext,
  size_t plaintext_capacity,
  size_t *plaintext_len);


#endif