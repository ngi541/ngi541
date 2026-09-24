/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void
print_bytes (
  const char *label,
  const uint8_t *data,
  size_t len)
{
  fprintf (stderr, "%s: ", label);

  for (size_t i = 0; i < len; i++)
    fprintf (stderr, "%02x", data[i]);

  fputc ('\n', stderr);
}


int
main (void)
{
  /*
   * AES-128-CBC known-answer vector.
   *
   * Four blocks are used intentionally so the test verifies CBC
   * chaining in addition to the underlying AES primitive.
   */
  static const uint8_t key[16] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c,
  };

  static const uint8_t iv[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
  };

  static const uint8_t plaintext[64] = {
    0x6b, 0xc1, 0xbe, 0xe2,
    0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11,
    0x73, 0x93, 0x17, 0x2a,

    0xae, 0x2d, 0x8a, 0x57,
    0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac,
    0x45, 0xaf, 0x8e, 0x51,

    0x30, 0xc8, 0x1c, 0x46,
    0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19,
    0x1a, 0x0a, 0x52, 0xef,

    0xf6, 0x9f, 0x24, 0x45,
    0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b,
    0xe6, 0x6c, 0x37, 0x10,
  };

  static const uint8_t expected_ciphertext[64] = {
    0x76, 0x49, 0xab, 0xac,
    0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b,
    0x12, 0xe9, 0x19, 0x7d,

    0x50, 0x86, 0xcb, 0x9b,
    0x50, 0x72, 0x19, 0xee,
    0x95, 0xdb, 0x11, 0x3a,
    0x91, 0x76, 0x78, 0xb2,

    0x73, 0xbe, 0xd6, 0xb8,
    0xe3, 0xc1, 0x74, 0x3b,
    0x71, 0x16, 0xe6, 0x9e,
    0x22, 0x22, 0x95, 0x16,

    0x3f, 0xf1, 0xca, 0xa1,
    0x68, 0x1f, 0xac, 0x09,
    0x12, 0x0e, 0xca, 0x30,
    0x75, 0x86, 0xe1, 0xa7,
  };

  uint8_t ciphertext[sizeof (plaintext)] = { 0 };
  uint8_t decrypted[sizeof (plaintext)] = { 0 };

  ngi541_cipher_request_t encrypt_request = {
    .struct_size = sizeof (ngi541_cipher_request_t),
    .algorithm = NGI541_CIPHER_AES_CBC,
    .key = key,
    .key_len = sizeof (key),
    .iv = iv,
    .iv_len = sizeof (iv),
    .input = plaintext,
    .input_len = sizeof (plaintext),
    .output = ciphertext,
    .output_capacity = sizeof (ciphertext),
  };

  ngi541_cipher_request_t decrypt_request = {
    .struct_size = sizeof (ngi541_cipher_request_t),
    .algorithm = NGI541_CIPHER_AES_CBC,
    .key = key,
    .key_len = sizeof (key),
    .iv = iv,
    .iv_len = sizeof (iv),
    .input = expected_ciphertext,
    .input_len = sizeof (expected_ciphertext),
    .output = decrypted,
    .output_capacity = sizeof (decrypted),
  };

  ngi541_status_t status;

  status = ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "ngi541_engine_init failed: status=%d\n",
        (int) status);

      return 1;
    }

  status =
    ngi541_crypto_cipher_encrypt (&encrypt_request);

  if (status == NGI541_STATUS_UNAVAILABLE)
    {
      fprintf (
        stderr,
        "AES-128-CBC encrypt handler is unavailable\n");

      return 2;
    }

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-128-CBC encryption failed: status=%d\n",
        (int) status);

      return 3;
    }

  if (memcmp (
        ciphertext,
        expected_ciphertext,
        sizeof (expected_ciphertext)) != 0)
    {
      fprintf (
        stderr,
        "AES-128-CBC encryption known-answer test failed\n");

      print_bytes (
        "expected",
        expected_ciphertext,
        sizeof (expected_ciphertext));

      print_bytes (
        "actual  ",
        ciphertext,
        sizeof (ciphertext));

      return 4;
    }

  status =
    ngi541_crypto_cipher_decrypt (&decrypt_request);

  if (status == NGI541_STATUS_UNAVAILABLE)
    {
      fprintf (
        stderr,
        "AES-128-CBC decrypt handler is unavailable\n");

      return 5;
    }

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-128-CBC decryption failed: status=%d\n",
        (int) status);

      return 6;
    }

  if (memcmp (
        decrypted,
        plaintext,
        sizeof (plaintext)) != 0)
    {
      fprintf (
        stderr,
        "AES-128-CBC decryption known-answer test failed\n");

      print_bytes (
        "expected",
        plaintext,
        sizeof (plaintext));

      print_bytes (
        "actual  ",
        decrypted,
        sizeof (decrypted));

      return 7;
    }

  return 0;
}