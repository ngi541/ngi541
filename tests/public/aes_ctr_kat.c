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
   * AES-128-CTR known-answer vector.
   *
   * Four blocks are used intentionally so the test verifies
   * counter progression in addition to the underlying AES primitive.
   */
  static const uint8_t key[16] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c,
  };

  static const uint8_t counter[16] = {
    0xf0, 0xf1, 0xf2, 0xf3,
    0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff,
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
    0x87, 0x4d, 0x61, 0x91,
    0xb6, 0x20, 0xe3, 0x26,
    0x1b, 0xef, 0x68, 0x64,
    0x99, 0x0d, 0xb6, 0xce,

    0x98, 0x06, 0xf6, 0x6b,
    0x79, 0x70, 0xfd, 0xff,
    0x86, 0x17, 0x18, 0x7b,
    0xb9, 0xff, 0xfd, 0xff,

    0x5a, 0xe4, 0xdf, 0x3e,
    0xdb, 0xd5, 0xd3, 0x5e,
    0x5b, 0x4f, 0x09, 0x02,
    0x0d, 0xb0, 0x3e, 0xab,

    0x1e, 0x03, 0x1d, 0xda,
    0x2f, 0xbe, 0x03, 0xd1,
    0x79, 0x21, 0x70, 0xa0,
    0xf3, 0x00, 0x9c, 0xee,
  };

  uint8_t ciphertext[sizeof (plaintext)] = { 0 };
  uint8_t decrypted[sizeof (plaintext)] = { 0 };

  ngi541_cipher_request_t encrypt_request = {
    .struct_size = sizeof (ngi541_cipher_request_t),
    .algorithm = NGI541_CIPHER_AES_CTR,
    .key = key,
    .key_len = sizeof (key),
    .iv = counter,
    .iv_len = sizeof (counter),
    .input = plaintext,
    .input_len = sizeof (plaintext),
    .output = ciphertext,
    .output_capacity = sizeof (ciphertext),
  };

  ngi541_cipher_request_t decrypt_request = {
    .struct_size = sizeof (ngi541_cipher_request_t),
    .algorithm = NGI541_CIPHER_AES_CTR,
    .key = key,
    .key_len = sizeof (key),
    .iv = counter,
    .iv_len = sizeof (counter),
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
        "AES-128-CTR encrypt handler is unavailable\n");

      return 2;
    }

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-128-CTR encryption failed: status=%d\n",
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
        "AES-128-CTR encryption known-answer test failed\n");

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

  /*
   * Decryption is tested against the independent known ciphertext,
   * not against the output produced by the encryption test.
   */
  status =
    ngi541_crypto_cipher_decrypt (&decrypt_request);

  if (status == NGI541_STATUS_UNAVAILABLE)
    {
      fprintf (
        stderr,
        "AES-128-CTR decrypt handler is unavailable\n");

      return 5;
    }

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-128-CTR decryption failed: status=%d\n",
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
        "AES-128-CTR decryption known-answer test failed\n");

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