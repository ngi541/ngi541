/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void
print_hex (const uint8_t *data, size_t len)
{
  for (size_t i = 0; i < len; i++)
    printf ("%02x", data[i]);

  putchar ('\n');
}

int
main (void)
{
  /*
   * Deterministic example values only.
   *
   * Real applications must use appropriate key management and must never
   * reuse an AES-CTR counter/IV with the same key.
   */
  static const uint8_t key[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
  };

  static const uint8_t counter[16] = {
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f,
  };

  static const char message[] = "NGI541 AES-CTR example";

  const uint8_t *plaintext = (const uint8_t *) message;
  const size_t plaintext_len = strlen (message);

  uint8_t ciphertext[sizeof (message) - 1] = { 0 };
  uint8_t decrypted[sizeof (message)] = { 0 };

  ngi541_status_t status = ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "ngi541_engine_init failed: status=%d\n",
        (int) status);
      return 1;
    }

  ngi541_cipher_request_t encrypt_request = {
    .struct_size = sizeof (encrypt_request),
    .algorithm = NGI541_CIPHER_AES_CTR,
    .key = key,
    .key_len = sizeof (key),
    .iv = counter,
    .iv_len = sizeof (counter),
    .input = plaintext,
    .input_len = plaintext_len,
    .output = ciphertext,
    .output_capacity = sizeof (ciphertext),
  };

  status = ngi541_crypto_cipher_encrypt (&encrypt_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR encryption failed: status=%d\n",
        (int) status);
      return 2;
    }

  ngi541_cipher_request_t decrypt_request = {
    .struct_size = sizeof (decrypt_request),
    .algorithm = NGI541_CIPHER_AES_CTR,
    .key = key,
    .key_len = sizeof (key),
    .iv = counter,
    .iv_len = sizeof (counter),
    .input = ciphertext,
    .input_len = sizeof (ciphertext),
    .output = decrypted,
    .output_capacity = sizeof (decrypted),
  };

  status = ngi541_crypto_cipher_decrypt (&decrypt_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR decryption failed: status=%d\n",
        (int) status);
      return 3;
    }

  if (memcmp (decrypted, plaintext, plaintext_len) != 0)
    {
      fprintf (stderr, "AES-CTR round-trip verification failed\n");
      return 4;
    }

  printf ("plaintext:  %s\n", message);
  printf ("ciphertext: ");
  print_hex (ciphertext, sizeof (ciphertext));
  printf ("decrypted:  %s\n", (char *) decrypted);

  return 0;
}
