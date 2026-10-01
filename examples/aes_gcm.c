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
   * reuse an AES-GCM IV/nonce with the same key.
   */
  static const uint8_t key[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
  };

  static const uint8_t iv[12] = {
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
  };

  static const uint8_t aad[] = {
    0x4e, 0x47, 0x49, 0x35, 0x34, 0x31
  };

  static const char message[] = "NGI541 AES-GCM example";

  const uint8_t *plaintext = (const uint8_t *) message;
  const size_t plaintext_len = strlen (message);

  uint8_t ciphertext[sizeof (message) - 1] = { 0 };
  uint8_t tag[16] = { 0 };
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

  ngi541_aead_encrypt_request_t encrypt_request = {
    .struct_size = sizeof (encrypt_request),
    .algorithm = NGI541_AEAD_AES_GCM,
    .key = key,
    .key_len = sizeof (key),
    .iv = iv,
    .iv_len = sizeof (iv),
    .aad = aad,
    .aad_len = sizeof (aad),
    .plaintext = plaintext,
    .plaintext_len = plaintext_len,
    .ciphertext = ciphertext,
    .ciphertext_capacity = sizeof (ciphertext),
    .tag = tag,
    .tag_len = sizeof (tag),
  };

  status = ngi541_crypto_aead_encrypt (&encrypt_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-GCM encryption failed: status=%d\n",
        (int) status);
      return 2;
    }

  ngi541_aead_decrypt_request_t decrypt_request = {
    .struct_size = sizeof (decrypt_request),
    .algorithm = NGI541_AEAD_AES_GCM,
    .key = key,
    .key_len = sizeof (key),
    .iv = iv,
    .iv_len = sizeof (iv),
    .aad = aad,
    .aad_len = sizeof (aad),
    .ciphertext = ciphertext,
    .ciphertext_len = sizeof (ciphertext),
    .tag = tag,
    .tag_len = sizeof (tag),
    .plaintext = decrypted,
    .plaintext_capacity = sizeof (decrypted),
  };

  status = ngi541_crypto_aead_decrypt (&decrypt_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-GCM decryption failed: status=%d\n",
        (int) status);
      return 3;
    }

  if (memcmp (decrypted, plaintext, plaintext_len) != 0)
    {
      fprintf (stderr, "AES-GCM round-trip verification failed\n");
      return 4;
    }

  printf ("plaintext:  %s\n", message);
  printf ("ciphertext: ");
  print_hex (ciphertext, sizeof (ciphertext));
  printf ("tag:        ");
  print_hex (tag, sizeof (tag));
  printf ("decrypted:  %s\n", (char *) decrypted);

  return 0;
}
