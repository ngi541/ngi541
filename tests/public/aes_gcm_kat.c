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

static int
buffer_is_zero (
  const uint8_t *data,
  size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      if (data[i] != 0)
        return 0;
    }

  return 1;
}


int
main (void)
{
  /*
   * AES-128-GCM known-answer vector.
   *
   * This vector includes AAD and a multi-block payload so the test
   * exercises both encryption and authentication processing.
   */
  static const uint8_t key[16] = {
    0xfe, 0xff, 0xe9, 0x92,
    0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94,
    0x67, 0x30, 0x83, 0x08,
  };

  static const uint8_t iv[12] = {
    0xca, 0xfe, 0xba, 0xbe,
    0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88,
  };

  static const uint8_t aad[20] = {
    0xfe, 0xed, 0xfa, 0xce,
    0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce,
    0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2,
  };

  static const uint8_t plaintext[60] = {
    0xd9, 0x31, 0x32, 0x25,
    0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5,
    0xaf, 0xf5, 0x26, 0x9a,

    0x86, 0xa7, 0xa9, 0x53,
    0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d,
    0x8a, 0x31, 0x8a, 0x72,

    0x1c, 0x3c, 0x0c, 0x95,
    0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24,
    0x49, 0xa6, 0xb5, 0x25,

    0xb1, 0x6a, 0xed, 0xf5,
    0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39,
  };

  static const uint8_t expected_ciphertext[60] = {
    0x42, 0x83, 0x1e, 0xc2,
    0x21, 0x77, 0x74, 0x24,
    0x4b, 0x72, 0x21, 0xb7,
    0x84, 0xd0, 0xd4, 0x9c,

    0xe3, 0xaa, 0x21, 0x2f,
    0x2c, 0x02, 0xa4, 0xe0,
    0x35, 0xc1, 0x7e, 0x23,
    0x29, 0xac, 0xa1, 0x2e,

    0x21, 0xd5, 0x14, 0xb2,
    0x54, 0x66, 0x93, 0x1c,
    0x7d, 0x8f, 0x6a, 0x5a,
    0xac, 0x84, 0xaa, 0x05,

    0x1b, 0xa3, 0x0b, 0x39,
    0x6a, 0x0a, 0xac, 0x97,
    0x3d, 0x58, 0xe0, 0x91,
  };

  static const uint8_t expected_tag[16] = {
    0x5b, 0xc9, 0x4f, 0xbc,
    0x32, 0x21, 0xa5, 0xdb,
    0x94, 0xfa, 0xe9, 0x5a,
    0xe7, 0x12, 0x1a, 0x47,
  };

  /*
   * AES-128-GCM zero-payload regression vector.
   *
   * This case verifies that non-empty AAD is still authenticated
   * correctly when the plaintext/ciphertext length is zero.
   *
   * It protects the encrypt-side GHASH final-length-block path.
   */
  static const uint8_t zero_payload_key[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
  };

  static const uint8_t zero_payload_iv[12] = {
    0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b,
  };

  static const uint8_t zero_payload_aad[16] = {
    0x50, 0x51, 0x52, 0x53,
    0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b,
    0x5c, 0x5d, 0x5e, 0x5f,
  };

  static const uint8_t zero_payload_expected_tag[16] = {
    0x46, 0x59, 0xf8, 0xb3,
    0x30, 0xa6, 0xac, 0x0f,
    0x6e, 0x45, 0x8f, 0x86,
    0xe7, 0x86, 0xac, 0xef,
  };

  uint8_t ciphertext[sizeof (plaintext)] = { 0 };
  uint8_t tag[16] = { 0 };
  uint8_t decrypted[sizeof (plaintext)] = { 0 };

  uint8_t bad_tag[sizeof (expected_tag)];
  uint8_t rejected_plaintext[sizeof (plaintext)];

  uint8_t zero_payload_tag[
    sizeof (zero_payload_expected_tag)] = { 0 };

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

  /*
   * Encryption KAT.
   */
  {
    ngi541_aead_encrypt_request_t request = {
      .struct_size =
        sizeof (ngi541_aead_encrypt_request_t),
      .algorithm = NGI541_AEAD_AES_GCM,
      .key = key,
      .key_len = sizeof (key),
      .iv = iv,
      .iv_len = sizeof (iv),
      .aad = aad,
      .aad_len = sizeof (aad),
      .plaintext = plaintext,
      .plaintext_len = sizeof (plaintext),
      .ciphertext = ciphertext,
      .ciphertext_capacity = sizeof (ciphertext),
      .tag = tag,
      .tag_len = sizeof (tag),
    };

    status =
      ngi541_crypto_aead_encrypt (&request);

    if (status == NGI541_STATUS_UNAVAILABLE)
      {
        fprintf (
          stderr,
          "AES-128-GCM encrypt handler is unavailable\n");

        return 2;
      }

    if (status != NGI541_STATUS_OK)
      {
        fprintf (
          stderr,
          "AES-128-GCM encryption failed: status=%d\n",
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
          "AES-128-GCM ciphertext known-answer test failed\n");

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

    if (memcmp (
          tag,
          expected_tag,
          sizeof (expected_tag)) != 0)
      {
        fprintf (
          stderr,
          "AES-128-GCM tag known-answer test failed\n");

        print_bytes (
          "expected",
          expected_tag,
          sizeof (expected_tag));

        print_bytes (
          "actual  ",
          tag,
          sizeof (tag));

        return 5;
      }
  }

  /*
   * Decryption uses the independent known ciphertext and tag rather
   * than the output produced by the encryption test.
   */
  {
    ngi541_aead_decrypt_request_t request = {
      .struct_size =
        sizeof (ngi541_aead_decrypt_request_t),
      .algorithm = NGI541_AEAD_AES_GCM,
      .key = key,
      .key_len = sizeof (key),
      .iv = iv,
      .iv_len = sizeof (iv),
      .aad = aad,
      .aad_len = sizeof (aad),
      .ciphertext = expected_ciphertext,
      .ciphertext_len = sizeof (expected_ciphertext),
      .tag = expected_tag,
      .tag_len = sizeof (expected_tag),
      .plaintext = decrypted,
      .plaintext_capacity = sizeof (decrypted),
    };

    status =
      ngi541_crypto_aead_decrypt (&request);

    if (status == NGI541_STATUS_UNAVAILABLE)
      {
        fprintf (
          stderr,
          "AES-128-GCM decrypt handler is unavailable\n");

        return 6;
      }

    if (status != NGI541_STATUS_OK)
      {
        fprintf (
          stderr,
          "AES-128-GCM decryption failed: status=%d\n",
          (int) status);

        return 7;
      }

    if (memcmp (
          decrypted,
          plaintext,
          sizeof (plaintext)) != 0)
      {
        fprintf (
          stderr,
          "AES-128-GCM decryption known-answer test failed\n");

        print_bytes (
          "expected",
          plaintext,
          sizeof (plaintext));

        print_bytes (
          "actual  ",
          decrypted,
          sizeof (decrypted));

        return 8;
      }
  }

  /*
   * Authentication-failure test.
   *
   * Start with a non-zero output buffer so the test verifies that
   * the public execution facade explicitly scrubs unauthenticated
   * plaintext before returning AUTH_FAILED.
   */
  memcpy (
    bad_tag,
    expected_tag,
    sizeof (bad_tag));

  bad_tag[0] ^= 0x01;

  memset (
    rejected_plaintext,
    0xa5,
    sizeof (rejected_plaintext));

  {
    ngi541_aead_decrypt_request_t request = {
      .struct_size =
        sizeof (ngi541_aead_decrypt_request_t),
      .algorithm = NGI541_AEAD_AES_GCM,
      .key = key,
      .key_len = sizeof (key),
      .iv = iv,
      .iv_len = sizeof (iv),
      .aad = aad,
      .aad_len = sizeof (aad),
      .ciphertext = expected_ciphertext,
      .ciphertext_len = sizeof (expected_ciphertext),
      .tag = bad_tag,
      .tag_len = sizeof (bad_tag),
      .plaintext = rejected_plaintext,
      .plaintext_capacity =
        sizeof (rejected_plaintext),
    };

    status =
      ngi541_crypto_aead_decrypt (&request);

    if (status != NGI541_STATUS_AUTH_FAILED)
      {
        fprintf (
          stderr,
          "AES-128-GCM bad-tag test returned "
          "unexpected status=%d\n",
          (int) status);

        return 9;
      }

    if (!buffer_is_zero (
          rejected_plaintext,
          sizeof (rejected_plaintext)))
      {
        fprintf (
          stderr,
          "AES-128-GCM unauthenticated plaintext "
          "was not scrubbed\n");

        print_bytes (
          "plaintext",
          rejected_plaintext,
          sizeof (rejected_plaintext));

        return 10;
      }
  }

  /*
   * Zero-payload encryption regression.
   *
   * A zero-length plaintext is represented by NULL input/output
   * buffers. Non-empty AAD must still contribute to GCM
   * authentication and produce the expected tag.
   */
  {
    ngi541_aead_encrypt_request_t request = {
      .struct_size =
        sizeof (ngi541_aead_encrypt_request_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = zero_payload_key,
      .key_len = sizeof (zero_payload_key),

      .iv = zero_payload_iv,
      .iv_len = sizeof (zero_payload_iv),

      .aad = zero_payload_aad,
      .aad_len = sizeof (zero_payload_aad),

      .plaintext = NULL,
      .plaintext_len = 0,

      .ciphertext = NULL,
      .ciphertext_capacity = 0,

      .tag = zero_payload_tag,
      .tag_len = sizeof (zero_payload_tag),
    };

    status =
      ngi541_crypto_aead_encrypt (&request);

    if (status != NGI541_STATUS_OK)
      {
        fprintf (
          stderr,
          "AES-128-GCM zero-payload encryption "
          "failed: status=%d\n",
          (int) status);

        return 11;
      }

    if (memcmp (
          zero_payload_tag,
          zero_payload_expected_tag,
          sizeof (zero_payload_expected_tag)) != 0)
      {
        fprintf (
          stderr,
          "AES-128-GCM zero-payload tag "
          "known-answer test failed\n");

        print_bytes (
          "expected",
          zero_payload_expected_tag,
          sizeof (zero_payload_expected_tag));

        print_bytes (
          "actual  ",
          zero_payload_tag,
          sizeof (zero_payload_tag));

        return 12;
      }
  }

  /*
   * Zero-payload decryption regression.
   *
   * Use the independent known-answer tag rather than the tag
   * generated by the encryption test above.
   */
  {
    ngi541_aead_decrypt_request_t request = {
      .struct_size =
        sizeof (ngi541_aead_decrypt_request_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = zero_payload_key,
      .key_len = sizeof (zero_payload_key),

      .iv = zero_payload_iv,
      .iv_len = sizeof (zero_payload_iv),

      .aad = zero_payload_aad,
      .aad_len = sizeof (zero_payload_aad),

      .ciphertext = NULL,
      .ciphertext_len = 0,

      .tag = zero_payload_expected_tag,
      .tag_len = sizeof (zero_payload_expected_tag),

      .plaintext = NULL,
      .plaintext_capacity = 0,
    };

    status =
      ngi541_crypto_aead_decrypt (&request);

    if (status != NGI541_STATUS_OK)
      {
        fprintf (
          stderr,
          "AES-128-GCM zero-payload decryption "
          "failed: status=%d\n",
          (int) status);

        return 13;
      }
  }

  return 0;
}