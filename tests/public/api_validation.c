/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>


static int
expect_status (
  const char *name,
  ngi541_status_t actual,
  ngi541_status_t expected)
{
  if (actual != expected)
    {
      fprintf (
        stderr,
        "%s returned status=%d, expected=%d\n",
        name,
        (int) actual,
        (int) expected);

      return 1;
    }

  return 0;
}


int
main (void)
{
  static const uint8_t key[32] = { 0 };
  static const uint8_t iv16[16] = { 0 };
  static const uint8_t iv12[12] = { 0 };
  static const uint8_t input[32] = { 0 };
  static const uint8_t aad[16] = { 0 };
  static const uint8_t tag[16] = { 0 };

  uint8_t output[32] = { 0 };
  uint8_t digest[32] = { 0 };

  ngi541_status_t status;
  int failed = 0;


  /*
   * All tests below exercise argument validation after successful
   * engine initialization.
   */
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
   * NULL request.
   *
   * This is intentionally tested after engine initialization.
   * The uninitialized-engine precedence is covered separately by
   * public.engine_not_initialized.
   */
  failed |=
    expect_status (
      "cipher encrypt NULL request",
      ngi541_crypto_cipher_encrypt (NULL),
      NGI541_STATUS_INVALID_ARGUMENT);

  failed |=
    expect_status (
      "cipher decrypt NULL request",
      ngi541_crypto_cipher_decrypt (NULL),
      NGI541_STATUS_INVALID_ARGUMENT);

  failed |=
    expect_status (
      "AEAD encrypt NULL request",
      ngi541_crypto_aead_encrypt (NULL),
      NGI541_STATUS_INVALID_ARGUMENT);

  failed |=
    expect_status (
      "AEAD decrypt NULL request",
      ngi541_crypto_aead_decrypt (NULL),
      NGI541_STATUS_INVALID_ARGUMENT);

  failed |=
    expect_status (
      "hash NULL request",
      ngi541_crypto_hash_compute (NULL),
      NGI541_STATUS_INVALID_ARGUMENT);


  /*
   * Cipher API validation.
   */
  {
    ngi541_cipher_request_t request = {
      .struct_size =
        sizeof (ngi541_cipher_request_t),

      .algorithm =
        NGI541_CIPHER_AES_CBC,

      .key = key,
      .key_len = 16,

      .iv = iv16,
      .iv_len = sizeof (iv16),

      .input = input,
      .input_len = 16,

      .output = output,
      .output_capacity = sizeof (output),
    };


    /*
     * struct_size.
     */
    {
      ngi541_cipher_request_t invalid = request;

      invalid.struct_size =
        sizeof (ngi541_cipher_request_t) - 1;

      failed |=
        expect_status (
          "cipher short struct_size",
          ngi541_crypto_cipher_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    /*
     * Unsupported public algorithm identifier.
     */
    {
      ngi541_cipher_request_t invalid = request;

      invalid.algorithm =
        (ngi541_cipher_algorithm_t) 0xffffffffU;

      failed |=
        expect_status (
          "cipher unsupported algorithm",
          ngi541_crypto_cipher_encrypt (&invalid),
          NGI541_STATUS_UNSUPPORTED);
    }


    /*
     * Required key.
     */
    {
      ngi541_cipher_request_t invalid = request;

      invalid.key = NULL;

      failed |=
        expect_status (
          "cipher NULL key",
          ngi541_crypto_cipher_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    /*
     * Unsupported AES key length.
     */
    {
      ngi541_cipher_request_t invalid = request;

      invalid.key_len = 15;

      failed |=
        expect_status (
          "cipher invalid key length",
          ngi541_crypto_cipher_encrypt (&invalid),
          NGI541_STATUS_UNSUPPORTED);
    }


    /*
     * Required IV.
     */
    {
      ngi541_cipher_request_t invalid = request;

      invalid.iv = NULL;

      failed |=
        expect_status (
          "cipher NULL IV",
          ngi541_crypto_cipher_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    /*
     * CBC/CTR public contract requires a complete 128-bit IV /
     * initial counter block.
     */
    {
      ngi541_cipher_request_t invalid = request;

      invalid.iv_len = 15;

      failed |=
        expect_status (
          "cipher invalid IV length",
          ngi541_crypto_cipher_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    /*
     * Non-empty input requires a valid input pointer.
     */
    {
      ngi541_cipher_request_t invalid = request;

      invalid.input = NULL;

      failed |=
        expect_status (
          "cipher NULL input",
          ngi541_crypto_cipher_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    /*
     * Output capacity is checked before the output pointer.
     */
    {
      ngi541_cipher_request_t invalid = request;

      invalid.output_capacity = 15;

      failed |=
        expect_status (
          "cipher short output buffer",
          ngi541_crypto_cipher_encrypt (&invalid),
          NGI541_STATUS_BUFFER_TOO_SMALL);
    }


    /*
     * Non-empty input requires a destination buffer when capacity
     * itself is sufficient.
     */
    {
      ngi541_cipher_request_t invalid = request;

      invalid.output = NULL;
      invalid.output_capacity = 16;

      failed |=
        expect_status (
          "cipher NULL output",
          ngi541_crypto_cipher_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    /*
     * AES-CBC operates on complete 128-bit blocks.
     */
    {
      ngi541_cipher_request_t invalid = request;

      invalid.input_len = 15;
      invalid.output_capacity = sizeof (output);

      failed |=
        expect_status (
          "CBC non-block-aligned input",
          ngi541_crypto_cipher_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }
  }


  /*
   * AES-GCM encryption API validation.
   */
  {
    ngi541_aead_encrypt_request_t request = {
      .struct_size =
        sizeof (ngi541_aead_encrypt_request_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = key,
      .key_len = 16,

      .iv = iv12,
      .iv_len = sizeof (iv12),

      .aad = aad,
      .aad_len = sizeof (aad),

      .plaintext = input,
      .plaintext_len = 16,

      .ciphertext = output,
      .ciphertext_capacity = sizeof (output),

      .tag = output + 16,
      .tag_len = 16,
    };


    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.struct_size =
        sizeof (ngi541_aead_encrypt_request_t) - 1;

      failed |=
        expect_status (
          "GCM encrypt short struct_size",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.algorithm =
        (ngi541_aead_algorithm_t) 0xffffffffU;

      failed |=
        expect_status (
          "GCM encrypt unsupported algorithm",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_UNSUPPORTED);
    }


    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.key = NULL;

      failed |=
        expect_status (
          "GCM encrypt NULL key",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.key_len = 15;

      failed |=
        expect_status (
          "GCM encrypt invalid key length",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_UNSUPPORTED);
    }


    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.iv = NULL;

      failed |=
        expect_status (
          "GCM encrypt NULL IV",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.iv_len = 11;

      failed |=
        expect_status (
          "GCM encrypt invalid IV length",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_UNSUPPORTED);
    }


    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.tag = NULL;

      failed |=
        expect_status (
          "GCM encrypt NULL tag",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.tag_len = 15;

      failed |=
        expect_status (
          "GCM encrypt invalid tag length",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_UNSUPPORTED);
    }


    /*
     * AAD may be NULL only when aad_len == 0.
     */
    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.aad = NULL;

      failed |=
        expect_status (
          "GCM encrypt NULL AAD",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    /*
     * Plaintext may be NULL for zero-length operations, but not
     * when plaintext_len is non-zero.
     */
    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.plaintext = NULL;

      failed |=
        expect_status (
          "GCM encrypt NULL plaintext",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.ciphertext_capacity = 15;

      failed |=
        expect_status (
          "GCM encrypt short ciphertext buffer",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_BUFFER_TOO_SMALL);
    }


    {
      ngi541_aead_encrypt_request_t invalid = request;

      invalid.ciphertext = NULL;
      invalid.ciphertext_capacity = 16;

      failed |=
        expect_status (
          "GCM encrypt NULL ciphertext",
          ngi541_crypto_aead_encrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }
  }


  /*
   * AES-GCM decryption API validation.
   *
   * Authentication correctness is covered by crypto.aes_gcm_kat.
   * These cases cover the request contract before authentication
   * is attempted.
   */
  {
    ngi541_aead_decrypt_request_t request = {
      .struct_size =
        sizeof (ngi541_aead_decrypt_request_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = key,
      .key_len = 16,

      .iv = iv12,
      .iv_len = sizeof (iv12),

      .aad = aad,
      .aad_len = sizeof (aad),

      .ciphertext = input,
      .ciphertext_len = 16,

      .tag = tag,
      .tag_len = sizeof (tag),

      .plaintext = output,
      .plaintext_capacity = sizeof (output),
    };


    {
      ngi541_aead_decrypt_request_t invalid = request;

      invalid.struct_size =
        sizeof (ngi541_aead_decrypt_request_t) - 1;

      failed |=
        expect_status (
          "GCM decrypt short struct_size",
          ngi541_crypto_aead_decrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    {
      ngi541_aead_decrypt_request_t invalid = request;

      invalid.tag = NULL;

      failed |=
        expect_status (
          "GCM decrypt NULL tag",
          ngi541_crypto_aead_decrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    {
      ngi541_aead_decrypt_request_t invalid = request;

      invalid.tag_len = 15;

      failed |=
        expect_status (
          "GCM decrypt invalid tag length",
          ngi541_crypto_aead_decrypt (&invalid),
          NGI541_STATUS_UNSUPPORTED);
    }


    {
      ngi541_aead_decrypt_request_t invalid = request;

      invalid.ciphertext = NULL;

      failed |=
        expect_status (
          "GCM decrypt NULL ciphertext",
          ngi541_crypto_aead_decrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    {
      ngi541_aead_decrypt_request_t invalid = request;

      invalid.plaintext_capacity = 15;

      failed |=
        expect_status (
          "GCM decrypt short plaintext buffer",
          ngi541_crypto_aead_decrypt (&invalid),
          NGI541_STATUS_BUFFER_TOO_SMALL);
    }


    {
      ngi541_aead_decrypt_request_t invalid = request;

      invalid.plaintext = NULL;
      invalid.plaintext_capacity = 16;

      failed |=
        expect_status (
          "GCM decrypt NULL plaintext",
          ngi541_crypto_aead_decrypt (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }
  }


  /*
   * SHA-256 public API validation.
   */
  {
    ngi541_hash_request_t request = {
      .struct_size =
        sizeof (ngi541_hash_request_t),

      .algorithm =
        NGI541_HASH_SHA2_256,

      .message = input,
      .message_len = sizeof (input),

      .digest = digest,
      .digest_capacity = sizeof (digest),
    };


    {
      ngi541_hash_request_t invalid = request;

      invalid.struct_size =
        sizeof (ngi541_hash_request_t) - 1;

      failed |=
        expect_status (
          "hash short struct_size",
          ngi541_crypto_hash_compute (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    {
      ngi541_hash_request_t invalid = request;

      invalid.algorithm =
        (ngi541_hash_algorithm_t) 0xffffffffU;

      failed |=
        expect_status (
          "hash unsupported algorithm",
          ngi541_crypto_hash_compute (&invalid),
          NGI541_STATUS_UNSUPPORTED);
    }


    /*
     * A NULL message is valid only when message_len == 0.
     */
    {
      ngi541_hash_request_t invalid = request;

      invalid.message = NULL;

      failed |=
        expect_status (
          "hash NULL message",
          ngi541_crypto_hash_compute (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    {
      ngi541_hash_request_t invalid = request;

      invalid.digest = NULL;

      failed |=
        expect_status (
          "hash NULL digest",
          ngi541_crypto_hash_compute (&invalid),
          NGI541_STATUS_INVALID_ARGUMENT);
    }


    /*
     * SHA-256 requires a 32-byte digest buffer.
     */
    {
      ngi541_hash_request_t invalid = request;

      invalid.digest_capacity = 31;

      failed |=
        expect_status (
          "SHA-256 short digest buffer",
          ngi541_crypto_hash_compute (&invalid),
          NGI541_STATUS_BUFFER_TOO_SMALL);
    }
  }


  if (failed)
    {
      fprintf (
        stderr,
        "public API validation failed\n");

      return 2;
    }

  return 0;
}