/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


#define NGI541_PREPARED_TEST_ITERATIONS 256
#define NGI541_PREPARED_MAX_PAYLOAD     1536
#define NGI541_PREPARED_MAX_AAD         32


static int
buffer_is_zero (
  const uint8_t *buffer,
  size_t length)
{
  for (size_t i = 0; i < length; i++)
    {
      if (buffer[i] != 0)
        return 0;
    }

  return 1;
}


static void
fill_test_data (
  uint8_t *buffer,
  size_t length,
  uint32_t seed)
{
  for (size_t i = 0; i < length; i++)
    {
      buffer[i] =
        (uint8_t) (
          seed +
          (uint32_t) (i * 29u) +
          (uint32_t) ((i >> 1) * 17u));
    }
}


static void
make_counter_value (
  uint8_t *value,
  size_t length,
  uint8_t domain,
  uint32_t iteration)
{
  memset (
    value,
    0,
    length);

  value[0] = domain;

  value[length - 4] =
    (uint8_t) (iteration >> 24);

  value[length - 3] =
    (uint8_t) (iteration >> 16);

  value[length - 2] =
    (uint8_t) (iteration >> 8);

  value[length - 1] =
    (uint8_t) iteration;
}


static size_t
payload_length (
  uint32_t iteration)
{
  switch (iteration % 6)
    {
    case 0:
      /*
       * QUIC AES header protection consumes five bytes of
       * keystream. Keep this geometry explicitly covered by
       * the reusable CTR path.
       */
      return 5;

    case 1:
      return 16;

    case 2:
      return 31;

    case 3:
      return 64;

    case 4:
      return 257;

    default:
      /*
       * Packet-sized workload representative of the future
       * HTTP/3 / QUIC integration path.
       */
      return
        1200 +
        (iteration % 260);
    }
}


static size_t
gcm_aad_length (
  uint32_t iteration)
{
  switch (iteration % 4)
    {
    case 0:
      return 0;

    case 1:
      return 8;

    case 2:
      return 12;

    default:
      return 23;
    }
}


static int
test_prepared_aes_ctr (void)
{
  static const uint8_t reference_key[16] = {
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f,
  };

  uint8_t creation_key[sizeof (reference_key)];

  uint8_t iv[16];

  uint8_t input[NGI541_PREPARED_MAX_PAYLOAD];
  uint8_t one_shot_output[NGI541_PREPARED_MAX_PAYLOAD];
  uint8_t prepared_output[NGI541_PREPARED_MAX_PAYLOAD];
  uint8_t decrypted[NGI541_PREPARED_MAX_PAYLOAD];

  ngi541_cipher_key_params_t key_params;
  ngi541_cipher_key_t *prepared_key = NULL;

  ngi541_status_t status;


  memcpy (
    creation_key,
    reference_key,
    sizeof (creation_key));

  key_params =
    (ngi541_cipher_key_params_t)
    {
      .struct_size =
        sizeof (ngi541_cipher_key_params_t),

      .algorithm =
        NGI541_CIPHER_AES_CTR,

      .key = creation_key,
      .key_len = sizeof (creation_key),
    };


  status =
    ngi541_crypto_cipher_key_create (
      &key_params,
      &prepared_key);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "prepared AES-CTR key creation failed: "
        "status=%d\n",
        (int) status);

      return 1;
    }


  /*
   * The prepared-key API must not retain the caller's raw key
   * pointer after key creation.
   */
  memset (
    creation_key,
    0,
    sizeof (creation_key));


  for (uint32_t iteration = 0;
       iteration < NGI541_PREPARED_TEST_ITERATIONS;
       iteration++)
    {
      const size_t length =
        payload_length (iteration);

      ngi541_cipher_request_t one_shot_request;
      ngi541_cipher_exec_request_t prepared_request;


      make_counter_value (
        iv,
        sizeof (iv),
        0xc1,
        iteration);

      fill_test_data (
        input,
        length,
        0x1000u + iteration);

      memset (
        one_shot_output,
        0,
        length);

      memset (
        prepared_output,
        0,
        length);

      memset (
        decrypted,
        0,
        length);


      one_shot_request =
        (ngi541_cipher_request_t)
        {
          .struct_size =
            sizeof (ngi541_cipher_request_t),

          .algorithm =
            NGI541_CIPHER_AES_CTR,

          .key = reference_key,
          .key_len = sizeof (reference_key),

          .iv = iv,
          .iv_len = sizeof (iv),

          .input = input,
          .input_len = length,

          .output = one_shot_output,
          .output_capacity =
            sizeof (one_shot_output),
        };


      status =
        ngi541_crypto_cipher_encrypt (
          &one_shot_request);

      if (status != NGI541_STATUS_OK)
        {
          fprintf (
            stderr,
            "one-shot AES-CTR encrypt failed: "
            "iteration=%u length=%zu status=%d\n",
            iteration,
            length,
            (int) status);

          ngi541_crypto_cipher_key_destroy (
            prepared_key);

          return 1;
        }


      prepared_request =
        (ngi541_cipher_exec_request_t)
        {
          .struct_size =
            sizeof (ngi541_cipher_exec_request_t),

          .iv = iv,
          .iv_len = sizeof (iv),

          .input = input,
          .input_len = length,

          .output = prepared_output,
          .output_capacity =
            sizeof (prepared_output),
        };


      status =
        ngi541_crypto_cipher_encrypt_prepared (
          prepared_key,
          &prepared_request);

      if (status != NGI541_STATUS_OK)
        {
          fprintf (
            stderr,
            "prepared AES-CTR encrypt failed: "
            "iteration=%u length=%zu status=%d\n",
            iteration,
            length,
            (int) status);

          ngi541_crypto_cipher_key_destroy (
            prepared_key);

          return 1;
        }


      if (memcmp (
            one_shot_output,
            prepared_output,
            length) != 0)
        {
          fprintf (
            stderr,
            "AES-CTR prepared/one-shot mismatch: "
            "iteration=%u length=%zu\n",
            iteration,
            length);

          ngi541_crypto_cipher_key_destroy (
            prepared_key);

          return 1;
        }


      prepared_request =
        (ngi541_cipher_exec_request_t)
        {
          .struct_size =
            sizeof (ngi541_cipher_exec_request_t),

          .iv = iv,
          .iv_len = sizeof (iv),

          .input = prepared_output,
          .input_len = length,

          .output = decrypted,
          .output_capacity =
            sizeof (decrypted),
        };


      status =
        ngi541_crypto_cipher_decrypt_prepared (
          prepared_key,
          &prepared_request);

      if (status != NGI541_STATUS_OK)
        {
          fprintf (
            stderr,
            "prepared AES-CTR decrypt failed: "
            "iteration=%u length=%zu status=%d\n",
            iteration,
            length,
            (int) status);

          ngi541_crypto_cipher_key_destroy (
            prepared_key);

          return 1;
        }


      if (memcmp (
            input,
            decrypted,
            length) != 0)
        {
          fprintf (
            stderr,
            "AES-CTR prepared decrypt mismatch: "
            "iteration=%u length=%zu\n",
            iteration,
            length);

          ngi541_crypto_cipher_key_destroy (
            prepared_key);

          return 1;
        }
    }


  ngi541_crypto_cipher_key_destroy (
    prepared_key);

  return 0;
}


static int
test_prepared_aes_gcm (void)
{
  static const uint8_t reference_key[16] = {
    0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f,
  };

  uint8_t creation_key[sizeof (reference_key)];

  uint8_t iv[12];
  uint8_t aad[NGI541_PREPARED_MAX_AAD];

  uint8_t plaintext[NGI541_PREPARED_MAX_PAYLOAD];

  uint8_t one_shot_ciphertext[
    NGI541_PREPARED_MAX_PAYLOAD];

  uint8_t prepared_ciphertext[
    NGI541_PREPARED_MAX_PAYLOAD];

  uint8_t decrypted[
    NGI541_PREPARED_MAX_PAYLOAD];

  uint8_t one_shot_tag[16];
  uint8_t prepared_tag[16];

  ngi541_aead_key_params_t key_params;
  ngi541_aead_key_t *prepared_key = NULL;

  ngi541_status_t status;


  memcpy (
    creation_key,
    reference_key,
    sizeof (creation_key));

  key_params =
    (ngi541_aead_key_params_t)
    {
      .struct_size =
        sizeof (ngi541_aead_key_params_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = creation_key,
      .key_len = sizeof (creation_key),
    };


  status =
    ngi541_crypto_aead_key_create (
      &key_params,
      &prepared_key);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "prepared AES-GCM key creation failed: "
        "status=%d\n",
        (int) status);

      return 1;
    }


  /*
   * Prove that prepared execution does not depend on the
   * caller-owned raw-key buffer after creation.
   */
  memset (
    creation_key,
    0,
    sizeof (creation_key));


  for (uint32_t iteration = 0;
       iteration < NGI541_PREPARED_TEST_ITERATIONS;
       iteration++)
    {
      const size_t plaintext_len =
        payload_length (iteration);

      const size_t aad_len =
        gcm_aad_length (iteration);

      ngi541_aead_encrypt_request_t
        one_shot_request;

      ngi541_aead_encrypt_exec_request_t
        prepared_encrypt_request;

      ngi541_aead_decrypt_exec_request_t
        prepared_decrypt_request;


      make_counter_value (
        iv,
        sizeof (iv),
        0xa1,
        iteration);

      fill_test_data (
        aad,
        aad_len,
        0x2000u + iteration);

      fill_test_data (
        plaintext,
        plaintext_len,
        0x3000u + iteration);


      memset (
        one_shot_ciphertext,
        0,
        plaintext_len);

      memset (
        prepared_ciphertext,
        0,
        plaintext_len);

      memset (
        decrypted,
        0,
        plaintext_len);

      memset (
        one_shot_tag,
        0,
        sizeof (one_shot_tag));

      memset (
        prepared_tag,
        0,
        sizeof (prepared_tag));


      one_shot_request =
        (ngi541_aead_encrypt_request_t)
        {
          .struct_size =
            sizeof (ngi541_aead_encrypt_request_t),

          .algorithm =
            NGI541_AEAD_AES_GCM,

          .key = reference_key,
          .key_len = sizeof (reference_key),

          .iv = iv,
          .iv_len = sizeof (iv),

          .aad =
            aad_len != 0
              ? aad
              : NULL,

          .aad_len = aad_len,

          .plaintext = plaintext,
          .plaintext_len =
            plaintext_len,

          .ciphertext =
            one_shot_ciphertext,

          .ciphertext_capacity =
            sizeof (one_shot_ciphertext),

          .tag = one_shot_tag,
          .tag_len =
            sizeof (one_shot_tag),
        };


      status =
        ngi541_crypto_aead_encrypt (
          &one_shot_request);

      if (status != NGI541_STATUS_OK)
        {
          fprintf (
            stderr,
            "one-shot AES-GCM encrypt failed: "
            "iteration=%u plaintext_len=%zu "
            "aad_len=%zu status=%d\n",
            iteration,
            plaintext_len,
            aad_len,
            (int) status);

          ngi541_crypto_aead_key_destroy (
            prepared_key);

          return 1;
        }


      prepared_encrypt_request =
        (ngi541_aead_encrypt_exec_request_t)
        {
          .struct_size =
            sizeof (
              ngi541_aead_encrypt_exec_request_t),

          .iv = iv,
          .iv_len = sizeof (iv),

          .aad =
            aad_len != 0
              ? aad
              : NULL,

          .aad_len = aad_len,

          .plaintext = plaintext,
          .plaintext_len =
            plaintext_len,

          .ciphertext =
            prepared_ciphertext,

          .ciphertext_capacity =
            sizeof (prepared_ciphertext),

          .tag = prepared_tag,
          .tag_len =
            sizeof (prepared_tag),
        };


      status =
        ngi541_crypto_aead_encrypt_prepared (
          prepared_key,
          &prepared_encrypt_request);

      if (status != NGI541_STATUS_OK)
        {
          fprintf (
            stderr,
            "prepared AES-GCM encrypt failed: "
            "iteration=%u plaintext_len=%zu "
            "aad_len=%zu status=%d\n",
            iteration,
            plaintext_len,
            aad_len,
            (int) status);

          ngi541_crypto_aead_key_destroy (
            prepared_key);

          return 1;
        }


      if (memcmp (
            one_shot_ciphertext,
            prepared_ciphertext,
            plaintext_len) != 0)
        {
          fprintf (
            stderr,
            "AES-GCM ciphertext mismatch: "
            "iteration=%u plaintext_len=%zu "
            "aad_len=%zu\n",
            iteration,
            plaintext_len,
            aad_len);

          ngi541_crypto_aead_key_destroy (
            prepared_key);

          return 1;
        }


      if (memcmp (
            one_shot_tag,
            prepared_tag,
            sizeof (prepared_tag)) != 0)
        {
          fprintf (
            stderr,
            "AES-GCM tag mismatch: "
            "iteration=%u plaintext_len=%zu "
            "aad_len=%zu\n",
            iteration,
            plaintext_len,
            aad_len);

          ngi541_crypto_aead_key_destroy (
            prepared_key);

          return 1;
        }


      prepared_decrypt_request =
        (ngi541_aead_decrypt_exec_request_t)
        {
          .struct_size =
            sizeof (
              ngi541_aead_decrypt_exec_request_t),

          .iv = iv,
          .iv_len = sizeof (iv),

          .aad =
            aad_len != 0
              ? aad
              : NULL,

          .aad_len = aad_len,

          .ciphertext =
            prepared_ciphertext,

          .ciphertext_len =
            plaintext_len,

          .tag = prepared_tag,
          .tag_len =
            sizeof (prepared_tag),

          .plaintext = decrypted,
          .plaintext_capacity =
            sizeof (decrypted),
        };


      status =
        ngi541_crypto_aead_decrypt_prepared (
          prepared_key,
          &prepared_decrypt_request);

      if (status != NGI541_STATUS_OK)
        {
          fprintf (
            stderr,
            "prepared AES-GCM decrypt failed: "
            "iteration=%u plaintext_len=%zu "
            "aad_len=%zu status=%d\n",
            iteration,
            plaintext_len,
            aad_len,
            (int) status);

          ngi541_crypto_aead_key_destroy (
            prepared_key);

          return 1;
        }


      if (memcmp (
            plaintext,
            decrypted,
            plaintext_len) != 0)
        {
          fprintf (
            stderr,
            "AES-GCM prepared decrypt mismatch: "
            "iteration=%u plaintext_len=%zu "
            "aad_len=%zu\n",
            iteration,
            plaintext_len,
            aad_len);

          ngi541_crypto_aead_key_destroy (
            prepared_key);

          return 1;
        }
    }


  /*
   * Dedicated authentication-failure check.
   *
   * The prepared decrypt path must preserve the one-shot API
   * guarantee that unauthenticated plaintext is cleared.
   */
  {
    const size_t plaintext_len = 321;
    const size_t aad_len = 23;

    uint8_t bad_tag[16];

    ngi541_aead_encrypt_exec_request_t
      encrypt_request;

    ngi541_aead_decrypt_exec_request_t
      decrypt_request;


    make_counter_value (
      iv,
      sizeof (iv),
      0xa2,
      NGI541_PREPARED_TEST_ITERATIONS);

    fill_test_data (
      aad,
      aad_len,
      0x4000u);

    fill_test_data (
      plaintext,
      plaintext_len,
      0x5000u);

    memset (
      prepared_ciphertext,
      0,
      plaintext_len);

    memset (
      prepared_tag,
      0,
      sizeof (prepared_tag));


    encrypt_request =
      (ngi541_aead_encrypt_exec_request_t)
      {
        .struct_size =
          sizeof (
            ngi541_aead_encrypt_exec_request_t),

        .iv = iv,
        .iv_len = sizeof (iv),

        .aad = aad,
        .aad_len = aad_len,

        .plaintext = plaintext,
        .plaintext_len =
          plaintext_len,

        .ciphertext =
          prepared_ciphertext,

        .ciphertext_capacity =
          sizeof (prepared_ciphertext),

        .tag = prepared_tag,
        .tag_len =
          sizeof (prepared_tag),
      };


    status =
      ngi541_crypto_aead_encrypt_prepared (
        prepared_key,
        &encrypt_request);

    if (status != NGI541_STATUS_OK)
      {
        fprintf (
          stderr,
          "AES-GCM bad-tag setup encrypt failed: "
          "status=%d\n",
          (int) status);

        ngi541_crypto_aead_key_destroy (
          prepared_key);

        return 1;
      }


    memcpy (
      bad_tag,
      prepared_tag,
      sizeof (bad_tag));

    bad_tag[0] ^= 0x01;


    /*
     * Fill with a non-zero marker so successful zeroization can be
     * distinguished from untouched output.
     */
    memset (
      decrypted,
      0xa5,
      plaintext_len);


    decrypt_request =
      (ngi541_aead_decrypt_exec_request_t)
      {
        .struct_size =
          sizeof (
            ngi541_aead_decrypt_exec_request_t),

        .iv = iv,
        .iv_len = sizeof (iv),

        .aad = aad,
        .aad_len = aad_len,

        .ciphertext =
          prepared_ciphertext,

        .ciphertext_len =
          plaintext_len,

        .tag = bad_tag,
        .tag_len =
          sizeof (bad_tag),

        .plaintext = decrypted,
        .plaintext_capacity =
          sizeof (decrypted),
      };


    status =
      ngi541_crypto_aead_decrypt_prepared (
        prepared_key,
        &decrypt_request);

    if (status !=
        NGI541_STATUS_AUTH_FAILED)
      {
        fprintf (
          stderr,
          "AES-GCM bad tag returned unexpected status: "
          "status=%d\n",
          (int) status);

        ngi541_crypto_aead_key_destroy (
          prepared_key);

        return 1;
      }


    if (!buffer_is_zero (
          decrypted,
          plaintext_len))
      {
        fprintf (
          stderr,
          "AES-GCM authentication failure left "
          "unauthenticated plaintext visible\n");

        ngi541_crypto_aead_key_destroy (
          prepared_key);

        return 1;
      }
  }


  ngi541_crypto_aead_key_destroy (
    prepared_key);

  return 0;
}


int
main (void)
{
  ngi541_status_t status;


  status =
    ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "ngi541_engine_init failed: "
        "status=%d\n",
        (int) status);

      return 1;
    }


  if (test_prepared_aes_ctr () != 0)
    return 1;


  if (test_prepared_aes_gcm () != 0)
    return 1;


  return 0;
}