/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/crypto.h>
#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define NGI541_CTR_MAX_TEST_LENGTH 129


typedef struct
{
  uint8_t *base;
  uint8_t *data;

  size_t size;
  size_t offset;
} ngi541_test_buffer_t;


static int
ngi541_test_buffer_allocate_suffix_exact (
  ngi541_test_buffer_t *buffer,
  size_t size,
  size_t offset)
{
  size_t allocation_size;

  if (buffer == NULL)
    return 1;

  *buffer = (ngi541_test_buffer_t) { 0 };

  /*
   * Zero-length public API paths deliberately use NULL.
   * There is no allocation to protect in this case.
   */
  if (size == 0)
    {
      if (offset != 0)
        return 1;

      return 0;
    }

  if (offset > SIZE_MAX - size)
    return 1;

  allocation_size = offset + size;

  buffer->base =
    malloc (allocation_size);

  if (buffer->base == NULL)
    return 1;

  buffer->data =
    buffer->base + offset;

  buffer->size = size;
  buffer->offset = offset;

  return 0;
}


static void
ngi541_test_buffer_free (
  ngi541_test_buffer_t *buffer)
{
  if (buffer == NULL)
    return;

  free (buffer->base);

  *buffer =
    (ngi541_test_buffer_t) { 0 };
}


static void
ngi541_fill_test_data (
  uint8_t *data,
  size_t length)
{
  for (size_t i = 0; i < length; i++)
    data[i] =
      (uint8_t) (
        (i * 29u + 7u) &
        0xffu);
}


static int
ngi541_run_ctr_exact_size_case (
  size_t length)
{
  static const uint8_t key[16] =
  {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
  };

  static const uint8_t iv[16] =
  {
    0xf0, 0xf1, 0xf2, 0xf3,
    0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff,
  };

  uint8_t source[NGI541_CTR_MAX_TEST_LENGTH];
  uint8_t reference[NGI541_CTR_MAX_TEST_LENGTH];

  ngi541_test_buffer_t input = { 0 };
  ngi541_test_buffer_t ciphertext = { 0 };
  ngi541_test_buffer_t plaintext = { 0 };

  ngi541_cipher_request_t request;
  ngi541_status_t status;

  int result = 1;


  if (length > sizeof (source))
    {
      fprintf (
        stderr,
        "AES-CTR exact-size: invalid test length=%zu\n",
        length);

      return 1;
    }


  ngi541_fill_test_data (
    source,
    sizeof (source));

  memset (
    reference,
    0xa5,
    sizeof (reference));


  /*
   * First produce the functional baseline using ordinary storage.
   *
   * M5.1 already established cipher correctness. This baseline lets
   * the geometry test isolate memory-layout dependent differences.
   */
  request = (ngi541_cipher_request_t)
  {
    .struct_size =
      sizeof (ngi541_cipher_request_t),

    .algorithm =
      NGI541_CIPHER_AES_CTR,

    .key = key,
    .key_len = sizeof (key),

    .iv = iv,
    .iv_len = sizeof (iv),

    .input =
      length != 0
        ? source
        : NULL,

    .input_len = length,

    .output =
      length != 0
        ? reference
        : NULL,

    .output_capacity = length,
  };

  status =
    ngi541_crypto_cipher_encrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR baseline encrypt failed: "
        "length=%zu status=%d\n",
        length,
        (int) status);

      goto out;
    }


  /*
   * The exact-size allocations intentionally contain no trailing
   * spare capacity. Under ASan, the byte immediately following each
   * allocation belongs to the allocator redzone.
   */
  if (ngi541_test_buffer_allocate_suffix_exact (
        &input,
        length,
        0) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR input allocation failed: "
        "length=%zu\n",
        length);

      goto out;
    }

  if (ngi541_test_buffer_allocate_suffix_exact (
        &ciphertext,
        length,
        0) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR ciphertext allocation failed: "
        "length=%zu\n",
        length);

      goto out;
    }

  if (ngi541_test_buffer_allocate_suffix_exact (
        &plaintext,
        length,
        0) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR plaintext allocation failed: "
        "length=%zu\n",
        length);

      goto out;
    }


  if (length != 0)
    {
      memcpy (
        input.data,
        source,
        length);

      memset (
        ciphertext.data,
        0xa5,
        length);

      memset (
        plaintext.data,
        0x5a,
        length);
    }


  request = (ngi541_cipher_request_t)
  {
    .struct_size =
      sizeof (ngi541_cipher_request_t),

    .algorithm =
      NGI541_CIPHER_AES_CTR,

    .key = key,
    .key_len = sizeof (key),

    .iv = iv,
    .iv_len = sizeof (iv),

    .input = input.data,
    .input_len = length,

    .output = ciphertext.data,
    .output_capacity = length,
  };

  status =
    ngi541_crypto_cipher_encrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR exact-size encrypt failed: "
        "length=%zu status=%d\n",
        length,
        (int) status);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        input.data,
        source,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR encrypt modified input: "
        "length=%zu\n",
        length);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        ciphertext.data,
        reference,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR exact-size ciphertext mismatch: "
        "length=%zu\n",
        length);

      goto out;
    }


  request = (ngi541_cipher_request_t)
  {
    .struct_size =
      sizeof (ngi541_cipher_request_t),

    .algorithm =
      NGI541_CIPHER_AES_CTR,

    .key = key,
    .key_len = sizeof (key),

    .iv = iv,
    .iv_len = sizeof (iv),

    .input = ciphertext.data,
    .input_len = length,

    .output = plaintext.data,
    .output_capacity = length,
  };

  status =
    ngi541_crypto_cipher_decrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR exact-size decrypt failed: "
        "length=%zu status=%d\n",
        length,
        (int) status);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        plaintext.data,
        source,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR exact-size plaintext mismatch: "
        "length=%zu\n",
        length);

      goto out;
    }


  /*
   * Ciphertext is const input to the public decrypt operation.
   * Verify that execution did not modify it in place.
   */
  if (length != 0 &&
      memcmp (
        ciphertext.data,
        reference,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR decrypt modified ciphertext input: "
        "length=%zu\n",
        length);

      goto out;
    }


  result = 0;


out:
  ngi541_test_buffer_free (
    &plaintext);

  ngi541_test_buffer_free (
    &ciphertext);

  ngi541_test_buffer_free (
    &input);

  return result;
}


int
main (void)
{
  static const size_t lengths[] =
  {
    0,
    1, 2, 3,
    7, 8, 9,
    15, 16, 17,
    31, 32, 33,
    63, 64, 65,
    127, 128, 129,
  };

  ngi541_status_t status;


  status =
    ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "NGI541 engine initialization failed: "
        "status=%d\n",
        (int) status);

      return 1;
    }


  for (
    size_t i = 0;
    i < sizeof (lengths) / sizeof (lengths[0]);
    i++)
    {
      if (ngi541_run_ctr_exact_size_case (
            lengths[i]) != 0)
        return 1;
    }


  printf (
    "AES-CTR exact-size buffer geometry passed: "
    "%zu lengths\n",
    sizeof (lengths) / sizeof (lengths[0]));

  return 0;
}