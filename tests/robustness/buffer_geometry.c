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
#define NGI541_TEST_GUARD_SIZE 32
#define NGI541_TEST_CANARY     0xa5


typedef struct
{
  uint8_t *base;
  uint8_t *data;

  size_t size;
  size_t offset;
} ngi541_test_buffer_t;

typedef struct
{
  uint8_t *base;
  uint8_t *data;

  size_t size;
  size_t prefix_size;
  size_t suffix_size;
} ngi541_guarded_buffer_t;


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

static int
ngi541_guarded_buffer_allocate (
  ngi541_guarded_buffer_t *buffer,
  size_t size,
  size_t offset)
{
  size_t prefix_size;
  size_t allocation_size;

  if (buffer == NULL)
    return 1;

  *buffer =
    (ngi541_guarded_buffer_t) { 0 };

  if (offset >
      SIZE_MAX - NGI541_TEST_GUARD_SIZE)
    return 1;

  prefix_size =
    NGI541_TEST_GUARD_SIZE + offset;

  if (size >
      SIZE_MAX - prefix_size)
    return 1;

  allocation_size =
    prefix_size + size;

  if (NGI541_TEST_GUARD_SIZE >
      SIZE_MAX - allocation_size)
    return 1;

  allocation_size +=
    NGI541_TEST_GUARD_SIZE;

  buffer->base =
    malloc (allocation_size);

  if (buffer->base == NULL)
    return 1;

  memset (
    buffer->base,
    NGI541_TEST_CANARY,
    allocation_size);

  buffer->data =
    buffer->base + prefix_size;

  buffer->size = size;
  buffer->prefix_size = prefix_size;
  buffer->suffix_size =
    NGI541_TEST_GUARD_SIZE;

  return 0;
}


static int
ngi541_guarded_buffer_verify (
  const ngi541_guarded_buffer_t *buffer,
  const char *buffer_name,
  const char *geometry,
  size_t length)
{
  if (buffer == NULL ||
      buffer->base == NULL ||
      buffer_name == NULL ||
      geometry == NULL)
    return 1;

  for (
    size_t i = 0;
    i < buffer->prefix_size;
    i++)
    {
      if (buffer->base[i] !=
          NGI541_TEST_CANARY)
        {
          fprintf (
            stderr,
            "AES-CTR prefix canary modified: "
            "geometry=%s buffer=%s "
            "length=%zu offset=%zu "
            "actual=0x%02x\n",
            geometry,
            buffer_name,
            length,
            i,
            buffer->base[i]);

          return 1;
        }
    }

  for (
    size_t i = 0;
    i < buffer->suffix_size;
    i++)
    {
      uint8_t actual =
        buffer->data[
          buffer->size + i];

      if (actual !=
          NGI541_TEST_CANARY)
        {
          fprintf (
            stderr,
            "AES-CTR suffix canary modified: "
            "geometry=%s buffer=%s "
            "length=%zu offset=%zu "
            "actual=0x%02x\n",
            geometry,
            buffer_name,
            length,
            i,
            actual);

          return 1;
        }
    }

  return 0;
}


static void
ngi541_guarded_buffer_free (
  ngi541_guarded_buffer_t *buffer)
{
  if (buffer == NULL)
    return;

  free (buffer->base);

  *buffer =
    (ngi541_guarded_buffer_t) { 0 };
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
ngi541_run_ctr_geometry_case (
  const char *geometry,
  size_t length,
  size_t key_offset,
  size_t iv_offset,
  size_t input_offset,
  size_t output_offset)
{
  static const uint8_t key_material[16] =
  {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
  };

  static const uint8_t iv_material[16] =
  {
    0xf0, 0xf1, 0xf2, 0xf3,
    0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff,
  };

  uint8_t source[NGI541_CTR_MAX_TEST_LENGTH];
  uint8_t reference[NGI541_CTR_MAX_TEST_LENGTH];

  ngi541_test_buffer_t key = { 0 };
  ngi541_test_buffer_t iv = { 0 };

  ngi541_test_buffer_t encrypt_input = { 0 };
  ngi541_test_buffer_t encrypt_output = { 0 };

  ngi541_test_buffer_t decrypt_input = { 0 };
  ngi541_test_buffer_t decrypt_output = { 0 };

  ngi541_cipher_request_t request;
  ngi541_status_t status;

  int result = 1;


  if (geometry == NULL ||
      length > sizeof (source))
    {
      fprintf (
        stderr,
        "AES-CTR geometry: invalid test case\n");

      return 1;
    }

  /*
   * Alignment of a zero-length data buffer has no meaning.
   *
   * M5.2.4a already covers the NULL/zero-length path.
   */
  if (length == 0 &&
      (input_offset != 0 ||
       output_offset != 0))
    {
      fprintf (
        stderr,
        "AES-CTR geometry: invalid zero-length offsets: "
        "geometry=%s input_offset=%zu output_offset=%zu\n",
        geometry,
        input_offset,
        output_offset);

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
   * Produce a normal aligned reference result.
   *
   * Differential correctness is already covered by M5.1; this
   * baseline isolates changes caused by buffer geometry.
   */
  request = (ngi541_cipher_request_t)
  {
    .struct_size =
      sizeof (ngi541_cipher_request_t),

    .algorithm =
      NGI541_CIPHER_AES_CTR,

    .key = key_material,
    .key_len = sizeof (key_material),

    .iv = iv_material,
    .iv_len = sizeof (iv_material),

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
        "geometry=%s length=%zu status=%d\n",
        geometry,
        length,
        (int) status);

      goto out;
    }


  /*
   * Allocate each public buffer independently.
   *
   * data = base + offset deliberately breaks natural alignment.
   * The logical buffer still ends exactly at the allocation end,
   * preserving the M5.2.4a suffix-boundary property.
   */
  if (ngi541_test_buffer_allocate_suffix_exact (
        &key,
        sizeof (key_material),
        key_offset) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR key allocation failed: "
        "geometry=%s offset=%zu\n",
        geometry,
        key_offset);

      goto out;
    }

  if (ngi541_test_buffer_allocate_suffix_exact (
        &iv,
        sizeof (iv_material),
        iv_offset) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR IV allocation failed: "
        "geometry=%s offset=%zu\n",
        geometry,
        iv_offset);

      goto out;
    }

  if (ngi541_test_buffer_allocate_suffix_exact (
        &encrypt_input,
        length,
        input_offset) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR encrypt input allocation failed: "
        "geometry=%s length=%zu offset=%zu\n",
        geometry,
        length,
        input_offset);

      goto out;
    }

  if (ngi541_test_buffer_allocate_suffix_exact (
        &encrypt_output,
        length,
        output_offset) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR encrypt output allocation failed: "
        "geometry=%s length=%zu offset=%zu\n",
        geometry,
        length,
        output_offset);

      goto out;
    }

  if (ngi541_test_buffer_allocate_suffix_exact (
        &decrypt_input,
        length,
        input_offset) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR decrypt input allocation failed: "
        "geometry=%s length=%zu offset=%zu\n",
        geometry,
        length,
        input_offset);

      goto out;
    }

  if (ngi541_test_buffer_allocate_suffix_exact (
        &decrypt_output,
        length,
        output_offset) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR decrypt output allocation failed: "
        "geometry=%s length=%zu offset=%zu\n",
        geometry,
        length,
        output_offset);

      goto out;
    }


  memcpy (
    key.data,
    key_material,
    sizeof (key_material));

  memcpy (
    iv.data,
    iv_material,
    sizeof (iv_material));


  if (length != 0)
    {
      memcpy (
        encrypt_input.data,
        source,
        length);

      memset (
        encrypt_output.data,
        0xa5,
        length);

      memcpy (
        decrypt_input.data,
        reference,
        length);

      memset (
        decrypt_output.data,
        0x5a,
        length);
    }


  /*
   * Encrypt through the public API using the requested geometry.
   */
  request = (ngi541_cipher_request_t)
  {
    .struct_size =
      sizeof (ngi541_cipher_request_t),

    .algorithm =
      NGI541_CIPHER_AES_CTR,

    .key = key.data,
    .key_len = sizeof (key_material),

    .iv = iv.data,
    .iv_len = sizeof (iv_material),

    .input = encrypt_input.data,
    .input_len = length,

    .output = encrypt_output.data,
    .output_capacity = length,
  };

  status =
    ngi541_crypto_cipher_encrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR geometry encrypt failed: "
        "geometry=%s length=%zu "
        "key=%zu iv=%zu input=%zu output=%zu "
        "status=%d\n",
        geometry,
        length,
        key_offset,
        iv_offset,
        input_offset,
        output_offset,
        (int) status);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        encrypt_input.data,
        source,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR geometry encrypt modified input: "
        "geometry=%s length=%zu\n",
        geometry,
        length);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        encrypt_output.data,
        reference,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR geometry ciphertext mismatch: "
        "geometry=%s length=%zu "
        "key=%zu iv=%zu input=%zu output=%zu\n",
        geometry,
        length,
        key_offset,
        iv_offset,
        input_offset,
        output_offset);

      goto out;
    }


  /*
   * Decrypt from an independently allocated input buffer.
   *
   * This is deliberate: input and output alignment must be tested
   * independently in both operation directions.
   */
  request = (ngi541_cipher_request_t)
  {
    .struct_size =
      sizeof (ngi541_cipher_request_t),

    .algorithm =
      NGI541_CIPHER_AES_CTR,

    .key = key.data,
    .key_len = sizeof (key_material),

    .iv = iv.data,
    .iv_len = sizeof (iv_material),

    .input = decrypt_input.data,
    .input_len = length,

    .output = decrypt_output.data,
    .output_capacity = length,
  };

  status =
    ngi541_crypto_cipher_decrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR geometry decrypt failed: "
        "geometry=%s length=%zu "
        "key=%zu iv=%zu input=%zu output=%zu "
        "status=%d\n",
        geometry,
        length,
        key_offset,
        iv_offset,
        input_offset,
        output_offset,
        (int) status);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        decrypt_output.data,
        source,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR geometry plaintext mismatch: "
        "geometry=%s length=%zu\n",
        geometry,
        length);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        decrypt_input.data,
        reference,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR geometry decrypt modified input: "
        "geometry=%s length=%zu\n",
        geometry,
        length);

      goto out;
    }


  /*
   * key and IV are const inputs to the public contract.
   */
  if (memcmp (
        key.data,
        key_material,
        sizeof (key_material)) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR geometry modified key: "
        "geometry=%s offset=%zu\n",
        geometry,
        key_offset);

      goto out;
    }


  if (memcmp (
        iv.data,
        iv_material,
        sizeof (iv_material)) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR geometry modified IV: "
        "geometry=%s offset=%zu\n",
        geometry,
        iv_offset);

      goto out;
    }


  result = 0;


out:
  ngi541_test_buffer_free (
    &decrypt_output);

  ngi541_test_buffer_free (
    &decrypt_input);

  ngi541_test_buffer_free (
    &encrypt_output);

  ngi541_test_buffer_free (
    &encrypt_input);

  ngi541_test_buffer_free (
    &iv);

  ngi541_test_buffer_free (
    &key);

  return result;
}


static int
ngi541_run_ctr_canary_case (
  const char *geometry,
  size_t length,
  size_t key_offset,
  size_t iv_offset,
  size_t input_offset,
  size_t output_offset)
{
  static const uint8_t key_material[16] =
  {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
  };

  static const uint8_t iv_material[16] =
  {
    0xf0, 0xf1, 0xf2, 0xf3,
    0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff,
  };

  uint8_t source[NGI541_CTR_MAX_TEST_LENGTH];
  uint8_t reference[NGI541_CTR_MAX_TEST_LENGTH];

  ngi541_guarded_buffer_t key = { 0 };
  ngi541_guarded_buffer_t iv = { 0 };

  ngi541_guarded_buffer_t encrypt_input = { 0 };
  ngi541_guarded_buffer_t encrypt_output = { 0 };

  ngi541_guarded_buffer_t decrypt_input = { 0 };
  ngi541_guarded_buffer_t decrypt_output = { 0 };

  ngi541_cipher_request_t request;
  ngi541_status_t status;

  int result = 1;


  if (geometry == NULL ||
      length > sizeof (source))
    return 1;


  ngi541_fill_test_data (
    source,
    sizeof (source));

  memset (
    reference,
    0,
    sizeof (reference));


  /*
   * Produce aligned functional reference.
   */
  request = (ngi541_cipher_request_t)
  {
    .struct_size =
      sizeof (ngi541_cipher_request_t),

    .algorithm =
      NGI541_CIPHER_AES_CTR,

    .key = key_material,
    .key_len = sizeof (key_material),

    .iv = iv_material,
    .iv_len = sizeof (iv_material),

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
        "AES-CTR canary baseline failed: "
        "geometry=%s length=%zu status=%d\n",
        geometry,
        length,
        (int) status);

      goto out;
    }


  if (ngi541_guarded_buffer_allocate (
        &key,
        sizeof (key_material),
        key_offset) != 0 ||
      ngi541_guarded_buffer_allocate (
        &iv,
        sizeof (iv_material),
        iv_offset) != 0 ||
      ngi541_guarded_buffer_allocate (
        &encrypt_input,
        length,
        input_offset) != 0 ||
      ngi541_guarded_buffer_allocate (
        &encrypt_output,
        length,
        output_offset) != 0 ||
      ngi541_guarded_buffer_allocate (
        &decrypt_input,
        length,
        input_offset) != 0 ||
      ngi541_guarded_buffer_allocate (
        &decrypt_output,
        length,
        output_offset) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR guarded allocation failed: "
        "geometry=%s length=%zu\n",
        geometry,
        length);

      goto out;
    }


  memcpy (
    key.data,
    key_material,
    sizeof (key_material));

  memcpy (
    iv.data,
    iv_material,
    sizeof (iv_material));


  if (length != 0)
    {
      memcpy (
        encrypt_input.data,
        source,
        length);

      memset (
        encrypt_output.data,
        0x5a,
        length);

      memcpy (
        decrypt_input.data,
        reference,
        length);

      memset (
        decrypt_output.data,
        0x5a,
        length);
    }


  /*
   * Notice that for length == 0 these pointers remain non-NULL.
   *
   * Any accidental output write lands directly in the suffix
   * canary because the logical data region has size zero.
   */
  request = (ngi541_cipher_request_t)
  {
    .struct_size =
      sizeof (ngi541_cipher_request_t),

    .algorithm =
      NGI541_CIPHER_AES_CTR,

    .key = key.data,
    .key_len = sizeof (key_material),

    .iv = iv.data,
    .iv_len = sizeof (iv_material),

    .input = encrypt_input.data,
    .input_len = length,

    .output = encrypt_output.data,
    .output_capacity = length,
  };

  status =
    ngi541_crypto_cipher_encrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR guarded encrypt failed: "
        "geometry=%s length=%zu status=%d\n",
        geometry,
        length,
        (int) status);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        encrypt_input.data,
        source,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR guarded encrypt modified input: "
        "geometry=%s length=%zu\n",
        geometry,
        length);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        encrypt_output.data,
        reference,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR guarded ciphertext mismatch: "
        "geometry=%s length=%zu\n",
        geometry,
        length);

      goto out;
    }


  if (memcmp (
        key.data,
        key_material,
        sizeof (key_material)) != 0 ||
      memcmp (
        iv.data,
        iv_material,
        sizeof (iv_material)) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR guarded encrypt modified "
        "key or IV: geometry=%s length=%zu\n",
        geometry,
        length);

      goto out;
    }


#define VERIFY_GUARD(buffer_)                                      \
  do                                                               \
    {                                                              \
      if (ngi541_guarded_buffer_verify (                            \
            &(buffer_),                                            \
            #buffer_,                                              \
            geometry,                                              \
            length) != 0)                                          \
        goto out;                                                  \
    }                                                              \
  while (0)

  VERIFY_GUARD (key);
  VERIFY_GUARD (iv);
  VERIFY_GUARD (encrypt_input);
  VERIFY_GUARD (encrypt_output);


  request = (ngi541_cipher_request_t)
  {
    .struct_size =
      sizeof (ngi541_cipher_request_t),

    .algorithm =
      NGI541_CIPHER_AES_CTR,

    .key = key.data,
    .key_len = sizeof (key_material),

    .iv = iv.data,
    .iv_len = sizeof (iv_material),

    .input = decrypt_input.data,
    .input_len = length,

    .output = decrypt_output.data,
    .output_capacity = length,
  };

  status =
    ngi541_crypto_cipher_decrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR guarded decrypt failed: "
        "geometry=%s length=%zu status=%d\n",
        geometry,
        length,
        (int) status);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        decrypt_input.data,
        reference,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR guarded decrypt modified input: "
        "geometry=%s length=%zu\n",
        geometry,
        length);

      goto out;
    }


  if (length != 0 &&
      memcmp (
        decrypt_output.data,
        source,
        length) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR guarded plaintext mismatch: "
        "geometry=%s length=%zu\n",
        geometry,
        length);

      goto out;
    }


  if (memcmp (
        key.data,
        key_material,
        sizeof (key_material)) != 0 ||
      memcmp (
        iv.data,
        iv_material,
        sizeof (iv_material)) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR guarded decrypt modified "
        "key or IV: geometry=%s length=%zu\n",
        geometry,
        length);

      goto out;
    }


  VERIFY_GUARD (key);
  VERIFY_GUARD (iv);
  VERIFY_GUARD (decrypt_input);
  VERIFY_GUARD (decrypt_output);

#undef VERIFY_GUARD


  result = 0;


out:
  ngi541_guarded_buffer_free (
    &decrypt_output);

  ngi541_guarded_buffer_free (
    &decrypt_input);

  ngi541_guarded_buffer_free (
    &encrypt_output);

  ngi541_guarded_buffer_free (
    &encrypt_input);

  ngi541_guarded_buffer_free (
    &iv);

  ngi541_guarded_buffer_free (
    &key);

  return result;
}

static int
ngi541_run_ctr_zero_length_null_case (void)
{
  uint8_t key[16] =
  {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
  };

  uint8_t iv[16] =
  {
    0xf0, 0xf1, 0xf2, 0xf3,
    0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff,
  };

  uint8_t expected_key[sizeof (key)];
  uint8_t expected_iv[sizeof (iv)];

  ngi541_cipher_request_t request;
  ngi541_status_t status;


  memcpy (
    expected_key,
    key,
    sizeof (key));

  memcpy (
    expected_iv,
    iv,
    sizeof (iv));


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

    .input = NULL,
    .input_len = 0,

    .output = NULL,
    .output_capacity = 0,
  };


  status =
    ngi541_crypto_cipher_encrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR NULL/zero encrypt failed: "
        "status=%d\n",
        (int) status);

      return 1;
    }


  status =
    ngi541_crypto_cipher_decrypt (
      &request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AES-CTR NULL/zero decrypt failed: "
        "status=%d\n",
        (int) status);

      return 1;
    }


  if (memcmp (
        key,
        expected_key,
        sizeof (key)) != 0 ||
      memcmp (
        iv,
        expected_iv,
        sizeof (iv)) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR NULL/zero modified "
        "key or IV\n");

      return 1;
    }


  return 0;
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

  static const size_t offsets[] =
  {
    1, 2, 3, 7, 15,
  };

  ngi541_status_t status;

  size_t exact_size_cases = 0;
  size_t unaligned_cases = 0;
  size_t canary_cases = 0;
  size_t zero_null_cases = 0;


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


  /*
   * M5.2.4a:
   * aligned exact-size boundary corpus.
   */
  for (
    size_t i = 0;
    i < sizeof (lengths) / sizeof (lengths[0]);
    i++)
    {
      if (ngi541_run_ctr_geometry_case (
            "exact-size",
            lengths[i],
            0,
            0,
            0,
            0) != 0)
        return 1;

      exact_size_cases++;
    }


  /*
   * M5.2.4b:
   *
   * Deliberately misalign one public buffer at a time.
   *
   * Length zero is already covered by M5.2.4a. Alignment has no
   * meaning for the NULL zero-length data path, so begin at index 1.
   */
  for (
    size_t offset_index = 0;
    offset_index <
      sizeof (offsets) / sizeof (offsets[0]);
    offset_index++)
    {
      size_t offset =
        offsets[offset_index];

      for (
        size_t length_index = 1;
        length_index <
          sizeof (lengths) / sizeof (lengths[0]);
        length_index++)
        {
          size_t length =
            lengths[length_index];


          if (ngi541_run_ctr_geometry_case (
                "unaligned-key",
                length,
                offset,
                0,
                0,
                0) != 0)
            return 1;

          unaligned_cases++;


          if (ngi541_run_ctr_geometry_case (
                "unaligned-iv",
                length,
                0,
                offset,
                0,
                0) != 0)
            return 1;

          unaligned_cases++;


          if (ngi541_run_ctr_geometry_case (
                "unaligned-input",
                length,
                0,
                0,
                offset,
                0) != 0)
            return 1;

          unaligned_cases++;


          if (ngi541_run_ctr_geometry_case (
                "unaligned-output",
                length,
                0,
                0,
                0,
                offset) != 0)
            return 1;

          unaligned_cases++;
        }
    }

  /*
   * M5.2.4c:
   * Guarded logical-boundary corpus.
   *
   * First repeat the complete aligned length corpus,
   * including non-NULL zero-length input/output.
   */
  for (
    size_t i = 0;
    i < sizeof (lengths) / sizeof (lengths[0]);
    i++)
    {
      if (ngi541_run_ctr_canary_case (
            "canary-aligned",
            lengths[i],
            0,
            0,
            0,
            0) != 0)
        return 1;

      canary_cases++;
    }


  /*
   * Combine logical guards with each deliberately
   * unaligned public buffer independently.
   */
  for (
    size_t offset_index = 0;
    offset_index <
      sizeof (offsets) / sizeof (offsets[0]);
    offset_index++)
    {
      size_t offset =
        offsets[offset_index];

      for (
        size_t length_index = 1;
        length_index <
          sizeof (lengths) / sizeof (lengths[0]);
        length_index++)
        {
          size_t length =
            lengths[length_index];


          if (ngi541_run_ctr_canary_case (
                "canary-unaligned-key",
                length,
                offset,
                0,
                0,
                0) != 0)
            return 1;

          canary_cases++;


          if (ngi541_run_ctr_canary_case (
                "canary-unaligned-iv",
                length,
                0,
                offset,
                0,
                0) != 0)
            return 1;

          canary_cases++;


          if (ngi541_run_ctr_canary_case (
                "canary-unaligned-input",
                length,
                0,
                0,
                offset,
                0) != 0)
            return 1;

          canary_cases++;


          if (ngi541_run_ctr_canary_case (
                "canary-unaligned-output",
                length,
                0,
                0,
                0,
                offset) != 0)
            return 1;

          canary_cases++;
        }
    }


  if (ngi541_run_ctr_zero_length_null_case () != 0)
    return 1;

  zero_null_cases++;

  printf (
    "AES-CTR buffer geometry passed: "
    "exact_size=%zu "
    "unaligned=%zu "
    "canary=%zu "
    "zero_null=%zu "
    "total=%zu\n",
    exact_size_cases,
    unaligned_cases,
    canary_cases,
    zero_null_cases,
    exact_size_cases +
      unaligned_cases +
      canary_cases +
      zero_null_cases);

  return 0;
}