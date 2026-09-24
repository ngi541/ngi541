/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SHA224_DIGEST_SIZE 28

static void
print_digest (
  const char *label,
  const uint8_t *digest,
  size_t len)
{
  fprintf (stderr, "%s: ", label);

  for (size_t i = 0; i < len; i++)
    fprintf (stderr, "%02x", digest[i]);

  fputc ('\n', stderr);
}


static int
run_sha224_kat (
  const char *name,
  const uint8_t *message,
  size_t message_len,
  const uint8_t expected_digest[SHA224_DIGEST_SIZE])
{
  uint8_t digest[SHA224_DIGEST_SIZE] = { 0 };

  ngi541_hash_request_t request = {
    .struct_size = sizeof (ngi541_hash_request_t),
    .algorithm = NGI541_HASH_SHA2_224,
    .message = message,
    .message_len = message_len,
    .digest = digest,
    .digest_capacity = sizeof (digest),
  };

  ngi541_status_t status =
    ngi541_crypto_hash_compute (&request);

  if (status == NGI541_STATUS_UNAVAILABLE)
    {
      fprintf (
        stderr,
        "%s: SHA-224 handler is unavailable\n",
        name);

      return 1;
    }

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "%s: SHA-224 execution failed: status=%d\n",
        name,
        (int) status);

      return 2;
    }

  if (memcmp (
        digest,
        expected_digest,
        sizeof (digest)) != 0)
    {
      fprintf (
        stderr,
        "%s: SHA-224 known-answer test failed\n",
        name);

      print_digest (
        "expected",
        expected_digest,
        sizeof (digest));

      print_digest (
        "actual  ",
        digest,
        sizeof (digest));

      return 3;
    }

  return 0;
}


int
main (void)
{
  static const uint8_t abc[] = {
    0x61, 0x62, 0x63
  };

  static const uint8_t empty_digest[SHA224_DIGEST_SIZE] = {
    0xd1, 0x4a, 0x02, 0x8c,
    0x2a, 0x3a, 0x2b, 0xc9,
    0x47, 0x61, 0x02, 0xbb,
    0x28, 0x82, 0x34, 0xc4,
    0x15, 0xa2, 0xb0, 0x1f,
    0x82, 0x8e, 0xa6, 0x2a,
    0xc5, 0xb3, 0xe4, 0x2f,
  };

  static const uint8_t abc_digest[SHA224_DIGEST_SIZE] = {
    0x23, 0x09, 0x7d, 0x22,
    0x34, 0x05, 0xd8, 0x22,
    0x86, 0x42, 0xa4, 0x77,
    0xbd, 0xa2, 0x55, 0xb3,
    0x2a, 0xad, 0xbc, 0xe4,
    0xbd, 0xa0, 0xb3, 0xf7,
    0xe3, 0x6c, 0x9d, 0xa7,
  };

  int result;
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
   * Zero-length input is part of the public API contract:
   * message may be NULL when message_len is zero.
   */
  result = run_sha224_kat (
    "empty message",
    NULL,
    0,
    empty_digest);

  if (result != 0)
    return 10 + result;

  result = run_sha224_kat (
    "\"abc\"",
    abc,
    sizeof (abc),
    abc_digest);

  if (result != 0)
    return 20 + result;

  return 0;
}