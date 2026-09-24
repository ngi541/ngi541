/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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


int
main (void)
{
  static const uint8_t message[] = {
    0x61, 0x62, 0x63
  };

  static const uint8_t expected_digest[32] = {
    0xba, 0x78, 0x16, 0xbf,
    0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde,
    0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3,
    0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61,
    0xf2, 0x00, 0x15, 0xad,
  };

  uint8_t digest[32] = { 0 };

  ngi541_hash_request_t request = {
    .struct_size = sizeof (ngi541_hash_request_t),
    .algorithm = NGI541_HASH_SHA2_256,
    .message = message,
    .message_len = sizeof (message),
    .digest = digest,
    .digest_capacity = sizeof (digest),
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

  status = ngi541_crypto_hash_compute (&request);

  if (status == NGI541_STATUS_UNAVAILABLE)
    {
    fprintf (
      stderr,
      "SHA-256 handler is unavailable after engine "
      "initialization\n");

      return 2;
    }

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "SHA-256 execution failed: status=%d\n",
        (int) status);

      return 3;
    }

  if (memcmp (
        digest,
        expected_digest,
        sizeof (expected_digest)) != 0)
    {
      fprintf (
        stderr,
        "SHA-256 known-answer test failed\n");

      print_digest (
        "expected",
        expected_digest,
        sizeof (expected_digest));

      print_digest (
        "actual  ",
        digest,
        sizeof (digest));

      return 4;
    }

  return 0;
}