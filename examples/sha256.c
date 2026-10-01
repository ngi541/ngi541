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
  static const char message[] = "Hello from NGI541";

  uint8_t digest[32] = { 0 };

  ngi541_hash_request_t request = {
    .struct_size = sizeof (request),
    .algorithm = NGI541_HASH_SHA2_256,
    .message = (const uint8_t *) message,
    .message_len = strlen (message),
    .digest = digest,
    .digest_capacity = sizeof (digest),
  };

  ngi541_status_t status = ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "ngi541_engine_init failed: status=%d\n",
        (int) status);
      return 1;
    }

  status = ngi541_crypto_hash_compute (&request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "SHA-256 failed: status=%d\n",
        (int) status);
      return 2;
    }

  printf ("message: %s\n", message);
  printf ("sha256:  ");
  print_hex (digest, sizeof (digest));

  return 0;
}
