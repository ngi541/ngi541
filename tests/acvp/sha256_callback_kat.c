/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <stdio.h>
#include <string.h>

#include <acvp/acvp.h>

#include <ngi541/engine.h>

#include "callbacks/sha2.h"

static const unsigned char message[] = {
  0x61, 0x62, 0x63
};

static const unsigned char expected_digest[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

int
main (void)
{
  unsigned char digest[32] = { 0 };

  ACVP_HASH_TC hash_tc = {
    .cipher = ACVP_HASH_SHA256,
    .test_type = ACVP_HASH_TEST_TYPE_AFT,
    .msg = (unsigned char *) message,
    .msg_len = sizeof (message),
    .md = digest,
  };

  ACVP_TEST_CASE test_case = { 0 };
  ngi541_status_t status;

  test_case.tc.hash = &hash_tc;

  status = ngi541_engine_init ();
  if (status != NGI541_STATUS_OK)
    {
      fprintf (stderr, "ngi541_engine_init failed: %d\n", status);
      return 1;
    }

  if (ngi541_acvp_sha2_handler (&test_case) != 0)
    {
      fprintf (stderr, "SHA-256 ACVP callback failed\n");
      return 1;
    }

  if (hash_tc.md_len != sizeof (expected_digest))
    {
      fprintf (
        stderr,
        "unexpected SHA-256 digest length: %u\n",
        hash_tc.md_len);
      return 1;
    }

  if (memcmp (digest, expected_digest, sizeof (expected_digest)) != 0)
    {
      fprintf (stderr, "SHA-256 digest mismatch\n");
      return 1;
    }

  return 0;
}