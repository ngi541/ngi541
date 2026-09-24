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

static const unsigned char expected_digest[28] = {
  0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
  0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
  0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
  0xe3, 0x6c, 0x9d, 0xa7
};

int
main (void)
{
  unsigned char digest[28] = { 0 };

  ACVP_HASH_TC hash_tc = {
    .cipher = ACVP_HASH_SHA224,
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
      fprintf (
        stderr,
        "ngi541_engine_init failed: %d\n",
        status);

      return 1;
    }

  if (ngi541_acvp_sha2_handler (&test_case) != 0)
    {
      fprintf (
        stderr,
        "SHA-224 ACVP callback failed\n");

      return 1;
    }

  if (hash_tc.md_len != sizeof (expected_digest))
    {
      fprintf (
        stderr,
        "unexpected SHA-224 digest length: %u\n",
        hash_tc.md_len);

      return 1;
    }

  if (memcmp (
        digest,
        expected_digest,
        sizeof (expected_digest)) != 0)
    {
      fprintf (
        stderr,
        "SHA-224 digest mismatch\n");

      return 1;
    }

  return 0;
}