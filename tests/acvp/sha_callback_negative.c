/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "callbacks/sha2.h"

#include <ngi541/engine.h>

#include <acvp/acvp.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>


static int
expect_rejected (
  const char *name,
  ACVP_HASH_TC *tc)
{
  ACVP_TEST_CASE test_case = { 0 };
  int rv;

  test_case.tc.hash = tc;

  rv =
    ngi541_acvp_sha2_handler (
      &test_case);

  if (rv == 0)
    {
      fprintf (
        stderr,
        "%s was unexpectedly accepted\n",
        name);

      return 1;
    }

  return 0;
}


static int
expect_accepted (
  const char *name,
  ACVP_HASH_TC *tc,
  unsigned int expected_md_len)
{
  ACVP_TEST_CASE test_case = { 0 };
  int rv;

  test_case.tc.hash = tc;

  rv =
    ngi541_acvp_sha2_handler (
      &test_case);

  if (rv != 0)
    {
      fprintf (
        stderr,
        "%s was unexpectedly rejected: rv=%d\n",
        name,
        rv);

      return 1;
    }

  if (tc->md_len != expected_md_len)
    {
      fprintf (
        stderr,
        "%s returned unexpected digest length=%u, expected=%u\n",
        name,
        tc->md_len,
        expected_md_len);

      return 1;
    }

  return 0;
}


static int
test_common_negative_cases (
  ACVP_CIPHER cipher,
  unsigned int digest_size,
  const char *prefix)
{
  static unsigned char message[] = {
    0x61, 0x62, 0x63
  };

  unsigned char digest[32] = { 0 };

  ACVP_HASH_TC valid = {
    .cipher = cipher,
    .test_type = ACVP_HASH_TEST_TYPE_AFT,
    .msg = message,
    .msg_len = sizeof (message),
    .md = digest,
  };

  int failed = 0;


  /*
   * Positive AFT control.
   */
  {
    ACVP_HASH_TC tc = valid;

    memset (
      digest,
      0,
      sizeof (digest));

    failed |=
      expect_accepted (
        prefix,
        &tc,
        digest_size);
  }


  /*
   * NULL digest output.
   */
  {
    ACVP_HASH_TC tc = valid;

    tc.md = NULL;

    failed |=
      expect_rejected (
        "SHA NULL digest",
        &tc);
  }


  /*
   * NONE / zero is not part of the current SHA-2 profile.
   */
  {
    ACVP_HASH_TC tc = valid;

    tc.test_type =
      ACVP_HASH_TEST_TYPE_NONE;

    failed |=
      expect_rejected (
        "SHA NONE test type",
        &tc);
  }


  /*
   * VOT is a SHAKE-oriented variable-output test and is not
   * part of the current NGI541 SHA-224/SHA-256 profile.
   */
  {
    ACVP_HASH_TC tc = valid;

    tc.test_type =
      ACVP_HASH_TEST_TYPE_VOT;

    failed |=
      expect_rejected (
        "SHA VOT test type",
        &tc);
  }


  /*
   * LDT is intentionally not part of the current profile.
   */
  {
    ACVP_HASH_TC tc = valid;

    tc.test_type =
      ACVP_HASH_TEST_TYPE_LDT;

    failed |=
      expect_rejected (
        "SHA LDT test type",
        &tc);
  }


  /*
   * AFT requires a message pointer whenever msg_len is
   * non-zero.
   */
  {
    ACVP_HASH_TC tc = valid;

    tc.msg = NULL;
    tc.msg_len = sizeof (message);

    failed |=
      expect_rejected (
        "SHA AFT NULL message with non-zero length",
        &tc);
  }


  /*
   * Empty-message hashing is valid.
   *
   * This is an important positive boundary case because the
   * public NGI541 hash contract explicitly allows NULL when
   * message_len is zero.
   */
  {
    ACVP_HASH_TC tc = valid;

    tc.msg = NULL;
    tc.msg_len = 0;

    memset (
      digest,
      0,
      sizeof (digest));

    failed |=
      expect_accepted (
        "SHA empty AFT message",
        &tc,
        digest_size);
  }


  /*
   * MCT requires all three libacvp-managed message components.
   */
  {
    unsigned char m1[32] = { 0 };
    unsigned char m2[32] = { 0 };
    unsigned char m3[32] = { 0 };

    ACVP_HASH_TC tc = {
      .cipher = cipher,

      .test_type =
        ACVP_HASH_TEST_TYPE_MCT,

      .md = digest,

      .m1 = m1,
      .m2 = m2,
      .m3 = m3,

      .m1_len = digest_size,
      .m2_len = digest_size,
      .m3_len = digest_size,

      .mct_version =
        ACVP_HASH_MCT_VERSION_STANDARD,
    };


    {
      ACVP_HASH_TC invalid = tc;

      invalid.m1 = NULL;

      failed |=
        expect_rejected (
          "SHA MCT NULL m1",
          &invalid);
    }


    {
      ACVP_HASH_TC invalid = tc;

      invalid.m2 = NULL;

      failed |=
        expect_rejected (
          "SHA MCT NULL m2",
          &invalid);
    }


    {
      ACVP_HASH_TC invalid = tc;

      invalid.m3 = NULL;

      failed |=
        expect_rejected (
          "SHA MCT NULL m3",
          &invalid);
    }
  }


  return failed;
}


int
main (void)
{
  ACVP_TEST_CASE test_case = { 0 };

  ngi541_status_t status;
  int failed = 0;


  status =
    ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "ngi541_engine_init failed: status=%d\n",
        (int) status);

      return 1;
    }


  /*
   * Top-level NULL testcase.
   */
  if (ngi541_acvp_sha2_handler (NULL) == 0)
    {
      fprintf (
        stderr,
        "SHA callback accepted NULL testcase\n");

      failed = 1;
    }


  /*
   * NULL hash testcase.
   */
  if (ngi541_acvp_sha2_handler (
        &test_case) == 0)
    {
      fprintf (
        stderr,
        "SHA callback accepted NULL hash testcase\n");

      failed = 1;
    }


  /*
   * Unsupported hash algorithm.
   */
  {
    unsigned char digest[64] = { 0 };

    ACVP_HASH_TC tc = {
      .cipher =
        ACVP_HASH_SHA384,

      .test_type =
        ACVP_HASH_TEST_TYPE_AFT,

      .msg = NULL,
      .msg_len = 0,

      .md = digest,
    };

    failed |=
      expect_rejected (
        "unsupported SHA cipher",
        &tc);
  }


  /*
   * SHA-224 validation.
   */
  failed |=
    test_common_negative_cases (
      ACVP_HASH_SHA224,
      28U,
      "valid SHA-224 AFT");


  /*
   * SHA-256 validation.
   */
  failed |=
    test_common_negative_cases (
      ACVP_HASH_SHA256,
      32U,
      "valid SHA-256 AFT");


  if (failed)
    {
      fprintf (
        stderr,
        "SHA callback negative validation failed\n");

      return 2;
    }

  return 0;
}