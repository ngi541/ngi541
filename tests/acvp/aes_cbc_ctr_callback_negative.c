/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "callbacks/aes_cbc.h"
#include "callbacks/aes_ctr.h"

#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>


typedef int (*handler_fn_t) (
  ACVP_TEST_CASE *test_case);


static int
expect_rejected (
  const char *name,
  handler_fn_t handler,
  ACVP_SYM_CIPHER_TC *tc)
{
  ACVP_TEST_CASE test_case = { 0 };
  int rv;

  test_case.tc.symmetric = tc;

  rv = handler (&test_case);

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
  handler_fn_t handler,
  ACVP_SYM_CIPHER_TC *tc)
{
  ACVP_TEST_CASE test_case = { 0 };
  int rv;

  test_case.tc.symmetric = tc;

  rv = handler (&test_case);

  if (rv != 0)
    {
      fprintf (
        stderr,
        "%s was unexpectedly rejected: rv=%d\n",
        name,
        rv);

      return 1;
    }

  return 0;
}


static int
expect_null_rejected (
  const char *name,
  handler_fn_t handler)
{
  ACVP_TEST_CASE test_case = { 0 };

  if (handler (NULL) == 0)
    {
      fprintf (
        stderr,
        "%s accepted NULL test_case\n",
        name);

      return 1;
    }

  if (handler (&test_case) == 0)
    {
      fprintf (
        stderr,
        "%s accepted NULL symmetric testcase\n",
        name);

      return 1;
    }

  return 0;
}


int
main (void)
{
  uint8_t key[32] = { 0 };

  uint8_t iv[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
  };

  uint8_t plaintext[32] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff,

    0x10, 0x21, 0x32, 0x43,
    0x54, 0x65, 0x76, 0x87,
    0x98, 0xa9, 0xba, 0xcb,
    0xdc, 0xed, 0xfe, 0x0f,
  };

  uint8_t ciphertext[32] = { 0 };

  ngi541_status_t status;
  int failed = 0;


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
   * ------------------------------------------------------------
   * AES-CBC
   * ------------------------------------------------------------
   */
  {
    ACVP_SYM_CIPHER_TC valid = {
      .cipher =
        ACVP_AES_CBC,

      .test_type =
        ACVP_SYM_TEST_TYPE_AFT,

      .direction =
        ACVP_SYM_CIPH_DIR_ENCRYPT,

      .key = key,
      .key_len = 128,

      .iv = iv,
      .iv_len = sizeof (iv),

      .pt = plaintext,
      .pt_len = 16,

      .ct = ciphertext,
      .ct_len = 16,
    };


    /*
     * Positive control.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      memset (
        ciphertext,
        0,
        sizeof (ciphertext));

      failed |=
        expect_accepted (
          "valid AES-CBC AFT",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    failed |=
      expect_null_rejected (
        "AES-CBC callback",
        ngi541_acvp_aes_cbc_handler);


    /*
     * Wrong cipher.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.cipher =
        ACVP_AES_CTR;

      failed |=
        expect_rejected (
          "CBC wrong cipher",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    /*
     * CBC supports AFT and MCT, but not CTR Counter Test.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.test_type =
        ACVP_SYM_TEST_TYPE_CTR;

      failed |=
        expect_rejected (
          "CBC CTR test type",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    /*
     * Zero is not a valid ACVP symmetric test type.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.test_type =
        (ACVP_SYM_CIPH_TESTTYPE) 0;

      failed |=
        expect_rejected (
          "CBC unknown test type",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    /*
     * Required key and IV.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.key = NULL;

      failed |=
        expect_rejected (
          "CBC NULL key",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.iv = NULL;

      failed |=
        expect_rejected (
          "CBC NULL IV",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    /*
     * AES key length is supplied in bits.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.key_len = 127;

      failed |=
        expect_rejected (
          "CBC non-byte-aligned key length",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.key_len = 160;

      failed |=
        expect_rejected (
          "CBC unsupported key length",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    /*
     * CBC requires a complete 128-bit IV.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.iv_len = 15;

      failed |=
        expect_rejected (
          "CBC invalid IV length",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    /*
     * CBC payload must consist of complete AES blocks.
     *
     * This is one of the explicit M4.4 roadmap cases.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.pt_len = 15;

      failed |=
        expect_rejected (
          "CBC non-block-aligned plaintext",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    /*
     * Non-empty encrypt input/output pointers.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.pt = NULL;

      failed |=
        expect_rejected (
          "CBC NULL plaintext",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.ct = NULL;

      failed |=
        expect_rejected (
          "CBC NULL ciphertext output",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    /*
     * Decrypt-side block validation.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.direction =
        ACVP_SYM_CIPH_DIR_DECRYPT;

      tc.ct_len = 15;

      failed |=
        expect_rejected (
          "CBC non-block-aligned ciphertext",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.direction =
        ACVP_SYM_CIPH_DIR_BOTH;

      failed |=
        expect_rejected (
          "CBC invalid testcase direction",
          ngi541_acvp_aes_cbc_handler,
          &tc);
    }
  }


  /*
   * ------------------------------------------------------------
   * AES-CTR
   * ------------------------------------------------------------
   */
  {
    ACVP_SYM_CIPHER_TC valid = {
      .cipher =
        ACVP_AES_CTR,

      .test_type =
        ACVP_SYM_TEST_TYPE_AFT,

      .direction =
        ACVP_SYM_CIPH_DIR_ENCRYPT,

      .key = key,
      .key_len = 128,

      .iv = iv,
      .iv_len = sizeof (iv),

      .pt = plaintext,
      .pt_len = 16,

      .ct = ciphertext,
      .ct_len = 16,
    };


    /*
     * Positive AFT control.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      memset (
        ciphertext,
        0,
        sizeof (ciphertext));

      failed |=
        expect_accepted (
          "valid AES-CTR AFT",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    /*
     * Counter Test is also part of the registered CTR profile.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.test_type =
        ACVP_SYM_TEST_TYPE_CTR;

      memset (
        ciphertext,
        0,
        sizeof (ciphertext));

      failed |=
        expect_accepted (
          "valid AES-CTR Counter Test",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    failed |=
      expect_null_rejected (
        "AES-CTR callback",
        ngi541_acvp_aes_ctr_handler);


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.cipher =
        ACVP_AES_CBC;

      failed |=
        expect_rejected (
          "CTR wrong cipher",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    /*
     * CTR MCT is not part of the current NGI541 profile.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.test_type =
        ACVP_SYM_TEST_TYPE_MCT;

      failed |=
        expect_rejected (
          "CTR MCT",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    /*
     * Unknown test types must not silently fall through as AFT.
     */
    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.test_type =
        (ACVP_SYM_CIPH_TESTTYPE) 0;

      failed |=
        expect_rejected (
          "CTR unknown test type",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.key = NULL;

      failed |=
        expect_rejected (
          "CTR NULL key",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.iv = NULL;

      failed |=
        expect_rejected (
          "CTR NULL IV",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.key_len = 127;

      failed |=
        expect_rejected (
          "CTR non-byte-aligned key length",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.key_len = 160;

      failed |=
        expect_rejected (
          "CTR unsupported key length",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.iv_len = 15;

      failed |=
        expect_rejected (
          "CTR invalid IV length",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    /*
     * Unlike CBC, CTR supports non-block-multiple payload sizes.
     * Therefore there is deliberately no "15-byte payload must
     * fail" testcase here.
     */


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.pt = NULL;

      failed |=
        expect_rejected (
          "CTR NULL plaintext",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.ct = NULL;

      failed |=
        expect_rejected (
          "CTR NULL ciphertext output",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.direction =
        ACVP_SYM_CIPH_DIR_DECRYPT;

      tc.ct = NULL;
      tc.ct_len = 16;

      failed |=
        expect_rejected (
          "CTR decrypt NULL ciphertext",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.direction =
        ACVP_SYM_CIPH_DIR_DECRYPT;

      tc.pt = NULL;
      tc.ct_len = 16;

      failed |=
        expect_rejected (
          "CTR decrypt NULL plaintext output",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }


    {
      ACVP_SYM_CIPHER_TC tc = valid;

      tc.direction =
        ACVP_SYM_CIPH_DIR_BOTH;

      failed |=
        expect_rejected (
          "CTR invalid testcase direction",
          ngi541_acvp_aes_ctr_handler,
          &tc);
    }
  }


  if (failed)
    {
      fprintf (
        stderr,
        "AES-CBC/CTR negative callback validation failed\n");

      return 2;
    }

  return 0;
}