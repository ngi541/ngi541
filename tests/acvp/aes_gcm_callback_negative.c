/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "callbacks/aes_gcm.h"

#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>


static int
expect_rejected (
  const char *name,
  ACVP_SYM_CIPHER_TC *tc)
{
  ACVP_TEST_CASE test_case = { 0 };
  int rv;

  test_case.tc.symmetric = tc;

  rv =
    ngi541_acvp_aes_gcm_handler (
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
  ACVP_SYM_CIPHER_TC *tc)
{
  ACVP_TEST_CASE test_case = { 0 };
  int rv;

  test_case.tc.symmetric = tc;

  rv =
    ngi541_acvp_aes_gcm_handler (
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

  return 0;
}


int
main (void)
{
  uint8_t key[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
  };

  uint8_t iv[12] = {
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
  };

  uint8_t aad[16] = {
    0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f,
  };

  uint8_t plaintext[16] = {
    0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x3e, 0x3f,
  };

  uint8_t ciphertext[16] = { 0 };
  uint8_t tag[16] = { 0 };

  ACVP_SYM_CIPHER_TC valid = {
    .cipher =
      ACVP_AES_GCM,

    .test_type =
      ACVP_SYM_TEST_TYPE_AFT,

    .direction =
      ACVP_SYM_CIPH_DIR_ENCRYPT,

    /*
     * External IV is the currently registered NGI541
     * AES-GCM validation profile.
     *
     * ivgen_mode intentionally remains zero here. Pinned
     * libacvp does not populate ivgen_mode for external-IV
     * test groups.
     */
    .ivgen_source =
      ACVP_SYM_CIPH_IVGEN_SRC_EXT,

    .key = key,
    .key_len = 128,

    .iv = iv,
    .iv_len = sizeof (iv),

    .aad = aad,
    .aad_len = sizeof (aad),

    .pt = plaintext,
    .pt_len = sizeof (plaintext),

    .ct = ciphertext,
    .ct_len = sizeof (ciphertext),

    .tag = tag,
    .tag_len = sizeof (tag),
  };

  ngi541_status_t status;
  int failed = 0;


  /*
   * Initialize first.
   *
   * Otherwise an invalid testcase that accidentally reaches
   * the public API could still be rejected only because the
   * engine is not initialized, producing a false-positive
   * callback validation result.
   */
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
   * Positive control.
   *
   * Negative validation is meaningful only if the same basic
   * testcase is accepted before one field is corrupted.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    memset (
      ciphertext,
      0,
      sizeof (ciphertext));

    memset (
      tag,
      0,
      sizeof (tag));

    failed |=
      expect_accepted (
        "valid AES-GCM AFT testcase",
        &tc);
  }


  /*
   * NULL top-level testcase.
   */
  if (ngi541_acvp_aes_gcm_handler (NULL) == 0)
    {
      fprintf (
        stderr,
        "NULL ACVP testcase was unexpectedly accepted\n");

      failed = 1;
    }


  /*
   * NULL symmetric testcase.
   */
  {
    ACVP_TEST_CASE test_case = { 0 };

    if (ngi541_acvp_aes_gcm_handler (
          &test_case) == 0)
      {
        fprintf (
          stderr,
          "NULL symmetric testcase was unexpectedly accepted\n");

        failed = 1;
      }
  }


  /*
   * Wrong cipher.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.cipher =
      ACVP_AES_CBC;

    failed |=
      expect_rejected (
        "wrong cipher",
        &tc);
  }


  /*
   * AES-GCM profile is AFT-only.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.test_type =
      ACVP_SYM_TEST_TYPE_MCT;

    failed |=
      expect_rejected (
        "AES-GCM MCT",
        &tc);
  }


  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.test_type =
      ACVP_SYM_TEST_TYPE_CTR;

    failed |=
      expect_rejected (
        "AES-GCM CTR test type",
        &tc);
  }


  /*
   * NGI541 currently registers externally supplied GCM IVs.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.ivgen_source =
      ACVP_SYM_CIPH_IVGEN_SRC_INT;

    failed |=
      expect_rejected (
        "internal IV source",
        &tc);
  }


  /*
   * Required pointers.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.key = NULL;

    failed |=
      expect_rejected (
        "NULL key",
        &tc);
  }


  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.iv = NULL;

    failed |=
      expect_rejected (
        "NULL IV",
        &tc);
  }


  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.tag = NULL;

    failed |=
      expect_rejected (
        "NULL tag",
        &tc);
  }


  /*
   * libacvp exposes AES key length in bits.
   *
   * 127 tests the non-byte-aligned rejection path.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.key_len = 127;

    failed |=
      expect_rejected (
        "non-byte-aligned key length",
        &tc);
  }


  /*
   * 160 bits is byte aligned but unsupported by AES.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.key_len = 160;

    failed |=
      expect_rejected (
        "unsupported AES key length",
        &tc);
  }


  /*
   * Current public GCM profile requires a 96-bit IV.
   * libacvp exposes iv_len to the callback in bytes.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.iv_len = 11;

    failed |=
      expect_rejected (
        "invalid GCM IV length",
        &tc);
  }


  /*
   * Current profile supports a 128-bit authentication tag.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.tag_len = 15;

    failed |=
      expect_rejected (
        "invalid GCM tag length",
        &tc);
  }


  /*
   * Non-zero AAD length requires an AAD pointer.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.aad = NULL;

    failed |=
      expect_rejected (
        "NULL AAD with non-zero AAD length",
        &tc);
  }


  /*
   * Non-zero encryption payload requires both input
   * and output buffers.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.pt = NULL;

    failed |=
      expect_rejected (
        "NULL plaintext with non-zero payload",
        &tc);
  }


  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.ct = NULL;

    failed |=
      expect_rejected (
        "NULL ciphertext output with non-zero payload",
        &tc);
  }


  /*
   * Decryption has the corresponding pointer requirements.
   *
   * These cases are rejected before authentication, so the
   * contents of ciphertext/tag are irrelevant here.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.direction =
      ACVP_SYM_CIPH_DIR_DECRYPT;

    tc.ct = NULL;
    tc.ct_len = sizeof (ciphertext);

    failed |=
      expect_rejected (
        "decrypt NULL ciphertext",
        &tc);
  }


  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.direction =
      ACVP_SYM_CIPH_DIR_DECRYPT;

    tc.pt = NULL;
    tc.ct_len = sizeof (ciphertext);

    failed |=
      expect_rejected (
        "decrypt NULL plaintext output",
        &tc);
  }


  /*
   * BOTH is valid capability-registration metadata but is not
   * a valid direction for execution of an individual testcase.
   */
  {
    ACVP_SYM_CIPHER_TC tc = valid;

    tc.direction =
      ACVP_SYM_CIPH_DIR_BOTH;

    failed |=
      expect_rejected (
        "invalid testcase direction",
        &tc);
  }


  if (failed)
    {
      fprintf (
        stderr,
        "AES-GCM negative callback validation failed\n");

      return 2;
    }

  return 0;
}