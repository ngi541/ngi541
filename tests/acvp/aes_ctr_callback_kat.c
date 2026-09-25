/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "callbacks/aes_ctr.h"

#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AES_CTR_KEY_BITS       128U
#define AES_CTR_IV_BYTES       16U
#define AES_CTR_PAYLOAD_BYTES  64U

static const unsigned char key[16] = {
  0x2b, 0x7e, 0x15, 0x16,
  0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88,
  0x09, 0xcf, 0x4f, 0x3c,
};

static const unsigned char counter[16] = {
  0xf0, 0xf1, 0xf2, 0xf3,
  0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb,
  0xfc, 0xfd, 0xfe, 0xff,
};

static const unsigned char plaintext[AES_CTR_PAYLOAD_BYTES] = {
  0x6b, 0xc1, 0xbe, 0xe2,
  0x2e, 0x40, 0x9f, 0x96,
  0xe9, 0x3d, 0x7e, 0x11,
  0x73, 0x93, 0x17, 0x2a,

  0xae, 0x2d, 0x8a, 0x57,
  0x1e, 0x03, 0xac, 0x9c,
  0x9e, 0xb7, 0x6f, 0xac,
  0x45, 0xaf, 0x8e, 0x51,

  0x30, 0xc8, 0x1c, 0x46,
  0xa3, 0x5c, 0xe4, 0x11,
  0xe5, 0xfb, 0xc1, 0x19,
  0x1a, 0x0a, 0x52, 0xef,

  0xf6, 0x9f, 0x24, 0x45,
  0xdf, 0x4f, 0x9b, 0x17,
  0xad, 0x2b, 0x41, 0x7b,
  0xe6, 0x6c, 0x37, 0x10,
};

static const unsigned char ciphertext[AES_CTR_PAYLOAD_BYTES] = {
  0x87, 0x4d, 0x61, 0x91,
  0xb6, 0x20, 0xe3, 0x26,
  0x1b, 0xef, 0x68, 0x64,
  0x99, 0x0d, 0xb6, 0xce,

  0x98, 0x06, 0xf6, 0x6b,
  0x79, 0x70, 0xfd, 0xff,
  0x86, 0x17, 0x18, 0x7b,
  0xb9, 0xff, 0xfd, 0xff,

  0x5a, 0xe4, 0xdf, 0x3e,
  0xdb, 0xd5, 0xd3, 0x5e,
  0x5b, 0x4f, 0x09, 0x02,
  0x0d, 0xb0, 0x3e, 0xab,

  0x1e, 0x03, 0x1d, 0xda,
  0x2f, 0xbe, 0x03, 0xd1,
  0x79, 0x21, 0x70, 0xa0,
  0xf3, 0x00, 0x9c, 0xee,
};

static int
test_encrypt (void)
{
  unsigned char output[AES_CTR_PAYLOAD_BYTES] = { 0 };

  ACVP_SYM_CIPHER_TC tc = { 0 };
  ACVP_TEST_CASE test_case = { 0 };

  tc.cipher = ACVP_AES_CTR;
  tc.test_type = ACVP_SYM_TEST_TYPE_AFT;
  tc.direction = ACVP_SYM_CIPH_DIR_ENCRYPT;

  tc.key = (unsigned char *) key;
  tc.key_len = AES_CTR_KEY_BITS;

  tc.iv = (unsigned char *) counter;
  tc.iv_len = AES_CTR_IV_BYTES;

  tc.pt = (unsigned char *) plaintext;
  tc.pt_len = AES_CTR_PAYLOAD_BYTES;

  tc.ct = output;
  tc.ct_len = AES_CTR_PAYLOAD_BYTES;

  test_case.tc.symmetric = &tc;

  if (ngi541_acvp_aes_ctr_handler (&test_case) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR ACVP encrypt callback failed\n");

      return 1;
    }

  if (tc.ct_len != AES_CTR_PAYLOAD_BYTES)
    return 2;

  if (memcmp (
        output,
        ciphertext,
        sizeof (output)) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR ACVP encrypt KAT mismatch\n");

      return 3;
    }

  return 0;
}

static int
test_decrypt (void)
{
  unsigned char output[AES_CTR_PAYLOAD_BYTES] = { 0 };

  ACVP_SYM_CIPHER_TC tc = { 0 };
  ACVP_TEST_CASE test_case = { 0 };

  tc.cipher = ACVP_AES_CTR;
  tc.test_type = ACVP_SYM_TEST_TYPE_AFT;
  tc.direction = ACVP_SYM_CIPH_DIR_DECRYPT;

  tc.key = (unsigned char *) key;
  tc.key_len = AES_CTR_KEY_BITS;

  tc.iv = (unsigned char *) counter;
  tc.iv_len = AES_CTR_IV_BYTES;

  tc.ct = (unsigned char *) ciphertext;
  tc.ct_len = AES_CTR_PAYLOAD_BYTES;

  tc.pt = output;
  tc.pt_len = AES_CTR_PAYLOAD_BYTES;

  test_case.tc.symmetric = &tc;

  if (ngi541_acvp_aes_ctr_handler (&test_case) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR ACVP decrypt callback failed\n");

      return 1;
    }

  if (tc.pt_len != AES_CTR_PAYLOAD_BYTES)
    return 2;

  if (memcmp (
        output,
        plaintext,
        sizeof (output)) != 0)
    {
      fprintf (
        stderr,
        "AES-CTR ACVP decrypt KAT mismatch\n");

      return 3;
    }

  return 0;
}

int
main (void)
{
  ngi541_status_t status;
  int result;

  status = ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "ngi541_engine_init failed: status=%d\n",
        (int) status);

      return 1;
    }

  result = test_encrypt ();

  if (result != 0)
    return 10 + result;

  result = test_decrypt ();

  if (result != 0)
    return 20 + result;

  return 0;
}