/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "callbacks/aes_gcm.h"

#include <ngi541/engine.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t key[16] = {
  0xfe, 0xff, 0xe9, 0x92,
  0x86, 0x65, 0x73, 0x1c,
  0x6d, 0x6a, 0x8f, 0x94,
  0x67, 0x30, 0x83, 0x08,
};

static const uint8_t iv[12] = {
  0xca, 0xfe, 0xba, 0xbe,
  0xfa, 0xce, 0xdb, 0xad,
  0xde, 0xca, 0xf8, 0x88,
};

static const uint8_t aad[20] = {
  0xfe, 0xed, 0xfa, 0xce,
  0xde, 0xad, 0xbe, 0xef,
  0xfe, 0xed, 0xfa, 0xce,
  0xde, 0xad, 0xbe, 0xef,
  0xab, 0xad, 0xda, 0xd2,
};

static const uint8_t plaintext[60] = {
  0xd9, 0x31, 0x32, 0x25,
  0xf8, 0x84, 0x06, 0xe5,
  0xa5, 0x59, 0x09, 0xc5,
  0xaf, 0xf5, 0x26, 0x9a,

  0x86, 0xa7, 0xa9, 0x53,
  0x15, 0x34, 0xf7, 0xda,
  0x2e, 0x4c, 0x30, 0x3d,
  0x8a, 0x31, 0x8a, 0x72,

  0x1c, 0x3c, 0x0c, 0x95,
  0x95, 0x68, 0x09, 0x53,
  0x2f, 0xcf, 0x0e, 0x24,
  0x49, 0xa6, 0xb5, 0x25,

  0xb1, 0x6a, 0xed, 0xf5,
  0xaa, 0x0d, 0xe6, 0x57,
  0xba, 0x63, 0x7b, 0x39,
};

static const uint8_t ciphertext[60] = {
  0x42, 0x83, 0x1e, 0xc2,
  0x21, 0x77, 0x74, 0x24,
  0x4b, 0x72, 0x21, 0xb7,
  0x84, 0xd0, 0xd4, 0x9c,

  0xe3, 0xaa, 0x21, 0x2f,
  0x2c, 0x02, 0xa4, 0xe0,
  0x35, 0xc1, 0x7e, 0x23,
  0x29, 0xac, 0xa1, 0x2e,

  0x21, 0xd5, 0x14, 0xb2,
  0x54, 0x66, 0x93, 0x1c,
  0x7d, 0x8f, 0x6a, 0x5a,
  0xac, 0x84, 0xaa, 0x05,

  0x1b, 0xa3, 0x0b, 0x39,
  0x6a, 0x0a, 0xac, 0x97,
  0x3d, 0x58, 0xe0, 0x91,
};

static const uint8_t tag[16] = {
  0x5b, 0xc9, 0x4f, 0xbc,
  0x32, 0x21, 0xa5, 0xdb,
  0x94, 0xfa, 0xe9, 0x5a,
  0xe7, 0x12, 0x1a, 0x47,
};

static int
buffer_is_zero (
  const uint8_t *data,
  size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      if (data[i] != 0)
        return 0;
    }

  return 1;
}

static int
test_encrypt (void)
{
  uint8_t output[sizeof (plaintext)] = { 0 };
  uint8_t output_tag[sizeof (tag)] = { 0 };

  ACVP_SYM_CIPHER_TC tc = { 0 };
  ACVP_TEST_CASE test_case = { 0 };

  tc.cipher = ACVP_AES_GCM;
  tc.test_type =
  ACVP_SYM_TEST_TYPE_AFT;
  tc.ivgen_source =
  ACVP_SYM_CIPH_IVGEN_SRC_EXT;
  tc.direction = ACVP_SYM_CIPH_DIR_ENCRYPT;

  tc.key = (unsigned char *) key;
  tc.key_len = 128U;

  tc.iv = (unsigned char *) iv;
  tc.iv_len = sizeof (iv);

  tc.aad = (unsigned char *) aad;
  tc.aad_len = sizeof (aad);

  tc.pt = (unsigned char *) plaintext;
  tc.pt_len = sizeof (plaintext);

  tc.ct = output;
  tc.ct_len = sizeof (output);

  tc.tag = output_tag;
  tc.tag_len = sizeof (output_tag);

  test_case.tc.symmetric = &tc;

  if (ngi541_acvp_aes_gcm_handler (&test_case) != 0)
    return 1;

  if (tc.ct_len != sizeof (plaintext))
    return 2;

  if (memcmp (
        output,
        ciphertext,
        sizeof (output)) != 0)
    return 3;

  if (memcmp (
        output_tag,
        tag,
        sizeof (output_tag)) != 0)
    return 4;

  return 0;
}

static int
test_decrypt (void)
{
  uint8_t output[sizeof (plaintext)] = { 0 };

  ACVP_SYM_CIPHER_TC tc = { 0 };
  ACVP_TEST_CASE test_case = { 0 };

  tc.cipher = ACVP_AES_GCM;
  tc.test_type =
  ACVP_SYM_TEST_TYPE_AFT;
  tc.ivgen_source =
  ACVP_SYM_CIPH_IVGEN_SRC_EXT;
  tc.direction = ACVP_SYM_CIPH_DIR_DECRYPT;

  tc.key = (unsigned char *) key;
  tc.key_len = 128U;

  tc.iv = (unsigned char *) iv;
  tc.iv_len = sizeof (iv);

  tc.aad = (unsigned char *) aad;
  tc.aad_len = sizeof (aad);

  tc.ct = (unsigned char *) ciphertext;
  tc.ct_len = sizeof (ciphertext);

  tc.tag = (unsigned char *) tag;
  tc.tag_len = sizeof (tag);

  tc.pt = output;
  tc.pt_len = sizeof (output);

  test_case.tc.symmetric = &tc;

  if (ngi541_acvp_aes_gcm_handler (&test_case) != 0)
    return 1;

  if (tc.pt_len != sizeof (plaintext))
    return 2;

  if (memcmp (
        output,
        plaintext,
        sizeof (output)) != 0)
    return 3;

  return 0;
}

static int
test_bad_tag (void)
{
  uint8_t bad_tag[sizeof (tag)];
  uint8_t output[sizeof (plaintext)];

  ACVP_SYM_CIPHER_TC tc = { 0 };
  ACVP_TEST_CASE test_case = { 0 };

  memcpy (
    bad_tag,
    tag,
    sizeof (bad_tag));

  bad_tag[0] ^= 0x01;

  memset (
    output,
    0xa5,
    sizeof (output));

  tc.cipher = ACVP_AES_GCM;
  tc.test_type =
  ACVP_SYM_TEST_TYPE_AFT;
  tc.ivgen_source =
  ACVP_SYM_CIPH_IVGEN_SRC_EXT;
  tc.direction = ACVP_SYM_CIPH_DIR_DECRYPT;

  tc.key = (unsigned char *) key;
  tc.key_len = 128U;

  tc.iv = (unsigned char *) iv;
  tc.iv_len = sizeof (iv);

  tc.aad = (unsigned char *) aad;
  tc.aad_len = sizeof (aad);

  tc.ct = (unsigned char *) ciphertext;
  tc.ct_len = sizeof (ciphertext);

  tc.tag = bad_tag;
  tc.tag_len = sizeof (bad_tag);

  tc.pt = output;
  tc.pt_len = sizeof (output);

  test_case.tc.symmetric = &tc;

  /*
   * Authentication failure is represented to libacvp by
   * a non-zero callback result.
   */
  if (ngi541_acvp_aes_gcm_handler (&test_case) == 0)
    return 1;

  /*
   * NGI541 guarantees that unauthenticated plaintext is
   * scrubbed before AUTH_FAILED is propagated.
   */
  if (!buffer_is_zero (
        output,
        sizeof (output)))
    return 2;

  if (tc.pt_len != 0)
    return 3;

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
    {
      fprintf (
        stderr,
        "AES-GCM ACVP encrypt KAT failed: %d\n",
        result);

      return 10 + result;
    }

  result = test_decrypt ();

  if (result != 0)
    {
      fprintf (
        stderr,
        "AES-GCM ACVP decrypt KAT failed: %d\n",
        result);

      return 20 + result;
    }

  result = test_bad_tag ();

  if (result != 0)
    {
      fprintf (
        stderr,
        "AES-GCM ACVP bad-tag test failed: %d\n",
        result);

      return 30 + result;
    }

  return 0;
}