/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "sha2.h"

#include <ngi541/crypto.h>

#include <stddef.h>
#include <stdlib.h>


#define NGI541_SHA224_DIGEST_SIZE 28U
#define NGI541_SHA256_DIGEST_SIZE 32U


int
ngi541_acvp_sha2_handler (ACVP_TEST_CASE *test_case)
{
  ACVP_HASH_TC *tc;

  ngi541_hash_algorithm_t algorithm;
  ngi541_hash_request_t request;
  ngi541_status_t status;

  const unsigned char *message;
  unsigned char *mct_message;

  size_t digest_size;
  size_t message_len;

  if (test_case == NULL)
    return 1;

  tc = test_case->tc.hash;

  if (tc == NULL)
    return 1;

  switch (tc->cipher)
    {
    case ACVP_HASH_SHA224:
      algorithm = NGI541_HASH_SHA2_224;
      digest_size = NGI541_SHA224_DIGEST_SIZE;
      break;

    case ACVP_HASH_SHA256:
      algorithm = NGI541_HASH_SHA2_256;
      digest_size = NGI541_SHA256_DIGEST_SIZE;
      break;

    default:
      return 1;
    }

  /*
   * libacvp owns the digest buffer and expects the IUT
   * callback to populate it.
   */
  if (tc->md == NULL)
    return 1;

  message = NULL;
  message_len = 0;
  mct_message = NULL;

  switch (tc->test_type)
    {
    case ACVP_HASH_TEST_TYPE_AFT:
      /*
       * AFT maps directly to the public one-shot NGI541
       * hash execution contract.
       */
      if (tc->msg_len != 0 && tc->msg == NULL)
        return 1;

      message = tc->msg;
      message_len = (size_t) tc->msg_len;

      break;

    case ACVP_HASH_TEST_TYPE_MCT:
      /*
       * libacvp performs the SHA Monte Carlo orchestration:
       *
       *   A = B = C = seed
       *
       * and, after each callback:
       *
       *   A = B
       *   B = C
       *   C = MD
       *
       * The IUT callback is responsible only for:
       *
       *   MD = SHA(A || B || C)
       *
       * acvp_hash_create_mct_msg() constructs the required
       * message from m1, m2 and m3 and also handles the
       * alternate-MCT truncation/padding rules.
       */
      if (tc->m1 == NULL ||
          tc->m2 == NULL ||
          tc->m3 == NULL)
        return 1;

      mct_message =
        acvp_hash_create_mct_msg (
          tc,
          &message_len);

      if (mct_message == NULL)
        return 1;

      message = mct_message;

      break;

    default:
      /*
       * VOT and LDT are intentionally not part of the
       * current NGI541 SHA-2 validation profile.
       */
      return 1;
    }

  request = (ngi541_hash_request_t) {
    .struct_size = sizeof (request),

    .algorithm = algorithm,

    .message = message,
    .message_len = message_len,

    .digest = tc->md,
    .digest_capacity = digest_size,
  };

  status =
    ngi541_crypto_hash_compute (&request);

  if (mct_message != NULL)
    free (mct_message);

  if (status != NGI541_STATUS_OK)
    return 1;

  tc->md_len = (unsigned int) digest_size;

  return 0;
}