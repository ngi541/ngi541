/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "sha2.h"

#include <ngi541/crypto.h>

#define NGI541_SHA224_DIGEST_SIZE 28U
#define NGI541_SHA256_DIGEST_SIZE 32U

int
ngi541_acvp_sha2_handler (ACVP_TEST_CASE *test_case)
{
  ACVP_HASH_TC *tc;
  ngi541_hash_algorithm_t algorithm;
  size_t digest_size;
  ngi541_hash_request_t request;
  ngi541_status_t status;

  if (test_case == NULL)
    return 1;

  tc = test_case->tc.hash;
  if (tc == NULL)
    return 1;

  /*
   * NGI541 currently exposes a one-shot hash API.
   *
   * AFT maps directly to that execution model.
   * MCT, VOT and LDT require additional ACVP-specific orchestration
   * and are intentionally not handled by this callback yet.
   */
  if (tc->test_type != ACVP_HASH_TEST_TYPE_AFT)
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
   * libacvp exposes msg_len in bytes.
   * NGI541 allows message == NULL only for an empty message.
   */
  if (tc->msg_len != 0 && tc->msg == NULL)
    return 1;

  /*
   * libacvp owns the digest buffer and expects the IUT callback
   * to populate it.
   */
  if (tc->md == NULL)
    return 1;

  request = (ngi541_hash_request_t) {
    .struct_size = sizeof (request),
    .algorithm = algorithm,
    .message = tc->msg,
    .message_len = tc->msg_len,
    .digest = tc->md,
    .digest_capacity = digest_size,
  };

  status = ngi541_crypto_hash_compute (&request);
  if (status != NGI541_STATUS_OK)
    return 1;

  tc->md_len = (unsigned int) digest_size;

  return 0;
}