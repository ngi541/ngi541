/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_VALIDATION_ACVP_REGISTRATIONS_PROFILE_V1_H
#define NGI541_VALIDATION_ACVP_REGISTRATIONS_PROFILE_V1_H

#include <acvp/acvp.h>

typedef enum
{
  NGI541_ACVP_PROFILE_AES_CBC =
    1u << 0,

  NGI541_ACVP_PROFILE_AES_CTR =
    1u << 1,

  NGI541_ACVP_PROFILE_AES_GCM =
    1u << 2,

  NGI541_ACVP_PROFILE_SHA2_256 =
    1u << 3,

  NGI541_ACVP_PROFILE_SHA2_224 =
    1u << 4,

  NGI541_ACVP_PROFILE_V1_ALL =
    NGI541_ACVP_PROFILE_AES_CBC |
    NGI541_ACVP_PROFILE_AES_CTR |
    NGI541_ACVP_PROFILE_AES_GCM |
    NGI541_ACVP_PROFILE_SHA2_256 |
    NGI541_ACVP_PROFILE_SHA2_224
} ngi541_acvp_profile_mask_t;


/*
 * Register the complete NGI541 ACVP profile v1.
 *
 * Existing callers use this entry point. Its behaviour must remain
 * identical to the pre-selective-registration implementation.
 */
ACVP_RESULT ngi541_acvp_register_profile_v1 (
  ACVP_CTX *ctx);


/*
 * Register a selected subset of NGI541 ACVP profile v1.
 *
 * This is primarily used by the ACVTS Demo runner so that live
 * submissions can be kept small and isolated by algorithm.
 */
ACVP_RESULT ngi541_acvp_register_profile_v1_selected (
  ACVP_CTX *ctx,
  unsigned int profile_mask);

#endif /* NGI541_VALIDATION_ACVP_REGISTRATIONS_PROFILE_V1_H */