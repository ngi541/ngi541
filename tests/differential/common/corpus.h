/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_TESTS_DIFFERENTIAL_CORPUS_H
#define NGI541_TESTS_DIFFERENTIAL_CORPUS_H

#include <stdint.h>


#define NGI541_DIFF_BASE_SEED \
  UINT64_C (0x4e47493534314d35)


typedef enum
{
  NGI541_DIFF_FAMILY_NONE = 0,

  NGI541_DIFF_FAMILY_AES_CBC = 1,
  NGI541_DIFF_FAMILY_AES_CTR = 2,
  NGI541_DIFF_FAMILY_AES_GCM = 3,
  NGI541_DIFF_FAMILY_SHA2 = 4,
} ngi541_diff_family_t;


uint64_t ngi541_diff_case_seed (
  uint64_t base_seed,
  ngi541_diff_family_t family,
  uint32_t variant,
  uint64_t case_index);


#endif