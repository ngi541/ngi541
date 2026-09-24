/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_INTERNAL_EXECUTE_H
#define NGI541_INTERNAL_EXECUTE_H

#include <stdint.h>

#include "engine/internal/crypto_types.h"

#define NGI541_EXEC_KEY_DATA_CAPACITY  2048
#define NGI541_EXEC_KEY_DATA_ALIGNMENT 64

/*
 * Scratch state for one internal primitive operation.
 *
 * empty is used for zero-length inputs so native handlers never receive
 * a NULL data pointer for a zero-length operation.
 *
 * iv_scratch and tag_scratch isolate caller-owned const buffers from
 * the current internal ABI, whose IV/tag pointers are not const-qualified.
 */
typedef struct
{
  ngi541_crypto_op_t op;
  ngi541_crypto_op_t *ops[1];

  _Alignas (16) uint8_t empty[16];
  _Alignas (16) uint8_t iv_scratch[16];
  _Alignas (16) uint8_t tag_scratch[16];
} ngi541_op_workspace_t;

/*
 * One-shot keyed execution workspace.
 *
 * The measured maximum native key-data requirement is currently
 * 1536 bytes (AES-GCM). 2048 bytes provides bounded headroom while
 * keeping allocation on the stack.
 */
typedef struct
{
  _Alignas (NGI541_EXEC_KEY_DATA_ALIGNMENT)
  uint8_t key_data[NGI541_EXEC_KEY_DATA_CAPACITY];

  ngi541_op_workspace_t operation;
} ngi541_keyed_workspace_t;

_Static_assert (
  NGI541_EXEC_KEY_DATA_CAPACITY %
      NGI541_EXEC_KEY_DATA_ALIGNMENT == 0,
  "NGI541 key-data capacity must be alignment-sized");

_Static_assert (
  _Alignof (ngi541_keyed_workspace_t) >=
      NGI541_EXEC_KEY_DATA_ALIGNMENT,
  "NGI541 keyed workspace alignment is insufficient");

#endif /* NGI541_INTERNAL_EXECUTE_H */