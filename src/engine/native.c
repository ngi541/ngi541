/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 *
 * Modified for NGI541: source layout and include paths.
 */

#include "engine/crypto_types.h"
#include "engine/crypto_native.h"
#include "engine/engine.h"

crypto_native_main_t crypto_native_main;

static vnet_crypto_engine_op_handlers_t
  op_handlers[VNET_CRYPTO_N_OP_IDS + 1];

static void
crypto_native_key_handler (
  vnet_crypto_key_op_t kop,
  vnet_crypto_key_handler_args_t a
)
{
  crypto_native_main_t *cm = &crypto_native_main;

  if (cm->key_fn[a.alg] == 0)
    return;

  cm->key_fn[a.alg] (kop, a);
}

static char *
crypto_native_init (vnet_crypto_engine_registration_t *r)
{
  crypto_native_main_t *cm = &crypto_native_main;

  if (cm->op_handlers == 0)
    return 0;

  crypto_native_op_handler_t *oh = cm->op_handlers;
  crypto_native_key_handler_t *kh = cm->key_handlers;

  crypto_native_op_handler_t
    *best_by_op_id[VNET_CRYPTO_N_OP_IDS] = { 0 };

  crypto_native_key_handler_t
    *best_by_alg_id[VNET_CRYPTO_N_ALGS] = { 0 };

  clib_memset (op_handlers, 0, sizeof (op_handlers));

  vnet_crypto_engine_op_handlers_t *ophp = op_handlers;

  while (oh)
    {
      ASSERT (oh->op_id < VNET_CRYPTO_N_OP_IDS);

      if (best_by_op_id[oh->op_id] == 0 ||
          best_by_op_id[oh->op_id]->priority < oh->priority)
        best_by_op_id[oh->op_id] = oh;

      oh = oh->next;
    }

  while (kh)
    {
      ASSERT (kh->alg_id < VNET_CRYPTO_N_ALGS);

      if (best_by_alg_id[kh->alg_id] == 0 ||
          best_by_alg_id[kh->alg_id]->priority < kh->priority)
        best_by_alg_id[kh->alg_id] = kh;

      r->key_data_sz[kh->alg_id] = kh->key_data_sz;
      kh = kh->next;
    }

  for (u32 i = 0; i < VNET_CRYPTO_N_OP_IDS; i++)
    {
      oh = best_by_op_id[i];

      if (oh)
        {
          ASSERT (
            (uword) (ophp - op_handlers) <
            ARRAY_LEN (op_handlers) - 1
          );

          *ophp++ = (vnet_crypto_engine_op_handlers_t) {
            .opt = oh->op_id,
            .fn = oh->fn,
            .cfn = oh->cfn,
          };
        }
    }

  for (u32 i = 0; i < VNET_CRYPTO_N_ALGS; i++)
    {
      kh = best_by_alg_id[i];

      if (kh)
        cm->key_fn[kh->alg_id] = kh->key_fn;
    }

  return 0;
}

VNET_CRYPTO_ENGINE_REGISTRATION () = {
  .name = "native",
  .desc = "Native ISA Optimized Crypto",
  .prio = 100,
  .init_fn = crypto_native_init,
  .key_handler = crypto_native_key_handler,
  .op_handlers = op_handlers,
};
