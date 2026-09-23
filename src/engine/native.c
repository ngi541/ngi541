/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 *
 * Modified for NGI541: internal native-provider registration and
 * NGI541 namespace.
 */

#include "engine/internal/native.h"

ngi541_native_registry_t ngi541_native_registry;

static ngi541_provider_op_handler_t
  op_handlers[NGI541_CRYPTO_N_OP_IDS + 1];

static void
ngi541_native_key_handler (
  ngi541_crypto_key_op_t op,
  ngi541_crypto_key_handler_args_t args)
{
  ngi541_native_registry_t *registry = &ngi541_native_registry;

  if (registry->key_fn[args.alg] == 0)
    return;

  registry->key_fn[args.alg] (op, args);
}

static char *
ngi541_native_init (ngi541_provider_t *provider)
{
  ngi541_native_registry_t *registry = &ngi541_native_registry;

  if (registry->op_handlers == 0)
    return 0;

  ngi541_native_op_handler_t *oh = registry->op_handlers;
  ngi541_native_key_handler_t *kh = registry->key_handlers;

  ngi541_native_op_handler_t
    *best_by_op_id[NGI541_CRYPTO_N_OP_IDS] = { 0 };

  ngi541_native_key_handler_t
    *best_by_alg_id[NGI541_CRYPTO_N_ALGS] = { 0 };

  clib_memset (op_handlers, 0, sizeof (op_handlers));

  ngi541_provider_op_handler_t *out = op_handlers;

  while (oh)
    {
      ASSERT (oh->op_id < NGI541_CRYPTO_N_OP_IDS);

      if (best_by_op_id[oh->op_id] == 0 ||
          best_by_op_id[oh->op_id]->priority < oh->priority)
        best_by_op_id[oh->op_id] = oh;

      oh = oh->next;
    }

  while (kh)
    {
      ASSERT (kh->alg_id < NGI541_CRYPTO_N_ALGS);

      if (best_by_alg_id[kh->alg_id] == 0 ||
          best_by_alg_id[kh->alg_id]->priority < kh->priority)
        best_by_alg_id[kh->alg_id] = kh;

      provider->key_data_size[kh->alg_id] = kh->key_data_size;
      kh = kh->next;
    }

  for (u32 i = 0; i < NGI541_CRYPTO_N_OP_IDS; i++)
    {
      oh = best_by_op_id[i];

      if (oh)
        {
          ASSERT (
            (uword) (out - op_handlers) <
            ARRAY_LEN (op_handlers) - 1
          );

          *out++ = (ngi541_provider_op_handler_t) {
            .op_id = oh->op_id,
            .fn = oh->fn,
            .cfn = oh->cfn,
          };
        }
    }

  for (u32 i = 0; i < NGI541_CRYPTO_N_ALGS; i++)
    {
      kh = best_by_alg_id[i];

      if (kh)
        registry->key_fn[kh->alg_id] = kh->key_fn;
    }

  return 0;
}

ngi541_provider_t ngi541_native_provider = {
  .name = "native",
  .description = "Native ISA Optimized Crypto",
  .priority = 100,
  .init = ngi541_native_init,
  .key_handler = ngi541_native_key_handler,
  .op_handlers = op_handlers,
};