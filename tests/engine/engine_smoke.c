/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "engine/internal/native.h"

int
main (void)
{
  ngi541_provider_t *provider = &ngi541_native_provider;
  char *error;
  int found_handler = 0;

  if (provider->init == 0)
    return 1;

  if (provider->key_handler == 0)
    return 2;

  if (provider->op_handlers == 0)
    return 3;

  if (provider->op_handler_count != NGI541_CRYPTO_N_OP_IDS)
    return 4;

  error = provider->init (provider);

  if (error != 0)
    return 5;

  /*
   * Operation ID zero is reserved for NGI541_CRYPTO_OP_NONE and
   * must not resolve to an executable provider handler.
   */
  if (provider->op_handlers[NGI541_CRYPTO_OP_NONE].fn != 0 ||
      provider->op_handlers[NGI541_CRYPTO_OP_NONE].cfn != 0)
    return 6;

  /*
   * At least one native implementation must have been selected.
   *
   * This intentionally avoids requiring a specific ISA-dependent
   * handler so the smoke test remains portable.
   */
  for (u32 i = 1; i < provider->op_handler_count; i++)
    {
      if (provider->op_handlers[i].fn != 0 ||
          provider->op_handlers[i].cfn != 0)
        {
          found_handler = 1;
          break;
        }
    }

  if (!found_handler)
    return 7;

  return 0;
}