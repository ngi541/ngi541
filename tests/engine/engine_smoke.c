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

  if (provider->init == 0)
    return 1;

  if (provider->key_handler == 0)
    return 2;

  if (provider->op_handlers == 0)
    return 3;

  error = provider->init (provider);

  if (error != 0)
    return 4;

  /*
   * At least one native operation handler must have been registered
   * by the handler constructors and selected during provider init.
   */
  if (provider->op_handlers[0].op_id == NGI541_CRYPTO_OP_NONE)
    return 5;

  return 0;
}