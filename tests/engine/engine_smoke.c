/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "engine/engine.h"

extern vnet_crypto_engine_registration_t __vnet_crypto_engine;

int
main (void)
{
  vnet_crypto_engine_registration_t *r = &__vnet_crypto_engine;
  char *err;

  if (r->init_fn == 0)
    return 1;

  if (r->key_handler == 0)
    return 2;

  if (r->op_handlers == 0)
    return 3;

  err = r->init_fn (r);

  if (err != 0)
    return 4;

  /*
   * At least one native handler must have been registered by
   * the handler constructors and selected during engine init.
   */
  if (r->op_handlers[0].opt == VNET_CRYPTO_OP_NONE)
    return 5;

  return 0;
}