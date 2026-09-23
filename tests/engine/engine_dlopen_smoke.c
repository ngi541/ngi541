/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <dlfcn.h>
#include <stdio.h>

#include "engine/engine.h"

int
main (int argc, char **argv)
{
  void *handle;
  vnet_crypto_engine_registration_t *r;
  const char *error;
  char *init_error;

  if (argc != 2)
    {
      fprintf (stderr, "usage: %s <engine-library>\n", argv[0]);
      return 1;
    }

  handle = dlopen (argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle)
    {
      fprintf (stderr, "dlopen failed: %s\n", dlerror ());
      return 2;
    }

  dlerror ();

  r = (vnet_crypto_engine_registration_t *)
    dlsym (handle, "__vnet_crypto_engine");

  error = dlerror ();
  if (error != NULL || r == NULL)
    {
      fprintf (stderr, "dlsym failed: %s\n",
               error ? error : "registration not found");
      dlclose (handle);
      return 3;
    }

  if (r->init_fn == NULL)
    {
      dlclose (handle);
      return 4;
    }

  if (r->key_handler == NULL)
    {
      dlclose (handle);
      return 5;
    }

  if (r->op_handlers == NULL)
    {
      dlclose (handle);
      return 6;
    }

  init_error = r->init_fn (r);

  if (init_error != NULL)
    {
      fprintf (stderr, "engine init failed: %s\n", init_error);
      dlclose (handle);
      return 7;
    }

  if (r->op_handlers[0].opt == VNET_CRYPTO_OP_NONE)
    {
      dlclose (handle);
      return 8;
    }

  dlclose (handle);

  return 0;
}