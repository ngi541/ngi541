/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <dlfcn.h>
#include <stdio.h>

static int
check_symbol_hidden (void *handle, const char *name)
{
  void *symbol;

  dlerror ();
  symbol = dlsym (handle, name);

  if (symbol != NULL)
    {
      fprintf (stderr, "internal symbol is exported: %s\n", name);
      return 0;
    }

  return 1;
}

int
main (int argc, char **argv)
{
  void *handle;

  if (argc != 2)
    {
      fprintf (stderr, "usage: %s <engine-library>\n", argv[0]);
      return 1;
    }

  handle = dlopen (argv[1], RTLD_NOW | RTLD_LOCAL);

  if (handle == NULL)
    {
      fprintf (stderr, "dlopen failed: %s\n", dlerror ());
      return 2;
    }

  if (!check_symbol_hidden (handle, "ngi541_native_provider"))
    {
      dlclose (handle);
      return 3;
    }

  if (!check_symbol_hidden (handle, "ngi541_native_registry"))
    {
      dlclose (handle);
      return 4;
    }

  if (!check_symbol_hidden (handle, "clib_c11_violation"))
    {
      dlclose (handle);
      return 5;
    }

  dlclose (handle);

  return 0;
}