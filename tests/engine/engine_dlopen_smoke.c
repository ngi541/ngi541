/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <dlfcn.h>
#include <stdio.h>

static int
check_symbol_exported (void *handle, const char *name)
{
  void *symbol;
  const char *error;

  dlerror ();

  symbol = dlsym (handle, name);
  error = dlerror ();

  if (error != NULL || symbol == NULL)
    {
      fprintf (
        stderr,
        "public symbol is not exported: %s\n",
        name);

      return 0;
    }

  return 1;
}


static int
check_symbol_hidden (void *handle, const char *name)
{
  const char *error;

  dlerror ();

  (void) dlsym (handle, name);
  error = dlerror ();

  if (error == NULL)
    {
      fprintf (
        stderr,
        "internal symbol is exported: %s\n",
        name);

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
      fprintf (
        stderr,
        "usage: %s <engine-library>\n",
        argv[0]);

      return 1;
    }

  handle = dlopen (
    argv[1],
    RTLD_NOW | RTLD_LOCAL);

  if (handle == NULL)
    {
      fprintf (
        stderr,
        "dlopen failed: %s\n",
        dlerror ());

      return 2;
    }

  if (!check_symbol_exported (
        handle,
        "ngi541_engine_init"))
    goto public_symbol_error;

  if (!check_symbol_exported (
        handle,
        "ngi541_crypto_cipher_encrypt"))
    goto public_symbol_error;

  if (!check_symbol_exported (
        handle,
        "ngi541_crypto_cipher_decrypt"))
    goto public_symbol_error;

  if (!check_symbol_exported (
        handle,
        "ngi541_crypto_aead_encrypt"))
    goto public_symbol_error;

  if (!check_symbol_exported (
        handle,
        "ngi541_crypto_aead_decrypt"))
    goto public_symbol_error;

  if (!check_symbol_exported (
        handle,
        "ngi541_crypto_hash_compute"))
    goto public_symbol_error;

  if (!check_symbol_hidden (
        handle,
        "ngi541_native_provider"))
    goto internal_symbol_error;

  if (!check_symbol_hidden (
        handle,
        "ngi541_native_registry"))
    goto internal_symbol_error;

  if (!check_symbol_hidden (
        handle,
        "clib_c11_violation"))
    goto internal_symbol_error;

  dlclose (handle);
  return 0;

public_symbol_error:
  dlclose (handle);
  return 3;

internal_symbol_error:
  dlclose (handle);
  return 4;
}