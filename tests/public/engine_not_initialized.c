/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <stdio.h>


static int
expect_not_initialized (
  const char *name,
  ngi541_status_t status)
{
  if (status != NGI541_STATUS_NOT_INITIALIZED)
    {
      fprintf (
        stderr,
        "%s returned unexpected status=%d\n",
        name,
        (int) status);

      return 1;
    }

  return 0;
}


int
main (void)
{
  int failed = 0;

  /*
   * Do not call ngi541_engine_init() in this executable.
   *
   * Engine state is process-global, so this test must execute
   * in a fresh process before any initialization occurs.
   */

  failed |=
    expect_not_initialized (
      "ngi541_crypto_cipher_encrypt(NULL)",
      ngi541_crypto_cipher_encrypt (NULL));

  failed |=
    expect_not_initialized (
      "ngi541_crypto_cipher_decrypt(NULL)",
      ngi541_crypto_cipher_decrypt (NULL));

  failed |=
    expect_not_initialized (
      "ngi541_crypto_aead_encrypt(NULL)",
      ngi541_crypto_aead_encrypt (NULL));

  failed |=
    expect_not_initialized (
      "ngi541_crypto_aead_decrypt(NULL)",
      ngi541_crypto_aead_decrypt (NULL));

  failed |=
    expect_not_initialized (
      "ngi541_crypto_hash_compute(NULL)",
      ngi541_crypto_hash_compute (NULL));

  if (failed)
    return 1;

  return 0;
}