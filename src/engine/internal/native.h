/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 *
 * Modified for NGI541: internal native-provider registration and
 * NGI541 namespace.
 */

#ifndef NGI541_INTERNAL_NATIVE_H
#define NGI541_INTERNAL_NATIVE_H

#include "engine/internal/provider.h"

typedef int (ngi541_native_probe_fn_t) (void);

typedef struct ngi541_native_op_handler
{
  struct ngi541_native_op_handler *next;

  ngi541_crypto_op_id_t op_id;
  ngi541_crypto_simple_op_fn_t *fn;
  ngi541_crypto_chained_op_fn_t *cfn;

  ngi541_native_probe_fn_t *probe;
  int priority;
} ngi541_native_op_handler_t;

typedef struct ngi541_native_key_handler
{
  struct ngi541_native_key_handler *next;

  ngi541_crypto_alg_t alg_id;
  ngi541_crypto_key_fn_t *key_fn;

  ngi541_native_probe_fn_t *probe;
  int priority;

  u16 key_data_size;
} ngi541_native_key_handler_t;

typedef struct
{
  ngi541_crypto_key_fn_t *key_fn[NGI541_CRYPTO_N_ALGS];

  ngi541_native_op_handler_t *op_handlers;
  ngi541_native_key_handler_t *key_handlers;
} ngi541_native_registry_t;

extern ngi541_native_registry_t ngi541_native_registry;
extern ngi541_provider_t ngi541_native_provider;

#define NGI541_NATIVE_OP_HANDLER(x)                                           \
  static ngi541_native_op_handler_t ngi541_native_op_handler_##x;             \
                                                                              \
  static void __clib_constructor                                              \
  ngi541_native_register_op_handler_##x (void)                                \
  {                                                                           \
    ngi541_native_registry_t *registry = &ngi541_native_registry;             \
    int priority = ngi541_native_op_handler_##x.probe ();                     \
                                                                              \
    if (priority >= 0)                                                        \
      {                                                                       \
        ngi541_native_op_handler_##x.priority = priority;                     \
        ngi541_native_op_handler_##x.next = registry->op_handlers;            \
        registry->op_handlers = &ngi541_native_op_handler_##x;                \
      }                                                                       \
  }                                                                           \
                                                                              \
  static ngi541_native_op_handler_t ngi541_native_op_handler_##x

#define NGI541_NATIVE_KEY_HANDLER(x)                                          \
  static ngi541_native_key_handler_t ngi541_native_key_handler_##x;           \
                                                                              \
  static void __clib_constructor                                              \
  ngi541_native_register_key_handler_##x (void)                               \
  {                                                                           \
    ngi541_native_registry_t *registry = &ngi541_native_registry;             \
    int priority = ngi541_native_key_handler_##x.probe ();                    \
                                                                              \
    if (priority >= 0)                                                        \
      {                                                                       \
        ngi541_native_key_handler_##x.priority = priority;                    \
        ngi541_native_key_handler_##x.next = registry->key_handlers;          \
        registry->key_handlers = &ngi541_native_key_handler_##x;              \
      }                                                                       \
  }                                                                           \
                                                                              \
  static ngi541_native_key_handler_t ngi541_native_key_handler_##x

#endif /* NGI541_INTERNAL_NATIVE_H */