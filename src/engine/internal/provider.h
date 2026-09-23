/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 *
 * Modified for NGI541: internal provider ABI and NGI541 namespace.
 */

#ifndef NGI541_INTERNAL_PROVIDER_H
#define NGI541_INTERNAL_PROVIDER_H

#include "engine/internal/crypto_types.h"

typedef struct
{
  ngi541_crypto_op_id_t op_id;
  ngi541_crypto_simple_op_fn_t *fn;
  ngi541_crypto_chained_op_fn_t *cfn;
} ngi541_provider_op_handler_t;

struct ngi541_provider;

typedef char *(
  ngi541_provider_init_fn_t) (struct ngi541_provider *);

typedef struct ngi541_provider
{
  char name[32];
  char description[128];

  int priority;
  u32 version;

  u16 key_data_size[NGI541_CRYPTO_N_ALGS];

  ngi541_provider_init_fn_t *init;
  ngi541_crypto_key_fn_t *key_handler;
  ngi541_provider_op_handler_t *op_handlers;
} ngi541_provider_t;

#endif /* NGI541_INTERNAL_PROVIDER_H */