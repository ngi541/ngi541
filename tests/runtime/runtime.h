/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 *
 * Modified for NGI541: test runtime extraction.
 */

#ifndef included_ngi541_test_runtime_h
#define included_ngi541_test_runtime_h

#include "engine/crypto_types.h"
#include "engine/engine.h"


typedef struct
{
  u32 index;
  u16 length;
  u8 is_link : 1;
  vnet_crypto_alg_t alg : 8;
  union
  {
    struct
    {
      u32 index_crypto;
      u32 index_integ;
    };
  };
  u8 data[];
} vnet_crypto_key_t;

typedef u32 vnet_crypto_key_index_t;

typedef struct
{
  char *name;
  u16 key_length;
  /* per-engine key data size */
  u16 per_engine_data_sz;
  /* per-thread key data size */
  u16 per_thread_key_size[VNET_CRYPTO_HANDLER_N_TYPES];
  u8 active_eidx[VNET_CRYPTO_HANDLER_N_TYPES];

  u8 is_aead : 1;
  u8 variable_key_length : 1;
  u8 is_link : 1;
  vnet_crypto_alg_t link_crypto_alg : 8;
  vnet_crypto_alg_t link_integ_alg : 8;
  vnet_crypto_op_id_t op_by_type[VNET_CRYPTO_OP_N_TYPES];

} vnet_crypto_alg_data_t;

typedef struct
{
  void *handlers[VNET_CRYPTO_HANDLER_N_TYPES];
} vnet_crypto_engine_op_t;

typedef struct
{
  char *name;
  char *desc;
  int priority;
  vnet_crypto_engine_op_t ops[VNET_CRYPTO_N_OP_IDS];
  u16 key_data_sz[VNET_CRYPTO_N_ALGS];
  void *per_thread_data;
  u32 per_thread_data_sz;
  vnet_crypto_key_fn_t *key_op_handler;
} vnet_crypto_engine_t;

typedef struct
{
  vnet_crypto_op_type_t type;
  vnet_crypto_alg_t alg;
  u8 active_engine_index[VNET_CRYPTO_HANDLER_N_TYPES];
  void *handlers[VNET_CRYPTO_HANDLER_N_TYPES];
} vnet_crypto_op_data_t;

typedef struct
{
  char *name;
  u8 is_disabled;
  u8 is_enabled;
} vnet_crypto_config_t;

typedef struct
{
  vnet_crypto_key_t **keys;
  u8 keys_lock;
  vnet_crypto_engine_t *engines;
  /* configs and hash by name */
  vnet_crypto_config_t *configs;
  uword *config_index_by_name;
  uword *engine_index_by_name;
  uword *alg_index_by_name;
  vnet_crypto_alg_data_t algs[VNET_CRYPTO_N_ALGS];
  vnet_crypto_op_data_t opt_data[VNET_CRYPTO_N_OP_IDS];
  u8 default_disabled;
} vnet_crypto_main_t;

typedef struct
{
  char *handler_name;
  char *engine;
  u8 set_simple : 1;
  u8 set_chained : 1;
} vnet_crypto_set_handlers_args_t;

extern vnet_crypto_main_t crypto_main;


u32
vnet_crypto_register_engine (char *name, int prio,
			     char *desc);


void vnet_crypto_register_ops_handler (u32 engine_index,
				       vnet_crypto_op_id_t opt,
				       vnet_crypto_simple_op_fn_t *oph);


void
vnet_crypto_register_chained_ops_handler (u32 engine_index,
					  vnet_crypto_op_id_t opt,
					  vnet_crypto_chained_op_fn_t *oph);


void vnet_crypto_register_ops_handlers (u32 engine_index,
					vnet_crypto_op_id_t opt,
					vnet_crypto_simple_op_fn_t *fn,
					vnet_crypto_chained_op_fn_t *cfn);

void vnet_crypto_register_key_handler (u32 engine_index,
				       vnet_crypto_key_fn_t *keyh);


u32 vnet_crypto_process_ops (vnet_crypto_op_t ops[], u32 n_ops);


u32 vnet_crypto_process_chained_ops (vnet_crypto_op_t ops[], vnet_crypto_op_chunk_t *chunks,
				     u32 n_ops);

int vnet_crypto_set_handlers (vnet_crypto_set_handlers_args_t *);

int vnet_crypto_is_set_handler (vnet_crypto_alg_t alg);

u32 vnet_crypto_key_add (vnet_crypto_alg_t alg,
			 u8 * data, u16 length);

vnet_crypto_key_t *vnet_crypto_key_add_ptr (vnet_crypto_alg_t alg, const u8 *data, u16 length);

void vnet_crypto_key_del (vnet_crypto_key_index_t index);
void vnet_crypto_key_del_ptr (vnet_crypto_key_t *key);

/**
 * Corner case: updating raw key data requires reallocating `key->data`
 * when the new key length differs from the current length (e.g. HMAC).
 * Limitation: update-by-pointer is only used for crypto key algs; it is
 * not used for linked keys (e.g. wireguard & QUIC).
 **/
void vnet_crypto_key_update (vnet_crypto_key_t *key, const u8 *data);

/**
 * Use crypto & integ keys data to generate new key
 * for linked algs (cipher + integ)
 * The returned key pointer is to be used for linked alg only.
 **/
vnet_crypto_key_t *vnet_crypto_integ_key_add (vnet_crypto_alg_t crypto_alg, const u8 *crypto_data,
					      u16 crypto_length, vnet_crypto_alg_t integ_alg,
					      const u8 *integ_data, u16 integ_length);

vnet_crypto_op_id_t *vnet_crypto_ops_from_alg (vnet_crypto_alg_t alg);

static_always_inline vnet_crypto_key_t *
vnet_crypto_get_key (vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  return cm->keys[index];
}

static_always_inline uword
vnet_crypto_get_key_data (vnet_crypto_key_t *key, vnet_crypto_handler_type_t t)
{
  vnet_crypto_main_t *cm = &crypto_main;

  if (!key)
    return 0;

  vnet_crypto_alg_data_t *ad = cm->algs + key->alg;
  u8 *key_data =
    (u8 *) key + round_pow2 (sizeof (vnet_crypto_key_t) + key->length, CLIB_CACHE_LINE_BYTES);

  if (t == VNET_CRYPTO_HANDLER_TYPE_CHAINED && ad->active_eidx[VNET_CRYPTO_HANDLER_TYPE_CHAINED] !=
						 ad->active_eidx[VNET_CRYPTO_HANDLER_TYPE_SIMPLE])
    {
      key_data += ad->per_engine_data_sz;
    }
  key_data += ad->per_thread_key_size[t]; //TODO ::  * vm->thread_index

  return (uword) key_data;
}

static_always_inline vnet_crypto_op_type_t
vnet_crypto_get_op_type (vnet_crypto_op_id_t id)
{
  vnet_crypto_main_t *cm = &crypto_main;
  ASSERT (id < VNET_CRYPTO_N_OP_IDS);
  vnet_crypto_op_data_t *od = cm->opt_data + id;
  return od->type;
}

static_always_inline vnet_crypto_alg_t
vnet_crypto_get_alg (vnet_crypto_op_id_t id)
{
  vnet_crypto_main_t *cm = &crypto_main;
  ASSERT (id < VNET_CRYPTO_N_OP_IDS);
  vnet_crypto_op_data_t *od = cm->opt_data + id;
  return od->alg;
}


#endif /* included_ngi541_test_runtime_h */