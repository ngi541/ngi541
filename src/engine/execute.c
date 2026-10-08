/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "engine/internal/execute.h"
#include "engine/internal/native.h"
#include "engine/internal/prepared.h"
#include "support/compat/memory.h"

typedef enum
{
  NGI541_ENGINE_STATE_UNINITIALIZED = 0,
  NGI541_ENGINE_STATE_INITIALIZING,
  NGI541_ENGINE_STATE_READY,
  NGI541_ENGINE_STATE_FAILED,
} ngi541_engine_state_t;

typedef struct
{
  ngi541_crypto_alg_t alg_id;
  ngi541_crypto_op_id_t op_id;
} ngi541_keyed_execution_plan_t;

#define NGI541_CIPHER_KEY_MAGIC 0x434b3534u
#define NGI541_AEAD_KEY_MAGIC   0x414b3534u

struct ngi541_cipher_key
{
  uint32_t magic;

  /*
   * Retained temporarily for the generic CBC fallback.
   * Direct CTR execution does not consult these fields in the data path.
   */
  ngi541_cipher_algorithm_t algorithm;
  size_t key_len;
  ngi541_crypto_alg_t alg_id;

  size_t key_data_size;
  void *key_data;

  bool direct_execution;

  ngi541_prepared_key_cleanup_fn_t *key_cleanup;
  ngi541_prepared_cipher_fn_t *encrypt;
  ngi541_prepared_cipher_fn_t *decrypt;
};


struct ngi541_aead_key
{
  uint32_t magic;

  size_t key_data_size;
  void *key_data;

  ngi541_prepared_key_cleanup_fn_t *key_cleanup;

  ngi541_prepared_aead_encrypt_fn_t *encrypt;
  ngi541_prepared_aead_decrypt_fn_t *decrypt;
};

static atomic_int ngi541_engine_state =
  ATOMIC_VAR_INIT (NGI541_ENGINE_STATE_UNINITIALIZED);

static ngi541_provider_t *const ngi541_engine_provider =
  &ngi541_native_provider;


/*
 * Explicitly clear sensitive temporary state.
 *
 * Volatile writes prevent the compiler from removing the operation
 * as a dead store after the key material is no longer referenced.
 */
static void
ngi541_secure_zero (void *ptr, size_t len)
{
  volatile uint8_t *p = (volatile uint8_t *) ptr;

  while (len != 0)
    {
      *p++ = 0;
      len--;
    }
}

static bool
ngi541_ranges_partially_overlap (
  const void *first,
  const void *second,
  size_t length)
{
  uintptr_t first_address;
  uintptr_t second_address;

  /*
   * Empty ranges never overlap.
   *
   * Exact aliasing is deliberately excluded here because AES-CTR
   * supports input == output as a defined public API operation.
   */
  if (length == 0 ||
      first == NULL ||
      second == NULL ||
      first == second)
    return false;

  /*
   * Compare integer representations rather than unrelated C
   * pointers. Avoid computing address + length so that the overlap
   * check itself cannot wrap at the end of the address space.
   */
  first_address =
    (uintptr_t) first;

  second_address =
    (uintptr_t) second;

  if (first_address < second_address)
    return
      second_address - first_address <
      length;

  return
    first_address - second_address <
    length;
}


static ngi541_status_t
ngi541_engine_ready_status (void)
{
  int state = atomic_load_explicit (
    &ngi541_engine_state,
    memory_order_acquire);

  switch (state)
    {
    case NGI541_ENGINE_STATE_READY:
      return NGI541_STATUS_OK;

    case NGI541_ENGINE_STATE_FAILED:
      return NGI541_STATUS_INTERNAL_ERROR;

    case NGI541_ENGINE_STATE_UNINITIALIZED:
    case NGI541_ENGINE_STATE_INITIALIZING:
      return NGI541_STATUS_NOT_INITIALIZED;

    default:
      return NGI541_STATUS_INTERNAL_ERROR;
    }
}


static const ngi541_provider_op_handler_t *
ngi541_get_simple_handler (ngi541_crypto_op_id_t op_id)
{
  const ngi541_provider_op_handler_t *handler;

  if (op_id == NGI541_CRYPTO_OP_NONE)
    return NULL;

  if ((u32) op_id >= ngi541_engine_provider->op_handler_count)
    return NULL;

  handler = &ngi541_engine_provider->op_handlers[op_id];

  if (handler->fn == NULL)
    return NULL;

  return handler;
}


static void
ngi541_prepare_operation (
  ngi541_op_workspace_t *workspace,
  ngi541_crypto_op_id_t op_id)
{
  workspace->ops[0] = &workspace->op;

  workspace->op.op = op_id;

  /*
   * Do not initialize this to COMPLETED.
   *
   * COMPLETED is currently enum value zero, so a zero-initialized
   * operation would otherwise appear successful even if a broken
   * handler failed to update its status.
   */
  workspace->op.status =
    (ngi541_crypto_op_status_t) NGI541_CRYPTO_OP_N_STATUS;
}


static ngi541_status_t
ngi541_translate_handler_result (
  const ngi541_crypto_op_t *op,
  u32 completed,
  bool allow_auth_failure)
{
  if (op->status == NGI541_CRYPTO_OP_STATUS_COMPLETED)
    {
      if (completed != 1)
        return NGI541_STATUS_INTERNAL_ERROR;

      return NGI541_STATUS_OK;
    }

  if (op->status == NGI541_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
    {
      if (!allow_auth_failure || completed != 0)
        return NGI541_STATUS_INTERNAL_ERROR;

      return NGI541_STATUS_AUTH_FAILED;
    }

  return NGI541_STATUS_INTERNAL_ERROR;
}


static ngi541_status_t
ngi541_execute_unkeyed (
  ngi541_op_workspace_t *workspace,
  bool allow_auth_failure)
{
  const ngi541_provider_op_handler_t *handler;
  u32 completed;

  handler = ngi541_get_simple_handler (workspace->op.op);

  if (handler == NULL)
    return NGI541_STATUS_UNAVAILABLE;

  completed = handler->fn (workspace->ops, 1);

  return ngi541_translate_handler_result (
    &workspace->op,
    completed,
    allow_auth_failure);
}


static ngi541_status_t
ngi541_prepare_key_data (
  ngi541_crypto_alg_t alg_id,
  const uint8_t *key,
  size_t key_len,
  void *key_data,
  size_t key_data_capacity,
  size_t *prepared_size)
{
  ngi541_crypto_key_handler_args_t key_args;
  size_t key_data_size;

  if (alg_id <= NGI541_CRYPTO_ALG_NONE ||
      alg_id >= NGI541_CRYPTO_N_ALGS)
    return NGI541_STATUS_INTERNAL_ERROR;

  if (key == NULL ||
      key_data == NULL ||
      prepared_size == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  if (key_len > UINT16_MAX)
    return NGI541_STATUS_INTERNAL_ERROR;

  if (ngi541_engine_provider->key_handler == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  key_data_size =
    ngi541_engine_provider->key_data_size[alg_id];

  if (key_data_size == 0)
    return NGI541_STATUS_UNAVAILABLE;

  if (key_data_size > key_data_capacity)
    return NGI541_STATUS_INTERNAL_ERROR;

  memset (
    key_data,
    0,
    key_data_size);

  key_args = (ngi541_crypto_key_handler_args_t) {
    .alg = alg_id,
    .key_data = key_data,
    .key = key,
    .key_length = (u16) key_len,
  };

  ngi541_engine_provider->key_handler (
    NGI541_CRYPTO_KEY_OP_ADD,
    key_args);

  *prepared_size = key_data_size;

  return NGI541_STATUS_OK;
}


static ngi541_status_t
ngi541_execute_prepared_key (
  ngi541_op_workspace_t *workspace,
  const ngi541_provider_op_handler_t *handler,
  void *key_data,
  bool allow_auth_failure)
{
  u32 completed;

  if (workspace == NULL ||
      handler == NULL ||
      key_data == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  /*
   * key_data contains provider-specific prepared key material.
   *
   * Execution must not modify or destroy this material. The internal
   * operation ABI is currently not const-qualified, so the immutable
   * prepared-key contract is enforced by the execution design rather
   * than by the type system at this stage.
   */
  workspace->op.key_data =
    key_data;

  completed = handler->fn (
    workspace->ops,
    1);

  return ngi541_translate_handler_result (
    &workspace->op,
    completed,
    allow_auth_failure);
}


static void
ngi541_release_key_data (
  ngi541_crypto_alg_t alg_id,
  void *key_data,
  size_t key_data_size)
{
  ngi541_crypto_key_handler_args_t key_args;

  if (key_data == NULL ||
      key_data_size == 0)
    return;

  /*
   * Raw key material is intentionally not required for deletion.
   *
   * A prepared-key object retains only provider-specific prepared
   * state. This invariant is required by the persistent-key API:
   * destruction must not depend on retaining the caller's raw key.
   */
  key_args = (ngi541_crypto_key_handler_args_t) {
    .alg = alg_id,
    .key_data = key_data,
    .key = NULL,
    .key_length = 0,
  };

  ngi541_engine_provider->key_handler (
    NGI541_CRYPTO_KEY_OP_DEL,
    key_args);

  ngi541_secure_zero (
    key_data,
    key_data_size);
}

static ngi541_status_t
ngi541_create_persistent_key_data (
  ngi541_crypto_alg_t alg_id,
  const uint8_t *key,
  size_t key_len,
  void **prepared_data,
  size_t *prepared_size)
{
  void *key_data;
  size_t key_data_size;
  size_t actual_size;
  ngi541_status_t status;

  if (prepared_data == NULL ||
      prepared_size == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  *prepared_data = NULL;
  *prepared_size = 0;

  if (alg_id <= NGI541_CRYPTO_ALG_NONE ||
      alg_id >= NGI541_CRYPTO_N_ALGS)
    return NGI541_STATUS_INTERNAL_ERROR;

  if (ngi541_engine_provider->key_handler == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  key_data_size =
    ngi541_engine_provider->key_data_size[alg_id];

  if (key_data_size == 0)
    return NGI541_STATUS_UNAVAILABLE;

  key_data =
    ngi541_aligned_alloc (
      key_data_size,
      NGI541_EXEC_KEY_DATA_ALIGNMENT);

  if (key_data == NULL)
    return NGI541_STATUS_NO_MEMORY;

  status = ngi541_prepare_key_data (
    alg_id,
    key,
    key_len,
    key_data,
    key_data_size,
    &actual_size);

  if (status != NGI541_STATUS_OK)
    {
      ngi541_secure_zero (
        key_data,
        key_data_size);

      ngi541_aligned_free (
        key_data);

      return status;
    }

  if (actual_size != key_data_size)
    {
      ngi541_release_key_data (
        alg_id,
        key_data,
        actual_size);

      ngi541_aligned_free (
        key_data);

      return NGI541_STATUS_INTERNAL_ERROR;
    }

  *prepared_data = key_data;
  *prepared_size = key_data_size;

  return NGI541_STATUS_OK;
}

static void
ngi541_destroy_persistent_key_data (
  ngi541_crypto_alg_t alg_id,
  void *key_data,
  size_t key_data_size)
{
  if (key_data == NULL)
    return;

  ngi541_release_key_data (
    alg_id,
    key_data,
    key_data_size);

  ngi541_aligned_free (
    key_data);
}

static ngi541_status_t
ngi541_create_direct_prepared_key_data (
  size_t key_data_size,
  ngi541_prepared_key_init_fn_t *key_init,
  const uint8_t *key,
  size_t key_len,
  void **prepared_data)
{
  void *key_data;
  ngi541_status_t status;

  if (prepared_data == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  *prepared_data = NULL;

  if (key_data_size == 0 ||
      key_init == NULL ||
      key == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  key_data =
    ngi541_aligned_alloc (
      key_data_size,
      NGI541_EXEC_KEY_DATA_ALIGNMENT);

  if (key_data == NULL)
    return NGI541_STATUS_NO_MEMORY;

  status =
    key_init (
      key_data,
      key,
      key_len);

  if (status != NGI541_STATUS_OK)
    {
      ngi541_secure_zero (
        key_data,
        key_data_size);

      ngi541_aligned_free (
        key_data);

      return status;
    }

  *prepared_data = key_data;

  return NGI541_STATUS_OK;
}


static void
ngi541_destroy_direct_prepared_key_data (
  void *key_data,
  size_t key_data_size,
  ngi541_prepared_key_cleanup_fn_t *key_cleanup)
{
  if (key_data == NULL)
    return;

  if (key_cleanup != NULL)
    key_cleanup (key_data);

  ngi541_secure_zero (
    key_data,
    key_data_size);

  ngi541_aligned_free (
    key_data);
}


static ngi541_status_t
ngi541_execute_keyed (
  ngi541_keyed_workspace_t *workspace,
  ngi541_crypto_alg_t alg_id,
  const uint8_t *key,
  size_t key_len,
  bool allow_auth_failure)
{
  const ngi541_provider_op_handler_t *handler;
  size_t key_data_size;
  ngi541_status_t status;

  if (alg_id <= NGI541_CRYPTO_ALG_NONE ||
      alg_id >= NGI541_CRYPTO_N_ALGS)
    return NGI541_STATUS_INTERNAL_ERROR;

  /*
   * Preserve the existing one-shot ordering: reject an unavailable
   * operation handler before performing key preparation.
   */
  handler =
    ngi541_get_simple_handler (
      workspace->operation.op.op);

  if (handler == NULL)
    return NGI541_STATUS_UNAVAILABLE;

  status = ngi541_prepare_key_data (
    alg_id,
    key,
    key_len,
    workspace->key_data,
    sizeof (workspace->key_data),
    &key_data_size);

  if (status != NGI541_STATUS_OK)
    return status;

  status = ngi541_execute_prepared_key (
    &workspace->operation,
    handler,
    workspace->key_data,
    allow_auth_failure);

  ngi541_release_key_data (
    alg_id,
    workspace->key_data,
    key_data_size);

  return status;
}


static ngi541_status_t
ngi541_map_cipher (
  ngi541_cipher_algorithm_t algorithm,
  size_t key_len,
  bool decrypt,
  ngi541_keyed_execution_plan_t *plan)
{
  switch (algorithm)
    {
    case NGI541_CIPHER_AES_CBC:
      switch (key_len)
        {
        case 16:
          plan->alg_id =
            NGI541_CRYPTO_ALG_AES_128_CBC;
          plan->op_id = decrypt
            ? NGI541_CRYPTO_OP_AES_128_CBC_DEC
            : NGI541_CRYPTO_OP_AES_128_CBC_ENC;
          return NGI541_STATUS_OK;

        case 24:
          plan->alg_id =
            NGI541_CRYPTO_ALG_AES_192_CBC;
          plan->op_id = decrypt
            ? NGI541_CRYPTO_OP_AES_192_CBC_DEC
            : NGI541_CRYPTO_OP_AES_192_CBC_ENC;
          return NGI541_STATUS_OK;

        case 32:
          plan->alg_id =
            NGI541_CRYPTO_ALG_AES_256_CBC;
          plan->op_id = decrypt
            ? NGI541_CRYPTO_OP_AES_256_CBC_DEC
            : NGI541_CRYPTO_OP_AES_256_CBC_ENC;
          return NGI541_STATUS_OK;

        default:
          return NGI541_STATUS_UNSUPPORTED;
        }

    case NGI541_CIPHER_AES_CTR:
      switch (key_len)
        {
        case 16:
          plan->alg_id =
            NGI541_CRYPTO_ALG_AES_128_CTR;
          plan->op_id = decrypt
            ? NGI541_CRYPTO_OP_AES_128_CTR_DEC
            : NGI541_CRYPTO_OP_AES_128_CTR_ENC;
          return NGI541_STATUS_OK;

        case 24:
          plan->alg_id =
            NGI541_CRYPTO_ALG_AES_192_CTR;
          plan->op_id = decrypt
            ? NGI541_CRYPTO_OP_AES_192_CTR_DEC
            : NGI541_CRYPTO_OP_AES_192_CTR_ENC;
          return NGI541_STATUS_OK;

        case 32:
          plan->alg_id =
            NGI541_CRYPTO_ALG_AES_256_CTR;
          plan->op_id = decrypt
            ? NGI541_CRYPTO_OP_AES_256_CTR_DEC
            : NGI541_CRYPTO_OP_AES_256_CTR_ENC;
          return NGI541_STATUS_OK;

        default:
          return NGI541_STATUS_UNSUPPORTED;
        }

    default:
      return NGI541_STATUS_UNSUPPORTED;
    }
}


static ngi541_status_t
ngi541_map_gcm (
  size_t key_len,
  size_t aad_len,
  bool decrypt,
  ngi541_keyed_execution_plan_t *plan)
{
  ngi541_crypto_op_id_t base_op;
  ngi541_crypto_op_id_t fast_aad8;
  ngi541_crypto_op_id_t fast_aad12;
  ngi541_crypto_op_id_t preferred;

  switch (key_len)
    {
    case 16:
      plan->alg_id =
        NGI541_CRYPTO_ALG_AES_128_GCM;

      base_op = decrypt
        ? NGI541_CRYPTO_OP_AES_128_GCM_DEC
        : NGI541_CRYPTO_OP_AES_128_GCM_ENC;

      fast_aad8 = decrypt
        ? NGI541_CRYPTO_OP_AES_128_GCM_TAG16_AAD8_DEC
        : NGI541_CRYPTO_OP_AES_128_GCM_TAG16_AAD8_ENC;

      fast_aad12 = decrypt
        ? NGI541_CRYPTO_OP_AES_128_GCM_TAG16_AAD12_DEC
        : NGI541_CRYPTO_OP_AES_128_GCM_TAG16_AAD12_ENC;
      break;

    case 24:
      plan->alg_id =
        NGI541_CRYPTO_ALG_AES_192_GCM;

      base_op = decrypt
        ? NGI541_CRYPTO_OP_AES_192_GCM_DEC
        : NGI541_CRYPTO_OP_AES_192_GCM_ENC;

      fast_aad8 = decrypt
        ? NGI541_CRYPTO_OP_AES_192_GCM_TAG16_AAD8_DEC
        : NGI541_CRYPTO_OP_AES_192_GCM_TAG16_AAD8_ENC;

      fast_aad12 = decrypt
        ? NGI541_CRYPTO_OP_AES_192_GCM_TAG16_AAD12_DEC
        : NGI541_CRYPTO_OP_AES_192_GCM_TAG16_AAD12_ENC;
      break;

    case 32:
      plan->alg_id =
        NGI541_CRYPTO_ALG_AES_256_GCM;

      base_op = decrypt
        ? NGI541_CRYPTO_OP_AES_256_GCM_DEC
        : NGI541_CRYPTO_OP_AES_256_GCM_ENC;

      fast_aad8 = decrypt
        ? NGI541_CRYPTO_OP_AES_256_GCM_TAG16_AAD8_DEC
        : NGI541_CRYPTO_OP_AES_256_GCM_TAG16_AAD8_ENC;

      fast_aad12 = decrypt
        ? NGI541_CRYPTO_OP_AES_256_GCM_TAG16_AAD12_DEC
        : NGI541_CRYPTO_OP_AES_256_GCM_TAG16_AAD12_ENC;
      break;

    default:
      return NGI541_STATUS_UNSUPPORTED;
    }

  preferred = NGI541_CRYPTO_OP_NONE;

  if (aad_len == 8)
    preferred = fast_aad8;
  else if (aad_len == 12)
    preferred = fast_aad12;

  /*
   * Specialized GCM variants are implementation optimizations,
   * never public capabilities. Fall back to the generic operation
   * when a specialized handler is unavailable.
   */
  if (preferred != NGI541_CRYPTO_OP_NONE &&
      ngi541_get_simple_handler (preferred) != NULL)
    plan->op_id = preferred;
  else
    plan->op_id = base_op;

  return NGI541_STATUS_OK;
}


static ngi541_status_t
ngi541_map_hash (
  ngi541_hash_algorithm_t algorithm,
  ngi541_crypto_op_id_t *op_id,
  size_t *digest_len)
{
  switch (algorithm)
    {
    case NGI541_HASH_SHA2_224:
      *op_id = NGI541_CRYPTO_OP_SHA224_HASH;
      *digest_len = 28;
      return NGI541_STATUS_OK;

    case NGI541_HASH_SHA2_256:
      *op_id = NGI541_CRYPTO_OP_SHA256_HASH;
      *digest_len = 32;
      return NGI541_STATUS_OK;

    default:
      return NGI541_STATUS_UNSUPPORTED;
    }
}


NGI541_API ngi541_status_t
ngi541_engine_init (void)
{
  int state;
  int expected;
  char *error;

  for (;;)
    {
      state = atomic_load_explicit (
        &ngi541_engine_state,
        memory_order_acquire);

      if (state == NGI541_ENGINE_STATE_READY)
        return NGI541_STATUS_OK;

      if (state == NGI541_ENGINE_STATE_FAILED)
        return NGI541_STATUS_INTERNAL_ERROR;

      if (state == NGI541_ENGINE_STATE_UNINITIALIZED)
        {
          expected =
            NGI541_ENGINE_STATE_UNINITIALIZED;

          if (!atomic_compare_exchange_strong_explicit (
                &ngi541_engine_state,
                &expected,
                NGI541_ENGINE_STATE_INITIALIZING,
                memory_order_acq_rel,
                memory_order_acquire))
            continue;

          if (ngi541_engine_provider == NULL ||
              ngi541_engine_provider->init == NULL ||
              ngi541_engine_provider->op_handlers == NULL ||
              ngi541_engine_provider->op_handler_count == 0 ||
              ngi541_engine_provider->key_handler == NULL)
            {
              atomic_store_explicit (
                &ngi541_engine_state,
                NGI541_ENGINE_STATE_FAILED,
                memory_order_release);

              return NGI541_STATUS_INTERNAL_ERROR;
            }

          error =
            ngi541_engine_provider->init (
              ngi541_engine_provider);

          if (error != NULL)
            {
              atomic_store_explicit (
                &ngi541_engine_state,
                NGI541_ENGINE_STATE_FAILED,
                memory_order_release);

              return NGI541_STATUS_INTERNAL_ERROR;
            }

          atomic_store_explicit (
            &ngi541_engine_state,
            NGI541_ENGINE_STATE_READY,
            memory_order_release);

          return NGI541_STATUS_OK;
        }

      if (state != NGI541_ENGINE_STATE_INITIALIZING)
        return NGI541_STATUS_INTERNAL_ERROR;

      /*
       * Another thread owns initialization. Provider initialization
       * is short, so this path only waits until the state changes.
       */
    }
}


static ngi541_status_t
ngi541_execute_cipher (
  const ngi541_cipher_request_t *request,
  bool decrypt)
{
  ngi541_keyed_execution_plan_t plan;
  ngi541_keyed_workspace_t workspace;
  ngi541_status_t status;

  memset (&workspace, 0, sizeof (workspace));

  status = ngi541_engine_ready_status ();

  if (status != NGI541_STATUS_OK)
    return status;

  if (request == NULL ||
      request->struct_size < sizeof (*request))
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->key == NULL ||
      request->iv == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->input_len != 0 &&
      request->input == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->output_capacity <
      request->input_len)
    return NGI541_STATUS_BUFFER_TOO_SMALL;

  if (request->input_len != 0 &&
      request->output == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->input_len > UINT32_MAX)
    return NGI541_STATUS_UNSUPPORTED;

  status = ngi541_map_cipher (
    request->algorithm,
    request->key_len,
    decrypt,
    &plan);

  if (status != NGI541_STATUS_OK)
    return status;

  if (request->iv_len != 16)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->algorithm ==
        NGI541_CIPHER_AES_CBC &&
      (request->input_len % 16) != 0)
    return NGI541_STATUS_INVALID_ARGUMENT;

  /*
   * AES-CTR supports exact in-place operation but not partial
   * input/output aliasing.
   *
   * Check only the input_len bytes that the operation actually
   * reads and writes. output_capacity may be larger than the
   * operation region and does not extend the overlap contract.
   */
  if (request->algorithm ==
        NGI541_CIPHER_AES_CTR &&
      ngi541_ranges_partially_overlap (
        request->input,
        request->output,
        request->input_len))
    return NGI541_STATUS_INVALID_ARGUMENT;

  ngi541_prepare_operation (
    &workspace.operation,
    plan.op_id);

  memcpy (
    workspace.operation.iv_scratch,
    request->iv,
    16);

  workspace.operation.op.src =
    request->input != NULL
      ? (u8 *) request->input
      : workspace.operation.empty;

  workspace.operation.op.dst =
    request->output != NULL
      ? request->output
      : workspace.operation.empty;

  workspace.operation.op.iv =
    workspace.operation.iv_scratch;

  workspace.operation.op.len =
    (u32) request->input_len;

  return ngi541_execute_keyed (
    &workspace,
    plan.alg_id,
    request->key,
    request->key_len,
    false);
}

NGI541_API ngi541_status_t
ngi541_crypto_cipher_key_create (
  const ngi541_cipher_key_params_t *params,
  ngi541_cipher_key_t **prepared_key)
{
  ngi541_keyed_execution_plan_t plan;
  const ngi541_prepared_cipher_impl_t *impl = NULL;
  ngi541_cipher_key_t *key;
  ngi541_status_t status;

  status = ngi541_engine_ready_status ();

  if (status != NGI541_STATUS_OK)
    return status;

  if (prepared_key == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  *prepared_key = NULL;

  if (params == NULL ||
      params->struct_size < sizeof (*params))
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (params->key == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  switch (params->algorithm)
    {
    case NGI541_CIPHER_AES_CTR:
      /*
       * AES-CTR uses the new direct prepared architecture.
       */
      if (params->key_len != 16 &&
          params->key_len != 24 &&
          params->key_len != 32)
        return NGI541_STATUS_UNSUPPORTED;

      impl =
        ngi541_native_prepared_aes_ctr_get (
          params->key_len);

      if (impl == NULL)
        return NGI541_STATUS_UNAVAILABLE;

      if (impl->key_data_size == 0 ||
          impl->key_init == NULL ||
          impl->encrypt == NULL ||
          impl->decrypt == NULL)
        return NGI541_STATUS_INTERNAL_ERROR;

      break;

    case NGI541_CIPHER_AES_CBC:
      /*
       * Temporary generic fallback.
       *
       * CBC will move to the direct prepared ABI separately so this patch
       * changes only the two QUIC primitives.
       */
      status =
        ngi541_map_cipher (
          params->algorithm,
          params->key_len,
          false,
          &plan);

      if (status != NGI541_STATUS_OK)
        return status;

      break;

    default:
      return NGI541_STATUS_UNSUPPORTED;
    }

  key =
    ngi541_aligned_alloc (
      sizeof (*key),
      NGI541_EXEC_KEY_DATA_ALIGNMENT);

  if (key == NULL)
    return NGI541_STATUS_NO_MEMORY;

  memset (
    key,
    0,
    sizeof (*key));

  if (impl != NULL)
    {
      status =
        ngi541_create_direct_prepared_key_data (
          impl->key_data_size,
          impl->key_init,
          params->key,
          params->key_len,
          &key->key_data);

      if (status == NGI541_STATUS_OK)
        {
          key->key_data_size =
            impl->key_data_size;

          key->key_cleanup =
            impl->key_cleanup;

          key->encrypt =
            impl->encrypt;

          key->decrypt =
            impl->decrypt;

          key->direct_execution = true;
        }
    }
  else
    {
      status =
        ngi541_create_persistent_key_data (
          plan.alg_id,
          params->key,
          params->key_len,
          &key->key_data,
          &key->key_data_size);

      if (status == NGI541_STATUS_OK)
        key->alg_id = plan.alg_id;
    }

  if (status != NGI541_STATUS_OK)
    {
      ngi541_secure_zero (
        key,
        sizeof (*key));

      ngi541_aligned_free (
        key);

      return status;
    }

  key->magic =
    NGI541_CIPHER_KEY_MAGIC;

  key->algorithm =
    params->algorithm;

  key->key_len =
    params->key_len;

  *prepared_key = key;

  return NGI541_STATUS_OK;
}

NGI541_API void
ngi541_crypto_cipher_key_destroy (
  ngi541_cipher_key_t *prepared_key)
{
  if (prepared_key == NULL)
    return;

  if (prepared_key->magic !=
      NGI541_CIPHER_KEY_MAGIC)
    return;

  prepared_key->magic = 0;

  if (prepared_key->direct_execution)
    {
      ngi541_destroy_direct_prepared_key_data (
        prepared_key->key_data,
        prepared_key->key_data_size,
        prepared_key->key_cleanup);
    }
  else
    {
      ngi541_destroy_persistent_key_data (
        prepared_key->alg_id,
        prepared_key->key_data,
        prepared_key->key_data_size);
    }

  ngi541_secure_zero (
    prepared_key,
    sizeof (*prepared_key));

  ngi541_aligned_free (
    prepared_key);
}

NGI541_API ngi541_status_t
ngi541_crypto_aead_key_create (
  const ngi541_aead_key_params_t *params,
  ngi541_aead_key_t **prepared_key)
{
  const ngi541_prepared_aead_impl_t *impl;
  ngi541_aead_key_t *key;
  ngi541_status_t status;

  status = ngi541_engine_ready_status ();

  if (status != NGI541_STATUS_OK)
    return status;

  if (prepared_key == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  *prepared_key = NULL;

  if (params == NULL ||
      params->struct_size < sizeof (*params))
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (params->key == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (params->algorithm !=
      NGI541_AEAD_AES_GCM)
    return NGI541_STATUS_UNSUPPORTED;

  /*
   * Public capability validation.
   *
   * Implementation selection happens once here, never in the data path.
   */
  if (params->key_len != 16 &&
      params->key_len != 24 &&
      params->key_len != 32)
    return NGI541_STATUS_UNSUPPORTED;

  impl =
    ngi541_native_prepared_aes_gcm_get (
      params->key_len);

  if (impl == NULL)
    return NGI541_STATUS_UNAVAILABLE;

  if (impl->key_data_size == 0 ||
      impl->key_init == NULL ||
      impl->encrypt == NULL ||
      impl->decrypt == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  key =
    ngi541_aligned_alloc (
      sizeof (*key),
      NGI541_EXEC_KEY_DATA_ALIGNMENT);

  if (key == NULL)
    return NGI541_STATUS_NO_MEMORY;

  memset (
    key,
    0,
    sizeof (*key));

  status =
    ngi541_create_direct_prepared_key_data (
      impl->key_data_size,
      impl->key_init,
      params->key,
      params->key_len,
      &key->key_data);

  if (status != NGI541_STATUS_OK)
    {
      ngi541_secure_zero (
        key,
        sizeof (*key));

      ngi541_aligned_free (
        key);

      return status;
    }

  /*
   * Bind the complete execution plan once.
   */
  key->key_data_size =
    impl->key_data_size;

  key->key_cleanup =
    impl->key_cleanup;

  key->encrypt =
    impl->encrypt;

  key->decrypt =
    impl->decrypt;

  key->magic =
    NGI541_AEAD_KEY_MAGIC;

  *prepared_key = key;

  return NGI541_STATUS_OK;
}

NGI541_API void
ngi541_crypto_aead_key_destroy (
  ngi541_aead_key_t *prepared_key)
{
  if (prepared_key == NULL)
    return;

  if (prepared_key->magic !=
      NGI541_AEAD_KEY_MAGIC)
    return;

  prepared_key->magic = 0;

  ngi541_destroy_direct_prepared_key_data (
    prepared_key->key_data,
    prepared_key->key_data_size,
    prepared_key->key_cleanup);

  ngi541_secure_zero (
    prepared_key,
    sizeof (*prepared_key));

  ngi541_aligned_free (
    prepared_key);
}

static ngi541_status_t
ngi541_execute_cipher_prepared (
  const ngi541_cipher_key_t *prepared_key,
  const ngi541_cipher_exec_request_t *request,
  bool decrypt)
{
  uint8_t iv_scratch[16];
  uint8_t empty = 0;

  const uint8_t *src;
  uint8_t *dst;

  ngi541_prepared_cipher_fn_t *direct_fn;

  ngi541_keyed_execution_plan_t plan;
  ngi541_op_workspace_t workspace;
  const ngi541_provider_op_handler_t *handler;
  ngi541_status_t status;

  /*
   * No engine-state atomic here.
   *
   * A valid prepared key can only exist after successful engine
   * initialization, and the engine has no shutdown transition while
   * prepared keys are alive.
   */

    if (prepared_key == NULL ||
        prepared_key->magic != NGI541_CIPHER_KEY_MAGIC)
    {
        status =
        ngi541_engine_ready_status ();

        if (status != NGI541_STATUS_OK)
        return status;

        return NGI541_STATUS_INVALID_ARGUMENT;
    }

  if (prepared_key->key_data == NULL ||
      prepared_key->key_data_size == 0)
    return NGI541_STATUS_INTERNAL_ERROR;

  if (request == NULL ||
      request->struct_size < sizeof (*request))
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->iv == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->input_len != 0 &&
      request->input == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->output_capacity <
      request->input_len)
    return NGI541_STATUS_BUFFER_TOO_SMALL;

  if (request->input_len != 0 &&
      request->output == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->input_len > UINT32_MAX)
    return NGI541_STATUS_UNSUPPORTED;

  if (request->iv_len != 16)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (prepared_key->algorithm ==
        NGI541_CIPHER_AES_CBC &&
      (request->input_len % 16) != 0)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (prepared_key->algorithm ==
        NGI541_CIPHER_AES_CTR &&
      ngi541_ranges_partially_overlap (
        request->input,
        request->output,
        request->input_len))
    return NGI541_STATUS_INVALID_ARGUMENT;

  /*
   * Direct prepared path.
   *
   * No algorithm mapping, op-id construction, provider registry lookup,
   * generic operation object or handler-result translation.
   */
  if (prepared_key->direct_execution)
    {
      if (prepared_key->algorithm !=
          NGI541_CIPHER_AES_CTR)
        return NGI541_STATUS_INTERNAL_ERROR;

      direct_fn =
        decrypt
          ? prepared_key->decrypt
          : prepared_key->encrypt;

      if (direct_fn == NULL)
        return NGI541_STATUS_INTERNAL_ERROR;

      memcpy (
        iv_scratch,
        request->iv,
        sizeof (iv_scratch));

      src =
        request->input != NULL
          ? request->input
          : &empty;

      dst =
        request->output != NULL
          ? request->output
          : &empty;

      return direct_fn (
        prepared_key->key_data,
        iv_scratch,
        src,
        dst,
        (uint32_t) request->input_len);
    }

  /*
   * Temporary generic CBC fallback.
   */
  memset (
    &workspace,
    0,
    sizeof (workspace));

  status =
    ngi541_map_cipher (
      prepared_key->algorithm,
      prepared_key->key_len,
      decrypt,
      &plan);

  if (status != NGI541_STATUS_OK)
    return status;

  if (plan.alg_id !=
      prepared_key->alg_id)
    return NGI541_STATUS_INTERNAL_ERROR;

  ngi541_prepare_operation (
    &workspace,
    plan.op_id);

  memcpy (
    workspace.iv_scratch,
    request->iv,
    16);

  workspace.op.src =
    request->input != NULL
      ? (u8 *) request->input
      : workspace.empty;

  workspace.op.dst =
    request->output != NULL
      ? request->output
      : workspace.empty;

  workspace.op.iv =
    workspace.iv_scratch;

  workspace.op.len =
    (u32) request->input_len;

  handler =
    ngi541_get_simple_handler (
      plan.op_id);

  if (handler == NULL)
    return NGI541_STATUS_UNAVAILABLE;

  return ngi541_execute_prepared_key (
    &workspace,
    handler,
    prepared_key->key_data,
    false);
}


NGI541_API ngi541_status_t
ngi541_crypto_cipher_encrypt_prepared (
  const ngi541_cipher_key_t *prepared_key,
  const ngi541_cipher_exec_request_t *request)
{
  return ngi541_execute_cipher_prepared (
    prepared_key,
    request,
    false);
}


NGI541_API ngi541_status_t
ngi541_crypto_cipher_decrypt_prepared (
  const ngi541_cipher_key_t *prepared_key,
  const ngi541_cipher_exec_request_t *request)
{
  return ngi541_execute_cipher_prepared (
    prepared_key,
    request,
    true);
}

NGI541_API ngi541_status_t
ngi541_crypto_aead_encrypt_prepared (
  const ngi541_aead_key_t *prepared_key,
  const ngi541_aead_encrypt_exec_request_t *request)
{
  uint8_t iv_scratch[12];
  uint8_t empty = 0;

  const uint8_t *aad;
  const uint8_t *src;
  uint8_t *dst;

    if (prepared_key == NULL ||
        prepared_key->magic != NGI541_AEAD_KEY_MAGIC)
    {
        ngi541_status_t status =
        ngi541_engine_ready_status ();

        if (status != NGI541_STATUS_OK)
        return status;

        return NGI541_STATUS_INVALID_ARGUMENT;
    }

  if (prepared_key->key_data == NULL ||
      prepared_key->key_data_size == 0 ||
      prepared_key->encrypt == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  if (request == NULL ||
      request->struct_size < sizeof (*request))
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->iv == NULL ||
      request->tag == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->aad_len != 0 &&
      request->aad == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->plaintext_len != 0 &&
      request->plaintext == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->ciphertext_capacity <
      request->plaintext_len)
    return NGI541_STATUS_BUFFER_TOO_SMALL;

  if (request->plaintext_len != 0 &&
      request->ciphertext == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->iv_len != 12 ||
      request->tag_len != 16)
    return NGI541_STATUS_UNSUPPORTED;

  if (request->plaintext_len > UINT32_MAX ||
      request->aad_len > UINT16_MAX)
    return NGI541_STATUS_UNSUPPORTED;

  memcpy (
    iv_scratch,
    request->iv,
    sizeof (iv_scratch));

  aad =
    request->aad != NULL
      ? request->aad
      : &empty;

  src =
    request->plaintext != NULL
      ? request->plaintext
      : &empty;

  dst =
    request->ciphertext != NULL
      ? request->ciphertext
      : &empty;

  return prepared_key->encrypt (
    prepared_key->key_data,
    iv_scratch,
    aad,
    (uint16_t) request->aad_len,
    src,
    dst,
    (uint32_t) request->plaintext_len,
    request->tag);
}

NGI541_API ngi541_status_t
ngi541_crypto_aead_decrypt_prepared (
  const ngi541_aead_key_t *prepared_key,
  const ngi541_aead_decrypt_exec_request_t *request)
{
  uint8_t iv_scratch[12];
  uint8_t tag_scratch[16];
  uint8_t empty = 0;

  const uint8_t *aad;
  const uint8_t *src;
  uint8_t *dst;

  ngi541_status_t status;

    if (prepared_key == NULL ||
        prepared_key->magic != NGI541_AEAD_KEY_MAGIC)
    {
        status =
        ngi541_engine_ready_status ();

        if (status != NGI541_STATUS_OK)
        return status;

        return NGI541_STATUS_INVALID_ARGUMENT;
    }

  if (prepared_key->key_data == NULL ||
      prepared_key->key_data_size == 0 ||
      prepared_key->decrypt == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  if (request == NULL ||
      request->struct_size < sizeof (*request))
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->iv == NULL ||
      request->tag == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->aad_len != 0 &&
      request->aad == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->ciphertext_len != 0 &&
      request->ciphertext == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->plaintext_capacity <
      request->ciphertext_len)
    return NGI541_STATUS_BUFFER_TOO_SMALL;

  if (request->ciphertext_len != 0 &&
      request->plaintext == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->iv_len != 12 ||
      request->tag_len != 16)
    return NGI541_STATUS_UNSUPPORTED;

  if (request->ciphertext_len > UINT32_MAX ||
      request->aad_len > UINT16_MAX)
    return NGI541_STATUS_UNSUPPORTED;

  memcpy (
    iv_scratch,
    request->iv,
    sizeof (iv_scratch));

  /*
   * Preserve the public const-tag contract until the AES-GCM core is
   * const-correct.
   */
  memcpy (
    tag_scratch,
    request->tag,
    sizeof (tag_scratch));

  aad =
    request->aad != NULL
      ? request->aad
      : &empty;

  src =
    request->ciphertext != NULL
      ? request->ciphertext
      : &empty;

  dst =
    request->plaintext != NULL
      ? request->plaintext
      : &empty;

  status =
    prepared_key->decrypt (
      prepared_key->key_data,
      iv_scratch,
      aad,
      (uint16_t) request->aad_len,
      src,
      dst,
      (uint32_t) request->ciphertext_len,
      tag_scratch);

  /*
   * Preserve the existing API guarantee:
   * unauthenticated plaintext must never remain visible.
   */
  if (status == NGI541_STATUS_AUTH_FAILED &&
      request->plaintext != NULL &&
      request->ciphertext_len != 0)
    {
      ngi541_secure_zero (
        request->plaintext,
        request->ciphertext_len);
    }

  return status;
}

NGI541_API ngi541_status_t
ngi541_crypto_cipher_encrypt (
  const ngi541_cipher_request_t *request)
{
  return ngi541_execute_cipher (
    request,
    false);
}


NGI541_API ngi541_status_t
ngi541_crypto_cipher_decrypt (
  const ngi541_cipher_request_t *request)
{
  return ngi541_execute_cipher (
    request,
    true);
}


NGI541_API ngi541_status_t
ngi541_crypto_aead_encrypt (
  const ngi541_aead_encrypt_request_t *request)
{
  ngi541_keyed_execution_plan_t plan;
  ngi541_keyed_workspace_t workspace;
  ngi541_status_t status;

  memset (&workspace, 0, sizeof (workspace));

  status = ngi541_engine_ready_status ();

  if (status != NGI541_STATUS_OK)
    return status;

  if (request == NULL ||
      request->struct_size < sizeof (*request))
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->key == NULL ||
      request->iv == NULL ||
      request->tag == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->aad_len != 0 &&
      request->aad == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->plaintext_len != 0 &&
      request->plaintext == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->ciphertext_capacity <
      request->plaintext_len)
    return NGI541_STATUS_BUFFER_TOO_SMALL;

  if (request->plaintext_len != 0 &&
      request->ciphertext == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->algorithm !=
      NGI541_AEAD_AES_GCM)
    return NGI541_STATUS_UNSUPPORTED;

  if (request->iv_len != 12 ||
      request->tag_len != 16)
    return NGI541_STATUS_UNSUPPORTED;

  if (request->plaintext_len > UINT32_MAX ||
      request->aad_len > UINT16_MAX)
    return NGI541_STATUS_UNSUPPORTED;

  status = ngi541_map_gcm (
    request->key_len,
    request->aad_len,
    false,
    &plan);

  if (status != NGI541_STATUS_OK)
    return status;

  ngi541_prepare_operation (
    &workspace.operation,
    plan.op_id);

  memcpy (
    workspace.operation.iv_scratch,
    request->iv,
    12);

  workspace.operation.op.src =
    request->plaintext != NULL
      ? (u8 *) request->plaintext
      : workspace.operation.empty;

  workspace.operation.op.dst =
    request->ciphertext != NULL
      ? request->ciphertext
      : workspace.operation.empty;

  workspace.operation.op.iv =
    workspace.operation.iv_scratch;

  workspace.operation.op.aad =
    request->aad != NULL
      ? (u8 *) request->aad
      : workspace.operation.empty;

  workspace.operation.op.tag =
    request->tag;

  workspace.operation.op.len =
    (u32) request->plaintext_len;

  workspace.operation.op.aad_len =
    (u16) request->aad_len;

  workspace.operation.op.tag_len =
    (u8) request->tag_len;

  return ngi541_execute_keyed (
    &workspace,
    plan.alg_id,
    request->key,
    request->key_len,
    false);
}


NGI541_API ngi541_status_t
ngi541_crypto_aead_decrypt (
  const ngi541_aead_decrypt_request_t *request)
{
  ngi541_keyed_execution_plan_t plan;
  ngi541_keyed_workspace_t workspace;
  ngi541_status_t status;

  memset (&workspace, 0, sizeof (workspace));

  status = ngi541_engine_ready_status ();

  if (status != NGI541_STATUS_OK)
    return status;

  if (request == NULL ||
      request->struct_size < sizeof (*request))
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->key == NULL ||
      request->iv == NULL ||
      request->tag == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->aad_len != 0 &&
      request->aad == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->ciphertext_len != 0 &&
      request->ciphertext == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->plaintext_capacity <
      request->ciphertext_len)
    return NGI541_STATUS_BUFFER_TOO_SMALL;

  if (request->ciphertext_len != 0 &&
      request->plaintext == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->algorithm !=
      NGI541_AEAD_AES_GCM)
    return NGI541_STATUS_UNSUPPORTED;

  if (request->iv_len != 12 ||
      request->tag_len != 16)
    return NGI541_STATUS_UNSUPPORTED;

  if (request->ciphertext_len > UINT32_MAX ||
      request->aad_len > UINT16_MAX)
    return NGI541_STATUS_UNSUPPORTED;

  status = ngi541_map_gcm (
    request->key_len,
    request->aad_len,
    true,
    &plan);

  if (status != NGI541_STATUS_OK)
    return status;

  ngi541_prepare_operation (
    &workspace.operation,
    plan.op_id);

  memcpy (
    workspace.operation.iv_scratch,
    request->iv,
    12);

  memcpy (
    workspace.operation.tag_scratch,
    request->tag,
    16);

  workspace.operation.op.src =
    request->ciphertext != NULL
      ? (u8 *) request->ciphertext
      : workspace.operation.empty;

  workspace.operation.op.dst =
    request->plaintext != NULL
      ? request->plaintext
      : workspace.operation.empty;

  workspace.operation.op.iv =
    workspace.operation.iv_scratch;

  workspace.operation.op.aad =
    request->aad != NULL
      ? (u8 *) request->aad
      : workspace.operation.empty;

  /*
   * Decrypt receives a caller-owned const tag. Use scratch storage
   * because the internal operation ABI is not const-qualified.
   */
  workspace.operation.op.tag =
    workspace.operation.tag_scratch;

  workspace.operation.op.len =
    (u32) request->ciphertext_len;

  workspace.operation.op.aad_len =
    (u16) request->aad_len;

  workspace.operation.op.tag_len =
    (u8) request->tag_len;

  status = ngi541_execute_keyed (
    &workspace,
    plan.alg_id,
    request->key,
    request->key_len,
    true);

  /*
   * Never leave unauthenticated plaintext available through the
   * public API after an authentication failure.
   */
  if (status == NGI541_STATUS_AUTH_FAILED &&
      request->plaintext != NULL &&
      request->ciphertext_len != 0)
    {
      ngi541_secure_zero (
        request->plaintext,
        request->ciphertext_len);
    }

  return status;
}


NGI541_API ngi541_status_t
ngi541_crypto_hash_compute (
  const ngi541_hash_request_t *request)
{
  ngi541_op_workspace_t workspace;
  ngi541_crypto_op_id_t op_id;
  ngi541_status_t status;
  size_t digest_len;

  memset (&workspace, 0, sizeof (workspace));

  status = ngi541_engine_ready_status ();

  if (status != NGI541_STATUS_OK)
    return status;

  if (request == NULL ||
      request->struct_size < sizeof (*request))
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->message_len != 0 &&
      request->message == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->digest == NULL)
    return NGI541_STATUS_INVALID_ARGUMENT;

  if (request->message_len > UINT32_MAX)
    return NGI541_STATUS_UNSUPPORTED;

  status = ngi541_map_hash (
    request->algorithm,
    &op_id,
    &digest_len);

  if (status != NGI541_STATUS_OK)
    return status;

  if (request->digest_capacity < digest_len)
    return NGI541_STATUS_BUFFER_TOO_SMALL;

  ngi541_prepare_operation (
    &workspace,
    op_id);

  workspace.op.src =
    request->message != NULL
      ? (u8 *) request->message
      : workspace.empty;

  workspace.op.len =
    (u32) request->message_len;

  workspace.op.digest =
    request->digest;

  workspace.op.digest_len =
    (u8) digest_len;

  return ngi541_execute_unkeyed (
    &workspace,
    false);
}