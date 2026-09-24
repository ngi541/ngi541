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
ngi541_execute_keyed (
  ngi541_keyed_workspace_t *workspace,
  ngi541_crypto_alg_t alg_id,
  const uint8_t *key,
  size_t key_len,
  bool allow_auth_failure)
{
  const ngi541_provider_op_handler_t *handler;
  ngi541_crypto_key_handler_args_t key_args;
  size_t key_data_size;
  u32 completed;
  ngi541_status_t status;

  if (alg_id <= NGI541_CRYPTO_ALG_NONE ||
      alg_id >= NGI541_CRYPTO_N_ALGS)
    return NGI541_STATUS_INTERNAL_ERROR;

  handler =
    ngi541_get_simple_handler (workspace->operation.op.op);

  if (handler == NULL)
    return NGI541_STATUS_UNAVAILABLE;

  if (ngi541_engine_provider->key_handler == NULL)
    return NGI541_STATUS_INTERNAL_ERROR;

  key_data_size =
    ngi541_engine_provider->key_data_size[alg_id];

  if (key_data_size == 0)
    return NGI541_STATUS_UNAVAILABLE;

  if (key_data_size > NGI541_EXEC_KEY_DATA_CAPACITY)
    return NGI541_STATUS_INTERNAL_ERROR;

  memset (
    workspace->key_data,
    0,
    key_data_size);

  key_args = (ngi541_crypto_key_handler_args_t) {
    .alg = alg_id,
    .key_data = workspace->key_data,
    .key = key,
    .key_length = (u16) key_len,
  };

  workspace->operation.op.key_data =
    workspace->key_data;

  ngi541_engine_provider->key_handler (
    NGI541_CRYPTO_KEY_OP_ADD,
    key_args);

  completed = handler->fn (
    workspace->operation.ops,
    1);

  status = ngi541_translate_handler_result (
    &workspace->operation.op,
    completed,
    allow_auth_failure);

  /*
   * Provider-specific cleanup is performed first. The execution
   * facade then unconditionally scrubs the complete expanded-key
   * region used by this provider.
   */
  ngi541_engine_provider->key_handler (
    NGI541_CRYPTO_KEY_OP_DEL,
    key_args);

  ngi541_secure_zero (
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