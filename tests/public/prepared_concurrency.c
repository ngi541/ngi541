/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <ngi541/engine.h>

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


#define NGI541_CONCURRENCY_THREADS       8
#define NGI541_CONCURRENCY_ITERATIONS    512
#define NGI541_CONCURRENCY_MAX_PAYLOAD   1460
#define NGI541_CONCURRENCY_MAX_AAD       32
#define NGI541_CONCURRENCY_CTR_LENGTH    5


static const uint8_t g_aead_key[16] = {
  0x20, 0x21, 0x22, 0x23,
  0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2a, 0x2b,
  0x2c, 0x2d, 0x2e, 0x2f,
};


static const uint8_t g_ctr_key[16] = {
  0x30, 0x31, 0x32, 0x33,
  0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x3a, 0x3b,
  0x3c, 0x3d, 0x3e, 0x3f,
};


typedef struct
{
  unsigned int thread_index;

  const ngi541_aead_key_t *aead_key;
  const ngi541_cipher_key_t *ctr_key;

  atomic_uint *ready_count;
  atomic_bool *start;
  atomic_uint *failures;
} ngi541_concurrency_worker_t;


static void
fill_test_data (
  uint8_t *buffer,
  size_t length,
  uint32_t seed)
{
  for (size_t i = 0; i < length; i++)
    {
      buffer[i] =
        (uint8_t) (
          seed +
          (uint32_t) (i * 29u) +
          (uint32_t) ((i >> 1) * 17u));
    }
}


static void
make_counter_value (
  uint8_t *value,
  size_t length,
  uint8_t domain,
  unsigned int thread_index,
  uint32_t iteration)
{
  memset (
    value,
    0,
    length);

  value[0] = domain;
  value[1] =
    (uint8_t) thread_index;

  value[length - 4] =
    (uint8_t) (iteration >> 24);

  value[length - 3] =
    (uint8_t) (iteration >> 16);

  value[length - 2] =
    (uint8_t) (iteration >> 8);

  value[length - 1] =
    (uint8_t) iteration;
}


static size_t
gcm_payload_length (
  unsigned int thread_index,
  uint32_t iteration)
{
  const uint32_t span =
    NGI541_CONCURRENCY_MAX_PAYLOAD - 63u;

  return
    64u +
    (
      (
        thread_index * 37u +
        iteration * 13u
      ) %
      span
    );
}


static size_t
gcm_aad_length (
  uint32_t iteration)
{
  switch (iteration % 4u)
    {
    case 0:
      return 0;

    case 1:
      return 8;

    case 2:
      return 12;

    default:
      return 23;
    }
}


static void
record_failure (
  ngi541_concurrency_worker_t *worker)
{
  atomic_fetch_add_explicit (
    worker->failures,
    1u,
    memory_order_relaxed);
}


static int
test_gcm_iteration (
  ngi541_concurrency_worker_t *worker,
  uint32_t iteration)
{
  uint8_t iv[12];
  uint8_t aad[NGI541_CONCURRENCY_MAX_AAD];

  uint8_t plaintext[
    NGI541_CONCURRENCY_MAX_PAYLOAD];

  uint8_t one_shot_ciphertext[
    NGI541_CONCURRENCY_MAX_PAYLOAD];

  uint8_t prepared_ciphertext[
    NGI541_CONCURRENCY_MAX_PAYLOAD];

  uint8_t decrypted[
    NGI541_CONCURRENCY_MAX_PAYLOAD];

  uint8_t one_shot_tag[16];
  uint8_t prepared_tag[16];

  const size_t plaintext_len =
    gcm_payload_length (
      worker->thread_index,
      iteration);

  const size_t aad_len =
    gcm_aad_length (
      iteration);

  ngi541_aead_encrypt_request_t
    one_shot_request;

  ngi541_aead_encrypt_exec_request_t
    prepared_encrypt_request;

  ngi541_aead_decrypt_exec_request_t
    prepared_decrypt_request;

  ngi541_status_t status;


  make_counter_value (
    iv,
    sizeof (iv),
    0xa1,
    worker->thread_index,
    iteration);

  fill_test_data (
    aad,
    aad_len,
    0x1000u +
      (worker->thread_index * 257u) +
      iteration);

  fill_test_data (
    plaintext,
    plaintext_len,
    0x2000u +
      (worker->thread_index * 521u) +
      iteration);


  memset (
    one_shot_ciphertext,
    0,
    plaintext_len);

  memset (
    prepared_ciphertext,
    0,
    plaintext_len);

  memset (
    decrypted,
    0,
    plaintext_len);

  memset (
    one_shot_tag,
    0,
    sizeof (one_shot_tag));

  memset (
    prepared_tag,
    0,
    sizeof (prepared_tag));


  one_shot_request =
    (ngi541_aead_encrypt_request_t)
    {
      .struct_size =
        sizeof (ngi541_aead_encrypt_request_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = g_aead_key,
      .key_len = sizeof (g_aead_key),

      .iv = iv,
      .iv_len = sizeof (iv),

      .aad =
        aad_len != 0
          ? aad
          : NULL,

      .aad_len = aad_len,

      .plaintext = plaintext,
      .plaintext_len =
        plaintext_len,

      .ciphertext =
        one_shot_ciphertext,

      .ciphertext_capacity =
        sizeof (one_shot_ciphertext),

      .tag = one_shot_tag,
      .tag_len =
        sizeof (one_shot_tag),
    };


  status =
    ngi541_crypto_aead_encrypt (
      &one_shot_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "one-shot GCM failed: status=%d\n",
        worker->thread_index,
        iteration,
        (int) status);

      return 1;
    }


  prepared_encrypt_request =
    (ngi541_aead_encrypt_exec_request_t)
    {
      .struct_size =
        sizeof (
          ngi541_aead_encrypt_exec_request_t),

      .iv = iv,
      .iv_len = sizeof (iv),

      .aad =
        aad_len != 0
          ? aad
          : NULL,

      .aad_len = aad_len,

      .plaintext = plaintext,
      .plaintext_len =
        plaintext_len,

      .ciphertext =
        prepared_ciphertext,

      .ciphertext_capacity =
        sizeof (prepared_ciphertext),

      .tag = prepared_tag,
      .tag_len =
        sizeof (prepared_tag),
    };


  status =
    ngi541_crypto_aead_encrypt_prepared (
      worker->aead_key,
      &prepared_encrypt_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "prepared GCM encrypt failed: status=%d\n",
        worker->thread_index,
        iteration,
        (int) status);

      return 1;
    }


  if (memcmp (
        one_shot_ciphertext,
        prepared_ciphertext,
        plaintext_len) != 0)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "GCM ciphertext mismatch\n",
        worker->thread_index,
        iteration);

      return 1;
    }


  if (memcmp (
        one_shot_tag,
        prepared_tag,
        sizeof (prepared_tag)) != 0)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "GCM tag mismatch\n",
        worker->thread_index,
        iteration);

      return 1;
    }


  prepared_decrypt_request =
    (ngi541_aead_decrypt_exec_request_t)
    {
      .struct_size =
        sizeof (
          ngi541_aead_decrypt_exec_request_t),

      .iv = iv,
      .iv_len = sizeof (iv),

      .aad =
        aad_len != 0
          ? aad
          : NULL,

      .aad_len = aad_len,

      .ciphertext =
        prepared_ciphertext,

      .ciphertext_len =
        plaintext_len,

      .tag = prepared_tag,
      .tag_len =
        sizeof (prepared_tag),

      .plaintext = decrypted,
      .plaintext_capacity =
        sizeof (decrypted),
    };


  status =
    ngi541_crypto_aead_decrypt_prepared (
      worker->aead_key,
      &prepared_decrypt_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "prepared GCM decrypt failed: status=%d\n",
        worker->thread_index,
        iteration,
        (int) status);

      return 1;
    }


  if (memcmp (
        plaintext,
        decrypted,
        plaintext_len) != 0)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "GCM plaintext mismatch\n",
        worker->thread_index,
        iteration);

      return 1;
    }


  return 0;
}


static int
test_ctr_iteration (
  ngi541_concurrency_worker_t *worker,
  uint32_t iteration)
{
  uint8_t iv[16];

  uint8_t input[
    NGI541_CONCURRENCY_CTR_LENGTH];

  uint8_t one_shot_output[
    NGI541_CONCURRENCY_CTR_LENGTH];

  uint8_t prepared_output[
    NGI541_CONCURRENCY_CTR_LENGTH];

  uint8_t decrypted[
    NGI541_CONCURRENCY_CTR_LENGTH];

  ngi541_cipher_request_t
    one_shot_request;

  ngi541_cipher_exec_request_t
    prepared_request;

  ngi541_status_t status;


  make_counter_value (
    iv,
    sizeof (iv),
    0xc1,
    worker->thread_index,
    iteration);

  fill_test_data (
    input,
    sizeof (input),
    0x3000u +
      (worker->thread_index * 131u) +
      iteration);


  one_shot_request =
    (ngi541_cipher_request_t)
    {
      .struct_size =
        sizeof (ngi541_cipher_request_t),

      .algorithm =
        NGI541_CIPHER_AES_CTR,

      .key = g_ctr_key,
      .key_len = sizeof (g_ctr_key),

      .iv = iv,
      .iv_len = sizeof (iv),

      .input = input,
      .input_len = sizeof (input),

      .output = one_shot_output,
      .output_capacity =
        sizeof (one_shot_output),
    };


  status =
    ngi541_crypto_cipher_encrypt (
      &one_shot_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "one-shot CTR failed: status=%d\n",
        worker->thread_index,
        iteration,
        (int) status);

      return 1;
    }


  prepared_request =
    (ngi541_cipher_exec_request_t)
    {
      .struct_size =
        sizeof (
          ngi541_cipher_exec_request_t),

      .iv = iv,
      .iv_len = sizeof (iv),

      .input = input,
      .input_len = sizeof (input),

      .output = prepared_output,
      .output_capacity =
        sizeof (prepared_output),
    };


  status =
    ngi541_crypto_cipher_encrypt_prepared (
      worker->ctr_key,
      &prepared_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "prepared CTR encrypt failed: status=%d\n",
        worker->thread_index,
        iteration,
        (int) status);

      return 1;
    }


  if (memcmp (
        one_shot_output,
        prepared_output,
        sizeof (prepared_output)) != 0)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "CTR ciphertext mismatch\n",
        worker->thread_index,
        iteration);

      return 1;
    }


  prepared_request.input =
    prepared_output;

  prepared_request.output =
    decrypted;


  status =
    ngi541_crypto_cipher_decrypt_prepared (
      worker->ctr_key,
      &prepared_request);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "prepared CTR decrypt failed: status=%d\n",
        worker->thread_index,
        iteration,
        (int) status);

      return 1;
    }


  if (memcmp (
        input,
        decrypted,
        sizeof (input)) != 0)
    {
      fprintf (
        stderr,
        "thread=%u iteration=%u: "
        "CTR plaintext mismatch\n",
        worker->thread_index,
        iteration);

      return 1;
    }


  return 0;
}


static void *
worker_main (
  void *argument)
{
  ngi541_concurrency_worker_t *worker =
    (ngi541_concurrency_worker_t *) argument;


  atomic_fetch_add_explicit (
    worker->ready_count,
    1u,
    memory_order_release);


  /*
   * Deliberately synchronize all worker entry points without placing
   * any lock around NGI541 execution itself.
   */
  while (!atomic_load_explicit (
           worker->start,
           memory_order_acquire))
    {
      sched_yield ();
    }


  for (uint32_t iteration = 0;
       iteration < NGI541_CONCURRENCY_ITERATIONS;
       iteration++)
    {
      if (test_gcm_iteration (
            worker,
            iteration) != 0)
        {
          record_failure (
            worker);

          return NULL;
        }


      if (test_ctr_iteration (
            worker,
            iteration) != 0)
        {
          record_failure (
            worker);

          return NULL;
        }
    }


  return NULL;
}


int
main (void)
{
  ngi541_aead_key_params_t
    aead_params;

  ngi541_cipher_key_params_t
    ctr_params;

  ngi541_aead_key_t *aead_key =
    NULL;

  ngi541_cipher_key_t *ctr_key =
    NULL;

  pthread_t threads[
    NGI541_CONCURRENCY_THREADS];

  ngi541_concurrency_worker_t workers[
    NGI541_CONCURRENCY_THREADS];

  atomic_uint ready_count;
  atomic_bool start;
  atomic_uint failures;

  ngi541_status_t status;

  unsigned int created_threads = 0;


  atomic_init (
    &ready_count,
    0u);

  atomic_init (
    &start,
    false);

  atomic_init (
    &failures,
    0u);


  status =
    ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "ngi541_engine_init failed: status=%d\n",
        (int) status);

      return 1;
    }


  aead_params =
    (ngi541_aead_key_params_t)
    {
      .struct_size =
        sizeof (ngi541_aead_key_params_t),

      .algorithm =
        NGI541_AEAD_AES_GCM,

      .key = g_aead_key,
      .key_len = sizeof (g_aead_key),
    };


  status =
    ngi541_crypto_aead_key_create (
      &aead_params,
      &aead_key);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "AEAD key creation failed: status=%d\n",
        (int) status);

      return 1;
    }


  ctr_params =
    (ngi541_cipher_key_params_t)
    {
      .struct_size =
        sizeof (ngi541_cipher_key_params_t),

      .algorithm =
        NGI541_CIPHER_AES_CTR,

      .key = g_ctr_key,
      .key_len = sizeof (g_ctr_key),
    };


  status =
    ngi541_crypto_cipher_key_create (
      &ctr_params,
      &ctr_key);

  if (status != NGI541_STATUS_OK)
    {
      fprintf (
        stderr,
        "CTR key creation failed: status=%d\n",
        (int) status);

      ngi541_crypto_aead_key_destroy (
        aead_key);

      return 1;
    }


  for (unsigned int i = 0;
       i < NGI541_CONCURRENCY_THREADS;
       i++)
    {
      workers[i] =
        (ngi541_concurrency_worker_t)
        {
          .thread_index = i,

          .aead_key = aead_key,
          .ctr_key = ctr_key,

          .ready_count =
            &ready_count,

          .start =
            &start,

          .failures =
            &failures,
        };


      if (pthread_create (
            &threads[i],
            NULL,
            worker_main,
            &workers[i]) != 0)
        {
          fprintf (
            stderr,
            "pthread_create failed: thread=%u\n",
            i);

          created_threads = i;

          atomic_store_explicit (
            &start,
            true,
            memory_order_release);

          goto join_threads;
        }


      created_threads =
        i + 1;
    }


  while (atomic_load_explicit (
           &ready_count,
           memory_order_acquire) !=
         NGI541_CONCURRENCY_THREADS)
    {
      sched_yield ();
    }


  /*
   * All workers now begin using the exact same immutable prepared
   * key objects concurrently.
   */
  atomic_store_explicit (
    &start,
    true,
    memory_order_release);


join_threads:

  for (unsigned int i = 0;
       i < created_threads;
       i++)
    {
      if (pthread_join (
            threads[i],
            NULL) != 0)
        {
          fprintf (
            stderr,
            "pthread_join failed: thread=%u\n",
            i);

          atomic_fetch_add_explicit (
            &failures,
            1u,
            memory_order_relaxed);
        }
    }


  ngi541_crypto_cipher_key_destroy (
    ctr_key);

  ngi541_crypto_aead_key_destroy (
    aead_key);


  if (created_threads !=
      NGI541_CONCURRENCY_THREADS)
    return 1;


  if (atomic_load_explicit (
        &failures,
        memory_order_relaxed) != 0)
    {
      fprintf (
        stderr,
        "prepared-key concurrency test failed: "
        "failures=%u\n",
        atomic_load_explicit (
          &failures,
          memory_order_relaxed));

      return 1;
    }


  return 0;
}