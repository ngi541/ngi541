/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "adapter.h"

#include "registrations/profile_v1.h"

#include <acvp/acvp.h>
#include <ngi541/engine.h>

int
ngi541_acvp_adapter_build_probe (void)
{
  ACVP_CTX *acvp_ctx = NULL;
  ACVP_RESULT result;
  ngi541_status_t status;

  status = ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    return 1;

  result =
    acvp_create_test_session (
      &acvp_ctx,
      NULL,
      ACVP_LOG_LVL_INFO);

  if (result != ACVP_SUCCESS)
    return 2;

  result =
    ngi541_acvp_register_profile_v1 (
      acvp_ctx);

  if (result != ACVP_SUCCESS)
    {
      acvp_free_test_session (acvp_ctx);
      return 3;
    }

  result =
    acvp_free_test_session (
      acvp_ctx);

  if (result != ACVP_SUCCESS)
    return 4;

  return 0;
}

int
ngi541_acvp_run_offline (
  const char *request_filename,
  const char *response_filename)
{
  ACVP_CTX *acvp_ctx = NULL;
  ACVP_RESULT result;
  ACVP_RESULT free_result;
  ngi541_status_t status;

  if (request_filename == NULL ||
      response_filename == NULL)
    return 1;

  status =
    ngi541_engine_init ();

  if (status != NGI541_STATUS_OK)
    return 2;

  result =
    acvp_create_test_session (
      &acvp_ctx,
      NULL,
      ACVP_LOG_LVL_INFO);

  if (result != ACVP_SUCCESS)
    return 3;

  result =
    ngi541_acvp_register_profile_v1 (
      acvp_ctx);

  if (result != ACVP_SUCCESS)
    {
      acvp_free_test_session (acvp_ctx);
      return 4;
    }

  /*
   * Parse the offline ACVP request, dispatch each test case
   * through the registered NGI541 callbacks, and serialize
   * the response JSON.
   */
  result =
    acvp_run_vectors_from_file_offline (
      acvp_ctx,
      request_filename,
      response_filename);

  free_result =
    acvp_free_test_session (
      acvp_ctx);

  if (result != ACVP_SUCCESS)
    return 5;

  if (free_result != ACVP_SUCCESS)
    return 6;

  return 0;
}