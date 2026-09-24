/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "adapter.h"

#include <acvp/acvp.h>
#include <ngi541/engine.h>

int
ngi541_acvp_adapter_build_probe (void)
{
  ACVP_CTX *acvp_ctx = NULL;
  ACVP_RESULT acvp_status;
  ngi541_status_t ngi541_status;

  /*
   * Verify that the validation executable is linked to and can
   * initialize the public NGI541 execution interface.
   */
  ngi541_status = ngi541_engine_init ();

  if (ngi541_status != NGI541_STATUS_OK)
    return 1;

  /*
   * Verify real linkage against libacvp rather than only compiling
   * against its public headers.
   *
   * No ACVP algorithm capability or network session is configured
   * at this stage.
   */
  acvp_status = acvp_create_test_session (
    &acvp_ctx,
    NULL,
    ACVP_LOG_LVL_INFO);

  if (acvp_status != ACVP_SUCCESS)
    return 2;

  acvp_status = acvp_free_test_session (acvp_ctx);

  if (acvp_status != ACVP_SUCCESS)
    return 3;

  return 0;
}