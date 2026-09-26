/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "registrations/profile_v1.h"

#include <acvp/acvp.h>

#include <stdio.h>
#include <stdlib.h>


int
main (void)
{
  ACVP_CTX *acvp_ctx = NULL;
  ACVP_RESULT result;
  ACVP_RESULT free_result;
  char *registration;


  /*
   * This probe must never contact an ACVP server.
   *
   * Its purpose is only to verify that the network-enabled
   * libacvp build:
   *
   *   - can be linked into NGI541;
   *   - can create an ACVP context;
   *   - can register the NGI541 capability profile;
   *   - can serialize that profile.
   *
   * Do not call acvp_run() here. acvp_run() begins the live
   * ACVTS login/session workflow.
   */
  result =
    acvp_create_test_session (
      &acvp_ctx,
      NULL,
      ACVP_LOG_LVL_INFO);

  if (result != ACVP_SUCCESS)
    {
      fprintf (
        stderr,
        "online libacvp context creation failed: %s\n",
        acvp_lookup_error_string (result));

      return 1;
    }


  result =
    ngi541_acvp_register_profile_v1 (
      acvp_ctx);

  if (result != ACVP_SUCCESS)
    {
      fprintf (
        stderr,
        "online NGI541 ACVP registration failed: %s\n",
        acvp_lookup_error_string (result));

      acvp_free_test_session (
        acvp_ctx);

      return 2;
    }


  registration =
    acvp_get_current_registration (
      acvp_ctx,
      NULL);

  if (registration == NULL)
    {
      fprintf (
        stderr,
        "online ACVP registration serialization failed\n");

      acvp_free_test_session (
        acvp_ctx);

      return 3;
    }


  free (registration);


  free_result =
    acvp_free_test_session (
      acvp_ctx);

  if (free_result != ACVP_SUCCESS)
    {
      fprintf (
        stderr,
        "online libacvp context cleanup failed: %s\n",
        acvp_lookup_error_string (free_result));

      return 4;
    }


  return 0;
}