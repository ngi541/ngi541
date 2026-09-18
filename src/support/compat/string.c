/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <stdio.h>

#include <vppinfra/string.h>

void
clib_c11_violation (const char *s)
{
  fprintf (stderr, "NGI541: C11 constraint violation: %s\n",
           s != NULL ? s : "(null)");
}
