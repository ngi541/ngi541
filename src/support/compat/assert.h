/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus
 *
 * Modified for NGI541: reduced to standalone assertion primitives
 * required by the crypto engine.
 */

#ifndef included_ngi541_compat_assert_h
#define included_ngi541_compat_assert_h

#include <stdlib.h>
#include <compat/compiler.h>

#ifndef CLIB_ASSERT_ENABLE
#define CLIB_ASSERT_ENABLE (CLIB_DEBUG > 0)
#endif

#define ASSERT(truth)                    \
  do                                     \
    {                                    \
      if (CLIB_ASSERT_ENABLE && !(truth)) \
        abort ();                        \
    }                                    \
  while (0)

#define STATIC_ASSERT(truth, ...) \
  _Static_assert (truth, __VA_ARGS__)

#define STATIC_ASSERT_SIZEOF(d, s) \
  STATIC_ASSERT (sizeof (d) == (s), \
                 "Size of " #d " must be " #s " bytes")

#endif /* included_ngi541_compat_assert_h */