/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus
 *
 * Modified for NGI541: reduced to compiler, build-mode, and
 * low-level utility definitions required by the standalone engine.
 */

#ifndef included_ngi541_compat_compiler_h
#define included_ngi541_compat_compiler_h

#include <stddef.h>
#include <stdalign.h>

/*
 * Preserve the standalone/platform semantics used by the imported
 * low-level support headers.
 */
#if !defined(CLIB_STANDALONE) && !defined(CLIB_LINUX_KERNEL)
#define CLIB_UNIX
#endif

#ifdef __linux__
#define CLIB_LINUX 1
#else
#define CLIB_LINUX 0
#endif

#ifndef CLIB_DEBUG
#define CLIB_DEBUG 0
#endif

#define BITS(x) (8 * sizeof (x))
#define ARRAY_LEN(x) (sizeof (x) / sizeof ((x)[0]))

#define CLIB_PACKED(x) x __attribute__ ((packed))

#define __clib_unused __attribute__ ((unused))
#define __clib_packed __attribute__ ((packed))
#define __clib_constructor __attribute__ ((constructor))
#define __clib_aligned(x) __attribute__ ((aligned (x)))
#define __clib_export __attribute__ ((visibility ("default")))

#define PREDICT_FALSE(x) __builtin_expect ((x), 0)
#define PREDICT_TRUE(x) __builtin_expect ((x), 1)

#define COMPILE_TIME_CONST(x) __builtin_constant_p (x)

#define CLIB_ASSUME(x)                                                        \
  do                                                                          \
    {                                                                         \
      if (!(x))                                                               \
        __builtin_unreachable ();                                             \
    }                                                                         \
  while (0)

#endif /* included_ngi541_compat_compiler_h */