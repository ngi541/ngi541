/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus
 *
 * Modified for NGI541: reduced to scalar helpers required by the
 * standalone crypto engine and retained low-level support headers.
 */

#ifndef included_ngi541_compat_base_h
#define included_ngi541_compat_base_h

#include <compat/compiler.h>
#include <vppinfra/types.h>

/*
 * These macros must be defined after types.h.
 *
 * types.h uses the compiler attribute spelling:
 *   __attribute__((always_inline))
 *
 * Defining the always_inline macro before parsing types.h would cause
 * macro substitution inside the attribute itself.
 */
#if CLIB_DEBUG > 0
#define always_inline static inline
#define static_always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#define static_always_inline static inline __attribute__ ((__always_inline__))
#endif

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

static_always_inline uword
pow2_mask (uword x)
{
#ifdef __BMI2__
  return _bzhi_u64 (-1ULL, x);
#else
  return ((uword) 1 << x) - (uword) 1;
#endif
}

static_always_inline uword
round_pow2 (uword x, uword pow2)
{
  return (x + pow2 - 1) & ~(pow2 - 1);
}

#define clib_min(x, y)                                                        \
  ({                                                                          \
    __typeof__ (x) _x = (x);                                                  \
    __typeof__ (y) _y = (y);                                                  \
    _x < _y ? _x : _y;                                                        \
  })

#endif /* included_ngi541_compat_base_h */