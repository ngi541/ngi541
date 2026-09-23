/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 *
 * Modified for NGI541: reduced CPU feature detection to the
 * capabilities required by the standalone crypto engine.
 */

#ifndef included_ngi541_compat_cpu_h
#define included_ngi541_compat_cpu_h

#include <stdint.h>

#if defined(__x86_64__)

#include <cpuid.h>

static inline int
ngi541_get_cpuid (uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                  uint32_t *ecx, uint32_t *edx)
{
  if ((uint32_t) __get_cpuid_max (0x80000000u & leaf, 0) < leaf)
    return 0;

  if (leaf == 7)
    __cpuid_count (leaf, 0, *eax, *ebx, *ecx, *edx);
  else
    __cpuid (leaf, *eax, *ebx, *ecx, *edx);

  return 1;
}

static inline int
clib_cpu_supports_x86_aes (void)
{
  uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

  if (!ngi541_get_cpuid (1, &eax, &ebx, &ecx, &edx))
    return 0;

  return (ecx & (1u << 25)) != 0;
}

static inline int
clib_cpu_supports_pclmulqdq (void)
{
  uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

  if (!ngi541_get_cpuid (1, &eax, &ebx, &ecx, &edx))
    return 0;

  return (ecx & (1u << 1)) != 0;
}

static inline int
clib_cpu_supports_avx2 (void)
{
  uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

  if (!ngi541_get_cpuid (7, &eax, &ebx, &ecx, &edx))
    return 0;

  return (ebx & (1u << 5)) != 0;
}

static inline int
clib_cpu_supports_avx512f (void)
{
  uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

  if (!ngi541_get_cpuid (7, &eax, &ebx, &ecx, &edx))
    return 0;

  return (ebx & (1u << 16)) != 0;
}

static inline int
clib_cpu_supports_sha (void)
{
  uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

  if (!ngi541_get_cpuid (7, &eax, &ebx, &ecx, &edx))
    return 0;

  return (ebx & (1u << 29)) != 0;
}

static inline int
clib_cpu_supports_vaes (void)
{
  uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

  if (!ngi541_get_cpuid (7, &eax, &ebx, &ecx, &edx))
    return 0;

  return (ecx & (1u << 9)) != 0;
}

static inline int
clib_cpu_supports_vpclmulqdq (void)
{
  uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

  if (!ngi541_get_cpuid (7, &eax, &ebx, &ecx, &edx))
    return 0;

  return (ecx & (1u << 10)) != 0;
}

#else /* !__x86_64__ */

static inline int
clib_cpu_supports_x86_aes (void)
{
  return 0;
}

static inline int
clib_cpu_supports_pclmulqdq (void)
{
  return 0;
}

static inline int
clib_cpu_supports_avx2 (void)
{
  return 0;
}

static inline int
clib_cpu_supports_avx512f (void)
{
  return 0;
}

static inline int
clib_cpu_supports_sha (void)
{
  return 0;
}

static inline int
clib_cpu_supports_vaes (void)
{
  return 0;
}

static inline int
clib_cpu_supports_vpclmulqdq (void)
{
  return 0;
}

#endif /* __x86_64__ */


#if defined(__aarch64__) && defined(__linux__)

#include <sys/auxv.h>

static inline int
clib_cpu_supports_aarch64_aes (void)
{
  unsigned long hwcap = getauxval (AT_HWCAP);

  return (hwcap & (1UL << 3)) != 0;
}

static inline int
clib_cpu_supports_sha2 (void)
{
  unsigned long hwcap = getauxval (AT_HWCAP);

  return (hwcap & (1UL << 6)) != 0;
}

#else /* !(__aarch64__ && __linux__) */

static inline int
clib_cpu_supports_aarch64_aes (void)
{
  return 0;
}

static inline int
clib_cpu_supports_sha2 (void)
{
  return 0;
}

#endif /* __aarch64__ && __linux__ */


static inline int
clib_cpu_supports_aes (void)
{
#if defined(__x86_64__)
  return clib_cpu_supports_x86_aes ();
#elif defined(__aarch64__) && defined(__linux__)
  return clib_cpu_supports_aarch64_aes ();
#else
  return 0;
#endif
}

#endif /* included_ngi541_compat_cpu_h */