/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include "compat/memory.h"

#include <stdint.h>
#include <stdlib.h>


static int
ngi541_is_power_of_two (
  size_t value)
{
  return
    value != 0 &&
    (value & (value - 1)) == 0;
}


void *
ngi541_aligned_alloc (
  size_t size,
  size_t alignment)
{
  void *ptr = NULL;

  if (size == 0 ||
      !ngi541_is_power_of_two (alignment))
    return NULL;

#if defined(_WIN32)

  return _aligned_malloc (
    size,
    alignment);

#else

  /*
   * POSIX requires alignment to be both a power of two and a
   * multiple of sizeof(void *).
   */
  if (alignment < sizeof (void *) ||
      (alignment % sizeof (void *)) != 0)
    return NULL;

  if (posix_memalign (
        &ptr,
        alignment,
        size) != 0)
    return NULL;

  return ptr;

#endif
}


void
ngi541_aligned_free (
  void *ptr)
{
#if defined(_WIN32)

  _aligned_free (ptr);

#else

  free (ptr);

#endif
}