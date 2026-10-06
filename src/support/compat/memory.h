/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#ifndef NGI541_SUPPORT_COMPAT_MEMORY_H
#define NGI541_SUPPORT_COMPAT_MEMORY_H

#include <stddef.h>


/*
 * Allocate size bytes aligned to alignment.
 *
 * alignment must be a non-zero power of two and must satisfy the
 * requirements of the underlying platform allocator.
 *
 * Returns NULL on allocation failure or invalid parameters.
 */
void *
ngi541_aligned_alloc (
  size_t size,
  size_t alignment);


/*
 * Release memory returned by ngi541_aligned_alloc().
 *
 * Passing NULL is allowed.
 */
void
ngi541_aligned_free (
  void *ptr);


#endif /* NGI541_SUPPORT_COMPAT_MEMORY_H */