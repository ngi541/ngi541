/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <stdio.h>

#include <vppinfra/vector.h>


#define NGI541_VECTOR_BYTES 16
#define NGI541_GUARD_BYTES  8
#define NGI541_CANARY       0xa5


static int
run_case (uword n)
{
  u8 source[NGI541_VECTOR_BYTES];
  u8 arena[
    NGI541_GUARD_BYTES +
    NGI541_VECTOR_BYTES +
    NGI541_GUARD_BYTES
  ];

  u8 *data = arena + NGI541_GUARD_BYTES;

  for (uword i = 0; i < NGI541_VECTOR_BYTES; i++)
    source[i] = (u8) (0x10 + i);

  for (uword i = 0; i < sizeof (arena); i++)
    arena[i] = NGI541_CANARY;

  u8x16 value = u8x16_load_unaligned (source);

  u8x16_store_partial (value, data, n);

  for (uword i = 0; i < NGI541_GUARD_BYTES; i++)
    {
      if (arena[i] != NGI541_CANARY)
        {
          fprintf (
            stderr,
            "prefix guard modified: n=%lu offset=%lu\n",
            (unsigned long) n,
            (unsigned long) i
          );

          return 1;
        }
    }

  for (uword i = 0; i < n; i++)
    {
      if (data[i] != source[i])
        {
          fprintf (
            stderr,
            "stored byte mismatch: n=%lu offset=%lu "
            "expected=0x%02x actual=0x%02x\n",
            (unsigned long) n,
            (unsigned long) i,
            source[i],
            data[i]
          );

          return 1;
        }
    }

  for (
    uword i = n;
    i < NGI541_VECTOR_BYTES + NGI541_GUARD_BYTES;
    i++
  )
    {
      if (data[i] != NGI541_CANARY)
        {
          fprintf (
            stderr,
            "suffix byte modified: n=%lu offset=%lu "
            "actual=0x%02x\n",
            (unsigned long) n,
            (unsigned long) i,
            data[i]
          );

          return 1;
        }
    }

  return 0;
}


int
main (void)
{
  for (uword n = 0; n <= NGI541_VECTOR_BYTES; n++)
    {
      if (run_case (n) != 0)
        return 1;
    }

  printf (
    "u8x16_store_partial regression passed "
    "for lengths 0..16\n"
  );

  return 0;
}