/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Ivan Ivanets
 */

#include <stdlib.h>
#include <unistd.h>

#include <vppinfra/os.h>

void
os_panic (void)
{
  abort ();
}

void
os_exit (int code)
{
  exit (code);
}

void
os_puts (u8 *string, uword length, uword is_error)
{
  int fd = is_error ? STDERR_FILENO : STDOUT_FILENO;

  while (length > 0)
    {
      ssize_t rv = write (fd, string, length);

      if (rv <= 0)
        break;

      string += rv;
      length -= (uword) rv;
    }
}