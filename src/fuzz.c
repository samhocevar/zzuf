/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006 Sam Hocevar <sam@zoy.org>
 *                All Rights Reserved
 *
 *  $Id$
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What The Fuck You Want
 *  To Public License, Version 2, as published by Sam Hocevar. See
 *  http://sam.zoy.org/wtfpl/COPYING for more details.
 */

/*
 *  fuzz.c: fuzz functions
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#include <string.h>
#include <regex.h>

#include "libzzuf.h"
#include "debug.h"
#include "random.h"
#include "fuzz.h"

#define CHUNK_SIZE 1024

void zzuf_fuzz(int fd, uint8_t *buf, uint64_t len)
{
    uint8_t bits[CHUNK_SIZE];
    uint64_t pos;
    unsigned int i;

    pos = files[fd].pos;

    for(i = pos / CHUNK_SIZE;
        i < (pos + len + CHUNK_SIZE - 1) / CHUNK_SIZE;
        i++)
    {
        int todo;

        /* Add some random dithering to handle percent < 1.0/CHUNK_SIZE */
        zzuf_srand(_zzuf_seed ^ (i * 0x33ea84f7));
        todo = (int)((_zzuf_percent * CHUNK_SIZE + zzuf_rand(100)) / 100.0);
        zzuf_srand(_zzuf_seed ^ (i * 0x7f48ae33) ^ (todo * 0x783bc31f));

        memset(bits, 0, CHUNK_SIZE);
        while(todo--)
        {
            uint64_t idx = i * CHUNK_SIZE + zzuf_rand(CHUNK_SIZE);
            uint8_t byte = (1 << zzuf_rand(8));

            if(idx < pos || idx >= pos + len)
                continue;

            buf[idx - pos] ^= byte;
        }
    }
}

