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

#define MAGIC1 0x33ea84f7
#define MAGIC2 0x783bc31f
/* We arbitrarily split files into 1024-byte chunks. Each chunk has an
 * associated seed that can be computed from the zzuf seed, the chunk
 * index and the fuzziness density. This allows us to predictably fuzz
 * any part of the file without reading the whole file. */
#define CHUNKSIZE 1024

void zzuf_fuzz(int fd, uint8_t *buf, uint64_t len)
{
    uint64_t start, stop;
    unsigned int i, todo;

    start = files[fd].pos;
    stop = start + len;

    for(i = start / CHUNKSIZE; i < (stop + CHUNKSIZE - 1) / CHUNKSIZE; i++)
    {
        uint32_t chunkseed = i * MAGIC1;

        /* Add some random dithering to handle ratio < 1.0/CHUNKSIZE */
        zzuf_srand(_zzuf_seed ^ chunkseed);
        todo = (int)((_zzuf_ratio * (CHUNKSIZE * 1000) + zzuf_rand(1000))
                     / 1000.0);
        zzuf_srand(_zzuf_seed ^ chunkseed ^ (todo * MAGIC2));

        while(todo--)
        {
            uint64_t idx = i * CHUNKSIZE + zzuf_rand(CHUNKSIZE);
            uint8_t byte = (1 << zzuf_rand(8));

            if(idx < start || idx >= stop)
                continue;

            buf[idx - start] ^= byte;
        }
    }
}

