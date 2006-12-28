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

void zzuf_fuzz(int fd, uint8_t *buf, uint64_t len)
{
    uint64_t start, stop;
    struct fuzz *fuzz;
    uint8_t *aligned_buf;
    unsigned long int pos = zfd_getpos(fd);
    unsigned int i, j, todo;

    fuzz = zfd_getfuzz(fd);

    aligned_buf = buf - pos;

    for(i = pos / CHUNKBYTES;
        i < (pos + len + CHUNKBYTES - 1) / CHUNKBYTES;
        i++)
    {
        /* Cache bitmask array */
        if(fuzz->cur != (int)i)
        {
            uint32_t chunkseed = i * MAGIC1;

            memset(fuzz->data, 0, CHUNKBYTES);

            /* Add some random dithering to handle ratio < 1.0/CHUNKBYTES */
            zzuf_srand(_zzuf_seed ^ chunkseed);
            todo = (int)((_zzuf_ratio * (8 * CHUNKBYTES * 1000)
                                                + zzuf_rand(1000)) / 1000.0);
            zzuf_srand(_zzuf_seed ^ chunkseed ^ (todo * MAGIC2));

            while(todo--)
            {
                unsigned int idx = zzuf_rand(CHUNKBYTES);
                uint8_t byte = (1 << zzuf_rand(8));

                fuzz->data[idx] ^= byte;
            }

            fuzz->cur = i;
        }

        /* Apply our bitmask array to the buffer */
        start = (i * CHUNKBYTES > pos) ? i * CHUNKBYTES : pos;

        stop = ((i + 1) * CHUNKBYTES < pos + len)
              ? (i + 1) * CHUNKBYTES : pos + len;

        for(j = start; j < stop; j++)
            aligned_buf[j] ^= fuzz->data[j % CHUNKBYTES];
    }
}

