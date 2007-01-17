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

#include "libzzuf.h"
#include "debug.h"
#include "random.h"
#include "fuzz.h"
#include "fd.h"

#define MAGIC1 0x33ea84f7
#define MAGIC2 0x783bc31f

/* Fuzzing variables */
static int protect[256];
static int refuse[256];

/* Local prototypes */
static void readchars(int *, char const *);

void _zz_protect(char const *list)
{
    readchars(protect, list);
}

void _zz_refuse(char const *list)
{
    readchars(refuse, list);
}

void _zz_fuzz(int fd, volatile uint8_t *buf, uint64_t len)
{
    uint64_t start, stop;
    struct fuzz *fuzz;
    volatile uint8_t *aligned_buf;
    unsigned long int pos = _zz_getpos(fd);
    unsigned int i, j, todo;

#if 0
    debug("fuzz(%i, %lli@%li)", fd, (unsigned long long int)len,
          (unsigned long int)pos);
#endif

    fuzz = _zz_getfuzz(fd);
    aligned_buf = buf - pos;

    for(i = pos / CHUNKBYTES;
        i < (pos + len + CHUNKBYTES - 1) / CHUNKBYTES;
        i++)
    {
        /* Cache bitmask array */
        if(fuzz->cur != (int)i)
        {
            uint32_t chunkseed = (i + (int)(fuzz->ratio * MAGIC1)) ^ MAGIC2;
            _zz_srand(fuzz->seed ^ chunkseed);

            memset(fuzz->data, 0, CHUNKBYTES);

            /* Add some random dithering to handle ratio < 1.0/CHUNKBYTES */
            todo = (int)((fuzz->ratio * (8 * CHUNKBYTES * 1000)
                                             + _zz_rand(1000)) / 1000.0);
            while(todo--)
            {
                unsigned int idx = _zz_rand(CHUNKBYTES);
                uint8_t bit = (1 << _zz_rand(8));

                fuzz->data[idx] ^= bit;
            }

            fuzz->cur = i;
        }

        /* Apply our bitmask array to the buffer */
        start = (i * CHUNKBYTES > pos) ? i * CHUNKBYTES : pos;

        stop = ((i + 1) * CHUNKBYTES < pos + len)
              ? (i + 1) * CHUNKBYTES : pos + len;

        for(j = start; j < stop; j++)
        {
            uint8_t byte = aligned_buf[j];

            if(protect[byte])
                continue;

            byte ^= fuzz->data[j % CHUNKBYTES];

            if(refuse[byte])
                continue;

            aligned_buf[j] = byte;
        }
    }
}

static void readchars(int *table, char const *list)
{
    static char const hex[] = "0123456789abcdef0123456789ABCDEF";
    char const *tmp;
    int a, b;

    memset(table, 0, 256 * sizeof(int));

    for(tmp = list, a = b = -1; *tmp; tmp++)
    {
        int new;

        if(*tmp == '\\' && tmp[1] == '\0')
            new = '\\';
        else if(*tmp == '\\')
        {
            tmp++;
            if(*tmp == 'n')
                new = '\n';
            else if(*tmp == 'r')
                new = '\r';
            else if(*tmp == 't')
                new = '\t';
            else if(tmp[0] >= '0' && tmp[0] <= '7' && tmp[1] >= '0'
                     && tmp[1] <= '7' && tmp[2] >= '0' && tmp[2] <= '7')
            {
                new = tmp[2] - '0';
                new |= (int)(tmp[1] - '0') << 3;
                new |= (int)(tmp[0] - '0') << 6;
                tmp += 2;
            }
            else if((*tmp == 'x' || *tmp == 'X')
                     && tmp[1] && strchr(hex, tmp[1])
                     && tmp[2] && strchr(hex, tmp[2]))
            {
                new = ((strchr(hex, tmp[1]) - hex) & 0xf) << 4;
                new |= (strchr(hex, tmp[2]) - hex) & 0xf;
                tmp += 2;
            }
            else
                new = (unsigned char)*tmp; /* XXX: OK for \\, but what else? */
        }
        else
            new = (unsigned char)*tmp;

        if(a != -1 && b == '-' && a <= new)
        {
            while(a <= new)
                table[a++] = 1;
            a = b = -1;
        }
        else
        {
            if(a != -1)
                table[a] = 1;
            a = b;
            b = new;
        }
    }

    if(a != -1)
        table[a] = 1;
    if(b != -1)
        table[b] = 1;
}

