/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006-2010 Sam Hocevar <sam@hocevar.net>
 *                All Rights Reserved
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
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "random.h"
#include "fuzz.h"
#include "fd.h"
#include "ranges.h"
#if defined LIBZZUF
#   include "debug.h"
#endif

#define MAGIC1 0x33ea84f7
#define MAGIC2 0x783bc31f
#define MAGIC3 0x9b5da2fb

/* Fuzzing mode */
static enum fuzzing
{
    FUZZING_XOR = 0, FUZZING_SET, FUZZING_UNSET
}
fuzzing;

/* Per-offset byte protection */
static int *ranges = NULL;
static int static_ranges[512];

/* Per-value byte protection */
static unsigned char protect[256];
static unsigned char refuse[256];

/* Local prototypes */
static void readchars(unsigned char *, char const *);

extern void _zz_fuzzing(char const *mode)
{
    if(!strcmp(mode, "xor"))
        fuzzing = FUZZING_XOR;
    else if(!strcmp(mode, "set"))
        fuzzing = FUZZING_SET;
    else if(!strcmp(mode, "unset"))
        fuzzing = FUZZING_UNSET;
}

void _zz_bytes(char const *list)
{
    /* TODO: free(ranges) if ranges != static_ranges */
    ranges = _zz_allocrange(list, static_ranges);
}

void _zz_protect(char const *list)
{
    readchars(protect, list);
}

void _zz_refuse(char const *list)
{
    readchars(refuse, list);
}

void _zz_fuzz(int fd, volatile uint8_t *buf, int64_t len)
{
    int64_t start, stop;
    int64_t pos = _zz_getpos(fd);
    struct fuzz *fuzz;
    volatile uint8_t *aligned_buf;
    int64_t i, j;
    int todo;

#if defined LIBZZUF
    debug2("... fuzz(%i, @%lli, %lli)", fd, (long long int)pos,
           (long long int)len);
#endif

    aligned_buf = buf - pos;
    fuzz = _zz_getfuzz(fd);

    for(i = pos / CHUNKBYTES;
        i < (pos + len + CHUNKBYTES - 1) / CHUNKBYTES;
        i++)
    {
        /* Cache bitmask array */
        if(fuzz->cur != (int)i)
        {
            uint32_t chunkseed;

            chunkseed = (uint32_t)i;
            chunkseed ^= MAGIC2;
            chunkseed += (uint32_t)(fuzz->ratio * MAGIC1);
            chunkseed ^= fuzz->seed;
            chunkseed += (uint32_t)(i * MAGIC3);

            _zz_srand(chunkseed);

            memset(fuzz->data, 0, CHUNKBYTES);

            /* Add some random dithering to handle ratio < 1.0/CHUNKBYTES */
            todo = (int)((fuzz->ratio * (8 * CHUNKBYTES) * 1000000.0
                                + _zz_rand(1000000)) / 1000000.0);
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
            uint8_t byte, fuzzbyte;

            if(ranges && !_zz_isinrange(j, ranges))
                continue; /* Not in one of the ranges, skip byte */

            byte = aligned_buf[j];

            if(protect[byte])
                continue;

            fuzzbyte = fuzz->data[j % CHUNKBYTES];

            if(!fuzzbyte)
                continue;

            switch(fuzzing)
            {
            case FUZZING_XOR:
                byte ^= fuzzbyte;
                break;
            case FUZZING_SET:
                byte |= fuzzbyte;
                break;
            case FUZZING_UNSET:
                byte &= ~fuzzbyte;
                break;
            }

            if(refuse[byte])
                continue;

            aligned_buf[j] = byte;
        }
    }

    /* Handle ungetc() */
    if(fuzz->uflag)
    {
        fuzz->uflag = 0;
        if(fuzz->upos == pos)
            buf[0] = fuzz->uchar;
    }
}

static void readchars(unsigned char *table, char const *list)
{
    static char const hex[] = "0123456789abcdef0123456789ABCDEF";
    char const *tmp;
    int a, b;

    memset(table, 0, 256 * sizeof(unsigned char));

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
                new = ((int)(strchr(hex, tmp[1]) - hex) & 0xf) << 4;
                new |= (int)(strchr(hex, tmp[2]) - hex) & 0xf;
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

