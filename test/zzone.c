/*
 *  zzone - check that all bits are set to one after some time
 *  Copyright (c) 2010 Sam Hocevar <sam@hocevar.net>
 *                All Rights Reserved
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What The Fuck You Want
 *  To Public License, Version 2, as published by Sam Hocevar. See
 *  http://sam.zoy.org/wtfpl/COPYING for more details.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <string.h>

int zero[16] =
{
    4, 3, 3, 2, 3, 2, 2, 1, 3, 2, 2, 1, 2, 1, 1, 0
};

int main(int argc, char *argv[])
{
    uint8_t *buf, *tmp;
    size_t i, last, size, count;

    if (argc != 3)
    {
        fprintf(stderr, "usage: zzone <size> <count>\n");
        return EXIT_FAILURE;
    }

    size = atoi(argv[1]);
    count = atoi(argv[2]);
    last = 0;

    buf = malloc(size);
    tmp = malloc(size);
    if (!buf || !tmp)
    {
        fprintf(stderr, "zzone: cannot alloc memory\n");
        return EXIT_FAILURE;
    }
    memset(buf, 0x00, size);

    while (count--)
    {
        fread(tmp, size, 1, stdin);
        for (i = last; i < size; i++)
        {
            buf[i] |= tmp[i];
        }

        while (last < size && buf[last] == 0xff)
            last++;
    }

    free(buf);
    free(tmp);

    if (last != size)
    {
        size_t zeros = 0;
        for (i = last; i < size; i++)
        {
            zeros += zero[buf[i] & 0xf];
            zeros += zero[buf[i] >> 4];
        }
        printf("%li\n", (long)zeros);
    }
    else
    {
        puts("0");
    }

    return EXIT_SUCCESS;
}

