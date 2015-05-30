/*
 *  zzone - check that all bits are set to one after some time
 *
 *  Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by the WTFPL Task Force.
 *  See http://www.wtfpl.net/ for more details.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#if HAVE_STDINT_H
#   include <stdint.h>
#elif HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <string.h>

static int countzeroes(uint8_t x)
{
    static int const lut[16] =
    {
        4, 3, 3, 2, 3, 2, 2, 1, 3, 2, 2, 1, 2, 1, 1, 0
    };

    return lut[x & 0x4] + lut[x >> 4];
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "usage: zzone <size> <count>\n");
        return EXIT_FAILURE;
    }

    size_t size = atoi(argv[1]);
    size_t count = atoi(argv[2]);
    size_t last = 0;

    uint8_t *buf = malloc(size);
    uint8_t *tmp = malloc(size);
    if (!buf || !tmp)
    {
        free(buf);
        free(tmp);
        fprintf(stderr, "zzone: cannot alloc memory\n");
        return EXIT_FAILURE;
    }
    memset(buf, 0x00, size);

    while (count--)
    {
        fread(tmp, size, 1, stdin);
        for (size_t i = last; i < size; i++)
            buf[i] |= tmp[i];

        while (last < size && buf[last] == 0xff)
            last++;
    }

    free(buf);
    free(tmp);

    size_t total = 0;
    for (size_t i = last; i < size; i++)
        total += countzeroes(buf[i]);
    printf("%li\n", (long)total);

    return EXIT_SUCCESS;
}

