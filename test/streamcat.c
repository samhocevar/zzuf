/*
 *  streamcat - cat reimplementation
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline int myrand(void)
{
    static int seed = 1;
    int x, y;
    x = (seed + 0x12345678) << 11;
    y = (seed + 0xfedcba98) >> 21;
    seed = x * 1010101 + y * 343434;
    return seed;
}

int main(int argc, char *argv[])
{
    long int pos;
    unsigned char *data;
    int i, j;
    FILE *stream;

    if(argc != 2)
        return EXIT_FAILURE;

    stream = fopen(argv[1], "r");
    if(!stream)
        return EXIT_FAILURE;

    fseek(stream, 0, SEEK_END);
    pos = ftell(stream);
    if(pos < 0)
        return EXIT_FAILURE;

    /* Read the whole file */
    data = malloc(pos + 16); /* 16 safety bytes */
    fseek(stream, 0, SEEK_SET);
    fread(data, pos, 1, stream);

    /* Read shit here and there */
    for(i = 0; i < 128; i++)
    {
        long int now;
        fseek(stream, myrand() % pos, SEEK_SET);
        for(j = 0; j < 16; j++)
            fread(data + ftell(stream), myrand() % 4096, 1, stream);
        fseek(stream, myrand() % pos, SEEK_SET);
        now = ftell(stream);
        for(j = 0; j < 16; j++)
            data[now + j] = getc(stream);
        now = ftell(stream);
        for(j = 0; j < 16; j++)
            data[now + j] = fgetc(stream);
    }

    fwrite(data, pos, 1, stdout);

    return EXIT_SUCCESS;
}

