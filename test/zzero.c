/*
 *  zzero - check how many bits zzuf changes in a stream of zeroes
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
#include <stdint.h>

static inline int countones(uint8_t x)
{
    static int const lut[16] =
    {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4
    };

    return lut[x & 0xf] + lut[x >> 4];
}

int main(void)
{
    int total = 0, ch;

    while ((ch = getc(stdin)) != EOF)
        total += countones((uint8_t)ch);

    printf("%i\n", total);

    return EXIT_SUCCESS;
}

