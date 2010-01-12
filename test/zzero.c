/*
 *  zzero - check how many bits zzuf changes in a stream of zeroes
 *  Copyright (c) 2008 Sam Hocevar <sam@hocevar.net>
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

int main(void)
{
    static const int lut[16] =
    {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4
    };

    int ones = 0, ch;

    while((ch = getc(stdin)) != EOF)
        ones += lut[ch & 0xf] + lut[(ch >> 4) & 0xf];

    printf("%i\n", ones);

    return EXIT_SUCCESS;
}

