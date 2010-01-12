/*
 *  bug-memory - program exhausting the memory when fuzzed
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
    int i, ch;

    while((ch = getc(stdin)) != EOF)
    {
        char *tmp = malloc(1 + ch * 1024 * 1024);
        for(i = 0; i < 1024; i++)
            tmp[ch * 1024 * i] = i;
    }

    return EXIT_SUCCESS;
}

