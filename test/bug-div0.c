/*
 *  bug-div0 - program dividing by zero when fuzzed
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
#include <signal.h>

int buf[1];

int main(void)
{
    int ch;

    while((ch = getc(stdin)) != EOF)
    {
        buf[0] = 1 / !ch;
        if(ch) raise(SIGFPE); /* Needed on OS X... sigh. */
    }

    return EXIT_SUCCESS;
}

