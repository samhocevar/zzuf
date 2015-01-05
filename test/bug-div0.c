/*
 *  bug-div0 - program dividing by zero when fuzzed
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
#include <signal.h>

volatile int buf[1];

int main(void)
{
    int ch;

    while ((ch = getc(stdin)) != EOF)
    {
        buf[0] = 1 / !ch;
        if (ch)
            raise(SIGFPE); /* Needed on OS X... sigh. */
    }

    return EXIT_SUCCESS;
}

