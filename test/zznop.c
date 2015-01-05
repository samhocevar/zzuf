/*
 *  zznop - almost empty program that does almost nothing
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

#if HAVE_WINDOWS_H
#   include <windows.h>
#endif

int main(void)
{
#if HAVE_WINDOWS_H
    /* Only for debugging purposes */
    AllocConsole();

    fprintf(stderr, "About to call LoadLibraryA()\n");
    LoadLibraryA("whatever");
    fprintf(stderr, "Finished calling LoadLibraryA()\n");

    getchar();
#endif

    return EXIT_SUCCESS;
}

