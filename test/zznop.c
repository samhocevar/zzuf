/*
 *  zznop - almost empty program that does almost nothing
 *  Copyright (c) 2009-2010 Sam Hocevar <sam@hocevar.net>
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

#if defined HAVE_WINDOWS_H
#   include <windows.h>
#endif

int main(void)
{
#if defined HAVE_WINDOWS_H
    AllocConsole();

    fprintf(stderr, "About to call LoadLibraryA()\n");
    //LoadLibraryA("whatever");
    fprintf(stderr, "Finished calling LoadLibraryA()\n");

    getchar();
#endif

    return EXIT_SUCCESS;
}

