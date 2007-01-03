/*
 *  fdcat - cat reimplementation
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

#define _LARGEFILE64_SOURCE /* for lseek64() */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    long int pos;
    unsigned char *data;
    int i, j, fd;

    srand(0);

    if(argc != 2)
        return EXIT_FAILURE;

    fd = open(argv[1], O_RDONLY);
    if(fd < 0)
        return EXIT_FAILURE;

    pos = lseek(fd, 0, SEEK_END);
    if(pos < 0)
        return EXIT_FAILURE;

    /* Read the whole file */
    data = malloc(pos);
    lseek(fd, 0, SEEK_SET);
    read(fd, data, pos);

    /* Read shit here and there */
    for(i = 0; i < 128; i++)
    {
        lseek(fd, rand() % pos, SEEK_SET);
        for(j = 0; j < 16; j++)
            read(fd, data + lseek(fd, 0, SEEK_CUR), rand() % 4096);
#ifdef HAVE_LSEEK64
        lseek64(fd, rand() % pos, SEEK_SET);
        for(j = 0; j < 16; j++)
            read(fd, data + lseek(fd, 0, SEEK_CUR), rand() % 4096);
#endif
    }

    fwrite(data, pos, 1, stdout);

    return EXIT_SUCCESS;
}

