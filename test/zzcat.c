/*
 *  zzcat - various cat reimplementations for testing purposes
 *  Copyright (c) 2006-2009 Sam Hocevar <sam@hocevar.net>
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

/* Needed for lseek64() */
#define _LARGEFILE64_SOURCE
/* Needed for O_RDONLY on HP-UX */
#define _INCLUDE_POSIX_SOURCE

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if defined HAVE_UNISTD_H
#   include <unistd.h>
#endif
#if defined HAVE_SYS_MMAN_H
#   include <sys/mman.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int zzcat_read(char const *, unsigned char *, int64_t);
static int zzcat_fread(char const *, unsigned char *, int64_t);
static int zzcat_getc(char const *, unsigned char *, int64_t, int);
static int zzcat_fgetc(char const *, unsigned char *, int64_t);
#if defined HAVE_GETLINE
static int zzcat_getdelim_getc(char const *, unsigned char *, int64_t, int);
#endif
static int zzcat_fread_getc(char const *, unsigned char *, int64_t, int);
static int zzcat_random_socket(char const *, unsigned char *, int64_t);
static int zzcat_random_stream(char const *, unsigned char *, int64_t);
#if defined HAVE_MMAP
static int zzcat_random_mmap(char const *, unsigned char *, int64_t);
#endif

static inline unsigned int myrand(void)
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
    int64_t len;
    unsigned char *data;
    char const *name;
    int ret, cmd, fd;

    if(argc != 3)
        return EXIT_FAILURE;

    name = argv[2];

    /* Read the whole file */
    fd = open(name, O_RDONLY);
    if(fd < 0)
        return EXIT_FAILURE;
    len = lseek(fd, 0, SEEK_END);
    if(len < 0)
        return EXIT_FAILURE;
    data = malloc(len + 16); /* 16 safety bytes */
    lseek(fd, 0, SEEK_SET);
    read(fd, data, len);
    close(fd);

    /* Read shit here and there, using different methods */
    switch((cmd = atoi(argv[1])))
    {
        case 0: ret = zzcat_read(name, data, len); break;
        case 20: ret = zzcat_fread(name, data, len); break;
        case 21: ret = zzcat_getc(name, data, len, 0); break;
#if defined HAVE_GETC_UNLOCKED
        case 22: ret = zzcat_getc(name, data, len, 1); break;
#endif
        case 23: ret = zzcat_fgetc(name, data, len); break;
#if defined HAVE_GETLINE
        case 24: ret = zzcat_getdelim_getc(name, data, len, 0); break;
#   if defined HAVE_GETC_UNLOCKED
        case 25: ret = zzcat_getdelim_getc(name, data, len, 1); break;
#   endif
#endif
        case 30: ret = zzcat_fread_getc(name, data, len, 0); break;
        case 31: ret = zzcat_fread_getc(name, data, len, 1); break;
        case 40: ret = zzcat_random_socket(name, data, len); break;
        case 41: ret = zzcat_random_stream(name, data, len); break;
#if defined HAVE_MMAP
        case 42: ret = zzcat_random_mmap(name, data, len); break;
#endif
        default: ret = EXIT_SUCCESS;
    }

    /* Write what we have read */
    fwrite(data, len, 1, stdout);
    free(data);

    return ret;
}

/* Only read(1) calls */
static int zzcat_read(char const *name, unsigned char *data, int64_t len)
{
    int i, fd = open(name, O_RDONLY);
    if(fd < 0)
        return EXIT_FAILURE;
    for(i = 0; i < len; i++)
        read(fd, data + i, 1);
    close(fd);
    return EXIT_SUCCESS;
}

/* Only fread() calls */
static int zzcat_fread(char const *name, unsigned char *data, int64_t len)
{
    FILE *stream = fopen(name, "r");
    int i;
    if(!stream)
        return EXIT_FAILURE;
    for(i = 0; i < len; i++)
        fread(data + i, 1, 1, stream);
    fclose(stream);
    return EXIT_SUCCESS;
}

/* Only getc() or getc_unlocked() calls */
static int zzcat_getc(char const *name, unsigned char *data, int64_t len,
                      int unlocked)
{
    FILE *stream = fopen(name, "r");
    int i;
    if(!stream)
        return EXIT_FAILURE;
    for(i = 0; i < len; i++)
#if defined HAVE_GETC_UNLOCKED
        data[i] = unlocked ? getc_unlocked(stream)
                           : getc(stream);
#else
        data[i] = getc(stream);
#endif
    fclose(stream);
    return EXIT_SUCCESS;
}

/* Only fgetc() calls */
static int zzcat_fgetc(char const *name, unsigned char *data, int64_t len)
{
    FILE *stream = fopen(name, "r");
    int i;
    if(!stream)
        return EXIT_FAILURE;
    for(i = 0; i < len; i++)
        data[i] = fgetc(stream);
    fclose(stream);
    return EXIT_SUCCESS;
}

#if defined HAVE_GETLINE
/* getdelim() and getc() calls */
static int zzcat_getdelim_getc(char const *name, unsigned char *data,
                               int64_t len, int unlocked)
{
    FILE *stream = fopen(name, "r");
    int i = 0, j;
    char c;
    if(!stream)
        return EXIT_FAILURE;
    (void)len;
#if defined HAVE_GETC_UNLOCKED
    while ((c = (unlocked ? getc_unlocked(stream) : getc(stream))) != EOF)
#else
    while ((c = getc(stream)) != EOF)
#endif
    {
        char *line;
        ssize_t ret;
        size_t n;

        ungetc(c, stream);
        line = NULL;
        ret = getline(&line, &n, stream);
        for (j = 0; j < ret; i++, j++)
            data[i] = line[j];
    }
    fclose(stream);
    return EXIT_SUCCESS;
}
#endif

/* One fread(), then only getc() or fgetc() calls */
static int zzcat_fread_getc(char const *name, unsigned char *data,
                            int64_t len, int use_fgetc)
{
    FILE *stream = fopen(name, "r");
    int i;
    if(!stream)
        return EXIT_FAILURE;
    fread(data, 1, 10, stream);
    for(i = 10; i < len; i++)
        data[i] = use_fgetc ? fgetc(stream) : getc(stream);
    fclose(stream);
    return EXIT_SUCCESS;
}

/* Socket seeks and reads */
static int zzcat_random_socket(char const *name, unsigned char *data,
                               int64_t len)
{
    int i, j, fd = open(name, O_RDONLY);
    if(fd < 0)
        return EXIT_FAILURE;
    for(i = 0; i < 128; i++)
    {
        lseek(fd, myrand() % len, SEEK_SET);
        for(j = 0; j < 4; j++)
            read(fd, data + lseek(fd, 0, SEEK_CUR), myrand() % 4096);
#ifdef HAVE_LSEEK64
        lseek64(fd, myrand() % len, SEEK_SET);
        for(j = 0; j < 4; j++)
            read(fd, data + lseek(fd, 0, SEEK_CUR), myrand() % 4096);
#endif
    }
    close(fd);
    return EXIT_SUCCESS;
}

/* Standard stream seeks and reads */
static int zzcat_random_stream(char const *name, unsigned char *data,
                               int64_t len)
{
    FILE *stream = fopen(name, "r");
    int i, j;
    if(!stream)
        return EXIT_FAILURE;
    for(i = 0; i < 128; i++)
    {
        long int now;
        fseek(stream, myrand() % len, SEEK_SET);
        for(j = 0; j < 4; j++)
            fread(data + ftell(stream),
                  myrand() % (len - ftell(stream)), 1, stream);
        fseek(stream, myrand() % len, SEEK_SET);
        now = ftell(stream);
        for(j = 0; j < 16; j++)
            data[now + j] = getc(stream);
        now = ftell(stream);
        for(j = 0; j < 16; j++)
            data[now + j] = fgetc(stream);
    }
    fclose(stream);
    return EXIT_SUCCESS;
}

#ifdef HAVE_MMAP
/* mmap() followed by random memory reads */
static int zzcat_random_mmap(char const *name, unsigned char *data,
                               int64_t len)
{
    int i, j, fd = open(name, O_RDONLY);
    if(fd < 0)
        return EXIT_FAILURE;
    for(i = 0; i < 128; i++)
    {
        char *map;
        int moff, mlen, pgsz = len + 1;
#ifdef HAVE_GETPAGESIZE
        pgsz = getpagesize();
#endif
        moff = len < pgsz ? 0 : (myrand() % (len / pgsz)) * pgsz;
        mlen = 1 + (myrand() % (len - moff));
        map = mmap(NULL, mlen, PROT_READ, MAP_PRIVATE, fd, moff);
        if(map == MAP_FAILED)
            return EXIT_FAILURE;
        for(j = 0; j < 128; j++)
        {
            int x = myrand() % mlen;
            data[moff + x] = map[x];
        }
        munmap(map, mlen);
    }
    close(fd);
    return EXIT_SUCCESS;
}
#endif

