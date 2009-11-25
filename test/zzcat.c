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

static int zzcat_read(char const *, unsigned char *, int64_t, int64_t);
static int zzcat_fread(char const *, unsigned char *, int64_t, int64_t);
static int zzcat_fread_fseek(char const *, unsigned char *, int64_t, int64_t);
static int zzcat_fseek_fread(char const *, unsigned char *, int64_t, int64_t);
#if defined HAVE_GETLINE
static int zzcat_getline_getc(char const *, unsigned char *, int64_t, int);
#endif
static int zzcat_fseek_getc(char const *, unsigned char *,
                            int64_t, int64_t, int);
static int zzcat_fread_getc(char const *, unsigned char *, int64_t,
                            int64_t, int);
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

static inline int mygetc(FILE *stream, int getc_method)
{
    switch (getc_method)
    {
#if defined HAVE_GETC_UNLOCKED
        case 3: return fgetc_unlocked(stream);
        case 2: return getc_unlocked(stream);
#endif
        case 1: return fgetc(stream);
        default: return getc(stream);
    }
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
        /* Simple socket calls */
        case 100: ret = zzcat_read(name, data, len, 1); break;
        case 101: ret = zzcat_read(name, data, len, 3); break;
        case 102: ret = zzcat_read(name, data, len, len); break;
        /* Simple stream calls */
        case 200: ret = zzcat_fread(name, data, len, 1); break;
        case 201: ret = zzcat_fread(name, data, len, 2); break;
        case 202: ret = zzcat_fread(name, data, len, len); break;
        case 203: ret = zzcat_fseek_getc(name, data, len, 0, 0); break;
        case 204: ret = zzcat_fseek_getc(name, data, len, 0, 1); break;
        case 205: ret = zzcat_fseek_getc(name, data, len, 2, 0); break;
        case 206: ret = zzcat_fseek_getc(name, data, len, 2, 1); break;
        case 207: ret = zzcat_fseek_getc(name, data, len, len / 2, 0); break;
        case 208: ret = zzcat_fseek_getc(name, data, len, len / 2, 1); break;
        case 209: ret = zzcat_fread_getc(name, data, len, 2, 0); break;
        case 210: ret = zzcat_fread_getc(name, data, len, 2, 1); break;
        case 211: ret = zzcat_fread_getc(name, data, len, len / 2, 0); break;
        case 212: ret = zzcat_fread_getc(name, data, len, len / 2, 1); break;
#if defined HAVE_GETLINE
        case 213: ret = zzcat_getline_getc(name, data, len, 0); break;
        case 214: ret = zzcat_getline_getc(name, data, len, 1); break;
#endif
        /* Simple unlocked stream calls */
#if defined HAVE_GETC_UNLOCKED
        case 300: ret = zzcat_fseek_getc(name, data, len, 0, 2); break;
        case 301: ret = zzcat_fseek_getc(name, data, len, 0, 3); break;
        case 302: ret = zzcat_fseek_getc(name, data, len, 2, 2); break;
        case 303: ret = zzcat_fseek_getc(name, data, len, 2, 3); break;
        case 304: ret = zzcat_fseek_getc(name, data, len, len / 2, 2); break;
        case 305: ret = zzcat_fseek_getc(name, data, len, len / 2, 3); break;
        case 306: ret = zzcat_fread_getc(name, data, len, 2, 2); break;
        case 307: ret = zzcat_fread_getc(name, data, len, 2, 3); break;
        case 308: ret = zzcat_fread_getc(name, data, len, len / 2, 2); break;
        case 309: ret = zzcat_fread_getc(name, data, len, len / 2, 3); break;
#   if defined HAVE_GETLINE
        case 310: ret = zzcat_getline_getc(name, data, len, 2); break;
        case 311: ret = zzcat_getline_getc(name, data, len, 3); break;
#   endif
#endif
        /* Incomplete calls (but still OK since data is pre-filled) */
        case 400: ret = zzcat_fread_fseek(name, data, len, 1); break;
        case 401: ret = zzcat_fread_fseek(name, data, len, 2); break;
        case 402: ret = zzcat_fread_fseek(name, data, len, 4000); break;
        case 403: ret = zzcat_fseek_fread(name, data, len, 1); break;
        case 404: ret = zzcat_fseek_fread(name, data, len, 2); break;
        case 405: ret = zzcat_fseek_fread(name, data, len, 4000); break;
        case 406: ret = zzcat_random_socket(name, data, len); break;
        case 407: ret = zzcat_random_stream(name, data, len); break;
        /* Misc */
#if defined HAVE_MMAP
        case 500: ret = zzcat_random_mmap(name, data, len); break;
#endif
        default: ret = EXIT_SUCCESS;
    }

    /* Write what we have read */
    fwrite(data, len, 1, stdout);
    free(data);

    return ret;
}

/* Only read() calls */
static int zzcat_read(char const *name, unsigned char *data, int64_t len,
                      int64_t chunk)
{
    int i, fd = open(name, O_RDONLY);
    if(fd < 0)
        return EXIT_FAILURE;
    for(i = 0; i < len; i += chunk)
        read(fd, data + i, chunk);
    close(fd);
    return EXIT_SUCCESS;
}

/* Only fread() calls */
static int zzcat_fread(char const *name, unsigned char *data, int64_t len,
                       int64_t chunk)
{
    FILE *stream = fopen(name, "r");
    int i;
    if(!stream)
        return EXIT_FAILURE;
    for(i = 0; i < len; i += chunk)
        fread(data + i, chunk, 1, stream);
    fclose(stream);
    return EXIT_SUCCESS;
}

/* Only fread() and fseek() calls */
static int zzcat_fread_fseek(char const *name, unsigned char *data,
                             int64_t len, int64_t chunk)
{
    FILE *stream = fopen(name, "r");
    int i;
    if(!stream)
        return EXIT_FAILURE;
    for(i = 0; i < len; )
    {
        fread(data + i, chunk, 1, stream);
        i += chunk;
        if (i >= len)
            break;
        fseek(stream, chunk, SEEK_CUR);
        i += chunk;
    }
    fclose(stream);
    return EXIT_SUCCESS;
}

/* Only fseek() and fread() calls */
static int zzcat_fseek_fread(char const *name, unsigned char *data,
                             int64_t len, int64_t chunk)
{
    FILE *stream = fopen(name, "r");
    int i;
    if(!stream)
        return EXIT_FAILURE;
    for(i = 0; i < len; )
    {
        fseek(stream, chunk, SEEK_CUR);
        i += chunk;
        if (i >= len)
            break;
        fread(data + i, chunk, 1, stream);
        i += chunk;
    }
    fclose(stream);
    return EXIT_SUCCESS;
}

#if defined HAVE_GETLINE
/* getdelim() and getc() calls */
static int zzcat_getline_getc(char const *name, unsigned char *data,
                              int64_t len, int getc_method)
{
    FILE *stream = fopen(name, "r");
    int i = 0, j;
    char c;
    if(!stream)
        return EXIT_FAILURE;
    (void)len;
    while ((c = mygetc(stream, getc_method)) != EOF)
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

/* One fseek(), then only getc() or fgetc() calls */
static int zzcat_fseek_getc(char const *name, unsigned char *data,
                            int64_t len, int64_t chunk, int getc_method)
{
    FILE *stream = fopen(name, "r");
    int i;
    if(!stream)
        return EXIT_FAILURE;
    if (chunk)
        fseek(stream, chunk, SEEK_CUR);
    for(i = chunk; i < len; i++)
        data[i] = mygetc(stream, getc_method);
    fclose(stream);
    return EXIT_SUCCESS;
}

/* One fread(), then only getc() or fgetc() calls */
static int zzcat_fread_getc(char const *name, unsigned char *data,
                            int64_t len, int64_t chunk, int getc_method)
{
    FILE *stream = fopen(name, "r");
    int i;
    if(!stream)
        return EXIT_FAILURE;
    if (chunk)
        fread(data, 1, chunk, stream);
    for(i = chunk; i < len; i++)
        data[i] = mygetc(stream, getc_method);
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

