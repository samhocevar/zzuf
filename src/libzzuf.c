/*
 *  zzuf - general purpose fuzzer
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

/*
 *  libzzuf.c: preloaded wrapper library
 */

#include "config.h"
#define _GNU_SOURCE

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <regex.h>

#include <stdarg.h>
#include <dlfcn.h>

#include "libzzuf.h"
#include "debug.h"
#include "load.h"

/* Global variables */
int   _zz_ready    = 0;
int   _zz_hasdebug = 0;
int   _zz_seed     = 0;
float _zz_ratio    = 0.004f;
regex_t * _zz_include = NULL;
regex_t * _zz_exclude = NULL;

/* Library initialisation shit */
void _zz_init(void)
{
    char *tmp;

    tmp = getenv("ZZUF_DEBUG");
    if(tmp && *tmp)
        _zz_hasdebug = 1;

    tmp = getenv("ZZUF_SEED");
    if(tmp && *tmp)
        _zz_seed = atol(tmp);

    tmp = getenv("ZZUF_RATIO");
    if(tmp && *tmp)
        _zz_ratio = atof(tmp);
    if(_zz_ratio < 0.0f)
        _zz_ratio = 0.0f;
    else if(_zz_ratio > 5.0f)
        _zz_ratio = 5.0f;

    tmp = getenv("ZZUF_INCLUDE");
    if(tmp && *tmp)
    {
        _zz_include = malloc(sizeof(*_zz_include));
        regcomp(_zz_include, tmp, 0);
    }

    tmp = getenv("ZZUF_EXCLUDE");
    if(tmp && *tmp)
    {
        _zz_exclude = malloc(sizeof(*_zz_exclude));
        regcomp(_zz_exclude, tmp, 0);
    }

    zfd_init();

    _zz_load_fd();
    _zz_load_stream();

    _zz_ready = 1;

    debug("libzzuf initialised");
}

/* Deinitialisation */
void _zz_fini(void)
{
    zfd_fini();
}

/* File descriptor stuff */
struct files
{
    int managed;
    uint64_t seed;
    uint64_t pos;
    /* Public stuff */
    struct fuzz fuzz;
}
*files;

int *fds;

int maxfd, nfiles;

void zfd_init(void)
{
    files = NULL;
    nfiles = 0;

    /* Start with one fd in the lookup table */
    fds = malloc(1 * sizeof(int));
    for(maxfd = 0; maxfd < 1; maxfd++)
        fds[maxfd] = -1;
}

void zfd_fini(void)
{
    int i;

    for(i = 0; i < maxfd; i++)
    {
        if(!files[fds[i]].managed)
            continue;

        /* XXX: What are we supposed to do? If filedescriptors weren't
         * closed properly, there's a leak, but it's not our problem. */
    }

    free(files);
    free(fds);
}

int zfd_ismanaged(int fd)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return 0;

    return 1;
}

void zfd_register(int fd)
{
    int i;

    if(fd < 0 || fd > 65535 || (fd < maxfd && fds[fd] != -1))
        return;

    while(fd >= maxfd)
    {
        fds = realloc(fds, 2 * maxfd * sizeof(int));
        for(i = maxfd; i < maxfd * 2; i++)
            fds[i] = -1;
        maxfd *= 2;
    }
            
    /* Find an empty slot */
    for(i = 0; i < nfiles; i++)
        if(files[i].managed == 0)
            break;

    /* No slot found, allocate memory */
    if(i == nfiles)
    {
        nfiles++;
        files = realloc(files, nfiles * sizeof(struct files));
    }

    files[i].managed = 1;
    files[i].pos = 0;
    files[i].fuzz.cur = -1;
    files[i].fuzz.data = malloc(CHUNKBYTES);

    fds[fd] = i;
}

void zfd_unregister(int fd)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return;

    files[fds[fd]].managed = 0;
    free(files[fds[fd]].fuzz.data);

    fds[fd] = -1;
}

long int zfd_getpos(int fd)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return 0;

    return files[fds[fd]].pos;
}

void zfd_setpos(int fd, long int pos)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return;

    files[fds[fd]].pos = pos;
}

void zfd_addpos(int fd, long int off)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return;

    files[fds[fd]].pos += off;
}

struct fuzz *zfd_getfuzz(int fd)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return NULL;

    return &files[fds[fd]].fuzz;
}

