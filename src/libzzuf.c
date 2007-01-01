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
float _zz_ratio    = 0.004f;
int   _zz_seed     = 0;
int   _zz_signal   = 0;

/* Local variables */
static regex_t * re_include = NULL;
static regex_t * re_exclude = NULL;

/* Local prototypes */
static void _zz_fd_init(void);
static void _zz_fd_fini(void);

/* Library initialisation shit */
void _zz_init(void)
{
    char *tmp;

    tmp = getenv("ZZUF_DEBUG");
    if(tmp && *tmp == '1')
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
        re_include = malloc(sizeof(*re_include));
        regcomp(re_include, tmp, REG_EXTENDED);
    }

    tmp = getenv("ZZUF_EXCLUDE");
    if(tmp && *tmp)
    {
        re_exclude = malloc(sizeof(*re_exclude));
        regcomp(re_exclude, tmp, REG_EXTENDED);
    }

    tmp = getenv("ZZUF_SIGNAL");
    if(tmp && *tmp == '1')
        _zz_signal = 1;

    _zz_fd_init();

    tmp = getenv("ZZUF_STDIN");
    if(tmp && *tmp == '1')
        _zz_register(0);

    _zz_load_fd();
    _zz_load_signal();
    _zz_load_stream();

    _zz_ready = 1;

    debug("libzzuf initialised");
}

/* Deinitialisation */
void _zz_fini(void)
{
    _zz_fd_fini();
}

/* File descriptor stuff */
static struct files
{
    int managed;
    uint64_t seed;
    uint64_t pos;
    /* Public stuff */
    struct fuzz fuzz;
}
*files;
static int *fds;
static int maxfd, nfiles;

static void _zz_fd_init(void)
{
    files = NULL;
    nfiles = 0;

    /* Start with one fd in the lookup table */
    fds = malloc(1 * sizeof(int));
    for(maxfd = 0; maxfd < 1; maxfd++)
        fds[maxfd] = -1;
}

static void _zz_fd_fini(void)
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

int _zz_mustwatch(char const *file)
{
    if(re_include && regexec(re_include, file, 0, NULL, 0) == REG_NOMATCH)
        return 0; /* not included: ignore */

    if(re_exclude && regexec(re_exclude, file, 0, NULL, 0) != REG_NOMATCH)
        return 0; /* excluded: ignore */

    return 1; /* default */
}

int _zz_iswatched(int fd)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return 0;

    return 1;
}

void _zz_register(int fd)
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

void _zz_unregister(int fd)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return;

    files[fds[fd]].managed = 0;
    free(files[fds[fd]].fuzz.data);

    fds[fd] = -1;
}

long int _zz_getpos(int fd)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return 0;

    return files[fds[fd]].pos;
}

void _zz_setpos(int fd, long int pos)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return;

    files[fds[fd]].pos = pos;
}

void _zz_addpos(int fd, long int off)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return;

    files[fds[fd]].pos += off;
}

struct fuzz *_zz_getfuzz(int fd)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return NULL;

    return &files[fds[fd]].fuzz;
}

