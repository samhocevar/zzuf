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
#include <stdlib.h>
#include <regex.h>
#include <string.h>

#include "libzzuf.h"
#include "fd.h"

/* Regex stuff */
static regex_t re_include, re_exclude;
static int has_include = 0, has_exclude = 0;

/* File descriptor stuff. When program is launched, we use the static array of
 * 32 structures, which ought to be enough for most programs. If it happens
 * not to be the case, ie. if the process opens more than 32 file descriptors
 * at the same time, a bigger array is malloc()ed and replaces the static one.
 */
#define STATIC_FILES 32
static struct files
{
    int managed;
    uint64_t seed;
    uint64_t pos;
    /* Public stuff */
    struct fuzz fuzz;
}
*files, static_files[STATIC_FILES];
static int *fds, static_fds[STATIC_FILES];
static int maxfd, nfiles;

void _zz_include(char const *regex)
{
    if(regcomp(&re_include, regex, REG_EXTENDED) == 0)
        has_include = 1;
}

void _zz_exclude(char const *regex)
{
    if(regcomp(&re_exclude, regex, REG_EXTENDED) == 0)
        has_exclude = 1;
}

void _zz_fd_init(void)
{
    /* We start with 32 file descriptors. This is to reduce the number of
     * calls to malloc() that we do, so we get better chances that memory
     * corruption errors are reproducible */
    files = static_files;
    for(nfiles = 0; nfiles < 32; nfiles++)
        files[nfiles].managed = 0;

    fds = static_fds;
    for(maxfd = 0; maxfd < 32; maxfd++)
        fds[maxfd] = -1;
}

void _zz_fd_fini(void)
{
    int i;

    for(i = 0; i < maxfd; i++)
    {
        if(!files[fds[i]].managed)
            continue;

        /* XXX: What are we supposed to do? If filedescriptors weren't
         * closed properly, there's a leak, but it's not our problem. */
    }

    if(files != static_files)
       free(files);
    if(fds != static_fds)
        free(fds);
}

int _zz_mustwatch(char const *file)
{
    if(has_include && regexec(&re_include, file, 0, NULL, 0) == REG_NOMATCH)
        return 0; /* not included: ignore */

    if(has_exclude && regexec(&re_exclude, file, 0, NULL, 0) != REG_NOMATCH)
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

    /* If filedescriptor is outside our bounds */
    while(fd >= maxfd)
    {
        if(fds == static_fds)
        {
            fds = malloc(2 * maxfd * sizeof(*fds));
            memcpy(fds, static_fds, maxfd * sizeof(*fds));
        }
        else
            fds = realloc(fds, 2 * maxfd * sizeof(*fds));
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
        if(files == static_files)
        {
            files = malloc(nfiles * sizeof(*files));
            memcpy(files, static_files, nfiles * sizeof(*files));
        }
        else
            files = realloc(files, nfiles * sizeof(*files));
    }

    files[i].managed = 1;
    files[i].pos = 0;
    files[i].fuzz.cur = -1;
#ifdef HAVE_FGETLN
    files[i].fuzz.tmp = NULL;
#endif

    fds[fd] = i;
}

void _zz_unregister(int fd)
{
    if(fd < 0 || fd >= maxfd || fds[fd] == -1)
        return;

    files[fds[fd]].managed = 0;
#ifdef HAVE_FGETLN
    if(files[fds[fd]].fuzz.tmp)
        free(files[fds[fd]].fuzz.tmp);
#endif

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

