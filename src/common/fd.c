/*
 *  zzuf - general purpose fuzzer
 *
 *  Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
 *              2012 Kévin Szkudłapski <kszkudlapski@quarkslab.com>
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by the WTFPL Task Force.
 *  See http://www.wtfpl.net/ for more details.
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
#if defined HAVE_REGEX_H
#   if _WIN32
#       include "util/regex.h"
#   else
#       include <regex.h>
#   endif
#endif
#if _WIN32
#   include <windows.h>
#endif
#include <string.h>
#include <math.h>

#include "common.h"
#include "fd.h"
#include "fuzz.h"
#include "ranges.h"
#if defined LIBZZUF
#   include "debug.h"
#   include "network.h"
#endif
#include "util/mutex.h"

/* Regex stuff */
#if defined HAVE_REGEX_H
static regex_t re_include, re_exclude;
static int has_include = 0, has_exclude = 0;
#endif

/* File descriptor cherry picking */
static int64_t *list = NULL;
static int64_t static_list[512];

/* File descriptor stuff. When program is launched, we use the static array of
 * 32 structures, which ought to be enough for most programs. If it happens
 * not to be the case, ie. if the process opens more than 32 file descriptors
 * at the same time, a bigger array is malloc()ed and replaces the static one.
 */
#define STATIC_FILES 32
static struct files
{
    int managed, locked, active, already_fuzzed;
    int64_t pos, already_pos;
    /* Public stuff */
    fuzz_context_t fuzz;
}
*files, static_files[STATIC_FILES];
static int *fds, static_fds[STATIC_FILES];
static int maxfd, nfiles;

/* Spinlock. This variable protects the fds variable. */
static zzuf_mutex_t fds_mutex = 0;

/* Create lock. This lock variable is used to disable file descriptor
 * creation wrappers. For instance on Mac OS X, fopen() calls open()
 * and we don’t want open() to do any zzuf-related stuff: fopen() takes
 * care of everything. */
static int create_lock = 0;

static int32_t seed = DEFAULT_SEED;
static double  minratio = DEFAULT_RATIO;
static double  maxratio = DEFAULT_RATIO;
static int     autoinc = 0;

void zzuf_include_pattern(char const *regex)
{
#if defined HAVE_REGEX_H
    if (regcomp(&re_include, regex, REG_EXTENDED) == 0)
        has_include = 1;
#else
    (void)regex;
#endif
}

void zzuf_exclude_pattern(char const *regex)
{
#if defined HAVE_REGEX_H
    if (regcomp(&re_exclude, regex, REG_EXTENDED) == 0)
        has_exclude = 1;
#else
    (void)regex;
#endif
}

void _zz_list(char const *fdlist)
{
    list = _zz_allocrange(fdlist, static_list);
}

void zzuf_set_seed(int32_t s)
{
    seed = s;
}

void zzuf_set_ratio(double r0, double r1)
{
    if (r0 == 0.0 && r1 == 0.0)
    {
        maxratio = minratio = 0.0;
        return;
    }

    minratio = r0 < MIN_RATIO ? MIN_RATIO : r0 > MAX_RATIO ? MAX_RATIO : r0;
    maxratio = r1 < MIN_RATIO ? MIN_RATIO : r1 > MAX_RATIO ? MAX_RATIO : r1;
    if (maxratio < minratio)
        maxratio = minratio;
}

double zzuf_get_ratio(void)
{
    uint8_t const shuffle[16] =
    { 0, 12, 2, 10,
      14, 8, 15, 7,
      9, 13, 3, 6,
      4, 1, 11, 5 };
    uint16_t rate;
    double min, max, cur;

    if (minratio == maxratio)
        return minratio; /* this also takes care of 0.0 */

    rate = shuffle[seed & 0xf] << 12;
    rate |= (seed & 0xf0) << 4;
    rate |= (seed & 0xf00) >> 4;
    rate |= (seed & 0xf000) >> 12;

    min = log(minratio);
    max = log(maxratio);

    cur = min + (max - min) * rate / 0xffff;

    return exp(cur);
}

void zzuf_set_auto_increment(void)
{
    autoinc = 1;
}

void _zz_fd_init(void)
{
    /* We start with 32 file descriptors. This is to reduce the number of
     * calls to malloc() that we do, so we get better chances that memory
     * corruption errors are reproducible */
    files = static_files;
    for (nfiles = 0; nfiles < 32; ++nfiles)
        files[nfiles].managed = 0;

    fds = static_fds;
    for (maxfd = 0; maxfd < 32; ++maxfd)
        fds[maxfd] = -1;
}

void _zz_fd_fini(void)
{
    for (int i = 0; i < maxfd; ++i)
    {
        if (!files[fds[i]].managed)
            continue;

        /* XXX: What are we supposed to do? If filedescriptors weren't
         * closed properly, there's a leak, but it's not our problem. */
    }

#if defined HAVE_REGEX_H
    if (has_include)
        regfree(&re_include);
    if (has_exclude)
        regfree(&re_exclude);
#endif

    if (files != static_files)
       free(files);
    if (fds != static_fds)
        free(fds);
    if (list != static_list)
        free(list);
}

int _zz_mustwatch(char const *file)
{
#if defined HAVE_REGEXEC
    if (has_include && regexec(&re_include, file, 0, NULL, 0) == REG_NOMATCH)
        return 0; /* not included: ignore */

    if (has_exclude && regexec(&re_exclude, file, 0, NULL, 0) != REG_NOMATCH)
        return 0; /* excluded: ignore */
#else
    (void)file;
#endif

    return 1; /* default */
}

int _zz_mustwatchw(wchar_t const *file)
{
#if defined HAVE_REGWEXEC
    if (has_include && regwexec(&re_include, file, 0, NULL, 0) == REG_NOMATCH)
        return 0; /* not included: ignore */

    if (has_exclude && regwexec(&re_exclude, file, 0, NULL, 0) != REG_NOMATCH)
        return 0; /* excluded: ignore */
#else
    (void)file;
#endif

    return 1; /* default */
}

int _zz_iswatched(int fd)
{
    int ret = 0;
    zzuf_mutex_lock(&fds_mutex);

    if (fd < 0 || fd >= maxfd || fds[fd] == -1)
        goto early_exit;

    ret = 1;

early_exit:
    zzuf_mutex_unlock(&fds_mutex);
    return ret;
}

void _zz_register(int fd)
{
    int i;

    zzuf_mutex_lock(&fds_mutex);

    if (fd < 0 || fd > 65535 || (fd < maxfd && fds[fd] != -1))
        goto early_exit;

#if defined LIBZZUF
    if (autoinc)
        debug2("using seed %li", (long int)seed);
#endif

    /* If filedescriptor is outside our bounds */
    while (fd >= maxfd)
    {
        if (fds == static_fds)
        {
            fds = malloc(2 * maxfd * sizeof(*fds));
            memcpy(fds, static_fds, maxfd * sizeof(*fds));
        }
        else
            fds = realloc(fds, 2 * maxfd * sizeof(*fds));
        for (i = maxfd; i < maxfd * 2; ++i)
            fds[i] = -1;
        maxfd *= 2;
    }

    /* Find an empty slot */
    for (i = 0; i < nfiles; ++i)
        if (files[i].managed == 0)
            break;

    /* No slot found, allocate memory */
    if (i == nfiles)
    {
        nfiles++;
        if (files == static_files)
        {
            files = malloc(nfiles * sizeof(*files));
            memcpy(files, static_files, nfiles * sizeof(*files));
        }
        else
            files = realloc(files, nfiles * sizeof(*files));
    }

    files[i].managed = 1;
    files[i].locked = 0;
    files[i].pos = 0;
    files[i].fuzz.seed = seed;
    files[i].fuzz.ratio = zzuf_get_ratio();
    files[i].fuzz.cur = -1;
#if defined HAVE_FGETLN
    files[i].fuzz.tmp = NULL;
#endif
    files[i].fuzz.uflag = 0;

    /* Check whether we should ignore the fd */
    if (list)
    {
        static int idx = 0;

        files[i].active = _zz_isinrange(++idx, list);
    }
    else
        files[i].active = 1;

    if (autoinc)
        seed++;

    fds[fd] = i;

early_exit:
    zzuf_mutex_unlock(&fds_mutex);
}

void _zz_unregister(int fd)
{
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        files[fds[fd]].managed = 0;
#if defined HAVE_FGETLN
        if (files[fds[fd]].fuzz.tmp)
            free(files[fds[fd]].fuzz.tmp);
#endif

        fds[fd] = -1;
    }

    zzuf_mutex_unlock(&fds_mutex);
}

void _zz_lockfd(int fd)
{
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        if (fd == -1)
            ++create_lock;
        else
            ++files[fds[fd]].locked;
    }

    zzuf_mutex_unlock(&fds_mutex);
}

void _zz_unlock(int fd)
{
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        if (fd == -1)
            --create_lock;
        else
            --files[fds[fd]].locked;
    }

    zzuf_mutex_unlock(&fds_mutex);
}

int _zz_islocked(int fd)
{
    int ret = 0;
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        if (fd == -1)
            ret = create_lock;
        else
            ret = files[fds[fd]].locked;
    }

    zzuf_mutex_unlock(&fds_mutex);
    return ret;
}

int _zz_isactive(int fd)
{
    int ret = 1;
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        ret = files[fds[fd]].active;
    }

    zzuf_mutex_unlock(&fds_mutex);
    return ret;
}

int64_t _zz_getpos(int fd)
{
    int64_t ret = 0;
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        ret = files[fds[fd]].pos;
    }

    zzuf_mutex_unlock(&fds_mutex);
    return ret;
}

void _zz_setpos(int fd, int64_t pos)
{
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        files[fds[fd]].pos = pos;
    }

    zzuf_mutex_unlock(&fds_mutex);
}

void _zz_addpos(int fd, int64_t off)
{
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        files[fds[fd]].pos += off;
    }

    zzuf_mutex_unlock(&fds_mutex);
}

void _zz_setfuzzed(int fd, int count)
{
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        /* FIXME: what if we just slightly advanced? */
        if (files[fds[fd]].pos != files[fds[fd]].already_pos
            || count > files[fds[fd]].already_fuzzed)
        {
#if defined LIBZZUF
            debug2("setfuzzed(%i, %i)", fd, count);
#endif

            files[fds[fd]].already_pos = files[fds[fd]].pos;
            files[fds[fd]].already_fuzzed = count;
        }
    }

    zzuf_mutex_unlock(&fds_mutex);
}

int _zz_getfuzzed(int fd)
{
    int ret = 0;
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        if (files[fds[fd]].pos >= files[fds[fd]].already_pos
             && files[fds[fd]].pos < files[fds[fd]].already_pos
                                      + files[fds[fd]].already_fuzzed)
            ret = (int)(files[fds[fd]].already_fuzzed
                      + files[fds[fd]].already_pos
                      - files[fds[fd]].pos);
    }

    zzuf_mutex_unlock(&fds_mutex);
    return ret;
}

/* FIXME: this is not safe because once we unlock fds_mutex the structure
 * may become invalid */
fuzz_context_t *_zz_getfuzz(int fd)
{
    fuzz_context_t *ret = NULL;
    zzuf_mutex_lock(&fds_mutex);

    if (fd >= 0 && fd < maxfd && fds[fd] != -1)
    {
        ret = &files[fds[fd]].fuzz;
    }

    zzuf_mutex_unlock(&fds_mutex);
    return ret;
}

