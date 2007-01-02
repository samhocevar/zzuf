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
 *  load-fd.c: loaded file descriptor functions
 */

#include "config.h"

/* Can't remember what that's for */
#define _GNU_SOURCE
/* Use this to get lseek64() */
#define _LARGEFILE64_SOURCE

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#include "libzzuf.h"
#include "debug.h"
#include "fuzz.h"
#include "load.h"

/* Library functions that we divert */
static int     (*open_orig)    (const char *file, int oflag, ...);
static int     (*open64_orig)  (const char *file, int oflag, ...);
static ssize_t (*read_orig)    (int fd, void *buf, size_t count);
static off_t   (*lseek_orig)   (int fd, off_t offset, int whence);
static off64_t (*lseek64_orig) (int fd, off64_t offset, int whence);
static int     (*close_orig)   (int fd);

void _zz_load_fd(void)
{
    LOADSYM(open);
    LOADSYM(open64);
    LOADSYM(read);
    LOADSYM(lseek);
    LOADSYM(lseek64);
    LOADSYM(close);
}

#define OPEN(fn) \
    do \
    { \
        int mode = 0; \
        if(!_zz_ready) \
            LOADSYM(fn); \
        if(oflag & O_CREAT) \
        { \
            va_list va; \
            va_start(va, oflag); \
            mode = va_arg(va, int); \
            va_end(va); \
            ret = ORIG(fn)(file, oflag, mode); \
        } \
        else \
        { \
            ret = ORIG(fn)(file, oflag); \
        } \
        if(!_zz_ready) \
            return ret; \
        if(ret >= 0 \
            && ((oflag & (O_RDONLY | O_RDWR | O_WRONLY)) != O_WRONLY) \
            && _zz_mustwatch(file)) \
        { \
            if(oflag & O_CREAT) \
                debug(STR(fn) "(\"%s\", %i, %i) = %i", \
                      file, oflag, mode, ret); \
            else \
                debug(STR(fn) "(\"%s\", %i) = %i", file, oflag, ret); \
            _zz_register(ret); \
        } \
    } while(0)

int open(const char *file, int oflag, ...)
{
    int ret; OPEN(open); return ret;
}

int open64(const char *file, int oflag, ...)
{
    int ret; OPEN(open64); return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
    int ret;

    if(!_zz_ready)
        LOADSYM(read);
    ret = read_orig(fd, buf, count);
    if(!_zz_ready || !_zz_iswatched(fd))
        return ret;

    debug("read(%i, %p, %li) = %i", fd, buf, (long int)count, ret);
    if(ret > 0)
    {
        _zz_fuzz(fd, buf, ret);
        _zz_addpos(fd, ret);
    }

    /* Sanity check, can be OK though (for instance with a character device) */
    if(lseek64_orig(fd, 0, SEEK_CUR) != _zz_getpos(fd))
        debug("warning: offset inconsistency");

    return ret;
}

#define LSEEK(fn, off_t) \
    do { \
        if(!_zz_ready) \
            LOADSYM(fn); \
        ret = ORIG(fn)(fd, offset, whence); \
        if(!_zz_ready || !_zz_iswatched(fd)) \
            return ret; \
        debug(STR(fn)"(%i, %lli, %i) = %lli", \
              fd, (long long int)offset, whence, (long long int)ret); \
        if(ret != (off_t)-1) \
            _zz_setpos(fd, ret); \
    } while(0)

off_t lseek(int fd, off_t offset, int whence)
{
    off_t ret;
    LSEEK(lseek, off_t);
    return ret;
}

off64_t lseek64(int fd, off64_t offset, int whence)
{
    off64_t ret;
    LSEEK(lseek64, off64_t);
    return ret;
}

int close(int fd)
{
    int ret;

    if(!_zz_ready)
        LOADSYM(close);

    /* Hey, it’s our debug channel! Silently pretend we closed it. */
    if(fd == DEBUG_FILENO)
        return 0;

    ret = close_orig(fd);
    if(!_zz_ready || !_zz_iswatched(fd))
        return ret;

    debug("close(%i) = %i", fd, ret);
    _zz_unregister(fd);

    return ret;
}

