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

/* Need this for RTLD_NEXT */
#define _GNU_SOURCE
/* Use this to get lseek64() on glibc systems */
#define _LARGEFILE64_SOURCE

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#include "libzzuf.h"
#include "debug.h"
#include "fuzz.h"
#include "load.h"
#include "fd.h"

#ifdef HAVE_SOCKLEN_T
#   define SOCKLEN_T socklen_t
#else
#   define SOCKLEN_T int
#endif

/* Library functions that we divert */
static int     (*open_orig)    (const char *file, int oflag, ...);
#ifdef HAVE_OPEN64
static int     (*open64_orig)  (const char *file, int oflag, ...);
#endif
static int     (*accept_orig)  (int sockfd, struct sockaddr *addr,
                                SOCKLEN_T *addrlen);
static int     (*socket_orig)  (int domain, int type, int protocol);
static ssize_t (*read_orig)    (int fd, void *buf, size_t count);
static off_t   (*lseek_orig)   (int fd, off_t offset, int whence);
#ifdef HAVE_LSEEK64
static off64_t (*lseek64_orig) (int fd, off64_t offset, int whence);
#endif
static int     (*close_orig)   (int fd);


void _zz_load_fd(void)
{
    LOADSYM(open);
#ifdef HAVE_OPEN64
    LOADSYM(open64);
#endif
    LOADSYM(accept);
    LOADSYM(socket);
    LOADSYM(read);
    LOADSYM(lseek);
#ifdef HAVE_LSEEK64
    LOADSYM(lseek64);
#endif
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
        if(!_zz_ready || _zz_disabled) \
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

#ifdef HAVE_OPEN64
int open64(const char *file, int oflag, ...)
{
    int ret; OPEN(open64); return ret;
}
#endif

int accept(int sockfd, struct sockaddr *addr, SOCKLEN_T *addrlen)
{
    int ret;

    if(!_zz_ready)
        LOADSYM(accept);
    ret = accept_orig(sockfd, addr, addrlen);
    if(!_zz_ready || _zz_disabled || !_zz_network)
        return ret;

    if(ret >= 0)
    {
        debug("accept(%i, %p, %p) = %i", sockfd, addr, addrlen, ret);
        _zz_register(ret);
    }

    return ret;
}

int socket(int domain, int type, int protocol)
{
    int ret;

    if(!_zz_ready)
        LOADSYM(socket);
    ret = socket_orig(domain, type, protocol);
    if(!_zz_ready || _zz_disabled || !_zz_network)
        return ret;

    if(ret >= 0)
    {
        debug("socket(%i, %i, %i) = %i", domain, type, protocol, ret);
        _zz_register(ret);
    }

    return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
    int ret;

    if(!_zz_ready)
        LOADSYM(read);
    ret = read_orig(fd, buf, count);
    if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled)
        return ret;

    if(ret > 0)
    {
        char *b = buf;

        _zz_fuzz(fd, buf, ret);
        _zz_addpos(fd, ret);

        if(ret >= 4)
            debug("read(%i, %p, %li) = %i \"%c%c%c%c...", fd, buf,
                  (long int)count, ret, b[0], b[1], b[2], b[3]);
        else
            debug("read(%i, %p, %li) = %i \"%c...", fd, buf,
                  (long int)count, ret, b[0]);
    }
    else
        debug("read(%i, %p, %li) = %i", fd, buf, (long int)count, ret);

    /* Sanity check, can be OK though (for instance with a character device) */
#ifdef HAVE_LSEEK64
    if(lseek64_orig(fd, 0, SEEK_CUR) != _zz_getpos(fd))
#else
    if(lseek_orig(fd, 0, SEEK_CUR) != _zz_getpos(fd))
#endif
        debug("warning: offset inconsistency");

    return ret;
}

#define LSEEK(fn, off_t) \
    do \
    { \
        if(!_zz_ready) \
            LOADSYM(fn); \
        ret = ORIG(fn)(fd, offset, whence); \
        if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled) \
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

#ifdef HAVE_LSEEK64
off64_t lseek64(int fd, off64_t offset, int whence)
{
    off64_t ret;
    LSEEK(lseek64, off64_t);
    return ret;
}
#endif

int close(int fd)
{
    int ret;

    if(!_zz_ready)
        LOADSYM(close);

    /* Hey, it’s our debug channel! Silently pretend we closed it. */
    if(fd == DEBUG_FILENO)
        return 0;

    ret = close_orig(fd);
    if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled)
        return ret;

    debug("close(%i) = %i", fd, ret);
    _zz_unregister(fd);

    return ret;
}

