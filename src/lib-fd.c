/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006, 2007 Sam Hocevar <sam@zoy.org>
 *                2007 Rémi Denis-Courmont <rdenis#simphalempin:com>
 *                2007 Clément Stenac <zorglub#diwi:org>
 *                2007 Dominik Kuhlen <dominik.kuhlen#gmit-gmbh:de>
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
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <aio.h>

#include "libzzuf.h"
#include "lib-load.h"
#include "debug.h"
#include "fuzz.h"
#include "fd.h"

#ifdef HAVE_SOCKLEN_T
#   define SOCKLEN_T socklen_t
#else
#   define SOCKLEN_T int
#endif

/* Local prototypes */
static void fuzz_iovec   (int fd, const struct iovec *iov, ssize_t ret);
static void offset_check (int fd);

/* Library functions that we divert */
static int     (*open_orig)    (const char *file, int oflag, ...);
#ifdef HAVE_OPEN64
static int     (*open64_orig)  (const char *file, int oflag, ...);
#endif
static int     (*accept_orig)  (int sockfd, struct sockaddr *addr,
                                SOCKLEN_T *addrlen);
static int     (*socket_orig)  (int domain, int type, int protocol);
static int     (*recv_orig)    (int s, void *buf, size_t len, int flags);
static int     (*recvfrom_orig)(int s, void *buf, size_t len, int flags,
                                struct sockaddr *from, SOCKLEN_T *fromlen);
static int     (*recvmsg_orig) (int s,  struct msghdr *hdr, int flags);
static ssize_t (*read_orig)    (int fd, void *buf, size_t count);
static ssize_t (*readv_orig)   (int fd, const struct iovec *iov, int count);
static ssize_t (*pread_orig)   (int fd, void *buf, size_t count, off_t offset);
static int     (*aio_read_orig)   (struct aiocb *aiocbp);
static ssize_t (*aio_return_orig) (struct aiocb *aiocbp);
static off_t   (*lseek_orig)   (int fd, off_t offset, int whence);
#ifdef HAVE_LSEEK64
static off64_t (*lseek64_orig) (int fd, off64_t offset, int whence);
#endif
static int     (*close_orig)   (int fd);

#define OPEN(fn) \
    do \
    { \
        int mode = 0; \
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
                debug("%s(\"%s\", %i, %i) = %i", \
                      __func__, file, oflag, mode, ret); \
            else \
                debug("%s(\"%s\", %i) = %i", __func__, file, oflag, ret); \
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

    LOADSYM(accept);
    ret = accept_orig(sockfd, addr, addrlen);
    if(!_zz_ready || _zz_disabled || !_zz_network)
        return ret;

    if(ret >= 0)
    {
        debug("%s(%i, %p, %p) = %i", __func__, sockfd, addr, addrlen, ret);
        _zz_register(ret);
    }

    return ret;
}

int socket(int domain, int type, int protocol)
{
    int ret;

    LOADSYM(socket);
    ret = socket_orig(domain, type, protocol);
    if(!_zz_ready || _zz_disabled || !_zz_network)
        return ret;

    if(ret >= 0)
    {
        debug("%s(%i, %i, %i) = %i", __func__, domain, type, protocol, ret);
        _zz_register(ret);
    }

    return ret;
}

int recv(int s, void *buf, size_t len, int flags)
{
    int ret;

    LOADSYM(recv);
    ret = recv_orig(s, buf, len, flags);
    if(!_zz_ready || _zz_disabled || !_zz_network)
        return ret;

    if(ret > 0) 
    {
        char *b = buf;

        _zz_fuzz(s, buf, ret);
        _zz_addpos(s, ret);

        if(ret >= 4)
            debug("%s(%i, %p, %li, 0x%x) = %i \"%c%c%c%c...", __func__,
                  s, buf, (long int)len, flags, ret, b[0], b[1], b[2], b[3]);
        else
            debug("%s(%i, %p, %li, 0x%x) = %i \"%c...", __func__,
                  s, buf, (long int)len, flags, ret, b[0]);
    }
    else
        debug("%s(%i, %p, %li, 0x%x) = %i", __func__,
              s, buf, (long int)len, flags, ret);

    return ret;
}

int recvfrom(int s, void *buf, size_t len, int flags,
             struct sockaddr *from, SOCKLEN_T *fromlen) 
{
    int ret;

    LOADSYM(recvfrom);
    ret = recvfrom_orig(s, buf, len, flags, from, fromlen);
    if(!_zz_ready || _zz_disabled || !_zz_network)
        return ret;

    if(ret > 0) 
    {
        char *b = buf;

        _zz_fuzz(s, buf, ret);
        _zz_addpos(s, ret);

        if(ret >= 4)
            debug("%s(%i, %p, %li, 0x%x, %p, %p) = %i \"%c%c%c%c...", __func__,
                  s, buf, (long int)len, flags, from, fromlen, ret,
                  b[0], b[1], b[2], b[3]);
        else
            debug("%s(%i, %p, %li, 0x%x, %p, %p) = %i \"%c...", __func__,
                  s, buf, (long int)len, flags, from, fromlen, ret, b[0]);
    }
    else
        debug("%s(%i, %p, %li, 0x%x, %p, %p) = %i", __func__,
              s, buf, (long int)len, flags, from, fromlen, ret);

    return ret;
}

int recvmsg(int s, struct msghdr *hdr, int flags)
{
    ssize_t ret;

    LOADSYM(recvmsg);
    ret = recvmsg_orig(s, hdr, flags);
    if(!_zz_ready || !_zz_iswatched(s) || _zz_disabled)
        return ret;

    fuzz_iovec(s, hdr->msg_iov, ret);
    debug("%s(%i, %p, %x) = %li", __func__, s, hdr, flags, (long int)ret);

    return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
    int ret;

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
            debug("%s(%i, %p, %li) = %i \"%c%c%c%c...", __func__, fd, buf,
                  (long int)count, ret, b[0], b[1], b[2], b[3]);
        else
            debug("%s(%i, %p, %li) = %i \"%c...", __func__, fd, buf,
                  (long int)count, ret, b[0]);
    }
    else
        debug("%s(%i, %p, %li) = %i", __func__, fd, buf, (long int)count, ret);

    offset_check(fd);
    return ret;
}

ssize_t readv(int fd, const struct iovec *iov, int count)
{
    ssize_t ret;

    LOADSYM(readv);
    ret = readv_orig(fd, iov, count);
    if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled)
        return ret;

    fuzz_iovec(fd, iov, ret);
    debug("%s(%i, %p, %i) = %li", __func__, fd, iov, count, (long int)ret);

    offset_check(fd);
    return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    int ret;

    LOADSYM(pread);
    ret = pread_orig(fd, buf, count, offset);
    if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled)
        return ret;

    if(ret > 0)
    {
        long int curoff = _zz_getpos(fd);
        char *b = buf;

        _zz_setpos(fd, offset);
        _zz_fuzz(fd, buf, ret);
        _zz_setpos(fd, curoff);

        if(ret >= 4)
            debug("%s(%i, %p, %li, %li) = %i \"%c%c%c%c...", __func__, fd, buf,
                  (long int)count, (long int)offset, ret,
                  b[0], b[1], b[2], b[3]);
        else
            debug("%s(%i, %p, %li, %li) = %i \"%c...", __func__, fd, buf,
                  (long int)count, (long int)offset, ret, b[0]);
    }
    else
        debug("%s(%i, %p, %li, %li) = %i", __func__, fd, buf,
              (long int)count, (long int)offset, ret);

    return ret;
}

#define LSEEK(fn, off_t) \
    do \
    { \
        LOADSYM(fn); \
        ret = ORIG(fn)(fd, offset, whence); \
        if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled) \
            return ret; \
        debug("%s(%i, %lli, %i) = %lli", __func__, fd, \
              (long long int)offset, whence, (long long int)ret); \
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

int aio_read(struct aiocb *aiocbp)
{
    int ret;
    int fd = aiocbp->aio_fildes;

    LOADSYM(aio_read);
    if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled)
        return aio_read_orig(aiocbp);

    _zz_disabled = 1;
    ret = aio_read_orig(aiocbp);

    debug("%s({%i, %i, %i, %p, %li, ..., %li}) = %i", __func__,
          fd, aiocbp->aio_lio_opcode, aiocbp->aio_reqprio, aiocbp->aio_buf,
          (long int)aiocbp->aio_nbytes, (long int)aiocbp->aio_offset, ret);

    return ret;
}

ssize_t aio_return(struct aiocb *aiocbp)
{
    ssize_t ret;
    int fd = aiocbp->aio_fildes;

    LOADSYM(aio_return);
    if(!_zz_ready || !_zz_iswatched(fd))
        return aio_return_orig(aiocbp);

    ret = aio_return_orig(aiocbp);
    _zz_disabled = 0;

    /* FIXME: make sure we’re actually *reading* */
    if(ret > 0)
    {
        _zz_setpos(fd, aiocbp->aio_offset);
        _zz_fuzz(fd, aiocbp->aio_buf, ret);
        _zz_addpos(fd, ret);
    }

    debug("%s({%i, %i, %i, %p, %li, ..., %li}) = %li", __func__,
          fd, aiocbp->aio_lio_opcode, aiocbp->aio_reqprio, aiocbp->aio_buf,
          (long int)aiocbp->aio_nbytes, (long int)aiocbp->aio_offset,
          (long int)ret);

    return ret;
}

int close(int fd)
{
    int ret;

    /* Hey, it’s our debug channel! Silently pretend we closed it. */
    if(fd == DEBUG_FILENO)
        return 0;

    LOADSYM(close);
    ret = close_orig(fd);
    if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled)
        return ret;

    debug("%s(%i) = %i", __func__, fd, ret);
    _zz_unregister(fd);

    return ret;
}

/* XXX: the following functions are local */

static void fuzz_iovec(int fd, const struct iovec *iov, ssize_t ret)
{
    /* NOTE: We assume that iov countains at least <ret> bytes. */
    while(ret > 0)
    {
        void *b = iov->iov_base;
        size_t len = iov->iov_len;

        if(len > (size_t)ret)
            len = ret;

        _zz_fuzz(fd, b, len);
        _zz_addpos(fd, len);

        iov++;
        ret -= len;
    }
}

static void offset_check(int fd)
{
    /* Sanity check, can be OK though (for instance with a character device) */
#ifdef HAVE_LSEEK64
    off64_t ret;
    LOADSYM(lseek64);
    ret = lseek64_orig(fd, 0, SEEK_CUR);
#else
    off_t ret;
    LOADSYM(lseek);
    ret = lseek_orig(fd, 0, SEEK_CUR);
#endif
    if(ret != -1 && ret != _zz_getpos(fd))
        debug("warning: offset inconsistency");
}

