/*
 *  zzuf - general purpose fuzzer
 *
 *  Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
 *              2007 Rémi Denis-Courmont <rdenis#simphalempin:com>
 *              2007 Clément Stenac <zorglub#diwi:org>
 *              2007 Dominik Kuhlen <dominik.kuhlen#gmit-gmbh:de>
 *              2009 Corentin Delorme <codelorme@gmail.com>
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by the WTFPL Task Force.
 *  See http://www.wtfpl.net/ for more details.
 */

/*
 *  load-fd.c: loaded file descriptor functions
 */

#include "config.h"

/* Use this to get lseek64() on glibc systems */
#define _LARGEFILE64_SOURCE
/* Use this to get pread() on glibc systems */
#define _POSIX_C_SOURCE 200809L
/* Use this to get off64_t() on Solaris systems */
#define _LARGEFILE_SOURCE
/* Use this to get proper prototypes on HP-UX systems */
#define _XOPEN_SOURCE_EXTENDED
#define _INCLUDE_POSIX_SOURCE

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#if defined HAVE_WINSOCK2_H
#   include <winsock2.h>
#endif
#include <sys/types.h>
#if defined HAVE_SYS_SOCKET_H
#   include <sys/socket.h>
#endif
#if defined HAVE_NETINET_IN_H
#   include <netinet/in.h>
#endif
#if defined HAVE_ARPA_INET_H
#   include <arpa/inet.h>
#endif
#if defined HAVE_SYS_UIO_H
#   include <sys/uio.h>
#endif
#if defined HAVE_UNISTD_H
#   include <unistd.h>
#endif
#include <fcntl.h>
#include <stdarg.h>
#if defined HAVE_AIO_H
#   include <aio.h>
#endif

#include "libzzuf.h"
#include "lib-load.h"
#include "debug.h"
#include "network.h"
#include "fuzz.h"
#include "fd.h"

#if defined HAVE_SOCKLEN_T
#   define SOCKLEN_T socklen_t
#else
#   define SOCKLEN_T int
#endif

#if defined CONNECT_USES_STRUCT_SOCKADDR
#   define SOCKADDR_T struct sockaddr
#elif defined HAVE_WINSOCK2_H
#   define SOCKADDR_T struct sockaddr
#else
#   define SOCKADDR_T void
#endif

/* Local prototypes */
#if defined HAVE_READV || defined HAVE_RECVMSG
static void fuzz_iovec   (int fd, const struct iovec *iov, ssize_t ret);
#endif
static void offset_check (int fd);

/* Library functions that we divert */
static int     (*ORIG(open))    (const char *file, int oflag, ...);
#if defined HAVE_OPEN64
static int     (*ORIG(open64))  (const char *file, int oflag, ...);
#endif
#if defined HAVE___OPEN64
static int     (*ORIG(__open64))(const char *file, int oflag, ...);
#endif
#if defined HAVE_DUP
static int     (*ORIG(dup))     (int oldfd);
#endif
#if defined HAVE_DUP2
static int     (*ORIG(dup2))    (int oldfd, int newfd);
#endif
#if defined HAVE_ACCEPT
static int     (*ORIG(accept))  (int sockfd, SOCKADDR_T *addr,
                                 SOCKLEN_T *addrlen);
#endif
#if defined HAVE_BIND
static int     (*ORIG(bind))    (int sockfd, const SOCKADDR_T *my_addr,
                                 SOCKLEN_T addrlen);
#endif
#if defined HAVE_CONNECT
static int     (*ORIG(connect)) (int sockfd, const SOCKADDR_T *serv_addr,
                                 SOCKLEN_T addrlen);
#endif
#if defined HAVE_SOCKET
static int     (*ORIG(socket))  (int domain, int type, int protocol);
#endif
#if defined HAVE_RECV
static RECV_T  (*ORIG(recv))    (int s, void *buf, size_t len, int flags);
#endif
#if defined HAVE___RECV_CHK
static RECV_T  (*ORIG(__recv_chk)) (int s, void *buf, size_t len,
                                    size_t buflen, int flags);
#endif
#if defined HAVE_RECVFROM
static RECV_T  (*ORIG(recvfrom))(int s, void *buf, size_t len, int flags,
                                 SOCKADDR_T *from, SOCKLEN_T *fromlen);
#endif
#if defined HAVE___RECVFROM_CHK
static RECV_T  (*ORIG(__recvfrom_chk))(int s, void *buf, size_t len,
                                       size_t buflen, int flags,
                                       SOCKADDR_T *from, SOCKLEN_T *fromlen);
#endif
#if defined HAVE_RECVMSG
static RECV_T  (*ORIG(recvmsg)) (int s,  struct msghdr *hdr, int flags);
#endif
#if defined READ_USES_SSIZE_T
static ssize_t (*ORIG(read))    (int fd, void *buf, size_t count);
#else
static int     (*ORIG(read))    (int fd, void *buf, unsigned int count);
#endif
#if defined HAVE___READ_CHK
static ssize_t (*ORIG(__read_chk)) (int fd, void *buf, size_t count,
                                    size_t buflen);
#endif
#if defined HAVE_READV
static ssize_t (*ORIG(readv))   (int fd, const struct iovec *iov, int count);
#endif
#if defined HAVE_PREAD
static ssize_t (*ORIG(pread))   (int fd, void *buf, size_t count, off_t offset);
#endif
#if defined HAVE_AIO_READ
static int     (*ORIG(aio_read))   (struct aiocb *aiocbp);
static ssize_t (*ORIG(aio_return)) (struct aiocb *aiocbp);
#endif
static off_t   (*ORIG(lseek))   (int fd, off_t offset, int whence);
#if defined HAVE_LSEEK64
static off64_t (*ORIG(lseek64)) (int fd, off64_t offset, int whence);
#endif
#if defined HAVE___LSEEK64
static off64_t (*ORIG(__lseek64)) (int fd, off64_t offset, int whence);
#endif
static int     (*ORIG(close))   (int fd);

#define ZZ_OPEN(myopen) \
    do \
    { \
        LOADSYM(myopen); \
        \
        int mode = 0; \
        if (oflag & O_CREAT) \
        { \
            va_list va; \
            va_start(va, oflag); \
            mode = va_arg(va, int); \
            va_end(va); \
            ret = ORIG(myopen)(file, oflag, mode); \
        } \
        else \
        { \
            ret = ORIG(myopen)(file, oflag); \
        } \
        if (!g_libzzuf_ready || _zz_islocked(-1)) \
            return ret; \
        if (ret >= 0 \
            && ((oflag & (O_RDONLY | O_RDWR | O_WRONLY)) != O_WRONLY) \
            && _zz_mustwatch(file)) \
        { \
            if (oflag & O_CREAT) \
                debug("%s(\"%s\", %i, %i) = %i", \
                      __func__, file, oflag, mode, ret); \
            else \
                debug("%s(\"%s\", %i) = %i", __func__, file, oflag, ret); \
            _zz_register(ret); \
        } \
    } while (0)

#undef open
int NEW(open)(const char *file, int oflag, ...)
{
    int ret; ZZ_OPEN(open); return ret;
}

#if defined HAVE_OPEN64
#undef open64
int NEW(open64)(const char *file, int oflag, ...)
{
    int ret; ZZ_OPEN(open64); return ret;
}
#endif

#if defined HAVE___OPEN64
#undef __open64
extern int __open64(const char *file, int oflag, ...);
int NEW(__open64)(const char *file, int oflag, ...)
{
    int ret; ZZ_OPEN(__open64); return ret;
}
#endif

#if defined HAVE_DUP
#undef dup
int NEW(dup)(int oldfd)
{
    LOADSYM(dup);

    int ret = ORIG(dup)(oldfd);
    if (!g_libzzuf_ready || _zz_islocked(-1) || !_zz_iswatched(oldfd)
         || !_zz_isactive(oldfd))
        return ret;

    if (ret >= 0)
    {
        debug("%s(%i) = %i", __func__, oldfd, ret);
        _zz_register(ret);
    }

    return ret;
}
#endif

#if defined HAVE_DUP2
#undef dup2
int NEW(dup2)(int oldfd, int newfd)
{
    LOADSYM(dup2);

    int ret = ORIG(dup2)(oldfd, newfd);
    if (!g_libzzuf_ready || _zz_islocked(-1) || !_zz_iswatched(oldfd)
         || !_zz_isactive(oldfd))
        return ret;

    if (ret >= 0)
    {
        /* We must close newfd if it was open, but only if oldfd != newfd
         * and if dup2() suceeded. */
        if (oldfd != newfd && _zz_iswatched(newfd) && _zz_isactive(newfd))
            _zz_unregister(newfd);

        debug("%s(%i, %i) = %i", __func__, oldfd, newfd, ret);
        _zz_register(ret);
    }

    return ret;
}
#endif

#if defined HAVE_ACCEPT
#undef accept
int NEW(accept)(int sockfd, SOCKADDR_T *addr, SOCKLEN_T *addrlen)
{
    LOADSYM(accept);

    int ret = ORIG(accept)(sockfd, addr, addrlen);
    if (!g_libzzuf_ready || _zz_islocked(-1) || !g_network_fuzzing
         || !_zz_iswatched(sockfd) || !_zz_isactive(sockfd))
        return ret;

    if (ret >= 0)
    {
        if (addrlen)
            debug("%s(%i, %p, &%i) = %i", __func__,
                  sockfd, addr, (int)*addrlen, ret);
        else
            debug("%s(%i, %p, NULL) = %i", __func__, sockfd, addr, ret);
        _zz_register(ret);
    }

    return ret;
}
#endif

#if defined AF_INET6
#   define case_AF_INET6 case AF_INET6:
#else
#   define case_AF_INET6
#endif

#define ZZ_CONNECT(myconnect, addr) \
    do \
    { \
        LOADSYM(myconnect); \
        \
        ret = ORIG(myconnect)(sockfd, addr, addrlen); \
        if (!g_libzzuf_ready || _zz_islocked(-1) || !g_network_fuzzing) \
            return ret; \
        if (ret >= 0) \
        { \
            struct sockaddr_in in; \
            long int port; \
            switch (addr->sa_family) \
            { \
            case AF_INET: \
            case_AF_INET6 \
                /* We need to copy rather than cast sockaddr* to sockaddr_in* \
                 * because sockaddr_in* has actually _larger_ alignment on \
                 * eg. Linux alpha. And we only need sin_port so we only copy \
                 * this member. */ \
                memcpy(&in.sin_port, \
                   (char const *)addr + ((char *)&in.sin_port - (char *)&in), \
                   sizeof(in.sin_port)); \
                port = ntohs(in.sin_port); \
                if (_zz_portwatched(port)) \
                    break; \
                /* Fall through */ \
            default: \
                _zz_unregister(sockfd); \
                return ret; \
            } \
            debug("%s(%i, %p, %i) = %i", __func__, \
                  sockfd, addr, (int)addrlen, ret); \
        } \
    } while (0);

#if defined HAVE_BIND
#undef bind
int NEW(bind)(int sockfd, const SOCKADDR_T *my_addr, SOCKLEN_T addrlen)
{
    int ret; ZZ_CONNECT(bind, my_addr); return ret;
}
#endif

#if defined HAVE_CONNECT
#undef connect
int NEW(connect)(int sockfd, const SOCKADDR_T *serv_addr,
                 SOCKLEN_T addrlen)
{
    int ret; ZZ_CONNECT(connect, serv_addr); return ret;
}
#endif

#if defined HAVE_SOCKET
#undef socket
int NEW(socket)(int domain, int type, int protocol)
{
    LOADSYM(socket);

    int ret = ORIG(socket)(domain, type, protocol);
    if (!g_libzzuf_ready || _zz_islocked(-1) || !g_network_fuzzing)
        return ret;

    if (ret >= 0)
    {
        debug("%s(%i, %i, %i) = %i", __func__, domain, type, protocol, ret);
        _zz_register(ret);
    }

    return ret;
}
#endif

#define ZZ_RECV(myrecv, myargs) \
    do \
    { \
        LOADSYM(myrecv); \
        \
        ret = ORIG(myrecv) myargs; \
        if (!must_fuzz_fd(s) || !_zz_hostwatched(s)) \
            return ret; \
        \
        if (ret > 0) \
        { \
            _zz_fuzz(s, buf, ret); \
            _zz_addpos(s, ret); \
        } \
        \
        char tmp[128]; \
        debug_str(tmp, buf, ret, 8); \
        debug("%s(%i, %p, %li, 0x%x) = %i %s", __func__, \
              s, buf, (long int)len, flags, ret, tmp); \
    } while (0);

#if defined HAVE_RECV
#undef recv
RECV_T NEW(recv)(int s, void *buf, size_t len, int flags)
{
    int ret; ZZ_RECV(recv, (s, buf, len, flags)); return ret;
}
#endif

#if defined HAVE___RECV_CHK
#undef __recv_chk
extern RECV_T __recv_chk(int s, void *buf, size_t len,
                         size_t buflen, int flags);
RECV_T NEW(__recv_chk)(int s, void *buf, size_t len, size_t buflen, int flags)
{
    int ret; ZZ_RECV(__recv_chk, (s, buf, len, buflen, flags)); return ret;
}
#endif

#define ZZ_RECVFROM(myrecvfrom, myargs) \
    do \
    { \
        LOADSYM(myrecvfrom); \
        \
        ret = ORIG(myrecvfrom) myargs; \
        if (!must_fuzz_fd(s) || !_zz_hostwatched(s)) \
            return ret; \
        \
        if (ret > 0) \
        { \
            _zz_fuzz(s, buf, ret); \
            _zz_addpos(s, ret); \
        } \
        \
        char tmp[128], tmp2[128]; \
        if (ret > 0 && fromlen) \
            sprintf(tmp, "&%i", (int)*fromlen); \
        else if (ret > 0) \
            strcpy(tmp, "NULL"); \
        else \
            tmp[0] = '\0'; \
        debug_str(tmp2, buf, ret, 8); \
        debug("%s(%i, %p, %li, 0x%x, %p, %s) = %i %s", __func__, \
              s, buf, (long int)len, flags, from, tmp, ret, tmp2); \
    } while (0)

#if defined HAVE_RECVFROM
#undef recvfrom
RECV_T NEW(recvfrom)(int s, void *buf, size_t len, int flags,
                     SOCKADDR_T *from, SOCKLEN_T *fromlen)
{
    int ret;
    ZZ_RECVFROM(recvfrom, (s, buf, len, flags, from, fromlen));
    return ret;
}
#endif

#if defined HAVE___RECVFROM_CHK
#undef __recvfrom_chk
extern RECV_T __recvfrom_chk(int s, void *buf, size_t len, size_t buflen,
                             int flags, SOCKADDR_T *from, SOCKLEN_T *fromlen);
RECV_T NEW(__recvfrom_chk)(int s, void *buf, size_t len, size_t buflen,
                           int flags, SOCKADDR_T *from, SOCKLEN_T *fromlen)
{
    int ret;
    ZZ_RECVFROM(__recvfrom_chk, (s, buf, len, buflen, flags, from, fromlen));
    return ret;
}
#endif

#if defined HAVE_RECVMSG
#undef recvmsg
RECV_T NEW(recvmsg)(int s, struct msghdr *hdr, int flags)
{
    LOADSYM(recvmsg);

    ssize_t ret = ORIG(recvmsg)(s, hdr, flags);
    if (!must_fuzz_fd(s) || !_zz_hostwatched(s))
        return ret;

    fuzz_iovec(s, hdr->msg_iov, ret);
    debug("%s(%i, %p, %x) = %li", __func__, s, hdr, flags, (long int)ret);

    return ret;
}
#endif

#define ZZ_READ(myread, myargs) \
    do \
    { \
        LOADSYM(myread); \
        \
        ret = ORIG(myread) myargs; \
        if (!must_fuzz_fd(fd) || !_zz_hostwatched(fd)) \
            return ret; \
        \
        if (ret > 0) \
        { \
            _zz_fuzz(fd, buf, ret); \
            _zz_addpos(fd, ret); \
        } \
        \
        char tmp[128]; \
        debug_str(tmp, buf, ret, 8); \
        debug("%s(%i, %p, %li) = %i %s", __func__, \
              fd, buf, (long int)count, ret, tmp); \
        \
        offset_check(fd); \
    } while (0)

#if defined READ_USES_SSIZE_T
#undef read
ssize_t NEW(read)(int fd, void *buf, size_t count)
{
    int ret; ZZ_READ(read, (fd, buf, count)); return (ssize_t)ret;
}
#else
#undef read
int NEW(read)(int fd, void *buf, unsigned int count)
{
    int ret; ZZ_READ(read, (fd, buf, count)); return ret;
}
#endif

#if defined HAVE___READ_CHK
#undef __read_chk
extern ssize_t __read_chk(int fd, void *buf, size_t count, size_t buflen);
ssize_t NEW(__read_chk)(int fd, void *buf, size_t count, size_t buflen)
{
    int ret; ZZ_READ(__read_chk, (fd, buf, count, buflen)); return (ssize_t)ret;
}
#endif

#if defined HAVE_READV
#undef readv
ssize_t NEW(readv)(int fd, const struct iovec *iov, int count)
{
    LOADSYM(readv);

    ssize_t ret = ORIG(readv)(fd, iov, count);
    if (!must_fuzz_fd(fd))
        return ret;

    fuzz_iovec(fd, iov, ret);
    debug("%s(%i, %p, %i) = %li", __func__, fd, iov, count, (long int)ret);

    offset_check(fd);
    return ret;
}
#endif

#if defined HAVE_PREAD
#undef pread
ssize_t NEW(pread)(int fd, void *buf, size_t count, off_t offset)
{
    LOADSYM(pread);

    int ret = ORIG(pread)(fd, buf, count, offset);
    if (!must_fuzz_fd(fd))
        return ret;

    if (ret > 0)
    {
        long int curoff = _zz_getpos(fd);

        _zz_setpos(fd, offset);
        _zz_fuzz(fd, buf, ret);
        _zz_setpos(fd, curoff);
    }

    char tmp[128];
    debug_str(tmp, buf, ret, 8);
    debug("%s(%i, %p, %li, %li) = %i %s", __func__,
          fd, buf, (long int)count, (long int)offset, ret, tmp);

    return ret;
}
#endif

#define ZZ_LSEEK(mylseek, off_t) \
    do \
    { \
        LOADSYM(mylseek); \
        \
        ret = ORIG(mylseek)(fd, offset, whence); \
        if (!must_fuzz_fd(fd)) \
            return ret; \
        \
        debug("%s(%i, %lli, %i) = %lli", __func__, fd, \
              (long long int)offset, whence, (long long int)ret); \
        if (ret != (off_t)-1) \
            _zz_setpos(fd, ret); \
    } while (0)

#undef lseek
off_t NEW(lseek)(int fd, off_t offset, int whence)
{
    off_t ret;
    ZZ_LSEEK(lseek, off_t);
    return ret;
}

#if defined HAVE_LSEEK64
#undef lseek64
off64_t NEW(lseek64)(int fd, off64_t offset, int whence)
{
    off64_t ret; ZZ_LSEEK(lseek64, off64_t); return ret;
}
#endif

#if defined HAVE___LSEEK64
#undef __lseek64
off64_t NEW(__lseek64)(int fd, off64_t offset, int whence)
{
    off64_t ret; ZZ_LSEEK(__lseek64, off64_t); return ret;
}
#endif

#if defined HAVE_AIO_READ
#undef aio_read
int NEW(aio_read)(struct aiocb *aiocbp)
{
    LOADSYM(aio_read);

    int fd = aiocbp->aio_fildes;
    if (!g_libzzuf_ready || !_zz_iswatched(fd) || !_zz_isactive(fd))
        return ORIG(aio_read)(aiocbp);

    _zz_lockfd(fd);
    int ret = ORIG(aio_read)(aiocbp);

    debug("%s({%i, %i, %i, %p, %li, ..., %li}) = %i", __func__,
          fd, aiocbp->aio_lio_opcode, aiocbp->aio_reqprio, aiocbp->aio_buf,
          (long int)aiocbp->aio_nbytes, (long int)aiocbp->aio_offset, ret);

    return ret;
}

#undef aio_return
ssize_t NEW(aio_return)(struct aiocb *aiocbp)
{
    LOADSYM(aio_return);

    int fd = aiocbp->aio_fildes;
    if (!g_libzzuf_ready || !_zz_iswatched(fd) || !_zz_isactive(fd))
        return ORIG(aio_return)(aiocbp);

    ssize_t ret = ORIG(aio_return)(aiocbp);
    _zz_unlock(fd);

    /* FIXME: make sure we’re actually *reading* */
    if (ret > 0)
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
#endif

#undef close
int NEW(close)(int fd)
{
    LOADSYM(close);

    /* Hey, it’s our debug channel! Silently pretend we closed it. */
    if (fd == g_debug_fd)
        return 0;

    int ret = ORIG(close)(fd);
    if (!g_libzzuf_ready || !_zz_iswatched(fd) || _zz_islocked(fd))
        return ret;

    debug("%s(%i) = %i", __func__, fd, ret);
    _zz_unregister(fd);

    return ret;
}

/* XXX: the following functions are local */

#if defined HAVE_READV || defined HAVE_RECVMSG
static void fuzz_iovec(int fd, const struct iovec *iov, ssize_t ret)
{
    /* NOTE: We assume that iov countains at least <ret> bytes. */
    while (ret > 0)
    {
        void *b = iov->iov_base;
        size_t len = iov->iov_len;

        if (len > (size_t)ret)
            len = ret;

        _zz_fuzz(fd, b, len);
        _zz_addpos(fd, len);

        iov++;
        ret -= len;
    }
}
#endif

/* Sanity check, can be OK though (for instance with a character device) */
static void offset_check(int fd)
{
    int orig_errno = errno;
#if defined HAVE_LSEEK64
    LOADSYM(lseek64);

    off64_t ret = ORIG(lseek64)(fd, 0, SEEK_CUR);
#else
    LOADSYM(lseek);

    off_t ret = ORIG(lseek)(fd, 0, SEEK_CUR);
#endif
    if (ret != -1 && ret != _zz_getpos(fd))
        debug("warning: lseek(%d, 0, SEEK_CUR) = %lli (expected %lli)",
              fd, (long long int)ret, (long long int)_zz_getpos(fd));
    errno = orig_errno;
}

/* Utility function to know how many bytes are left until the end of
 * the file. */
size_t _zz_bytes_until_eof(int fd, size_t offset)
{
    int orig_errno = errno;
#if defined HAVE_LSEEK64
    LOADSYM(lseek64);

    off64_t current = ORIG(lseek64)(fd, 0, SEEK_CUR);
    off64_t begin = ORIG(lseek64)(fd, offset, SEEK_CUR);
    off64_t end = ORIG(lseek64)(fd, 0, SEEK_END);
    ORIG(lseek64)(fd, current, SEEK_SET);
#else
    LOADSYM(lseek);

    off_t current = ORIG(lseek)(fd, 0, SEEK_CUR);
    off_t begin = ORIG(lseek)(fd, offset, SEEK_CUR);
    off_t end = ORIG(lseek)(fd, 0, SEEK_END);
    ORIG(lseek)(fd, current, SEEK_SET);
#endif
    errno = orig_errno;

    return (begin >= end) ? 0 : (size_t)(end - begin);
}

