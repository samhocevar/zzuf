/*
 *  zzuf - general purpose fuzzer
 *
 *  Copyright © 2002—2016 Sam Hocevar <sam@hocevar.net>
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by the WTFPL Task Force.
 *  See http://www.wtfpl.net/ for more details.
 */

/*
 *  load-stream.c: loaded stream functions
 */

#include "config.h"

/* Needed for getline() and getdelim() */
#define _GNU_SOURCE
/* Needed for getc_unlocked() on OpenSolaris */
#define __EXTENSIONS__

/* Define the best ftell() clone */
#if defined HAVE_FTELLO64
#   define ZZ_FTELL ftello64
#elif defined HAVE___FTELLO64
#   define ZZ_FTELL __ftello64
#elif defined HAVE_FTELLO
#   define ZZ_FTELL ftello
#else
#   define ZZ_FTELL ftell
#endif

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>
#include <string.h> /* Needed for memcpy */

#include <stdio.h>
#include <sys/types.h>
#if defined HAVE_UNISTD_H
#   include <unistd.h> /* Needed for __srefill’s lseek() call */
#endif

#include "common.h"
#include "libzzuf.h"
#include "lib-load.h"
#include "debug.h"
#include "fuzz.h"
#include "fd.h"

#if defined HAVE_FPOS64_T
#   define FPOS64_T fpos64_t
#else
#   define FPOS64_T fpos_t
#endif

#if defined HAVE___SREFILL
#undef __srefill
int NEW(__srefill)(FILE *fp);
#endif

#if defined HAVE___FILBUF
#undef __filbuf
int NEW(__filbuf)(FILE *fp);
#endif

#if defined HAVE___SRGET && !defined HAVE___SREFILL
#undef __srget
int NEW(__srget)(FILE *fp);
#endif

#if defined HAVE___UFLOW
#undef __uflow
int NEW(__uflow)(FILE *fp);
#endif

/* Library functions that we divert */
static FILE *  (*ORIG(fopen))    (const char *path, const char *mode);
#if defined HAVE_FOPEN64
static FILE *  (*ORIG(fopen64))  (const char *path, const char *mode);
#endif
#if defined HAVE___FOPEN64
static FILE *  (*ORIG(__fopen64))(const char *path, const char *mode);
#endif
static FILE *  (*ORIG(freopen))  (const char *path, const char *mode,
                                  FILE *stream);
#if defined HAVE_FREOPEN64
static FILE *  (*ORIG(freopen64))(const char *path, const char *mode,
                                  FILE *stream);
#endif
#if defined HAVE___FREOPEN64
static FILE *  (*ORIG(__freopen64)) (const char *path, const char *mode,
                                     FILE *stream);
#endif
static int     (*ORIG(fseek))    (FILE *stream, long offset, int whence);
#if defined HAVE_FSEEKO
static int     (*ORIG(fseeko))   (FILE *stream, off_t offset, int whence);
#endif
#if defined HAVE_FSEEKO64
static int     (*ORIG(fseeko64)) (FILE *stream, off64_t offset, int whence);
#endif
#if defined HAVE___FSEEKO64
static int     (*ORIG(__fseeko64)) (FILE *stream, off64_t offset, int whence);
#endif
#if defined HAVE_FSETPOS64
static int     (*ORIG(fsetpos64))(FILE *stream, const FPOS64_T *pos);
#endif
#if defined HAVE___FSETPOS64
static int     (*ORIG(__fsetpos64)) (FILE *stream, const FPOS64_T *pos);
#endif
static void    (*ORIG(rewind))   (FILE *stream);
static size_t  (*ORIG(fread))    (void *ptr, size_t size, size_t nmemb,
                                  FILE *stream);
#if defined HAVE_FREAD_UNLOCKED
static size_t  (*ORIG(fread_unlocked))  (void *ptr, size_t size, size_t nmemb,
                                         FILE *stream);
#endif
#if defined HAVE___FREAD_CHK
static size_t  (*ORIG(__fread_chk))  (void *ptr, size_t ptrlen, size_t size,
                                      size_t nmemb, FILE *stream);
#endif
#if defined HAVE___FREAD_UNLOCKED_CHK
static size_t  (*ORIG(__fread_unlocked_chk)) (void *ptr, size_t ptrlen, size_t
                                              size, size_t nmemb, FILE *stream);
#endif
static int     (*ORIG(getc))     (FILE *stream);
static int     (*ORIG(getchar))  (void);
static int     (*ORIG(fgetc))    (FILE *stream);
#if defined HAVE__IO_GETC
static int     (*ORIG(_IO_getc)) (FILE *stream);
#endif
#if defined HAVE_GETC_UNLOCKED
static int     (*ORIG(getc_unlocked))    (FILE *stream);
#endif
#if defined HAVE_GETCHAR_UNLOCKED
static int     (*ORIG(getchar_unlocked)) (void);
#endif
#if defined HAVE_FGETC_UNLOCKED
static int     (*ORIG(fgetc_unlocked))   (FILE *stream);
#endif
static char *  (*ORIG(fgets))    (char *s, int size, FILE *stream);
#if defined HAVE_FGETS_UNLOCKED
static char *  (*ORIG(fgets_unlocked))   (char *s, int size, FILE *stream);
#endif
#if defined HAVE___FGETS_CHK
static char *  (*ORIG(__fgets_chk)) (char *s, size_t ptrlen,
                                     int size, FILE *stream);
#endif
#if defined HAVE___FGETS_UNLOCKED_CHK
static char *  (*ORIG(__fgets_unlocked_chk)) (char *s, size_t ptrlen,
                                              int size, FILE *stream);
#endif
static int     (*ORIG(ungetc))   (int c, FILE *stream);
static int     (*ORIG(fclose))   (FILE *fp);

/* Additional GNUisms */
#if defined HAVE_GETLINE
static ssize_t (*ORIG(getline))    (char **lineptr, size_t *n, FILE *stream);
#endif
#if defined HAVE_GETDELIM
static ssize_t (*ORIG(getdelim))   (char **lineptr, size_t *n, int delim,
                                    FILE *stream);
#endif
#if defined HAVE___GETDELIM
static ssize_t (*ORIG(__getdelim)) (char **lineptr, size_t *n, int delim,
                                    FILE *stream);
#endif
#if defined HAVE___UFLOW
static int     (*ORIG(__uflow))    (FILE *fp);
#endif

/* Additional BSDisms */
#if defined HAVE_FGETLN
static char *  (*ORIG(fgetln))    (FILE *stream, size_t *len);
#endif
#if defined HAVE___SREFILL
int            (*ORIG(__srefill)) (FILE *fp);
#endif
#if defined HAVE___SRGET && !defined HAVE___SREFILL
int            (*ORIG(__srget))   (FILE *fp);
#endif

/* Additional HP-UXisms */
#if defined HAVE___FILBUF
int            (*ORIG(__filbuf))  (FILE *fp);
#endif

/* Helper functions for refill-like functions */
static inline uint8_t * get_streambuf_base(FILE *stream)
{
#if defined HAVE_GLIBC_FILE
    return (uint8_t *)stream->_IO_read_base;
#elif defined HAVE_FREEBSD_FILE
    return (uint8_t *)stream->_bf._base;
#elif defined HAVE_SOLARIS_FILE
    return (uint8_t *)stream->_base;
#else
    (void)stream;
    return NULL;
#endif
}

static inline uint8_t *get_streambuf_pos(FILE *stream)
{
#if defined HAVE_GLIBC_FILE
    return (uint8_t *)stream->_IO_read_ptr;
#elif defined HAVE_FREEBSD_FILE
    return (uint8_t *)stream->_p;
#elif defined HAVE_SOLARIS_FILE
    return (uint8_t *)stream->_ptr;
#else
    (void)stream;
    return NULL;
#endif
}

static inline int get_streambuf_count(FILE *stream)
{
#if defined HAVE_GLIBC_FILE
    return (int)((uint8_t *)stream->_IO_read_end
                  - (uint8_t *)stream->_IO_read_ptr);
#elif defined HAVE_FREEBSD_FILE
    return stream->_r;
#elif defined HAVE_SOLARIS_FILE
    return stream->_cnt;
#else
    (void)stream;
    return 0;
#endif
}

static inline int get_streambuf_offset(FILE *stream)
{
    return (int)(get_streambuf_pos(stream) - get_streambuf_base(stream));
}

static inline int get_streambuf_size(FILE *stream)
{
    return get_streambuf_offset(stream) + get_streambuf_count(stream);
}

static char const *get_seek_mode_name(int mode)
{
    /* We don’t use switch/case to avoid duplicate labels */
    if (mode == SEEK_CUR)
        return "SEEK_CUR";
    if (mode == SEEK_SET)
        return "SEEK_SET";
    if (mode == SEEK_END)
        return "SEEK_END";
    return "SEEK_???";
}

static inline void debug_stream(char const *prefix, FILE *s)
{
    char tmp1[128], tmp2[128];
    debug_str(tmp1, get_streambuf_base(s), get_streambuf_offset(s), 10);
    debug_str(tmp2, get_streambuf_pos(s), get_streambuf_count(s), 10);

    debug2("... %s: stream([%i], %p + %i %s + %i %s)", prefix, fileno(s),
           get_streambuf_base(s), get_streambuf_offset(s), tmp1,
           get_streambuf_count(s), tmp2);
}

/*
 * fopen, fopen64 etc.
 * freopen, freopen64 etc.
 *
 * Strategy: we call the original function, register the new file descriptor
 * and immediately fuzz whatever's preloaded in the stream structure.
 */

#define ZZ_FOPEN(myfopen) \
    do \
    { \
        LOADSYM(myfopen); \
        \
        if (!g_libzzuf_ready) \
            return ORIG(myfopen)(path, mode); \
        _zz_lockfd(-1); \
        ret = ORIG(myfopen)(path, mode); \
        _zz_unlock(-1); \
        if (ret && _zz_mustwatch(path)) \
        { \
            int fd = fileno(ret); \
            _zz_register(fd); \
            _zz_fuzz(fd, get_streambuf_base(ret), get_streambuf_size(ret)); \
            debug_stream("after", ret); \
            debug("%s(\"%s\", \"%s\") = [%i]", __func__, path, mode, fd); \
        } \
    } while (0)

#define ZZ_FREOPEN(myfreopen) \
    do \
    { \
        LOADSYM(myfreopen); \
        \
        int fd0 = -1, fd1 = -1, disp = 0; \
        if (g_libzzuf_ready && (fd0 = fileno(stream)) >= 0 && _zz_iswatched(fd0)) \
        { \
            _zz_unregister(fd0); \
            disp = 1; \
        } \
        _zz_lockfd(-1); \
        ret = ORIG(myfreopen)(path, mode, stream); \
        _zz_unlock(-1); \
        if (ret && _zz_mustwatch(path)) \
        { \
            fd1 = fileno(ret); \
            _zz_register(fd1); \
            _zz_fuzz(fd1, get_streambuf_base(ret), get_streambuf_size(ret)); \
            disp = 1; \
        } \
        if (disp) \
            debug("%s(\"%s\", \"%s\", [%i]) = [%i]", __func__, \
                  path, mode, fd0, fd1); \
    } while (0)

#undef fopen
FILE *NEW(fopen)(const char *path, const char *mode)
{
    FILE *ret; ZZ_FOPEN(fopen); return ret;
}

#if defined HAVE_FOPEN64
#undef fopen64
FILE *NEW(fopen64)(const char *path, const char *mode)
{
    FILE *ret; ZZ_FOPEN(fopen64); return ret;
}
#endif

#if defined HAVE___FOPEN64
#undef __fopen64
FILE *NEW(__fopen64)(const char *path, const char *mode)
{
    FILE *ret; ZZ_FOPEN(__fopen64); return ret;
}
#endif

#undef freopen
FILE *NEW(freopen)(const char *path, const char *mode, FILE *stream)
{
    FILE *ret; ZZ_FREOPEN(freopen); return ret;
}

#if defined HAVE_FREOPEN64
#undef freopen64
FILE *NEW(freopen64)(const char *path, const char *mode, FILE *stream)
{
    FILE *ret; ZZ_FREOPEN(freopen64); return ret;
}
#endif

#if defined HAVE___FREOPEN64
#undef __freopen64
FILE *NEW(__freopen64)(const char *path, const char *mode, FILE *stream)
{
    FILE *ret; ZZ_FREOPEN(__freopen64); return ret;
}
#endif

/* Quick shuffle table:
 * strings /dev/urandom | grep . -nm256 | sort -k2 -t: | sed 's|:.*|,|'
 * Then just replace “256” with “0”. */
static int const shuffle[256] =
{
    111, 14, 180, 186, 221, 114, 219, 79, 66, 46, 152, 81, 246, 200,
    141, 172, 85, 244, 112, 92, 34, 106, 218, 205, 236, 7, 121, 115,
    109, 131, 10, 96, 188, 148, 17, 107, 94, 182, 235, 163, 143, 63,
    248, 202, 52, 154, 37, 241, 53, 129, 25, 159, 242, 38, 171, 213,
    6, 203, 255, 193, 42, 209, 28, 176, 210, 60, 54, 144, 3, 71, 89,
    116, 12, 237, 67, 216, 252, 178, 174, 164, 98, 234, 32, 26, 175,
    24, 130, 128, 113, 99, 212, 62, 11, 75, 185, 73, 93, 31, 30, 44,
    122, 173, 139, 91, 136, 162, 194, 41, 56, 101, 68, 69, 211, 151,
    97, 55, 83, 33, 50, 119, 156, 149, 208, 157, 253, 247, 161, 133,
    230, 166, 225, 204, 224, 13, 110, 123, 142, 64, 65, 155, 215, 9,
    197, 140, 58, 77, 214, 126, 195, 179, 220, 232, 125, 147, 8, 39,
    187, 27, 217, 100, 134, 199, 88, 206, 231, 250, 74, 2, 135, 120,
    21, 245, 118, 243, 82, 183, 238, 150, 158, 61, 4, 177, 146, 153,
    117, 249, 254, 233, 90, 222, 207, 48, 15, 18, 20, 16, 47, 0, 51,
    165, 138, 127, 169, 72, 1, 201, 145, 191, 192, 239, 49, 19, 160,
    226, 228, 84, 181, 251, 36, 87, 22, 43, 70, 45, 105, 5, 189, 95,
    40, 196, 59, 57, 190, 80, 104, 167, 78, 124, 103, 240, 184, 170,
    137, 29, 23, 223, 108, 102, 86, 198, 227, 35, 229, 76, 168, 132,
};

/*
 * fseek, fseeko etc.
 * fsetpos64, __fsetpos64
 * rewind
 *
 * Strategy: we store the previous file position and internal buffer
 * status, then call the original function. If the new file position
 * lies outside the previous internal buffer, it means the buffer has
 * been invalidated, so we fuzz whatever's preloaded in it.
 *
 * It may also happen that the internal buffer is re-filled for no
 * reason, as is the case on glibc versions from ca. 2015. Since we
 * have no robust way of detecting this, we save the internal buffer
 * to a temporary area and replace it with pseudorandom data, then
 * check the data for changes after the fseek() call.
 */

#define ZZ_FSEEK(myfseek) \
    do \
    { \
        LOADSYM(myfseek); \
        \
        int fd = fileno(stream); \
        if (!must_fuzz_fd(fd)) \
            return ORIG(myfseek)(stream, offset, whence); \
        \
        debug_stream("before", stream); \
        /* FIXME: ftell() will return -1 on a pipe such as stdin */ \
        int64_t oldpos = ZZ_FTELL(stream); \
        int oldoff = get_streambuf_offset(stream); \
        int oldcnt = get_streambuf_count(stream); \
        \
        /* backup the internal stream buffer and replace it with
         * some random data in order to detect possible changes. */ \
        uint8_t seed = shuffle[fd & 0xff]; \
        uint8_t oldbuf[oldoff + oldcnt]; \
        uint8_t *buf = get_streambuf_base(stream); \
        for (int i = 0; i < oldoff + oldcnt; ++i) \
        { \
            oldbuf[i] = buf[i]; \
            buf[i] = shuffle[(i + seed) & 0xff]; \
        } \
        \
        _zz_lockfd(fd); \
        ret = ORIG(myfseek)(stream, offset, whence); \
        _zz_unlock(fd); \
        \
        int64_t newpos = ZZ_FTELL(stream); \
        int newoff = get_streambuf_offset(stream); \
        int newcnt = get_streambuf_count(stream); \
        int changed = (newpos > oldpos + oldcnt || newpos < oldpos - oldoff \
             || (newpos == oldpos + oldcnt && newcnt != 0) \
             || (newoff + newcnt != oldoff + oldcnt)); \
        \
        /* check whether the buffer contents have changed */ \
        uint8_t *newbuf = get_streambuf_base(stream); \
        for (int i = 0; !changed && i < newoff + newcnt; ++i) \
            if (newbuf[i] != shuffle[(i + seed) & 0xff]) \
                changed = 1; \
        \
        /* if the internal buffer has not changed, restore it */ \
        if (!changed) \
            memcpy(newbuf, oldbuf, newoff + newcnt); \
        \
        debug_stream(changed ? "modified" : "unchanged", stream); \
        if (changed) \
        { \
            _zz_setpos(fd, newpos - get_streambuf_offset(stream)); \
            _zz_fuzz(fd, get_streambuf_base(stream), get_streambuf_size(stream)); \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        debug("%s([%i], %lli, %s) = %i", __func__, \
              fd, (long long int)offset, get_seek_mode_name(whence), ret); \
    } while (0)

#if HAVE_FPOS64_T
#   define FPOS_T_TO_INT64_T(x) ((int64_t)FPOS64_CAST(x))
#else
#   define FPOS_T_TO_INT64_T(x) ((int64_t)(x))
#endif

#define ZZ_FSETPOS(myfsetpos) \
    do \
    { \
        LOADSYM(myfsetpos); \
        \
        int fd = fileno(stream); \
        if (!must_fuzz_fd(fd)) \
            return ORIG(myfsetpos)(stream, pos); \
        \
        debug_stream("before", stream); \
        /* FIXME: ftell() will return -1 on a pipe such as stdin */ \
        int64_t oldpos = ZZ_FTELL(stream); \
        int oldoff = get_streambuf_offset(stream); \
        int oldcnt = get_streambuf_count(stream); \
        _zz_lockfd(fd); \
        ret = ORIG(myfsetpos)(stream, pos); \
        _zz_unlock(fd); \
        int64_t newpos = ZZ_FTELL(stream); \
        int newcnt = get_streambuf_count(stream); \
        int changed = (newpos > oldpos + oldcnt || newpos < oldpos - oldoff \
             || (newpos == oldpos + oldcnt && newcnt != 0)); \
        debug_stream(changed ? "modified" : "unchanged", stream); \
        if (changed) \
        { \
            _zz_setpos(fd, newpos - get_streambuf_offset(stream)); \
            _zz_fuzz(fd, get_streambuf_base(stream), get_streambuf_size(stream)); \
        } \
        _zz_setpos(fd, FPOS_T_TO_INT64_T(*pos)); \
        debug_stream("after", stream); \
        debug("%s([%i], %lli) = %i", __func__, \
              fd, (long long int)FPOS_T_TO_INT64_T(*pos), ret); \
    } \
    while (0)

#define ZZ_REWIND(myrewind) \
    do \
    { \
        LOADSYM(rewind); \
        \
        int fd = fileno(stream); \
        if (!must_fuzz_fd(fd)) \
        { \
            ORIG(rewind)(stream); \
            return; \
        } \
        debug_stream("before", stream); \
        /* FIXME: ftell() will return -1 on a pipe such as stdin */ \
        int64_t oldpos = ZZ_FTELL(stream); \
        int oldoff = get_streambuf_offset(stream); \
        int oldcnt = get_streambuf_count(stream); \
        _zz_lockfd(fd); \
        ORIG(rewind)(stream); \
        _zz_unlock(fd); \
        int64_t newpos = ZZ_FTELL(stream); \
        int newcnt = get_streambuf_count(stream); \
        int changed = (newpos > oldpos + oldcnt || newpos < oldpos - oldoff \
             || (newpos == oldpos + oldcnt && newcnt != 0)); \
        debug_stream(changed ? "modified" : "unchanged", stream); \
        if (changed) \
        { \
            _zz_setpos(fd, newpos - get_streambuf_offset(stream)); \
            _zz_fuzz(fd, get_streambuf_base(stream), get_streambuf_size(stream)); \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        debug("%s([%i])", __func__, fd); \
    } while (0)

#undef fseek
int NEW(fseek)(FILE *stream, long offset, int whence)
{
    int ret; ZZ_FSEEK(fseek); return ret;
}

#if defined HAVE_FSEEKO
#undef fseeko
int NEW(fseeko)(FILE *stream, off_t offset, int whence)
{
    int ret; ZZ_FSEEK(fseeko); return ret;
}
#endif

#if defined HAVE_FSEEKO64
#undef fseeko64
int NEW(fseeko64)(FILE *stream, off64_t offset, int whence)
{
    int ret; ZZ_FSEEK(fseeko64); return ret;
}
#endif

#if defined HAVE___FSEEKO64
#undef __fseeko64
int NEW(__fseeko64)(FILE *stream, off64_t offset, int whence)
{
    int ret; ZZ_FSEEK(__fseeko64); return ret;
}
#endif

#if defined HAVE_FSETPOS64
#undef fsetpos64
int NEW(fsetpos64)(FILE *stream, const FPOS64_T *pos)
{
    int ret; ZZ_FSETPOS(fsetpos64); return ret;
}
#endif

#if defined HAVE___FSETPOS64
#undef __fsetpos64
int NEW(__fsetpos64)(FILE *stream, const FPOS64_T *pos)
{
    int ret; ZZ_FSETPOS(__fsetpos64); return ret;
}
#endif

#undef rewind
void NEW(rewind)(FILE *stream)
{
    ZZ_REWIND(rewind);
}

/*
 * fread, fread_unlocked
 *
 * Strategy: we store the previous file position and internal buffer
 * status, then call the original function. If the new file position
 * lies outside the previous internal buffer, it means the buffer has
 * been invalidated, so we fuzz whatever's preloaded in it.
 */

#define ZZ_FREAD(myfread, myargs) /* NEW */ \
    do \
    { \
        LOADSYM(myfread); \
        \
        uint8_t *b = (uint8_t *)ptr; \
        int fd = fileno(stream); \
        if (!must_fuzz_fd(fd)) \
            return ORIG(myfread) myargs; \
        \
        debug_stream("before", stream); \
        /* FIXME: ftell() will return -1 on a pipe such as stdin */ \
        int64_t oldpos = ZZ_FTELL(stream); \
        int oldcnt = get_streambuf_count(stream); \
        _zz_lockfd(fd); \
        ret = ORIG(myfread) myargs; \
        _zz_unlock(fd); \
        int64_t newpos = ZZ_FTELL(stream); \
        int newcnt = get_streambuf_count(stream); \
        int changed = (newpos > oldpos + oldcnt \
             || (newpos == oldpos + oldcnt && newcnt != 0)); \
        debug_stream(changed ? "modified" : "unchanged", stream); \
        if (changed) \
        { \
            /* The internal stream buffer is completely different, so we need
             * to fuzz it entirely. */ \
            _zz_setpos(fd, newpos - get_streambuf_offset(stream)); \
            _zz_fuzz(fd, get_streambuf_base(stream), get_streambuf_size(stream)); \
            /* Fuzz returned data that wasn't in the old internal buffer */ \
            _zz_setpos(fd, oldpos + oldcnt); \
            _zz_fuzz(fd, b + oldcnt, newpos - oldpos - oldcnt); \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        \
        char tmp[128]; \
        debug_str(tmp, b, newpos - oldpos, 8); \
        debug("%s(%p, %li, %li, [%i]) = %li %s", __func__, ptr, \
              (long int)size, (long int)nmemb, fd, (long int)ret, tmp); \
    } while (0)

#undef fread
size_t NEW(fread)(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret; ZZ_FREAD(fread, (ptr, size, nmemb, stream)); return ret;
}

#if defined HAVE_FREAD_UNLOCKED
#undef fread_unlocked
size_t NEW(fread_unlocked)(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret;
    ZZ_FREAD(fread_unlocked, (ptr, size, nmemb, stream));
    return ret;
}
#endif

#if defined HAVE___FREAD_CHK
#undef __fread_chk
extern size_t __fread_chk(void *ptr, size_t ptrlen, size_t size,
                          size_t nmemb, FILE *stream);
size_t NEW(__fread_chk)(void *ptr, size_t ptrlen, size_t size, size_t nmemb,
                        FILE *stream)
{
    size_t ret;
    ZZ_FREAD(__fread_chk, (ptr, ptrlen, size, nmemb, stream));
    return ret;
}
#endif

#if defined HAVE___FREAD_UNLOCKED_CHK
#undef __fread_unlocked_chk
extern size_t __fread_unlocked_chk(void *ptr, size_t ptrlen, size_t size,
                                   size_t nmemb, FILE *stream);
size_t NEW(__fread_unlocked_chk)(void *ptr, size_t ptrlen, size_t size,
                                 size_t nmemb, FILE *stream)
{
    size_t ret;
    ZZ_FREAD(__fread_unlocked_chk, (ptr, ptrlen, size, nmemb, stream));
    return ret;
}
#endif

/*
 * getc, getchar, fgetc etc.
 *
 * Strategy: we store the previous file position and internal buffer
 * status, then call the original function. If the new file position
 * lies outside the previous internal buffer, it means the buffer has
 * been invalidated, so we fuzz whatever's preloaded in it.
 */

#define ZZ_FGETC(myfgetc, stream, arg) \
    do { \
        LOADSYM(myfgetc); \
        \
        int fd = fileno(stream); \
        if (!must_fuzz_fd(fd)) \
            return ORIG(myfgetc)(arg); \
        \
        debug_stream("before", stream); \
        int64_t oldpos = ZZ_FTELL(stream); \
        int oldcnt = get_streambuf_count(stream); \
        _zz_lockfd(fd); \
        ret = ORIG(myfgetc)(arg); \
        _zz_unlock(fd); \
        int64_t newpos = ZZ_FTELL(stream); \
        int newcnt = get_streambuf_count(stream); \
        int changed = (newpos > oldpos + oldcnt \
             || (newpos == oldpos + oldcnt && newcnt != 0)); \
        debug_stream(changed ? "modified" : "unchanged", stream); \
        if (oldcnt == 0 && ret != EOF) \
        { \
            /* Fuzz returned data that wasn't in the old internal buffer */ \
            uint8_t ch = ret; \
            _zz_setpos(fd, oldpos); \
            _zz_fuzz(fd, &ch, 1); \
            ret = ch; \
        } \
        if (changed) \
        { \
            /* Fuzz the internal stream buffer */ \
            _zz_setpos(fd, newpos - get_streambuf_offset(stream)); \
            _zz_fuzz(fd, get_streambuf_base(stream), get_streambuf_size(stream)); \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        if (ret == EOF) \
            debug("%s([%i]) = EOF", __func__, fd); \
        else \
            debug("%s([%i]) = '%c'", __func__, fd, ret); \
    } while (0)

#undef getc
int NEW(getc)(FILE *stream)
{
    int ret; ZZ_FGETC(getc, stream, stream); return ret;
}

#undef getchar
int NEW(getchar)(void)
{
    int ret; ZZ_FGETC(getchar, stdin, /* empty */); return ret;
}

#undef fgetc
int NEW(fgetc)(FILE *stream)
{
    int ret; ZZ_FGETC(fgetc, stream, stream); return ret;
}

#if defined HAVE__IO_GETC
#undef _IO_fgetc
int NEW(_IO_getc)(FILE *stream)
{
    int ret; ZZ_FGETC(_IO_getc, stream, stream); return ret;
}
#endif

#if defined HAVE_GETC_UNLOCKED
#undef getc_unlocked
int NEW(getc_unlocked)(FILE *stream)
{
    int ret; ZZ_FGETC(getc_unlocked, stream, stream); return ret;
}
#endif

#if defined HAVE_GETCHAR_UNLOCKED
#undef getchar_unlocked
int NEW(getchar_unlocked)(void)
{
    int ret; ZZ_FGETC(getchar_unlocked, stdin, /* empty */); return ret;
}
#endif

#if defined HAVE_FGETC_UNLOCKED
#undef fgetc_unlocked
int NEW(fgetc_unlocked)(FILE *stream)
{
    int ret; ZZ_FGETC(fgetc_unlocked, stream, stream); return ret;
}
#endif

/*
 * fgets, fgets_unlocked
 */

#define ZZ_FGETS(myfgets, myfgetc, myargs) \
    do \
    { \
        LOADSYM(myfgets); \
        LOADSYM(myfgetc); \
        \
        ret = s; \
        int fd = fileno(stream); \
        if (!must_fuzz_fd(fd)) \
            return ORIG(myfgets) myargs; \
        \
        debug_stream("before", stream); \
        int64_t oldpos = ZZ_FTELL(stream); \
        int oldcnt = get_streambuf_count(stream); \
        int64_t newpos = oldpos; \
        if (size <= 0) \
            ret = NULL; \
        else if (size == 1) \
            s[0] = '\0'; \
        else \
        { \
            for (int i = 0; i < size - 1; ++i) \
            { \
                int chr; \
                _zz_lockfd(fd); \
                chr = ORIG(myfgetc)(stream); \
                _zz_unlock(fd); \
                newpos = oldpos + 1; \
                if (oldcnt == 0 && chr != EOF) \
                { \
                    /* Fuzz returned data that wasn't in the old buffer */ \
                    uint8_t ch = chr; \
                    _zz_setpos(fd, oldpos); \
                    _zz_fuzz(fd, &ch, 1); \
                    chr = ch; \
                } \
                int newcnt = get_streambuf_count(stream); \
                if (newpos > oldpos + oldcnt \
                     || (newpos == oldpos + oldcnt && newcnt != 0)) \
                { \
                    /* Fuzz the internal stream buffer, if necessary */ \
                    _zz_setpos(fd, newpos - get_streambuf_offset(stream)); \
                    _zz_fuzz(fd, get_streambuf_base(stream), \
                                 get_streambuf_size(stream)); \
                } \
                oldpos = newpos; \
                oldcnt = newcnt; \
                if (chr == EOF) \
                { \
                    s[i] = '\0'; \
                    if (!i) \
                        ret = NULL; \
                    break; \
                } \
                s[i] = (char)(unsigned char)chr; \
                if (s[i] == '\n') \
                { \
                    s[i + 1] = '\0'; \
                    break; \
                } \
            } \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        debug("%s(%p, %i, [%i]) = %p", __func__, s, size, fd, ret); \
    } while (0)

#undef fgets
char *NEW(fgets)(char *s, int size, FILE *stream)
{
    char *ret; ZZ_FGETS(fgets, fgetc, (s, size, stream)); return ret;
}

#if defined HAVE_FGETS_UNLOCKED
#undef fgets_unlocked
char *NEW(fgets_unlocked)(char *s, int size, FILE *stream)
{
    char *ret;
    ZZ_FGETS(fgets_unlocked, fgetc_unlocked, (s, size, stream));
    return ret;
}
#endif

#if defined HAVE___FGETS_CHK
#undef __fgets_chk
extern char *__fgets_chk(char *s, size_t ptrlen, int size, FILE *stream);
char *NEW(__fgets_chk)(char *s, size_t ptrlen, int size, FILE *stream)
{
    char *ret;
    ZZ_FGETS(__fgets_chk, fgetc, (s, ptrlen, size, stream));
    return ret;
}
#endif

#if defined HAVE___FGETS_UNLOCKED_CHK
#undef __fgets_unlocked_chk
extern char *__fgets_unlocked_chk(char *s, size_t ptrlen, int size,
                                  FILE *stream);
char *NEW(__fgets_unlocked_chk)(char *s, size_t ptrlen, int size,
                                FILE *stream)
{
    char *ret;
    ZZ_FGETS(__fgets_unlocked_chk, fgetc_unlocked, (s, ptrlen, size, stream));
    return ret;
}
#endif

/*
 * ungetc
 */

#undef ungetc
int NEW(ungetc)(int c, FILE *stream)
{
    LOADSYM(ungetc);

    int fd = fileno(stream);
    if (!must_fuzz_fd(fd))
        return ORIG(ungetc)(c, stream);

    debug_stream("before", stream);
    int oldpos = ZZ_FTELL(stream);
    _zz_lockfd(fd);
    int ret = ORIG(ungetc)(c, stream);
    _zz_unlock(fd);
    _zz_setpos(fd, oldpos - 1);

    debug_stream("after", stream);
    if (ret == EOF)
        debug("%s(0x%02x, [%i]) = EOF", __func__, c, fd);
    else
        debug("%s(0x%02x, [%i]) = '%c'", __func__, c, fd, ret);
    return ret;
}

/*
 * fclose
 */

#undef fclose
int NEW(fclose)(FILE *fp)
{
    LOADSYM(fclose);

    int fd = fileno(fp);
    if (!g_libzzuf_ready || !_zz_iswatched(fd))
        return ORIG(fclose)(fp);

    debug_stream("before", fp);
    _zz_lockfd(fd);
    int ret = ORIG(fclose)(fp);
    _zz_unlock(fd);
    debug("%s([%i]) = %i", __func__, fd, ret);
    _zz_unregister(fd);

    return ret;
}

/*
 * getline, getdelim etc.
 */

#define ZZ_GETDELIM(mygetdelim, delim, need_delim) \
    do { \
        LOADSYM(mygetdelim); \
        LOADSYM(getdelim); \
        LOADSYM(fgetc); \
        \
        int fd = fileno(stream); \
        if (!must_fuzz_fd(fd)) \
            return ORIG(getdelim)(lineptr, n, delim, stream); \
        \
        debug_stream("before", stream); \
        int64_t oldpos = ZZ_FTELL(stream); \
        int oldcnt = get_streambuf_count(stream); \
        int64_t newpos = oldpos; \
        char *line = *lineptr; \
        ssize_t size = line ? *n : 0; \
        ssize_t done = 0; \
        int finished = 0; \
        ret = 0; \
        for (;;) \
        { \
            int chr; \
            if (done >= size) /* highly inefficient but I don't care */ \
                line = realloc(line, size = done + 1); \
            if (finished) \
            { \
                line[done] = '\0'; \
                *n = size; \
                *lineptr = line; \
                break; \
            } \
            _zz_lockfd(fd); \
            chr = ORIG(fgetc)(stream); \
            _zz_unlock(fd); \
            newpos = oldpos + 1; \
            if (oldcnt == 0 && chr != EOF) \
            { \
                /* Fuzz returned data that wasn't in the old buffer */ \
                uint8_t ch = chr; \
                _zz_setpos(fd, oldpos); \
                _zz_fuzz(fd, &ch, 1); \
                chr = ch; \
            } \
            int newcnt = get_streambuf_count(stream); \
            if (newpos > oldpos + oldcnt \
                 || (newpos == oldpos + oldcnt && newcnt != 0)) \
            { \
                /* Fuzz the internal stream buffer, if necessary */ \
                _zz_setpos(fd, newpos - get_streambuf_offset(stream)); \
                _zz_fuzz(fd, get_streambuf_base(stream), \
                             get_streambuf_size(stream)); \
            } \
            oldpos = newpos; \
            oldcnt = newcnt; \
            if (chr == EOF) \
            { \
                finished = 1; \
                ret = done ? done : -1; \
            } \
            else \
            { \
                unsigned char c = chr; \
                line[done++] = c; \
                if (c == delim) \
                { \
                    finished = 1; \
                    ret = done; \
                } \
            } \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        if (need_delim) \
            debug("%s(%p, %p, '%c', [%i]) = %li", __func__, \
                  lineptr, n, delim, fd, (long int)ret); \
        else \
            debug("%s(%p, %p, [%i]) = %li", __func__, \
                  lineptr, n, fd, (long int)ret); \
        break; \
    } while (0)

#if defined HAVE_GETLINE
#undef getline
ssize_t NEW(getline)(char **lineptr, size_t *n, FILE *stream)
{
    ssize_t ret; ZZ_GETDELIM(getline, '\n', 0); return ret;
}
#endif

#if defined HAVE_GETDELIM
#undef getdelim
ssize_t NEW(getdelim)(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret; ZZ_GETDELIM(getdelim, delim, 1); return ret;
}
#endif

#if defined HAVE___GETDELIM
#undef __getdelim
ssize_t NEW(__getdelim)(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret; ZZ_GETDELIM(__getdelim, delim, 1); return ret;
}
#endif

/*
 * fgetln
 */

#if defined HAVE_FGETLN
#undef fgetln
char *NEW(fgetln)(FILE *stream, size_t *len)
{
    LOADSYM(fgetln);
    LOADSYM(fgetc);

    int fd = fileno(stream);
    if (!must_fuzz_fd(fd))
        return ORIG(fgetln)(stream, len);

    debug_stream("before", stream);
    int64_t oldpos = ZZ_FTELL(stream);
    int oldoff = get_streambuf_offset(stream);
    int oldcnt = get_streambuf_count(stream);
    int64_t newpos = oldpos;

    fuzz_context_t *fuzz = _zz_getfuzz(fd);

    size_t i = 0, size = 0;
    do
    {
        _zz_lockfd(fd);
        int chr = ORIG(fgetc)(stream);
        _zz_unlock(fd);

        newpos = oldpos + 1;
        if (oldcnt == 0 && chr != EOF)
        {
            /* Fuzz returned data that wasn't in the old buffer */
            uint8_t ch = chr;
            _zz_setpos(fd, oldpos);
            _zz_fuzz(fd, &ch, 1);
            chr = ch;
        }

        int newcnt = get_streambuf_count(stream);
        if (newpos > oldpos + oldcnt
             || (newpos == oldpos + oldcnt && newcnt != 0))
        {
            /* Fuzz the internal stream buffer, if necessary */
            _zz_setpos(fd, newpos - get_streambuf_offset(stream));
            _zz_fuzz(fd, get_streambuf_base(stream), get_streambuf_size(stream));
        }
        oldpos = newpos;
        oldcnt = newcnt;
        oldoff = get_streambuf_offset(stream);

        if (chr == EOF)
            break;

        if (i >= size)
            fuzz->tmp = realloc(fuzz->tmp, (size += 80));

        fuzz->tmp[i] = (char)(unsigned char)chr;
    }
    while (fuzz->tmp[i++] != '\n');

    *len = i;
    char *ret = fuzz->tmp;

    debug_stream("after", stream);
    debug("%s([%i], &%li) = %p", __func__, fd, (long int)*len, ret);
    return ret;
}
#endif

/*
 * __srefill, __filbuf, __srget, __uflow
 */

#if defined HAVE___UFLOW
#   define REFILL_RETURNS_INT 0
#else
#   define REFILL_RETURNS_INT 1
#endif

#define ZZ_REFILL(myrefill, fn_advances) \
    do \
    { \
        LOADSYM(myrefill); \
        \
        int fd = fileno(fp); \
        if (!must_fuzz_fd(fd)) \
            return ORIG(myrefill)(fp); \
        \
        debug_stream("before", fp); \
        int64_t pos = _zz_getpos(fd); \
        _zz_lockfd(fd); \
        ret = ORIG(myrefill)(fp); \
        off_t newpos = lseek(fd, 0, SEEK_CUR); \
        _zz_unlock(fd); \
        debug_stream("during", fp); \
        if (ret != EOF) \
        { \
            int already_fuzzed = 0; \
            if (fn_advances) \
            { \
                uint8_t ch = (uint8_t)(unsigned int)ret; \
                if (newpos != -1) \
                    _zz_setpos(fd, newpos - get_streambuf_count(fp) - 1); \
                already_fuzzed = _zz_getfuzzed(fd); \
                _zz_fuzz(fd, &ch, 1); \
                ret = get_streambuf_pos(fp)[-1] = ch; \
                _zz_setfuzzed(fd, get_streambuf_count(fp) + 1); \
                _zz_addpos(fd, 1); \
            } \
            else \
            { \
                _zz_setfuzzed(fd, get_streambuf_count(fp)); \
                if (newpos != -1) \
                    _zz_setpos(fd, newpos - get_streambuf_count(fp)); \
            } \
            if (get_streambuf_count(fp) > already_fuzzed) \
            { \
                _zz_addpos(fd, already_fuzzed); \
                _zz_fuzz(fd, get_streambuf_pos(fp), \
                             get_streambuf_count(fp) - already_fuzzed); \
            } \
            _zz_addpos(fd, get_streambuf_count(fp) - already_fuzzed); \
        } \
        _zz_setpos(fd, pos); /* FIXME: do we always need to do this? */ \
        debug_stream("after", fp); \
        if (REFILL_RETURNS_INT) \
            debug("%s([%i]) = %i", __func__, fd, ret); \
        else if (ret == EOF) \
            debug("%s([%i]) = EOF", __func__, fd); \
        else \
            debug("%s([%i]) = '%c'", __func__, fd, ret); \
    } \
    while (0)

#if defined HAVE___SREFILL
#undef __srefill
int NEW(__srefill)(FILE *fp)
{
    int ret; ZZ_REFILL(__srefill, 0); return ret;
}
#endif

#if defined HAVE___SRGET && !defined HAVE___SREFILL
#undef __srget
int NEW(__srget)(FILE *fp)
{
    int ret; ZZ_REFILL(__srget, 1); return ret;
}
#endif

#if defined HAVE___FILBUF
#undef __filbuf
int NEW(__filbuf)(FILE *fp)
{
    int ret; ZZ_REFILL(__filbuf, 1); return ret;
}
#endif

#if defined HAVE___UFLOW
#undef __uflow
int NEW(__uflow)(FILE *fp)
{
    int ret; ZZ_REFILL(__uflow, 1); return ret;
}
#endif

