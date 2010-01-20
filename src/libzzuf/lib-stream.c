/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006-2010 Sam Hocevar <sam@hocevar.net>
 *                All Rights Reserved
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What The Fuck You Want
 *  To Public License, Version 2, as published by Sam Hocevar. See
 *  http://sam.zoy.org/wtfpl/COPYING for more details.
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

#if defined HAVE___SREFILL
int NEW(__srefill)(FILE *fp);
#endif

#if defined HAVE___FILBUF
int NEW(__filbuf)(FILE *fp);
#endif

#if defined HAVE___SRGET && !defined HAVE___SREFILL
int NEW(__srget)(FILE *fp);
#endif

#if defined HAVE___UFLOW
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
static int     (*ORIG(fseeko64)) (FILE *stream, off_t offset, int whence);
#endif
#if defined HAVE___FSEEKO64
static int     (*ORIG(__fseeko64)) (FILE *stream, off_t offset, int whence);
#endif
#if defined HAVE_FSETPOS64
static int     (*ORIG(fsetpos64))(FILE *stream, const fpos64_t *pos);
#endif
#if defined HAVE___FSETPOS64
static int     (*ORIG(__fsetpos64)) (FILE *stream, const fpos64_t *pos);
#endif
static void    (*ORIG(rewind))   (FILE *stream);
static size_t  (*ORIG(fread))    (void *ptr, size_t size, size_t nmemb,
                                  FILE *stream);
#if defined HAVE_FREAD_UNLOCKED
static size_t  (*ORIG(fread_unlocked))  (void *ptr, size_t size, size_t nmemb,
                                         FILE *stream);
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
static inline uint8_t *get_stream_ptr(FILE *stream)
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

static inline int get_stream_off(FILE *stream)
{
#if defined HAVE_GLIBC_FILE
    return (int)((uint8_t *)stream->_IO_read_ptr
                  - (uint8_t *)stream->_IO_read_base);
#elif defined HAVE_FREEBSD_FILE
    return (int)((uint8_t *)stream->_p - (uint8_t *)stream->_bf._base);
#elif defined HAVE_SOLARIS_FILE
    return (int)((uint8_t *)stream->_ptr - (uint8_t *)stream->_base);
#else
    (void)stream;
    return 0;
#endif
}

static inline int get_stream_cnt(FILE *stream)
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

static inline void debug_stream(char const *prefix, FILE *stream)
{
    debug2("... %s: stream([%i], %p, %i + %i)", prefix, fileno(stream),
           get_stream_ptr(stream), get_stream_off(stream),
           get_stream_cnt(stream));
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
        if(!_zz_ready) \
            return ORIG(myfopen)(path, mode); \
        _zz_lock(-1); \
        ret = ORIG(myfopen)(path, mode); \
        _zz_unlock(-1); \
        if(ret && _zz_mustwatch(path)) \
        { \
            int fd = fileno(ret); \
            _zz_register(fd); \
            _zz_fuzz(fd, get_stream_ptr(ret), get_stream_cnt(ret)); \
            debug_stream("after", ret); \
            debug("%s(\"%s\", \"%s\") = [%i]", __func__, path, mode, fd); \
        } \
    } while(0)

#define ZZ_FREOPEN(myfreopen) \
    do \
    { \
        int fd0 = -1, fd1 = -1, disp = 0; \
        LOADSYM(myfreopen); \
        if(_zz_ready && (fd0 = fileno(stream)) >= 0 && _zz_iswatched(fd0)) \
        { \
            _zz_unregister(fd0); \
            disp = 1; \
        } \
        _zz_lock(-1); \
        ret = ORIG(myfreopen)(path, mode, stream); \
        _zz_unlock(-1); \
        if(ret && _zz_mustwatch(path)) \
        { \
            fd1 = fileno(ret); \
            _zz_register(fd1); \
            _zz_fuzz(fd1, get_stream_ptr(ret), get_stream_cnt(ret)); \
            disp = 1; \
        } \
        if(disp) \
            debug("%s(\"%s\", \"%s\", [%i]) = [%i]", __func__, \
                  path, mode, fd0, fd1); \
    } while(0)

FILE *NEW(fopen)(const char *path, const char *mode)
{
    FILE *ret; ZZ_FOPEN(fopen); return ret;
}

#if defined HAVE_FOPEN64
FILE *NEW(fopen64)(const char *path, const char *mode)
{
    FILE *ret; ZZ_FOPEN(fopen64); return ret;
}
#endif

#if defined HAVE___FOPEN64
FILE *NEW(__fopen64)(const char *path, const char *mode)
{
    FILE *ret; ZZ_FOPEN(__fopen64); return ret;
}
#endif

FILE *NEW(freopen)(const char *path, const char *mode, FILE *stream)
{
    FILE *ret; ZZ_FREOPEN(freopen); return ret;
}

#if defined HAVE_FREOPEN64
FILE *NEW(freopen64)(const char *path, const char *mode, FILE *stream)
{
    FILE *ret; ZZ_FREOPEN(freopen64); return ret;
}
#endif

#if defined HAVE___FREOPEN64
FILE *NEW(__freopen64)(const char *path, const char *mode, FILE *stream)
{
    FILE *ret; ZZ_FREOPEN(__freopen64); return ret;
}
#endif

/*
 * fseek, fseeko etc.
 * fsetpos64, __fsetpos64
 * rewind
 *
 * Strategy: we store the previous file position and internal buffer
 * status, then call the original function. If the new file position
 * lies outside the previous internal buffer, it means the buffer has
 * been invalidated, so we fuzz whatever's preloaded in it.
 */

#define ZZ_FSEEK(myfseek) \
    do \
    { \
        int64_t oldpos, newpos; \
        int oldoff, oldcnt; \
        int fd; \
        LOADSYM(myfseek); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd) || !_zz_isactive(fd) \
             || _zz_islocked(fd)) \
            return ORIG(myfseek)(stream, offset, whence); \
        debug_stream("before", stream); \
        /* FIXME: ftell() will return -1 on a pipe such as stdin */ \
        oldpos = ZZ_FTELL(stream); \
        oldoff = get_stream_off(stream); \
        oldcnt = get_stream_cnt(stream); \
        _zz_lock(fd); \
        ret = ORIG(myfseek)(stream, offset, whence); \
        _zz_unlock(fd); \
        newpos = ZZ_FTELL(stream); \
        if (newpos >= oldpos + oldcnt || newpos < oldpos - oldoff) \
        { \
            _zz_setpos(fd, newpos - get_stream_off(stream)); \
            _zz_fuzz(fd, get_stream_ptr(stream) - get_stream_off(stream), \
                         get_stream_cnt(stream) + get_stream_off(stream)); \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        debug("%s([%i], %lli, %s) = %i", __func__, \
              fd, (long long int)offset, get_seek_mode_name(whence), ret); \
    } while(0)

#define ZZ_FSETPOS(myfsetpos) \
    do \
    { \
        int64_t oldpos, newpos; \
        int oldoff, oldcnt; \
        int fd; \
        LOADSYM(myfsetpos); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd) || !_zz_isactive(fd) \
             || _zz_islocked(fd)) \
            return ORIG(myfsetpos)(stream, pos); \
        debug_stream("before", stream); \
        /* FIXME: ftell() will return -1 on a pipe such as stdin */ \
        oldpos = ZZ_FTELL(stream); \
        oldoff = get_stream_off(stream); \
        oldcnt = get_stream_cnt(stream); \
        _zz_lock(fd); \
        ret = ORIG(myfsetpos)(stream, pos); \
        _zz_unlock(fd); \
        newpos = ZZ_FTELL(stream); \
        if (newpos >= oldpos + oldcnt || newpos < oldpos - oldoff) \
        { \
            _zz_setpos(fd, newpos - get_stream_off(stream)); \
            _zz_fuzz(fd, get_stream_ptr(stream) - get_stream_off(stream), \
                         get_stream_cnt(stream) + get_stream_off(stream)); \
        } \
        _zz_setpos(fd, (int64_t)FPOS_CAST(*pos)); \
        debug_stream("after", stream); \
        debug("%s([%i], %lli) = %i", __func__, \
              fd, (long long int)FPOS_CAST(*pos), ret); \
    } \
    while(0)

#define ZZ_REWIND(myrewind) \
    do \
    { \
        int64_t oldpos, newpos; \
        int oldoff, oldcnt; \
        int fd; \
        LOADSYM(rewind); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd) || !_zz_isactive(fd) \
             || _zz_islocked(fd)) \
            return ORIG(rewind)(stream); \
        debug_stream("before", stream); \
        /* FIXME: ftell() will return -1 on a pipe such as stdin */ \
        oldpos = ZZ_FTELL(stream); \
        oldoff = get_stream_off(stream); \
        oldcnt = get_stream_cnt(stream); \
        _zz_lock(fd); \
        ORIG(rewind)(stream); \
        _zz_unlock(fd); \
        newpos = ZZ_FTELL(stream); \
        if (newpos >= oldpos + oldcnt || newpos < oldpos - oldoff) \
        { \
            _zz_setpos(fd, newpos - get_stream_off(stream)); \
            _zz_fuzz(fd, get_stream_ptr(stream) - get_stream_off(stream), \
                         get_stream_cnt(stream) + get_stream_off(stream)); \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        debug("%s([%i])", __func__, fd); \
    } while(0)

int NEW(fseek)(FILE *stream, long offset, int whence)
{
    int ret; ZZ_FSEEK(fseek); return ret;
}

#if defined HAVE_FSEEKO
int NEW(fseeko)(FILE *stream, off_t offset, int whence)
{
    int ret; ZZ_FSEEK(fseeko); return ret;
}
#endif

#if defined HAVE_FSEEKO64
int NEW(fseeko64)(FILE *stream, off64_t offset, int whence)
{
    int ret; ZZ_FSEEK(fseeko64); return ret;
}
#endif

#if defined HAVE___FSEEKO64
int NEW(__fseeko64)(FILE *stream, off64_t offset, int whence)
{
    int ret; ZZ_FSEEK(__fseeko64); return ret;
}
#endif

#if defined HAVE_FSETPOS64
int NEW(fsetpos64)(FILE *stream, const fpos64_t *pos)
{
    int ret; ZZ_FSETPOS(fsetpos64); return ret;
}
#endif

#if defined HAVE___FSETPOS64
int NEW(__fsetpos64)(FILE *stream, const fpos64_t *pos)
{
    int ret; ZZ_FSETPOS(__fsetpos64); return ret;
}
#endif

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

#define ZZ_FREAD(myfread) /* NEW */ \
    do \
    { \
        int64_t oldpos, newpos; \
        uint8_t *b = ptr;\
        int oldoff, oldcnt; \
        int fd; \
        LOADSYM(myfread); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd) || !_zz_isactive(fd) \
             || _zz_islocked(fd)) \
            return ORIG(myfread)(ptr, size, nmemb, stream); \
        debug_stream("before", stream); \
        /* FIXME: ftell() will return -1 on a pipe such as stdin */ \
        oldpos = ZZ_FTELL(stream); \
        oldoff = get_stream_off(stream); \
        oldcnt = get_stream_cnt(stream); \
        _zz_lock(fd); \
        ret = ORIG(myfread)(ptr, size, nmemb, stream); \
        _zz_unlock(fd); \
        newpos = ZZ_FTELL(stream); \
        if (newpos >= oldpos + oldcnt) \
        { \
            /* Fuzz returned data that wasn't in the old internal buffer */ \
            _zz_setpos(fd, oldpos + oldcnt); \
            _zz_fuzz(fd, b + oldcnt, newpos - oldpos - oldcnt); \
            /* Fuzz the internal stream buffer */ \
            _zz_setpos(fd, newpos - get_stream_off(stream)); \
            _zz_fuzz(fd, get_stream_ptr(stream) - get_stream_off(stream), \
                         get_stream_cnt(stream) + get_stream_off(stream)); \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        if (newpos >= oldpos + 4) \
            debug("%s(%p, %li, %li, [%i]) = %li \"%c%c%c%c...", __func__, \
                  ptr, (long int)size, (long int)nmemb, fd, \
                  (long int)ret, b[0], b[1], b[2], b[3]); \
        else if (newpos > oldpos) \
            debug("%s(%p, %li, %li, [%i]) = %li \"%c...", __func__, ptr, \
                  (long int)size, (long int)nmemb, fd, \
                  (long int)ret, b[0]); \
        else \
            debug("%s(%p, %li, %li, [%i]) = %li", __func__, ptr, \
                  (long int)size, (long int)nmemb, fd, (long int)ret); \
    } while(0)

size_t NEW(fread)(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret; ZZ_FREAD(fread); return ret;
}

#if defined HAVE_FREAD_UNLOCKED
#undef fread_unlocked /* can be a macro; we don’t want that */
size_t NEW(fread_unlocked)(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret; ZZ_FREAD(fread_unlocked); return ret;
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

#define ZZ_FGETC(myfgetc, s, arg) \
    do { \
        int64_t oldpos, newpos; \
        int oldoff, oldcnt; \
        int fd; \
        LOADSYM(myfgetc); \
        fd = fileno(s); \
        if(!_zz_ready || !_zz_iswatched(fd) || !_zz_isactive(fd) \
             || _zz_islocked(fd)) \
            return ORIG(myfgetc)(arg); \
        debug_stream("before", s); \
        oldpos = ZZ_FTELL(s); \
        oldoff = get_stream_off(s); \
        oldcnt = get_stream_cnt(s); \
        _zz_lock(fd); \
        ret = ORIG(myfgetc)(arg); \
        _zz_unlock(fd); \
        newpos = ZZ_FTELL(s); \
        if (oldcnt == 0 && ret != EOF) \
        { \
            /* Fuzz returned data that wasn't in the old internal buffer */ \
            uint8_t ch = ret; \
            _zz_setpos(fd, oldpos); \
            _zz_fuzz(fd, &ch, 1); \
            ret = ch; \
        } \
        if (newpos >= oldpos + oldcnt) \
        { \
            /* Fuzz the internal stream buffer */ \
            _zz_setpos(fd, newpos - get_stream_off(s)); \
            _zz_fuzz(fd, get_stream_ptr(s) - get_stream_off(s), \
                         get_stream_cnt(s) + get_stream_off(s)); \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", s); \
        if(ret == EOF) \
            debug("%s([%i]) = EOF", __func__, fd); \
        else \
            debug("%s([%i]) = '%c'", __func__, fd, ret); \
    } while(0)

#undef getc /* can be a macro; we don’t want that */
int NEW(getc)(FILE *stream)
{
    int ret; ZZ_FGETC(getc, stream, stream); return ret;
}

#undef getchar /* can be a macro; we don’t want that */
int NEW(getchar)(void)
{
    int ret; ZZ_FGETC(getchar, stdin, /* empty */); return ret;
}

int NEW(fgetc)(FILE *stream)
{
    int ret; ZZ_FGETC(fgetc, stream, stream); return ret;
}

#if defined HAVE__IO_GETC
int NEW(_IO_getc)(FILE *stream)
{
    int ret; ZZ_FGETC(_IO_getc, stream, stream); return ret;
}
#endif

#if defined HAVE_GETC_UNLOCKED
#undef getc_unlocked /* can be a macro; we don’t want that */
int NEW(getc_unlocked)(FILE *stream)
{
    int ret; ZZ_FGETC(getc_unlocked, stream, stream); return ret;
}
#endif

#if defined HAVE_GETCHAR_UNLOCKED
#undef getchar_unlocked /* can be a macro; we don’t want that */
int NEW(getchar_unlocked)(void)
{
    int ret; ZZ_FGETC(getchar_unlocked, stdin, /* empty */); return ret;
}
#endif

#if defined HAVE_FGETC_UNLOCKED
#undef fgetc_unlocked /* can be a macro; we don’t want that */
int NEW(fgetc_unlocked)(FILE *stream)
{
    int ret; ZZ_FGETC(fgetc_unlocked, stream, stream); return ret;
}
#endif

/*
 * fgets, fgets_unlocked
 */

#define ZZ_FGETS(myfgets, myfgetc) \
    do \
    { \
        int64_t oldpos, newpos; \
        int oldoff, oldcnt; \
        int fd; \
        ret = s; \
        LOADSYM(myfgets); \
        LOADSYM(myfgetc); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd) || !_zz_isactive(fd) \
             || _zz_islocked(fd)) \
            return ORIG(myfgets)(s, size, stream); \
        debug_stream("before", stream); \
        oldpos = ZZ_FTELL(stream); \
        oldoff = get_stream_off(stream); \
        oldcnt = get_stream_cnt(stream); \
        newpos = oldpos; \
        if(size <= 0) \
            ret = NULL; \
        else if(size == 1) \
            s[0] = '\0'; \
        else \
        { \
            int i; \
            for(i = 0; i < size - 1; i++) \
            { \
                int chr; \
                _zz_lock(fd); \
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
                if (newpos >= oldpos + oldcnt) \
                { \
                    /* Fuzz the internal stream buffer, if necessary */ \
                    _zz_setpos(fd, newpos - get_stream_off(stream)); \
                    _zz_fuzz(fd, get_stream_ptr(stream) - get_stream_off(stream), \
                                 get_stream_cnt(stream) + get_stream_off(stream)); \
                } \
                oldpos = newpos; \
                oldoff = get_stream_off(stream); \
                oldcnt = get_stream_cnt(stream); \
                if(chr == EOF) \
                { \
                    s[i] = '\0'; \
                    if(!i) \
                        ret = NULL; \
                    break; \
                } \
                s[i] = (char)(unsigned char)chr; \
                if(s[i] == '\n') \
                { \
                    s[i + 1] = '\0'; \
                    break; \
                } \
            } \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        debug("%s(%p, %i, [%i]) = %p", __func__, s, size, fd, ret); \
    } while(0)

char *NEW(fgets)(char *s, int size, FILE *stream)
{
    char *ret; ZZ_FGETS(fgets, fgetc); return ret;
}

#if defined HAVE_FGETS_UNLOCKED
char *NEW(fgets_unlocked)(char *s, int size, FILE *stream)
{
    char *ret; ZZ_FGETS(fgets_unlocked, fgetc_unlocked); return ret;
}
#endif

/*
 * ungetc
 */

int NEW(ungetc)(int c, FILE *stream)
{
    int oldpos, ret, fd;

    LOADSYM(ungetc);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd) || !_zz_isactive(fd)
         || _zz_islocked(fd))
        return ORIG(ungetc)(c, stream);

    debug_stream("before", stream);
    oldpos = ZZ_FTELL(stream);
    _zz_lock(fd);
    ret = ORIG(ungetc)(c, stream);
    _zz_unlock(fd);
    _zz_setpos(fd, oldpos - 1);

    debug_stream("after", stream);
    if(ret == EOF)
        debug("%s(0x%02x, [%i]) = EOF", __func__, c, fd);
    else
        debug("%s(0x%02x, [%i]) = '%c'", __func__, c, fd, ret);
    return ret;
}

/*
 * fclose
 */

int NEW(fclose)(FILE *fp)
{
    int ret, fd;

    LOADSYM(fclose);
    fd = fileno(fp);
    if(!_zz_ready || !_zz_iswatched(fd))
        return ORIG(fclose)(fp);

    debug_stream("before", fp);
    _zz_lock(fd);
    ret = ORIG(fclose)(fp);
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
        int64_t oldpos, newpos; \
        char *line; \
        ssize_t done, size; \
        int oldoff, oldcnt; \
        int fd, finished = 0; \
        LOADSYM(mygetdelim); \
        LOADSYM(getdelim); \
        LOADSYM(fgetc); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd) || !_zz_isactive(fd) \
             || _zz_islocked(fd)) \
            return ORIG(getdelim)(lineptr, n, delim, stream); \
        debug_stream("before", stream); \
        oldpos = ZZ_FTELL(stream); \
        oldoff = get_stream_off(stream); \
        oldcnt = get_stream_cnt(stream); \
        newpos = oldpos; \
        line = *lineptr; \
        size = line ? *n : 0; \
        ret = done = finished = 0; \
        for(;;) \
        { \
            int chr; \
            if(done >= size) /* highly inefficient but I don't care */ \
                line = realloc(line, size = done + 1); \
            if(finished) \
            { \
                line[done] = '\0'; \
                *n = size; \
                *lineptr = line; \
                break; \
            } \
            _zz_lock(fd); \
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
            if (newpos >= oldpos + oldcnt) \
            { \
                /* Fuzz the internal stream buffer, if necessary */ \
                _zz_setpos(fd, newpos - get_stream_off(stream)); \
                _zz_fuzz(fd, get_stream_ptr(stream) - get_stream_off(stream), \
                             get_stream_cnt(stream) + get_stream_off(stream)); \
            } \
            oldpos = newpos; \
            oldoff = get_stream_off(stream); \
            oldcnt = get_stream_cnt(stream); \
            if(chr == EOF) \
            { \
                finished = 1; \
                ret = done ? done : -1; \
            } \
            else \
            { \
                unsigned char c = chr; \
                line[done++] = c; \
                if(c == delim) \
                { \
                    finished = 1; \
                    ret = done; \
                } \
            } \
        } \
        _zz_setpos(fd, newpos); \
        debug_stream("after", stream); \
        if(need_delim) \
            debug("%s(%p, %p, '%c', [%i]) = %li", __func__, \
                  lineptr, n, delim, fd, (long int)ret); \
        else \
            debug("%s(%p, %p, [%i]) = %li", __func__, \
                  lineptr, n, fd, (long int)ret); \
        break; \
    } while(0)

#if defined HAVE_GETLINE
ssize_t NEW(getline)(char **lineptr, size_t *n, FILE *stream)
{
    ssize_t ret; ZZ_GETDELIM(getline, '\n', 0); return ret;
}
#endif

#if defined HAVE_GETDELIM
ssize_t NEW(getdelim)(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret; ZZ_GETDELIM(getdelim, delim, 1); return ret;
}
#endif

#if defined HAVE___GETDELIM
ssize_t NEW(__getdelim)(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret; ZZ_GETDELIM(__getdelim, delim, 1); return ret;
}
#endif

/*
 * fgetln
 */

#if defined HAVE_FGETLN
char *NEW(fgetln)(FILE *stream, size_t *len)
{
    int64_t oldpos, newpos;
    char *ret;
    struct fuzz *fuzz;
    size_t i, size;
    int oldoff, oldcnt, fd;

    LOADSYM(fgetln);
    LOADSYM(fgetc);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd) || !_zz_isactive(fd)
         || _zz_islocked(fd))
        return ORIG(fgetln)(stream, len);

    debug_stream("before", stream);
    oldpos = ZZ_FTELL(stream);
    oldoff = get_stream_off(stream);
    oldcnt = get_stream_cnt(stream);
    newpos = oldpos;

    fuzz = _zz_getfuzz(fd);

    for(i = size = 0; ; /* i is incremented below */)
    {
        int chr;

        _zz_lock(fd);
        chr = ORIG(fgetc)(stream);
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
        if (newpos >= oldpos + oldcnt)
        {
            /* Fuzz the internal stream buffer, if necessary */
            _zz_setpos(fd, newpos - get_stream_off(stream));
            _zz_fuzz(fd, get_stream_ptr(stream) - get_stream_off(stream),
                         get_stream_cnt(stream) + get_stream_off(stream));
        }
        oldpos = newpos;
        oldoff = get_stream_off(stream);
        oldcnt = get_stream_cnt(stream);

        if(chr == EOF)
            break;

        if(i >= size)
            fuzz->tmp = realloc(fuzz->tmp, (size += 80));

        fuzz->tmp[i] = (char)(unsigned char)chr;

        if(fuzz->tmp[i++] == '\n')
            break;
    }

    *len = i;
    ret = fuzz->tmp;

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
        int64_t pos; \
        off_t newpos; \
        int fd; \
        LOADSYM(myrefill); \
        fd = fileno(fp); \
        if(!_zz_ready || !_zz_iswatched(fd) || !_zz_isactive(fd) \
             || _zz_islocked(fd)) \
            return ORIG(myrefill)(fp); \
        debug_stream("before", fp); \
        pos = _zz_getpos(fd); \
        _zz_lock(fd); \
        ret = ORIG(myrefill)(fp); \
        newpos = lseek(fd, 0, SEEK_CUR); \
        _zz_unlock(fd); \
        if(ret != EOF) \
        { \
            int already_fuzzed = 0; \
            if(fn_advances) \
            { \
                uint8_t ch = (uint8_t)(unsigned int)ret; \
                if(newpos != -1) \
                    _zz_setpos(fd, newpos - get_stream_cnt(fp) - 1); \
                already_fuzzed = _zz_getfuzzed(fd); \
                _zz_fuzz(fd, &ch, 1); \
                ret = get_stream_ptr(fp)[-1] = ch; \
                _zz_setfuzzed(fd, get_stream_cnt(fp) + 1); \
                _zz_addpos(fd, 1); \
            } \
            else \
            { \
                _zz_setfuzzed(fd, get_stream_cnt(fp)); \
                if(newpos != -1) \
                    _zz_setpos(fd, newpos - get_stream_cnt(fp)); \
            } \
            if(get_stream_cnt(fp) > already_fuzzed) \
            { \
                _zz_addpos(fd, already_fuzzed); \
                _zz_fuzz(fd, get_stream_ptr(fp), \
                             get_stream_cnt(fp) - already_fuzzed); \
            } \
            _zz_addpos(fd, get_stream_cnt(fp) - already_fuzzed); \
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
    while(0)

#if defined HAVE___SREFILL
int NEW(__srefill)(FILE *fp)
{
    int ret; ZZ_REFILL(__srefill, 0); return ret;
}
#endif

#if defined HAVE___SRGET && !defined HAVE___SREFILL
int NEW(__srget)(FILE *fp)
{
    int ret; ZZ_REFILL(__srget, 1); return ret;
}
#endif

#if defined HAVE___FILBUF
int NEW(__filbuf)(FILE *fp)
{
    int ret; ZZ_REFILL(__filbuf, 1); return ret;
}
#endif

#if defined HAVE___UFLOW
int NEW(__uflow)(FILE *fp)
{
    int ret; ZZ_REFILL(__uflow, 1); return ret;
}
#endif

