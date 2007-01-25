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
 *  load-stream.c: loaded stream functions
 */

#include "config.h"

#define _GNU_SOURCE /* for getline() and getdelim() */

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>

#include <stdio.h>
#include <sys/types.h>
#if defined HAVE___SREFILL
#   include <unistd.h> /* Needed for __srefill’s lseek() call */
#endif

#include "libzzuf.h"
#include "lib-load.h"
#include "debug.h"
#include "fuzz.h"
#include "fd.h"

#if defined HAVE___SREFILL
int NEW(__srefill)(FILE *fp);
#endif

/* Library functions that we divert */
static FILE *  (*ORIG(fopen))    (const char *path, const char *mode);
#if defined HAVE_FOPEN64
static FILE *  (*ORIG(fopen64))  (const char *path, const char *mode);
#endif
static FILE *  (*ORIG(freopen))  (const char *path, const char *mode,
                                  FILE *stream);
static int     (*ORIG(fseek))    (FILE *stream, long offset, int whence);
#if defined HAVE_FSEEKO
static int     (*ORIG(fseeko))   (FILE *stream, off_t offset, int whence);
#endif
static void    (*ORIG(rewind))   (FILE *stream);
static size_t  (*ORIG(fread))    (void *ptr, size_t size, size_t nmemb,
                                  FILE *stream);
static int     (*ORIG(getc))     (FILE *stream);
static int     (*ORIG(fgetc))    (FILE *stream);
#if defined HAVE__IO_GETC
static int     (*ORIG(_IO_getc)) (FILE *stream);
#endif
static char *  (*ORIG(fgets))    (char *s, int size, FILE *stream);
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

/* Additional BSDisms */
#if defined HAVE_FGETLN
static char *  (*ORIG(fgetln))    (FILE *stream, size_t *len);
#endif
#if defined HAVE___SREFILL
int            (*ORIG(__srefill)) (FILE *fp);
#endif

/* Our function wrappers */
#define FOPEN(fn) \
    do \
    { \
        LOADSYM(fn); \
        if(!_zz_ready) \
            return ORIG(fn)(path, mode); \
        _zz_lock(-1); \
        ret = ORIG(fn)(path, mode); \
        _zz_unlock(-1); \
        if(ret && _zz_mustwatch(path)) \
        { \
            int fd = fileno(ret); \
            _zz_register(fd); \
            debug("%s(\"%s\", \"%s\") = [%i]", __func__, path, mode, fd); \
        } \
    } while(0)

FILE *NEW(fopen)(const char *path, const char *mode)
{
    FILE *ret; FOPEN(fopen); return ret;
}

#if defined HAVE_FOPEN64
FILE *NEW(fopen64)(const char *path, const char *mode)
{
    FILE *ret; FOPEN(fopen64); return ret;
}
#endif

FILE *NEW(freopen)(const char *path, const char *mode, FILE *stream)
{
    FILE *ret;
    int fd0 = -1, fd1 = -1, disp = 0;

    LOADSYM(freopen);
    if(_zz_ready && (fd0 = fileno(stream)) >= 0 && _zz_iswatched(fd0))
    {
        _zz_unregister(fd0);
        disp = 1;
    }

    _zz_lock(-1);
    ret = ORIG(freopen)(path, mode, stream);
    _zz_unlock(-1);

    if(ret && _zz_mustwatch(path))
    {
        fd1 = fileno(ret);
        _zz_register(fd1);
        disp = 1;
    }

    if(disp)
        debug("%s(\"%s\", \"%s\", [%i]) = [%i]", __func__,
              path, mode, fd0, fd1);

    return ret;
}

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#   define FSEEK_FUZZ(fn2)
#else
#   define FSEEK_FUZZ(fn2) \
        if(ret == 0) \
        { \
            /* FIXME: check what happens when fseek()ing a pipe */ \
            switch(whence) \
            { \
                case SEEK_END: \
                    offset = fn2(stream); \
                    /* fall through */ \
                case SEEK_SET: \
                    _zz_setpos(fd, offset); \
                    break; \
                case SEEK_CUR: \
                    _zz_addpos(fd, offset); \
                    break; \
            } \
        }
#endif

#define FSEEK(fn, fn2) \
    do \
    { \
        int fd; \
        LOADSYM(fn); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd)) \
            return ORIG(fn)(stream, offset, whence); \
        _zz_lock(fd); \
        ret = ORIG(fn)(stream, offset, whence); \
        _zz_unlock(fd); \
        debug("%s([%i], %lli, %i) = %i", __func__, \
              fd, (long long int)offset, whence, ret); \
        FSEEK_FUZZ(fn2) \
    } while(0)

int NEW(fseek)(FILE *stream, long offset, int whence)
{
    int ret; FSEEK(fseek, ftell); return ret;
}

#if defined HAVE_FSEEKO
int NEW(fseeko)(FILE *stream, off_t offset, int whence)
{
    int ret; FSEEK(fseeko, ftello); return ret;
}
#endif

void NEW(rewind)(FILE *stream)
{
    int fd;

    LOADSYM(rewind);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
    {
        ORIG(rewind)(stream);
        return;
    }

    _zz_lock(fd);
    ORIG(rewind)(stream);
    _zz_unlock(fd);
    debug("%s([%i])", __func__, fd);

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    /* FIXME: check what happens when rewind()ing a pipe */
    _zz_setpos(fd, 0);
#endif
}

size_t NEW(fread)(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    long int pos;
#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    long int newpos;
#endif
    size_t ret;
    int fd;

    LOADSYM(fread);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return ORIG(fread)(ptr, size, nmemb, stream);

    pos = ftell(stream);
    _zz_lock(fd);
    ret = ORIG(fread)(ptr, size, nmemb, stream);
    _zz_unlock(fd);

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    newpos = ftell(stream);
    /* XXX: the number of bytes read is not ret * size, because
     * a partial read may have advanced the stream pointer. However,
     * when reading from a pipe ftell() will return 0, and ret * size
     * is then better than nothing. */
    if(newpos <= 0)
    {
        pos = _zz_getpos(fd);
        newpos = pos + ret * size;
    }
    if(newpos != pos)
    {
        char *b = ptr;

        _zz_fuzz(fd, ptr, newpos - pos);
        _zz_setpos(fd, newpos);

        if(newpos >= pos + 4)
            debug("%s(%p, %li, %li, [%i]) = %li \"%c%c%c%c...", __func__, ptr,
                  (long int)size, (long int)nmemb, fd, (long int)ret,
                  b[0], b[1], b[2], b[3]);
        else
            debug("%s(%p, %li, %li, [%i]) = %li \"%c...", __func__, ptr,
                  (long int)size, (long int)nmemb, fd, (long int)ret, b[0]);
    }
    else
#endif
        debug("%s(%p, %li, %li, [%i]) = %li", __func__, ptr,
              (long int)size, (long int)nmemb, fd, (long int)ret);

    return ret;
}

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#   define FGETC_FUZZ
#else
#   define FGETC_FUZZ \
        if(ret != EOF) \
        { \
            uint8_t ch = ret; \
            _zz_fuzz(fd, &ch, 1); \
            _zz_addpos(fd, 1); \
            ret = ch; \
        }
#endif

#define FGETC(fn) \
    do { \
        int fd; \
        LOADSYM(fn); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd)) \
            return ORIG(fn)(stream); \
        _zz_lock(fd); \
        ret = ORIG(fn)(stream); \
        _zz_unlock(fd); \
        FGETC_FUZZ \
        debug("%s([%i]) = '%c'", __func__, fd, ret); \
    } while(0)

#undef getc /* can be a macro; we don’t want that */
int NEW(getc)(FILE *stream)
{
    int ret; FGETC(getc); return ret;
}

int NEW(fgetc)(FILE *stream)
{
    int ret; FGETC(fgetc); return ret;
}

#if defined HAVE__IO_GETC
int NEW(_IO_getc)(FILE *stream)
{
    int ret; FGETC(_IO_getc); return ret;
}
#endif

char *NEW(fgets)(char *s, int size, FILE *stream)
{
    char *ret = s;
    int fd;

    LOADSYM(fgets);
    LOADSYM(fgetc);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return ORIG(fgets)(s, size, stream);

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
    _zz_lock(fd);
    ret = ORIG(fgets)(s, size, stream);
    _zz_unlock(fd);
#else
    if(size <= 0)
        ret = NULL;
    else if(size == 1)
        s[0] = '\0';
    else
    {
        int i;

        for(i = 0; i < size - 1; i++)
        {
            int ch;

            _zz_lock(fd);
            ch = ORIG(fgetc)(stream);
            _zz_unlock(fd);

            if(ch == EOF)
            {
                s[i] = '\0';
                if(!i)
                    ret = NULL;
                break;
            }
            s[i] = (char)(unsigned char)ch;
            _zz_fuzz(fd, (uint8_t *)s + i, 1); /* rather inefficient */
            _zz_addpos(fd, 1);
            if(s[i] == '\n')
            {
                s[i + 1] = '\0';
                break;
            }
        }
    }
#endif

    debug("%s(%p, %i, [%i]) = %p", __func__, s, size, fd, ret);
    return ret;
}

int NEW(ungetc)(int c, FILE *stream)
{
    unsigned char ch = c;
    int ret, fd;

    LOADSYM(ungetc);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return ORIG(ungetc)(c, stream);

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    _zz_addpos(fd, -1);
    _zz_fuzz(fd, &ch, 1);
#endif
    _zz_lock(fd);
    ret = ORIG(ungetc)((int)ch, stream);
    _zz_unlock(fd);

    if(ret >= 0)
        ret = c;
#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    else
        _zz_addpos(fd, 1); /* revert what we did */
#endif

    debug("%s(0x%02x, [%i]) = '%c'", __func__, c, fd, ret);
    return ret;
}

int NEW(fclose)(FILE *fp)
{
    int ret, fd;

    LOADSYM(fclose);
    fd = fileno(fp);
    if(!_zz_ready || !_zz_iswatched(fd))
        return ORIG(fclose)(fp);

    _zz_lock(fd);
    ret = ORIG(fclose)(fp);
    _zz_unlock(fd);
    debug("%s([%i]) = %i", __func__, fd, ret);
    _zz_unregister(fd);

    return ret;
}

#define GETDELIM(fn, delim, need_delim) \
    do { \
        char *line; \
        ssize_t done, size; \
        int fd, finished = 0; \
        LOADSYM(fn); \
        LOADSYM(getdelim); \
        LOADSYM(fgetc); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd)) \
            return ORIG(getdelim)(lineptr, n, delim, stream); \
        line = *lineptr; \
        size = line ? *n : 0; \
        ret = done = finished = 0; \
        for(;;) \
        { \
            int ch; \
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
            ch = ORIG(fgetc)(stream); \
            _zz_unlock(fd); \
            if(ch == EOF) \
            { \
                finished = 1; \
                ret = done; \
            } \
            else \
            { \
                unsigned char c = ch; \
                _zz_fuzz(fd, &c, 1); /* even more inefficient */ \
                line[done++] = c; \
                _zz_addpos(fd, 1); \
                if(c == delim) \
                { \
                    finished = 1; \
                    ret = done; \
                } \
            } \
        } \
        if(need_delim) \
            debug("%s(%p, %p, '%c', [%i]) = %li", __func__, \
                  lineptr, n, delim, fd, (long int)ret); \
        else \
            debug("%s(%p, %p, [%i]) = %li", __func__, \
                  lineptr, n, fd, (long int)ret); \
        return ret; \
    } while(0)

#if defined HAVE_GETLINE
ssize_t NEW(getline)(char **lineptr, size_t *n, FILE *stream)
{
    ssize_t ret; GETDELIM(getline, '\n', 0); return ret;
}
#endif

#if defined HAVE_GETDELIM
ssize_t NEW(getdelim)(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret; GETDELIM(getdelim, delim, 1); return ret;
}
#endif

#if defined HAVE___GETDELIM
ssize_t NEW(__getdelim)(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret; GETDELIM(__getdelim, delim, 1); return ret;
}
#endif

#if defined HAVE_FGETLN
char *NEW(fgetln)(FILE *stream, size_t *len)
{
    char *ret;
#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    struct fuzz *fuzz;
    size_t i, size;
#endif
    int fd;

    LOADSYM(fgetln);
    LOADSYM(fgetc);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return ORIG(fgetln)(stream, len);

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
    _zz_lock(fd);
    ret = ORIG(fgetln)(stream, len);
    _zz_unlock(fd);
#else
    fuzz = _zz_getfuzz(fd);

    for(i = size = 0; ; /* i is incremented below */)
    {
        int ch;

        _zz_lock(fd);
        ch = ORIG(fgetc)(stream);
        _zz_unlock(fd);

        if(ch == EOF)
            break;

        if(i >= size)
            fuzz->tmp = realloc(fuzz->tmp, (size += 80));

        fuzz->tmp[i] = (char)(unsigned char)ch;
        _zz_fuzz(fd, (uint8_t *)fuzz->tmp + i, 1); /* rather inefficient */
        _zz_addpos(fd, 1);

        if(fuzz->tmp[i++] == '\n')
            break;
    }

    *len = i;
    ret = fuzz->tmp;
#endif

    debug("%s([%i], &%li) = %p", __func__, fd, (long int)*len, ret);
    return ret;
}
#endif

#if defined HAVE___SREFILL
int NEW(__srefill)(FILE *fp)
{
    off_t newpos;
    int ret, fd, tmp;

    LOADSYM(__srefill);
    fd = fileno(fp);
    if(!_zz_ready || !_zz_iswatched(fd))
        return ORIG(__srefill)(fp);

    _zz_lock(fd);
    ret = ORIG(__srefill)(fp);
    newpos = lseek(fd, 0, SEEK_CUR);
    _zz_unlock(fd);
    if(ret != EOF)
    {
        if(newpos != -1)
            _zz_setpos(fd, newpos - fp->_r);
        _zz_fuzz(fd, fp->_p, fp->_r);
        _zz_addpos(fd, fp->_r);
    }

    if(!_zz_islocked(fd))
        debug("%s([%i]) = %i", __func__, fd, ret);

    return ret;
}
#endif

