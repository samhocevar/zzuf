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
#include <dlfcn.h>

#include <stdio.h>
#include <sys/types.h>

#include "libzzuf.h"
#include "debug.h"
#include "fuzz.h"
#include "load.h"

#if !defined __FreeBSD__ && !defined __OpenBSD__
#   undef HAVE___SREFILL
#endif

#ifdef HAVE___SREFILL
int __srefill(FILE *fp);
#endif

/* Library functions that we divert */
static FILE *  (*fopen_orig)    (const char *path, const char *mode);
#ifdef HAVE_FOPEN64
static FILE *  (*fopen64_orig)  (const char *path, const char *mode);
#endif
static int     (*fseek_orig)    (FILE *stream, long offset, int whence);
#ifdef HAVE_FSEEKO
static int     (*fseeko_orig)   (FILE *stream, off_t offset, int whence);
#endif
static void    (*rewind_orig)   (FILE *stream);
static size_t  (*fread_orig)    (void *ptr, size_t size, size_t nmemb,
                                 FILE *stream);
static int     (*getc_orig)     (FILE *stream);
static int     (*fgetc_orig)    (FILE *stream);
#ifdef HAVE__IO_GETC
static int     (*_IO_getc_orig) (FILE *stream);
#endif
static char *  (*fgets_orig)    (char *s, int size, FILE *stream);
static int     (*ungetc_orig)   (int c, FILE *stream);
static int     (*fclose_orig)   (FILE *fp);

/* Additional GNUisms */
#ifdef HAVE_GETLINE
static ssize_t (*getline_orig)    (char **lineptr, size_t *n, FILE *stream);
#endif
#ifdef HAVE_GETDELIM
static ssize_t (*getdelim_orig)   (char **lineptr, size_t *n, int delim,
                                   FILE *stream);
#endif
#ifdef HAVE___GETDELIM
static ssize_t (*__getdelim_orig) (char **lineptr, size_t *n, int delim,
                                   FILE *stream);
#endif

/* Additional BSDisms */
#ifdef HAVE_FGETLN
static char *  (*fgetln_orig)    (FILE *stream, size_t *len);
#endif
#ifdef HAVE___SREFILL
int            (*__srefill_orig) (FILE *fp);
#endif


void _zz_load_stream(void)
{
    LOADSYM(fopen);
#ifdef HAVE_FOPEN64
    LOADSYM(fopen64);
#endif
    LOADSYM(fseek);
#ifdef HAVE_FSEEKO
    LOADSYM(fseeko);
#endif
    LOADSYM(rewind);
    LOADSYM(fread);
    LOADSYM(getc);
    LOADSYM(fgetc);
#ifdef HAVE__IO_GETC
    LOADSYM(_IO_getc);
#endif
    LOADSYM(fgets);
    LOADSYM(ungetc);
    LOADSYM(fclose);
#ifdef HAVE_GETLINE
    LOADSYM(getline);
#endif
#ifdef HAVE_GETDELIM
    LOADSYM(getdelim);
#endif
#ifdef HAVE___GETDELIM
    LOADSYM(__getdelim);
#endif
#ifdef HAVE_FGETLN
    LOADSYM(fgetln);
#endif
#ifdef HAVE___SREFILL
    LOADSYM(__srefill);
#endif
}

/* Our function wrappers */
#define FOPEN(fn) \
    do \
    { \
        if(!_zz_ready) \
        { \
            LOADSYM(fn); \
            return ORIG(fn)(path, mode); \
        } \
        _zz_disabled = 1; \
        ret = ORIG(fn)(path, mode); \
        _zz_disabled = 0; \
        if(ret && _zz_mustwatch(path)) \
        { \
            int fd = fileno(ret); \
            _zz_register(fd); \
            debug(STR(fn) "(\"%s\", \"%s\") = [%i]", path, mode, fd); \
        } \
    } while(0)

FILE *fopen(const char *path, const char *mode)
{
    FILE *ret; FOPEN(fopen); return ret;
}

#ifdef HAVE_FOPEN64
FILE *fopen64(const char *path, const char *mode)
{
    FILE *ret; FOPEN(fopen64); return ret;
}
#endif

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
        if(!_zz_ready) \
            LOADSYM(fn); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd)) \
            return ORIG(fn)(stream, offset, whence); \
        _zz_disabled = 1; \
        ret = ORIG(fn)(stream, offset, whence); \
        _zz_disabled = 0; \
        debug(STR(fn)"([%i], %lli, %i) = %i", \
              fd, (long long int)offset, whence, ret); \
        FSEEK_FUZZ(fn2) \
    } while(0)

int fseek(FILE *stream, long offset, int whence)
{
    int ret; FSEEK(fseek, ftell); return ret;
}

#ifdef HAVE_FSEEKO
int fseeko(FILE *stream, off_t offset, int whence)
{
    int ret; FSEEK(fseeko, ftello); return ret;
}
#endif

void rewind(FILE *stream)
{
    int fd;

    if(!_zz_ready)
        LOADSYM(rewind);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
    {
        rewind_orig(stream);
        return;
    }

    _zz_disabled = 1;
    rewind_orig(stream);
    _zz_disabled = 0;
    debug("rewind([%i])", fd);

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    /* FIXME: check what happens when rewind()ing a pipe */
    _zz_setpos(fd, 0);
#endif
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    long int pos;
#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    long int newpos;
#endif
    size_t ret;
    int fd;

    if(!_zz_ready)
        LOADSYM(fread);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return fread_orig(ptr, size, nmemb, stream);

    pos = ftell(stream);
    _zz_disabled = 1;
    ret = fread_orig(ptr, size, nmemb, stream);
    _zz_disabled = 0;
    debug("fread(%p, %li, %li, [%i]) = %li",
          ptr, (long int)size, (long int)nmemb, fd, (long int)ret);

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    newpos = ftell(stream);
    /* XXX: the number of bytes read is not ret * size, because
     * a partial read may have advanced the stream pointer. However,
     * when reading from a pipe ftell() will return 0, and ret * size
     * is then better than nothing. */
    if(newpos <= 0)
        newpos = ret * size;
    if(newpos != pos)
    {
        _zz_fuzz(fd, ptr, newpos - pos);
        _zz_setpos(fd, newpos);
    }
#endif

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
        if(!_zz_ready) \
            LOADSYM(fn); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd)) \
            return ORIG(fn)(stream); \
        _zz_disabled = 1; \
        ret = ORIG(fn)(stream); \
        _zz_disabled = 0; \
        FGETC_FUZZ \
        if(ret >= 0x20 && ret <= 0x7f) \
            debug(STR(fn)"([%i]) = 0x%02x '%c'", fd, ret, (char)ret); \
        else \
            debug(STR(fn)"([%i]) = 0x%02x", fd, ret); \
    } while(0)

#undef getc /* can be a macro; we don’t want that */
int getc(FILE *stream)
{
    int ret; FGETC(getc); return ret;
}

int fgetc(FILE *stream)
{
    int ret; FGETC(fgetc); return ret;
}

#ifdef HAVE__IO_GETC
int _IO_getc(FILE *stream)
{
    int ret; FGETC(_IO_getc); return ret;
}
#endif

char *fgets(char *s, int size, FILE *stream)
{
    char *ret = s;
    int fd;

    if(!_zz_ready)
        LOADSYM(fgets);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return fgets_orig(s, size, stream);

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
    _zz_disabled = 1;
    ret = fgets_orig(s, size, stream);
    _zz_disabled = 0;
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

            _zz_disabled = 1;
            ch = fgetc_orig(stream);
            _zz_disabled = 0;

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

    debug("fgets(%p, %i, [%i]) = %p", s, size, fd, ret);
    return ret;
}

int ungetc(int c, FILE *stream)
{
    unsigned char ch = c;
    int ret, fd;

    if(!_zz_ready)
        LOADSYM(ungetc);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return ungetc_orig(c, stream);

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    _zz_addpos(fd, -1);
    _zz_fuzz(fd, &ch, 1);
#endif
    _zz_disabled = 1;
    ret = ungetc_orig((int)ch, stream);
    _zz_disabled = 0;

    if(ret >= 0)
        ret = c;
#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    else
        _zz_addpos(fd, 1); /* revert what we did */
#endif

    if(ret >= 0x20 && ret <= 0x7f)
        debug("ungetc(0x%02x, [%i]) = 0x%02x '%c'", c, fd, ret, ret);
    else
        debug("ungetc(0x%02x, [%i]) = 0x%02x", c, fd, ret);
    return ret;
}

int fclose(FILE *fp)
{
    int ret, fd;

    if(!_zz_ready)
        LOADSYM(fclose);
    fd = fileno(fp);
    if(!_zz_ready || !_zz_iswatched(fd))
        return fclose_orig(fp);

    _zz_disabled = 1;
    ret = fclose_orig(fp);
    _zz_disabled = 0;
    debug("fclose([%i]) = %i", fd, ret);
    _zz_unregister(fd);

    return ret;
}

#define GETDELIM(fn, delim, need_delim) \
    do { \
        char *line; \
        ssize_t done, size; \
        int fd, finished = 0; \
        if(!_zz_ready) \
            LOADSYM(fn); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd)) \
            return getdelim_orig(lineptr, n, delim, stream); \
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
            _zz_disabled = 1; \
            ch = fgetc_orig(stream); \
            _zz_disabled = 0; \
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
            debug(STR(fn) "(%p, %p, 0x%02x, [%i]) = %li", \
                  lineptr, n, delim, fd, (long int)ret); \
        else \
            debug(STR(fn) "(%p, %p, [%i]) = %li", \
                  lineptr, n, fd, (long int)ret); \
        return ret; \
    } while(0)

#ifdef HAVE_GETLINE
ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    ssize_t ret; GETDELIM(getline, '\n', 0); return ret;
}
#endif

#ifdef HAVE_GETDELIM
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret; GETDELIM(getdelim, delim, 1); return ret;
}
#endif

#ifdef HAVE___GETDELIM
ssize_t __getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret; GETDELIM(__getdelim, delim, 1); return ret;
}
#endif

#ifdef HAVE_FGETLN
char *fgetln(FILE *stream, size_t *len)
{
    char *ret;
#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
#else
    struct fuzz *fuzz;
    size_t i, size;
#endif
    int fd;

    if(!_zz_ready)
        LOADSYM(fgetln);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return fgetln_orig(stream, len);

#if defined HAVE___SREFILL /* Don't fuzz or seek if we have __srefill() */
    _zz_disabled = 1;
    ret = fgetln_orig(stream, len);
    _zz_disabled = 0;
#else
    fuzz = _zz_getfuzz(fd);

    for(i = size = 0; ; /* i is incremented below */)
    {
        int ch;

        _zz_disabled = 1;
        ch = fgetc_orig(stream);
        _zz_disabled = 0;

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

    debug("fgetln([%i], &%li) = %p", fd, (long int)*len, ret);
    return ret;
}
#endif

#ifdef HAVE___SREFILL
int __srefill(FILE *fp)
{
    off_t newpos;
    int ret, fd, tmp;

    if(!_zz_ready)
        LOADSYM(__srefill);
    fd = fileno(fp);
    if(!_zz_ready || !_zz_iswatched(fd))
        return __srefill_orig(fp);

    ret = __srefill_orig(fp);
    tmp = _zz_disabled;
    _zz_disabled = 1;
    newpos = lseek(fd, 0, SEEK_CUR);
    _zz_disabled = tmp;
    if(ret != EOF)
    {
        if(newpos != -1)
            _zz_setpos(fd, newpos - fp->_r);
        _zz_fuzz(fd, fp->_p, fp->_r);
        _zz_addpos(fd, fp->_r);
    }

    if(!_zz_disabled)
        debug("__srefill([%i]) = %i", fd, ret);

    return ret;
}
#endif

