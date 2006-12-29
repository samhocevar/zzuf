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

#include "libzzuf.h"
#include "debug.h"
#include "fuzz.h"
#include "load.h"

/* Library functions that we divert */
static FILE *  (*fopen_orig)   (const char *path, const char *mode);
static FILE *  (*fopen64_orig) (const char *path, const char *mode);
static int     (*fseek_orig)   (FILE *stream, long offset, int whence);
static size_t  (*fread_orig)   (void *ptr, size_t size, size_t nmemb,
                                FILE *stream);
static int     (*getc_orig)    (FILE *stream);
static int     (*fgetc_orig)   (FILE *stream);
static char *  (*fgets_orig)   (char *s, int size, FILE *stream);
static int     (*ungetc_orig)  (int c, FILE *stream);
static int     (*fclose_orig)  (FILE *fp);

/* Additional GNUisms */
static ssize_t (*getline_orig)    (char **lineptr, size_t *n, FILE *stream);
static ssize_t (*getdelim_orig)   (char **lineptr, size_t *n, int delim,
                                   FILE *stream);
static ssize_t (*__getdelim_orig) (char **lineptr, size_t *n, int delim,
                                   FILE *stream);

void _zz_load_stream(void)
{
    LOADSYM(fopen);
    LOADSYM(fopen64);
    LOADSYM(fseek);
    LOADSYM(fread);
    LOADSYM(getc);
    LOADSYM(fgetc);
    LOADSYM(fgets);
    LOADSYM(ungetc);
    LOADSYM(fclose);

    LOADSYM(getline);
    LOADSYM(getdelim);
    LOADSYM(__getdelim);
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
        ret = ORIG(fn)(path, mode); \
        if(ret && _zz_mustwatch(path)) \
        { \
            int fd = fileno(ret); \
            _zz_register(fd); \
            debug(STR(fn) "(\"%s\", \"%s\") = %p", path, mode, ret); \
        } \
    } while(0)

FILE *fopen(const char *path, const char *mode)
{
    FILE *ret; FOPEN(fopen); return ret;
}

FILE *fopen64(const char *path, const char *mode)
{
    FILE *ret; FOPEN(fopen64); return ret;
}

int fseek(FILE *stream, long offset, int whence)
{
    int ret, fd;

    if(!_zz_ready)
        LOADSYM(fseek);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return fseek_orig(stream, offset, whence);

    ret = fseek_orig(stream, offset, whence);
    debug("fseek(%p, %li, %i) = %i", stream, offset, whence, ret);
    if(ret != 0)
        return ret;

    switch(whence)
    {
        case SEEK_END:
            offset = ftell(stream);
            /* fall through */
        case SEEK_SET:
            _zz_setpos(fd, offset);
            break;
        case SEEK_CUR:
            _zz_addpos(fd, offset);
            break;
    }
    return 0;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    long int pos;
    size_t ret;
    int fd;

    if(!_zz_ready)
        LOADSYM(fread);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return fread_orig(ptr, size, nmemb, stream);

    pos = ftell(stream);
    ret = fread_orig(ptr, size, nmemb, stream);
    debug("fread(%p, %li, %li, %p) = %li",
          ptr, (long int)size, (long int)nmemb, stream, (long int)ret);
    if(ret >= 0)
    {
        /* XXX: the number of bytes read is not ret * size, because
         * a partial read may have advanced the stream pointer */
        long int newpos = ftell(stream);
        _zz_fuzz(fd, ptr, newpos - pos);
        _zz_setpos(fd, newpos);
    }
    return ret;
}

#define FGETC(fn) \
    do { \
        int fd; \
        if(!_zz_ready) \
            LOADSYM(fn); \
        fd = fileno(stream); \
        if(!_zz_ready || !_zz_iswatched(fd)) \
            return ORIG(fn)(stream); \
        ret = ORIG(fn)(stream); \
        if(ret != EOF) \
        { \
            uint8_t ch = ret; \
            _zz_fuzz(fd, &ch, 1); \
            _zz_addpos(fd, 1); \
            ret = ch; \
        } \
        debug(STR(fn)"(%p) = 0x%02x", stream, ret); \
    } while(0)

int getc(FILE *stream)
{
    int ret; FGETC(getc); return ret;
}

int fgetc(FILE *stream)
{
    int ret; FGETC(fgetc); return ret;
}

char *fgets(char *s, int size, FILE *stream)
{
    char *ret = s;
    int i, fd;

    if(!_zz_ready)
        LOADSYM(fgets);
    fd = fileno(stream);
    if(!_zz_ready || !_zz_iswatched(fd))
        return fgets_orig(s, size, stream);

    if(size <= 0)
        ret = NULL;
    else if(size == 1)
        s[0] = '\0';
    else
    {
        for(i = 0; i < size - 1; i++)
        {
            int ch = fgetc_orig(stream);

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

    debug("fgets(%p, %i, %p) = %p", s, size, stream, ret);
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

    _zz_addpos(fd, -1);
    _zz_fuzz(fd, &ch, 1);
    ret = ungetc_orig((int)ch, stream);
    if(ret >= 0)
        ret = c;
    else
        _zz_addpos(fd, 1); /* revert what we did */
    debug("ungetc(0x%02x, %p) = 0x%02x", c, stream, ret);
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

    ret = fclose_orig(fp);
    debug("fclose(%p) = %i", fp, ret);
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
            ch = fgetc_orig(stream); \
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
            debug(STR(fn) "(%p, %p, 0x%02x, %p) = %li", \
                  lineptr, n, delim, stream, (long int)ret); \
        else \
            debug(STR(fn) "(%p, %p, %p) = %li", \
                  lineptr, n, stream, (long int)ret); \
        return ret; \
    } while(0)

ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    ssize_t ret; GETDELIM(getline, '\n', 0); return ret;
}

ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret; GETDELIM(getdelim, delim, 1); return ret;
}

ssize_t __getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret; GETDELIM(__getdelim, delim, 1); return ret;
}

