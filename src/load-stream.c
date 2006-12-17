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
#include <regex.h>
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

void zzuf_load_stream(void)
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
        if(!_zzuf_ready) \
        { \
            LOADSYM(fn); \
            return ORIG(fn)(path, mode); \
        } \
        ret = ORIG(fn)(path, mode); \
        if(ret) \
        { \
            if(_zzuf_include && \
                regexec(_zzuf_include, path, 0, NULL, 0) == REG_NOMATCH) \
                /* not included: ignore */ ; \
            else if(_zzuf_exclude && \
                    regexec(_zzuf_exclude, path, 0, NULL, 0) != REG_NOMATCH) \
                /* excluded: ignore */ ; \
            else \
            { \
                int fd = fileno(ret); \
                files[fd].managed = 1; \
                files[fd].pos = 0; \
                files[fd].cur = -1; \
                files[fd].data = malloc(CHUNKBYTES); \
                debug(STR(fn) "(\"%s\", \"%s\") = %p", path, mode, ret); \
            } \
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

    if(!_zzuf_ready)
        LOADSYM(fseek);
    fd = fileno(stream);
    if(!_zzuf_ready || !files[fd].managed)
        return fseek_orig(stream, offset, whence);

    ret = fseek_orig(stream, offset, whence);
    debug("fseek(%p, %li, %i) = %i", stream, offset, whence, ret);
    if(ret == 0)
    {
        switch(whence)
        {
            case SEEK_SET: files[fd].pos = offset; break;
            case SEEK_CUR: files[fd].pos += offset; break;
            case SEEK_END: files[fd].pos = ftell(stream); break;
        }
    }
    return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret;
    int fd;

    if(!_zzuf_ready)
        LOADSYM(fread);
    fd = fileno(stream);
    if(!_zzuf_ready || !files[fd].managed)
        return fread_orig(ptr, size, nmemb, stream);

    ret = fread_orig(ptr, size, nmemb, stream);
    debug("fread(%p, %li, %li, %p) = %li",
          ptr, (long int)size, (long int)nmemb, stream, (long int)ret);
    if(ret > 0)
    {
        zzuf_fuzz(fd, ptr, ret * size);
        files[fd].pos += ret * size;
    }
    return ret;
}

#define FGETC(fn) \
    do { \
        int fd; \
        if(!_zzuf_ready) \
            LOADSYM(fn); \
        fd = fileno(stream); \
        if(!_zzuf_ready || !files[fd].managed) \
            return ORIG(fn)(stream); \
        ret = ORIG(fn)(stream); \
        if(ret != EOF) \
        { \
            uint8_t ch = ret; \
            zzuf_fuzz(fd, &ch, 1); \
            files[fd].pos += 1; \
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

    if(!_zzuf_ready)
        LOADSYM(fgets);
    fd = fileno(stream);
    if(!_zzuf_ready || !files[fd].managed)
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
            zzuf_fuzz(fd, (uint8_t *)s + i, 1); /* rather inefficient */
            files[fd].pos++;
            if(s[i] == '\n')
            {
                s[i + 1] = '\0';
                break;
            }
        }
    }

    debug("fgets(%p, %i, %p) = %p", s, size, stream, ret);
    if(ret >= 0)
        files[fd].pos += 1;
    return ret;
}

int ungetc(int c, FILE *stream)
{
    unsigned char ch = c;
    int ret, fd;

    if(!_zzuf_ready)
        LOADSYM(ungetc);
    fd = fileno(stream);
    if(!_zzuf_ready || !files[fd].managed)
        return ungetc_orig(c, stream);

    files[fd].pos -= 1;
    zzuf_fuzz(fd, &ch, 1);
    ret = ungetc_orig((int)ch, stream);
    if(ret >= 0)
        ret = c;
    else
        files[fd].pos += 1; /* revert what we did */
    debug("ungetc(0x%02x, %p) = 0x%02x", c, stream, ret);
    return ret;
}

int fclose(FILE *fp)
{
    int ret, fd;

    if(!_zzuf_ready)
        LOADSYM(fclose);
    fd = fileno(fp);
    if(!_zzuf_ready || !files[fd].managed)
        return fclose_orig(fp);

    ret = fclose_orig(fp);
    debug("fclose(%p) = %i", fp, ret);
    files[fd].managed = 0;
    free(files[fd].data);

    return ret;
}

#define GETDELIM(fn, delim, need_delim) \
    do { \
        char *line; \
        ssize_t done, size; \
        int fd, finished = 0; \
        if(!_zzuf_ready) \
            LOADSYM(fn); \
        fd = fileno(stream); \
        if(!_zzuf_ready || !files[fd].managed) \
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
                zzuf_fuzz(fd, &c, 1); /* even more inefficient */ \
                line[done++] = c; \
                files[fd].pos++; \
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

