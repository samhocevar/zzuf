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

/* Can't remember what that's for */
#define _GNU_SOURCE

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
static int     (*fclose_orig)  (FILE *fp);

void zzuf_load_stream(void)
{
    LOADSYM(fopen);
    LOADSYM(fopen64);
    LOADSYM(fseek);
    LOADSYM(fread);
    LOADSYM(fclose);
}

/* Our function wrappers */
#define FOPEN(fn) \
    do \
    { \
        if(!_zzuf_ready) \
            LOADSYM(fn); \
        ret = ORIG(fn)(path, mode); \
        if(!_zzuf_ready) \
            return ret; \
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
    ret = fseek_orig(stream, offset, whence);
    if(!_zzuf_ready)
        return ret;

    fd = fileno(stream);
    if(!files[fd].managed)
        return ret;

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
    ret = fread_orig(ptr, size, nmemb, stream);
    if(!_zzuf_ready)
        return ret;

    fd = fileno(stream);
    if(!files[fd].managed)
        return ret;

    debug("fread(%p, %li, %li, %p) = %li",
          ptr, (long int)size, (long int)nmemb, stream, (long int)ret);
    if(ret > 0)
    {
        zzuf_fuzz(fd, ptr, ret * size);
        files[fd].pos += ret * size;
    }
    return ret;
}

int fclose(FILE *fp)
{
    int ret, fd;

    if(!_zzuf_ready)
        LOADSYM(fclose);
    fd = fileno(fp);
    ret = fclose_orig(fp);
    if(!_zzuf_ready)
        return ret;

    if(!files[fd].managed)
        return ret;

    debug("fclose(%p) = %i", fp, ret);
    files[fd].managed = 0;

    return ret;
}

