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
 *  preload.c: preloaded library functions
 */

#include "config.h"

/* Can't remember what that's for */
#define _GNU_SOURCE
/* Use this to get lseek64() */
#define _LARGEFILE64_SOURCE

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <regex.h>

#include <stdarg.h>
#include <dlfcn.h>

#include "libzzuf.h"
#include "debug.h"
#include "fuzz.h"
#include "preload.h"

/* Library functions that we divert */
static FILE *  (*fopen_orig)   (const char *path, const char *mode);
static FILE *  (*fopen64_orig) (const char *path, const char *mode);
static int     (*fseek_orig)   (FILE *stream, long offset, int whence);
static size_t  (*fread_orig)   (void *ptr, size_t size, size_t nmemb,
                                FILE *stream);
static int     (*fclose_orig)  (FILE *fp);

static int     (*open_orig)    (const char *file, int oflag, ...);
static int     (*open64_orig)  (const char *file, int oflag, ...);
static ssize_t (*read_orig)    (int fd, void *buf, size_t count);
static off64_t (*lseek64_orig) (int fd, off64_t offset, int whence);
static int     (*close_orig)   (int fd);

#define STR(x) #x
#define ORIG(x) x##_orig

#define LOADSYM(x) \
    do { \
        ORIG(x) = dlsym(RTLD_NEXT, STR(x)); \
        if(!ORIG(x)) \
            abort(); \
    } while(0)

int zzuf_preload(void)
{
    LOADSYM(fopen);
    LOADSYM(fopen64);
    LOADSYM(fseek);
    LOADSYM(fread);
    LOADSYM(fclose);

    LOADSYM(open);
    LOADSYM(open64);
    LOADSYM(read);
    LOADSYM(lseek64);
    LOADSYM(close);

    debug("libzzuf initialised");

    return 0;
}

/* Our function wrappers */
#define FOPEN(fn, path, mode) \
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
    FILE *ret; FOPEN(fopen, path, mode); return ret;
}

FILE *fopen64(const char *path, const char *mode)
{
    FILE *ret; FOPEN(fopen64, path, mode); return ret;
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

#define OPEN(fn, file, oflag) \
    do \
    { \
        int mode = 0; \
        if(!_zzuf_ready) \
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
        if(!_zzuf_ready) \
            return ret; \
        if(ret >= 0 \
            && ((oflag & (O_RDONLY | O_RDWR | O_WRONLY)) != O_WRONLY)) \
        { \
            if(_zzuf_include && \
                regexec(_zzuf_include, file, 0, NULL, 0) == REG_NOMATCH) \
                /* not included: ignore */ ; \
            else if(_zzuf_exclude && \
                    regexec(_zzuf_exclude, file, 0, NULL, 0) != REG_NOMATCH) \
                /* excluded: ignore */ ; \
            else \
            { \
                if(oflag & O_CREAT) \
                    debug(STR(fn) "(\"%s\", %i, %i) = %i", \
                          file, oflag, mode, ret); \
                else \
                    debug(STR(fn) "(\"%s\", %i) = %i", file, oflag, ret); \
                files[ret].managed = 1; \
                files[ret].pos = 0; \
            } \
        } \
    } while(0)

int open(const char *file, int oflag, ...)
{
    int ret; OPEN(open, file, oflag); return ret;
}

int open64(const char *file, int oflag, ...)
{
    int ret; OPEN(open64, file, oflag); return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
    int ret;

    if(!_zzuf_ready)
        LOADSYM(read);
    ret = read_orig(fd, buf, count);
    if(!_zzuf_ready)
        return ret;

    if(!files[fd].managed)
        return ret;

    debug("read(%i, %p, %li) = %i", fd, buf, (long int)count, ret);
    if(ret > 0)
    {
        zzuf_fuzz(fd, buf, ret);
        files[fd].pos += ret;
    }
    return ret;
}

off64_t lseek64(int fd, off64_t offset, int whence)
{
    int ret;

    if(!_zzuf_ready)
        LOADSYM(lseek64);
    ret = lseek64_orig(fd, offset, whence);
    if(!_zzuf_ready)
        return ret;

    if(!files[fd].managed)
        return ret;

    debug("lseek64(%i, %lli, %i) = %i", fd, (long long int)offset, whence, ret);
    if(ret != (off64_t)-1)
        files[fd].pos = (int64_t)ret;

    return ret;
}

int close(int fd)
{
    int ret;

    if(!_zzuf_ready)
        LOADSYM(close);
    ret = close_orig(fd);
    if(!_zzuf_ready)
        return ret;

    if(!files[fd].managed)
        return ret;

    debug("close(%i) = %i", fd, ret);
    files[fd].managed = 0;

    return ret;
}

