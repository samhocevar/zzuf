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
#define _GNU_SOURCE

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
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
static size_t  (*fread_orig)   (void *ptr, size_t size, size_t nmemb,
                                FILE *stream);
static int     (*open_orig)    (const char *file, int oflag, ...);
static int     (*open64_orig)  (const char *file, int oflag, ...);
static ssize_t (*read_orig)    (int fd, void *buf, size_t count);

#define STR(x) #x
#define ORIG(x) x##_orig

#define LOADSYM(x) \
    do { \
        ORIG(x) = dlsym(RTLD_NEXT, STR(x)); \
        if(!ORIG(x)) \
            return -1; \
    } while(0)

int zzuf_preload(void)
{
    LOADSYM(fopen);
    LOADSYM(fopen64);
    LOADSYM(fread);
    LOADSYM(open);
    LOADSYM(open64);
    LOADSYM(read);

    debug("libzzuf initialised");

    return 0;
}

/* Our function wrappers */
#define FOPEN(ret, fn, path, mode) \
    do \
    { \
        ret = ORIG(fn)(path, mode); \
        debug(STR(fn) "(\"%s\", \"%s\") = %p", path, mode, ret); \
        if(ret \
            && (!_zzuf_include || !regexec(_zzuf_include, path, 0, NULL, 0)) \
            && (!_zzuf_exclude || regexec(_zzuf_exclude, path, 0, NULL, 0))) \
        { \
            int fd = fileno(ret); \
            files[fd].managed = 1; \
            files[fd].pos = 0; \
        } \
    } while(0)

FILE *fopen(const char *path, const char *mode)
{
    FILE *f; FOPEN(f, fopen, path, mode); return f;
}

FILE *fopen64(const char *path, const char *mode)
{
    FILE *f; FOPEN(f, fopen64, path, mode); return f;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret = fread_orig(ptr, size, nmemb, stream);
    debug("fread(%p, %li, %li, \"%s\") = %li",
          ptr, (long int)size, (long int)nmemb, stream, (long int)ret);
    if(ret > 0)
    {
        zzuf_fuzz(fileno(stream), ptr, ret * size);
        files[fileno(stream)].pos += ret * size;
    }
    return ret;
}

#define OPEN(ret, fn, file, oflag) \
    do \
    { \
        if(oflag & O_CREAT) \
        { \
            int mode; \
            va_list va; \
            va_start(va, oflag); \
            mode = va_arg(va, int); \
            va_end(va); \
            ret = ORIG(fn)(file, oflag, mode); \
            debug(STR(fn) "(\"%s\", %i, %i) = %i", file, oflag, mode, ret); \
        } \
        else \
        { \
            ret = ORIG(fn)(file, oflag); \
            debug(STR(fn) "(\"%s\", %i) = %i", file, oflag, ret); \
        } \
        \
        if(ret >= 0 \
            && ((oflag & (O_RDONLY | O_RDWR | O_WRONLY)) != O_WRONLY) \
            && (!_zzuf_include || !regexec(_zzuf_include, file, 0, NULL, 0)) \
            && (!_zzuf_exclude || regexec(_zzuf_exclude, file, 0, NULL, 0))) \
        { \
            files[ret].managed = 1; \
            files[ret].pos = 0; \
        } \
    } while(0)

int open(const char *file, int oflag, ...)
{
    int ret; OPEN(ret, open, file, oflag); return ret;
}

int open64(const char *file, int oflag, ...)
{
    int ret; OPEN(ret, open64, file, oflag); return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
    int ret = read_orig(fd, buf, count);
    debug("read(%i, %p, %li) = %i", fd, buf, (long int)count, ret);
    if(ret > 0)
    {
        zzuf_fuzz(fd, buf, ret);
        files[fd].pos += ret;
    }
    return ret;
}

