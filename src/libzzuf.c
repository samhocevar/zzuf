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
 *  libzzuf.c: preloaded wrapper library
 */

#include "config.h"
#define _GNU_SOURCE

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <stdarg.h>
#include <dlfcn.h>

static int do_debug = 0;
static void debug(const char *format, ...)
{
    if(!do_debug)
        return;

    va_list args;
    va_start(args, format);
    fprintf(stderr, "** zzuf debug ** ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* Library functions that we divert */
static FILE * (*fopen_orig) (const char *path, const char *mode);
static int (*open_orig) (const char *file, int oflag, ...);
static int (*open64_orig) (const char *file, int oflag, ...);

/* Library initialisation shit */
void zzufinit(void) __attribute__((constructor));
void zzufinit(void)
{
    char *tmp;

    fopen_orig = dlsym(RTLD_NEXT, "fopen");
    open_orig  = dlsym(RTLD_NEXT, "open");
    open64_orig  = dlsym(RTLD_NEXT, "open");

    tmp = getenv("ZZUF_DEBUG");
    if(tmp && *tmp)
        do_debug = 1;
}

/* Our function wrappers */
FILE *fopen(const char *path, const char *mode)
{
    debug("fopen(\"%s\", \"%s\");", path, mode);
    return fopen_orig(path, mode);
}

#define STR(x) STR2(x)
#define STR2(x) #x
#define ORIG(x) ORIG2(x)
#define ORIG2(x) x##_orig
#define OPEN(ret, fn, file, oflag) \
    do { if(oflag & O_CREAT) \
    { \
        int mode; \
        va_list va; \
        va_start(va, oflag); \
        mode = va_arg(va, int); \
        va_end(va); \
        debug(STR(fn) "(\"%s\", %i, %i);", file, oflag, mode); \
        ret = ORIG(fn)(file, oflag, mode); \
    } \
    else \
    { \
        debug(STR(fn) "(\"%s\", %i);", file, oflag); \
        ret = ORIG(fn)(file, oflag); \
    } } while(0)

int open(const char *file, int oflag, ...)
{
    int ret;
    OPEN(ret, open, file, oflag);
    return ret;
}

int open64(const char *file, int oflag, ...)
{
    int ret;
    OPEN(ret, open64, file, oflag);
    return ret;
}

