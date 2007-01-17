/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006,2007 Sam Hocevar <sam@zoy.org>
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
 *  load-mem.c: loaded memory handling functions
 */

#include "config.h"

/* Need this for RTLD_NEXT */
#define _GNU_SOURCE
/* Use this to get mmap64() on glibc systems */
#define _LARGEFILE64_SOURCE
/* Use this to get posix_memalign */
#if defined HAVE_POSIX_MEMALIGN
#   define _XOPEN_SOURCE 600
#endif

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>

#if defined HAVE_MALLOC_H
#   include <malloc.h>
#endif
#include <unistd.h>
#include <sys/mman.h>
#if defined HAVE_LIBC_H
#   include <libc.h>
#endif

#include "libzzuf.h"
#include "lib-load.h"
#include "debug.h"
#include "fuzz.h"
#include "fd.h"

/* TODO: mremap, maybe brk/sbrk (haha) */

/* Library functions that we divert */
static void *  (*calloc_orig)   (size_t nmemb, size_t size);
static void *  (*malloc_orig)   (size_t size);
static void    (*free_orig)     (void *ptr);
static void *  (*valloc_orig)   (size_t size);
#ifdef HAVE_MEMALIGN
static void *  (*memalign_orig) (size_t boundary, size_t size);
#endif
#ifdef HAVE_POSIX_MEMALIGN
static int     (*posix_memalign_orig) (void **memptr, size_t alignment,
                                       size_t size);
#endif
static void *  (*realloc_orig)  (void *ptr, size_t size);

static void *  (*mmap_orig)     (void *start, size_t length, int prot,
                                 int flags, int fd, off_t offset);
#ifdef HAVE_MMAP64
static void *  (*mmap64_orig)   (void *start, size_t length, int prot,
                                 int flags, int fd, off64_t offset);
#endif
static int     (*munmap_orig)   (void *start, size_t length);
#ifdef HAVE_MAP_FD
static kern_return_t (*map_fd_orig) (int fd, vm_offset_t offset,
                                     vm_offset_t *addr, boolean_t find_space,
                                     vm_size_t numbytes);
#endif

/* We need a static memory buffer because some functions call memory
 * allocation routines before our library is loaded. Hell, even dlsym()
 * calls calloc(), so we need to do something about it */
#define DUMMY_BYTES 655360 /* 640 kB ought to be enough for anybody */
static uint64_t dummy_buffer[DUMMY_BYTES / 8];
static int dummy_offset = 0;
#define DUMMY_START ((uintptr_t)dummy_buffer)
#define DUMMY_STOP ((uintptr_t)dummy_buffer + DUMMY_BYTES)

void *calloc(size_t nmemb, size_t size)
{
    void *ret;
    if(!calloc_orig)
    {
        ret = dummy_buffer + dummy_offset;
        memset(ret, 0, (nmemb * size + 7) / 8);
        dummy_offset += (nmemb * size + 7) / 8;
        return ret;
    }
    ret = calloc_orig(nmemb, size);
    if(ret == NULL && _zz_memory && errno == ENOMEM)
        raise(SIGKILL);
    return ret;
}

void *malloc(size_t size)
{
    void *ret;
    if(!malloc_orig)
    {
        ret = dummy_buffer + dummy_offset;
        dummy_offset += (size + 7) / 8;
        return ret;
    }
    ret = malloc_orig(size);
    if(ret == NULL && _zz_memory && errno == ENOMEM)
        raise(SIGKILL);
    return ret;
}

void free(void *ptr)
{
    if((uintptr_t)ptr >= DUMMY_START && (uintptr_t)ptr < DUMMY_STOP)
        return;
    LOADSYM(free);
    free_orig(ptr);
}

void *realloc(void *ptr, size_t size)
{
    void *ret;
    if((uintptr_t)ptr >= DUMMY_START && (uintptr_t)ptr < DUMMY_STOP)
    {
        ret = dummy_buffer + dummy_offset;
        memcpy(ret, ptr, size);
        dummy_offset += (size + 7) * 8;
        return ret;
    }
    LOADSYM(realloc);
    ret = realloc_orig(ptr, size);
    if(ret == NULL && _zz_memory && errno == ENOMEM)
        raise(SIGKILL);
    return ret;
}

void *valloc(size_t size)
{
    void *ret;
    LOADSYM(valloc);
    ret = valloc_orig(size);
    if(ret == NULL && _zz_memory && errno == ENOMEM)
        raise(SIGKILL);
    return ret;
}

#ifdef HAVE_MEMALIGN
void *memalign(size_t boundary, size_t size)
{
    void *ret;
    LOADSYM(memalign);
    ret = memalign_orig(boundary, size);
    if(ret == NULL && _zz_memory && errno == ENOMEM)
        raise(SIGKILL);
    return ret;
}
#endif

#ifdef HAVE_POSIX_MEMALIGN
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    int ret;
    LOADSYM(posix_memalign);
    ret = posix_memalign_orig(memptr, alignment, size);
    if(ret == ENOMEM && _zz_memory)
        raise(SIGKILL);
    return ret;
}
#endif

/* Table used for mmap() and munmap() */
void **maps = NULL;
int nbmaps = 0;

#define MMAP(fn, off_t) \
    do { \
        LOADSYM(fn); \
        ret = ORIG(fn)(start, length, prot, flags, fd, offset); \
        if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled) \
            return ret; \
        if(ret && length) \
        { \
            char *b = malloc(length); \
            int i, oldpos; \
            for(i = 0; i < nbmaps; i += 2) \
                if(maps[i] == NULL) \
                    break; \
            if(i == nbmaps) \
            { \
                nbmaps += 2; \
                maps = realloc(maps, nbmaps * sizeof(void *)); \
            } \
            maps[i] = b; \
            maps[i + 1] = ret; \
            oldpos = _zz_getpos(fd); \
            _zz_setpos(fd, offset); /* mmap() maps the fd at offset 0 */ \
            memcpy(b, ret, length); /* FIXME: get rid of this */ \
            _zz_fuzz(fd, (uint8_t *)b, length); \
            _zz_setpos(fd, oldpos); \
            ret = b; \
            if(length >= 4) \
                debug("%s(%p, %li, %i, %i, %i, %lli) = %p \"%c%c%c%c...", \
                      __func__, start, (long int)length, prot, flags, fd, \
                      (long long int)offset, ret, b[0], b[1], b[2], b[3]); \
            else \
                debug("%s(%p, %li, %i, %i, %i, %lli) = %p \"%c...", \
                      __func__, start, (long int)length, prot, flags, fd, \
                      (long long int)offset, ret, b[0]); \
        } \
        else \
            debug("%s(%p, %li, %i, %i, %i, %lli) = %p", \
                  __func__, start, (long int)length, prot, flags, fd, \
                  (long long int)offset, ret); \
    } while(0)

void *mmap(void *start, size_t length, int prot, int flags,
           int fd, off_t offset)
{
    void *ret; MMAP(mmap, off_t); return ret;
}

#ifdef HAVE_MMAP64
void *mmap64(void *start, size_t length, int prot, int flags,
             int fd, off64_t offset)
{
    void *ret; MMAP(mmap64, off64_t); return ret;
}
#endif

int munmap(void *start, size_t length)
{
    int ret, i;

    LOADSYM(munmap);
    for(i = 0; i < nbmaps; i++)
    {
        if(maps[i] != start)
            continue;

        free(start);
        ret = munmap_orig(maps[i + 1], length);
        maps[i] = NULL;
        maps[i + 1] = NULL;
        debug("%s(%p, %li) = %i", __func__, start, (long int)length, ret);
        return ret;
    }

    return munmap_orig(start, length);
}

#ifdef HAVE_MAP_FD
kern_return_t map_fd(int fd, vm_offset_t offset, vm_offset_t *addr,
                     boolean_t find_space, vm_size_t numbytes)
{
    kern_return_t ret;

    LOADSYM(map_fd);
    ret = map_fd_orig(fd, offset, addr, find_space, numbytes);
    if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled)
        return ret;

    if(ret == 0 && numbytes)
    {
        /* FIXME: do we also have to rewind the filedescriptor like in mmap? */
        char *b = malloc(numbytes);
        memcpy(b, (void *)*addr, numbytes);
        _zz_fuzz(fd, (void *)b, numbytes);
        *addr = (vm_offset_t)b;
        /* FIXME: the map is never freed; there is no such thing as unmap_fd,
         * but I suppose that kind of map should go when the filedescriptor is
         * closed (unlike mmap, which returns a persistent buffer). */

        if(numbytes >= 4)
           debug("%s(%i, %lli, &%p, %i, %lli) = %i \"%c%c%c%c", __func__,
                 fd, (long long int)offset, (void *)*addr, (int)find_space,
                 (long long int)numbytes, ret, b[0], b[1], b[2], b[3]);
        else
           debug("%s(%i, %lli, &%p, %i, %lli) = %i \"%c", __func__, fd,
                 (long long int)offset, (void *)*addr, (int)find_space,
                 (long long int)numbytes, ret, b[0]);
    }
    else
        debug("%s(%i, %lli, &%p, %i, %lli) = %i", __func__, fd,
              (long long int)offset, (void *)*addr, (int)find_space,
              (long long int)numbytes, ret);

    return ret;
}
#endif

