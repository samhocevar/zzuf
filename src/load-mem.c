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

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <unistd.h>
#include <sys/mman.h>
#if defined HAVE_LIBC_H
#   include <libc.h>
#endif

#include "libzzuf.h"
#include "debug.h"
#include "fuzz.h"
#include "load.h"
#include "fd.h"

/* Library functions that we divert */
static void *  (*mmap_orig)    (void *start, size_t length, int prot,
                                int flags, int fd, off_t offset);
#ifdef HAVE_MMAP64
static void *  (*mmap64_orig)  (void *start, size_t length, int prot,
                                int flags, int fd, off64_t offset);
#endif
static int     (*munmap_orig)  (void *start, size_t length);
#ifdef HAVE_MAP_FD
static kern_return_t (*map_fd_orig) (int fd, vm_offset_t offset,
                                     vm_offset_t *addr, boolean_t find_space,
                                     vm_size_t numbytes);
#endif

void _zz_load_mem(void)
{
    LOADSYM(mmap);
#ifdef HAVE_MMAP64
    LOADSYM(mmap64);
#endif
    LOADSYM(munmap);
#ifdef HAVE_MAP_FD
    LOADSYM(map_fd);
#endif
}

/* Table used for mmap() and munmap() */
void **maps = NULL;
int nbmaps = 0;

#define MMAP(fn, off_t) \
    do { \
        if(!_zz_ready) \
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
                debug(STR(fn)"(%p, %li, %i, %i, %i, %lli) = %p \"%c%c%c%c...", \
                      start, (long int)length, prot, flags, fd, \
                      (long long int)offset, ret, b[0], b[1], b[2], b[3]); \
            else \
                debug(STR(fn)"(%p, %li, %i, %i, %i, %lli) = %p \"%c...", \
                      start, (long int)length, prot, flags, fd, \
                      (long long int)offset, ret, b[0]); \
        } \
        else \
            debug(STR(fn)"(%p, %li, %i, %i, %i, %lli) = %p", \
                  start, (long int)length, prot, flags, fd, \
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

    if(!_zz_ready)
        LOADSYM(munmap);
    for(i = 0; i < nbmaps; i++)
    {
        if(maps[i] != start)
            continue;

        free(start);
        ret = munmap_orig(maps[i + 1], length);
        maps[i] = NULL;
        maps[i + 1] = NULL;
        debug("munmap(%p, %li) = %i", start, (long int)length, ret);
        return ret;
    }

    return munmap_orig(start, length);
}

#ifdef HAVE_MAP_FD
kern_return_t map_fd(int fd, vm_offset_t offset, vm_offset_t *addr,
                     boolean_t find_space, vm_size_t numbytes)
{
    kern_return_t ret;

    if(!_zz_ready)
        LOADSYM(map_fd);
    ret = map_fd_orig(fd, offset, addr, find_space, numbytes);
    if(!_zz_ready || !_zz_iswatched(fd) || _zz_disabled)
        return ret;

    if(ret == 0 && numbytes)
    {
        /* FIXME: do we also have to rewind the filedescriptor like in mmap? */
        void *b = malloc(numbytes);
        memcpy(b, (void *)*addr, numbytes);
        _zz_fuzz(fd, b, numbytes);
        *addr = (vm_offset_t)b;
        /* FIXME: the map is never freed; there is no such thing as unmap_fd,
         * but I suppose that kind of map should go when the filedescriptor is
         * closed (unlike mmap, which returns a persistent buffer). */

        if(numbytes >= 4)
           debug("map_fd(%i, %lli, &%p, %i, %lli) = %i \"%c%c%c%c", fd,
                 (long long int)offset, (void *)*addr, (int)find_space,
                 (long long int)numbytes, ret, b[0], b[1], b[2], b[3]);
        else
           debug("map_fd(%i, %lli, &%p, %i, %lli) = %i \"%c", fd,
                 (long long int)offset, (void *)*addr, (int)find_space,
                 (long long int)numbytes, ret, b[0]);
    }
    else
        debug("map_fd(%i, %lli, &%p, %i, %lli) = %i", fd, (long long int)offset,
              (void *)*addr, (int)find_space, (long long int)numbytes, ret);

    return ret;
}
#endif

