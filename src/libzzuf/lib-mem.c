/*
 *  zzuf - general purpose fuzzer
 *
 *  Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by the WTFPL Task Force.
 *  See http://www.wtfpl.net/ for more details.
 */

/*
 *  load-mem.c: loaded memory handling functions
 */

#include "config.h"

/* Need this for off64_t */
#define _GNU_SOURCE
/* Need this for MAP_ANON and valloc() on FreeBSD (together with cdefs.h) */
#define _BSD_SOURCE
#if defined HAVE_SYS_CDEFS_H
#   include <sys/cdefs.h>
#endif
/* Use this to get mmap64() on glibc systems */
#undef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
/* Use this to get ENOMEM on HP-UX */
#define _INCLUDE_POSIX_SOURCE
/* Need this to get standard mmap() on OpenSolaris */
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 3
/* Need this to get valloc() on OpenSolaris */
#define __EXTENSIONS__
/* Need this to include <libc.h> on OS X */
#define _DARWIN_C_SOURCE
/* Use this to get posix_memalign */
#if defined HAVE_POSIX_MEMALIGN && !defined __sun
#   undef _XOPEN_SOURCE
#   define _XOPEN_SOURCE 600
#endif

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#if defined HAVE_MALLOC_H
#   include <malloc.h>
#endif
#if defined HAVE_UNISTD_H
#   include <unistd.h>
#endif
#if defined HAVE_SYS_MMAN_H
#   include <sys/mman.h>
#endif
#if defined HAVE_LIBC_H
#   include <libc.h>
#endif
#if defined HAVE_MACH_TASK_H
#   include <mach/mach.h>
#   include <mach/task.h>
#endif

#include "libzzuf.h"
#include "lib-load.h"
#include "debug.h"
#include "fuzz.h"
#include "fd.h"

#if !defined SIGKILL
#   define SIGKILL 9
#endif

#if !defined MAP_ANONYMOUS
#   define MAP_ANONYMOUS MAP_ANON
#endif

/* TODO: mremap, maybe brk/sbrk (haha) */

/* Library functions that we divert */
static void *  (*ORIG(calloc))   (size_t nmemb, size_t size);
static void *  (*ORIG(malloc))   (size_t size);
static void    (*ORIG(free))     (void *ptr);
#if defined HAVE_VALLOC
static void *  (*ORIG(valloc))   (size_t size);
#endif
#if defined HAVE_MEMALIGN
static void *  (*ORIG(memalign)) (size_t boundary, size_t size);
#endif
#if defined HAVE_POSIX_MEMALIGN
static int     (*ORIG(posix_memalign)) (void **memptr, size_t alignment,
                                        size_t size);
#endif
static void *  (*ORIG(realloc))  (void *ptr, size_t size);

#if defined HAVE_MMAP
static void *  (*ORIG(mmap))     (void *start, size_t length, int prot,
                                  int flags, int fd, off_t offset);
#endif
#if defined HAVE_MMAP64
static void *  (*ORIG(mmap64))   (void *start, size_t length, int prot,
                                  int flags, int fd, off64_t offset);
#endif
#if defined HAVE_MUNMAP
static int     (*ORIG(munmap))   (void *start, size_t length);
#endif
#if defined HAVE_MAP_FD
static kern_return_t (*ORIG(map_fd)) (int fd, vm_offset_t offset,
                                      vm_offset_t *addr, boolean_t find_space,
                                      vm_size_t numbytes);
#endif

/* We need a static memory buffer because some functions call memory
 * allocation routines before our library is loaded. Hell, even dlsym()
 * calls calloc(), so we need to do something about it. The dummy buffer
 * is defined as an uint64_t array to ensure at least 8-byte alignment. */
#define DUMMY_BYTES 640*1024 /* 640 kB ought to be enough for anybody */
#define DUMMY_TYPE uint64_t
#define DUMMY_ALIGNMENT (sizeof(DUMMY_TYPE))
static DUMMY_TYPE dummy_buffer[DUMMY_BYTES / DUMMY_ALIGNMENT];
static int64_t dummy_offset = 0;
#define DUMMY_START ((uintptr_t)dummy_buffer)
#define DUMMY_STOP ((uintptr_t)dummy_buffer + DUMMY_BYTES)

/* setrlimit(RLIMIT_AS) is ignored on OS X, we need to check memory usage
 * from inside the process. Oh, and getrusage() doesn't work either. */
static int memory_exceeded(void)
{
#if defined HAVE_MACH_TASK_H
    struct task_basic_info tbi;
    mach_msg_type_number_t mmtn = TASK_BASIC_INFO_COUNT;

    if (task_info(mach_task_self(), TASK_BASIC_INFO,
                  (task_info_t)&tbi, &mmtn) == KERN_SUCCESS
         && (int64_t)tbi.resident_size / 1048576 > (int64_t)g_memory_limit)
        return 1;
#endif
    return 0;
}

void _zz_mem_init(void)
{
    LOADSYM(free);
    LOADSYM(calloc);
    LOADSYM(malloc);
    LOADSYM(realloc);
}

#undef calloc
void *NEW(calloc)(size_t nmemb, size_t size)
{
    if (!ORIG(calloc))
    {
        /* Store the chunk length just before the buffer we'll return */
        size_t lsize = size;
        memcpy(dummy_buffer + dummy_offset, &lsize, sizeof(size_t));
        dummy_offset++;

        void *ret = dummy_buffer + dummy_offset;
        memset(ret, 0, nmemb * size);
        dummy_offset += (nmemb * size + DUMMY_ALIGNMENT - 1) / DUMMY_ALIGNMENT;
        debug("%s(%li, %li) = %p", __func__,
              (long int)nmemb, (long int)size, ret);
        return ret;
    }

    void *ret = ORIG(calloc)(nmemb, size);
    if (ret == NULL && g_memory_limit && errno == ENOMEM)
        raise(SIGKILL);
    return ret;
}

#undef malloc
void *NEW(malloc)(size_t size)
{
    void *ret;
    if (!ORIG(malloc))
    {
        /* Store the chunk length just before the buffer we'll return */
        memcpy(dummy_buffer + dummy_offset, &size, sizeof(size_t));
        dummy_offset++;

        ret = dummy_buffer + dummy_offset;
        dummy_offset += (size + DUMMY_ALIGNMENT - 1) / DUMMY_ALIGNMENT;
        debug("%s(%li) = %p", __func__, (long int)size, ret);
        return ret;
    }
    ret = ORIG(malloc)(size);
    if (g_memory_limit && ((!ret && errno == ENOMEM)
                        || (ret && memory_exceeded())))
        raise(SIGKILL);
    return ret;
}

#undef free
void NEW(free)(void *ptr)
{
    if ((uintptr_t)ptr >= DUMMY_START && (uintptr_t)ptr < DUMMY_STOP)
    {
        debug("%s(%p)", __func__, ptr);
        return;
    }
    if (!ORIG(free))
    {
        /* FIXME: if free() doesn't exist yet, we have a memory leak */
        debug("%s(%p) IGNORED", __func__, ptr);
        return;
    }
    ORIG(free)(ptr);
}

#undef realloc
void *NEW(realloc)(void *ptr, size_t size)
{
    if (!ORIG(realloc)
        || ((uintptr_t)ptr >= DUMMY_START && (uintptr_t)ptr < DUMMY_STOP))
    {
        size_t oldsize;

        /* Store the chunk length just before the buffer we'll return */
        memcpy(dummy_buffer + dummy_offset, &size, sizeof(size_t));
        dummy_offset++;

        void *ret = dummy_buffer + dummy_offset;
        if ((uintptr_t)ptr >= DUMMY_START && (uintptr_t)ptr < DUMMY_STOP)
            memcpy(&oldsize, (DUMMY_TYPE *)ptr - 1, sizeof(size_t));
        else
            oldsize = 0;
        memcpy(ret, ptr, size < oldsize ? size : oldsize);
        dummy_offset += (size + DUMMY_ALIGNMENT - 1) / DUMMY_ALIGNMENT;
        debug("%s(%p, %li) = %p", __func__, ptr, (long int)size, ret);
        return ret;
    }

    LOADSYM(realloc);

    void *ret = ORIG(realloc)(ptr, size);
    if (g_memory_limit && ((!ret && errno == ENOMEM)
                        || (ret && memory_exceeded())))
        raise(SIGKILL);
    return ret;
}

#if defined HAVE_VALLOC
#undef valloc
void *NEW(valloc)(size_t size)
{
    LOADSYM(valloc);

    void *ret = ORIG(valloc)(size);
    if (g_memory_limit && ((!ret && errno == ENOMEM)
                        || (ret && memory_exceeded())))
        raise(SIGKILL);
    return ret;
}
#endif

#if defined HAVE_MEMALIGN
#undef memalign
void *NEW(memalign)(size_t boundary, size_t size)
{
    LOADSYM(memalign);

    void *ret = ORIG(memalign)(boundary, size);
    if (g_memory_limit && ((!ret && errno == ENOMEM)
                        || (ret && memory_exceeded())))
        raise(SIGKILL);
    return ret;
}
#endif

#if defined HAVE_POSIX_MEMALIGN
#undef posix_memalign
int NEW(posix_memalign)(void **memptr, size_t alignment, size_t size)
{
    LOADSYM(posix_memalign);

    int ret = ORIG(posix_memalign)(memptr, alignment, size);
    if (g_memory_limit && ((!ret && errno == ENOMEM)
                        || (ret && memory_exceeded())))
        raise(SIGKILL);
    return ret;
}
#endif

/* Table used for mmap() and munmap() */
void **maps = NULL;
int nbmaps = 0;

#define ZZ_MMAP(mymmap, off_t) \
    do { \
        LOADSYM(mymmap); \
        \
        if (!must_fuzz_fd(fd)) \
            return ORIG(mymmap)(start, length, prot, flags, fd, offset); \
        \
        char *b = MAP_FAILED; \
        \
        ret = ORIG(mymmap)(NULL, length, prot, flags, fd, offset); \
        if (ret != MAP_FAILED && length) \
        { \
            b = ORIG(mymmap)(start, length, PROT_READ | PROT_WRITE, \
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); \
            if (b == MAP_FAILED) \
            { \
                munmap(ret, length); \
                ret = MAP_FAILED; \
            } \
        } \
        \
        size_t data_length = 0; \
        if (b != MAP_FAILED) \
        { \
            int i, oldpos; \
            for (i = 0; i < nbmaps; i += 2) \
                if (maps[i] == NULL) \
                    break; \
            if (i == nbmaps) \
            { \
                nbmaps += 2; \
                maps = realloc(maps, nbmaps * sizeof(void *)); \
            } \
            maps[i] = b; \
            maps[i + 1] = ret; \
            \
            /* If we requested a memory area larger than the end of the
             * file, it was not actually allocated, so do not try to
             * copy data beyond that point. */ \
            data_length = _zz_bytes_until_eof(fd, offset); \
            if (data_length > length) \
                data_length = length; \
            \
            oldpos = _zz_getpos(fd); \
            _zz_setpos(fd, offset); /* mmap() maps the fd at offset 0 */ \
            /* FIXME: we should not blindly memcpy() here because the
             * memory area might be immense; instead, rely on mprotect()
             * and sigaction() to detect page faults and only copy memory
             * areas that get accessed. */ \
            memcpy(b, ret, data_length); \
            _zz_fuzz(fd, (uint8_t *)b, length); \
            _zz_setpos(fd, oldpos); \
            ret = b; \
        } \
        \
        char tmp[128]; \
        debug_str(tmp, (uint8_t *)b, (unsigned)data_length, 8); \
        debug("%s(%p, %li, %i, %i, %i, %lli) = %p %s", __func__, start, \
              (long int)length, prot, flags, fd, (long long int)offset, \
              ret, tmp); \
    } while (0)

#if defined HAVE_MMAP
#undef mmap
void *NEW(mmap)(void *start, size_t length, int prot, int flags,
                int fd, off_t offset)
{
    void *ret; ZZ_MMAP(mmap, off_t); return ret;
}
#endif

#if defined HAVE_MMAP64
#undef mmap64
void *NEW(mmap64)(void *start, size_t length, int prot, int flags,
                  int fd, off64_t offset)
{
    void *ret; ZZ_MMAP(mmap64, off64_t); return ret;
}
#endif

#if defined HAVE_MUNMAP
#undef munmap
int NEW(munmap)(void *start, size_t length)
{
    LOADSYM(munmap);

    for (int i = 0; i < nbmaps; ++i)
    {
        if (maps[i] != start)
            continue;

        ORIG(munmap)(start, length);
        int ret = ORIG(munmap)(maps[i + 1], length);
        maps[i] = NULL;
        maps[i + 1] = NULL;
        debug("%s(%p, %li) = %i", __func__, start, (long int)length, ret);
        return ret;
    }

    return ORIG(munmap)(start, length);
}
#endif

#if defined HAVE_MAP_FD
#undef map_fd
kern_return_t NEW(map_fd)(int fd, vm_offset_t offset, vm_offset_t *addr,
                          boolean_t find_space, vm_size_t numbytes)
{
    LOADSYM(map_fd);

    kern_return_t ret = ORIG(map_fd)(fd, offset, addr, find_space, numbytes);
    if (!must_fuzz_fd(fd))
        return ret;

    if (ret != 0)
        numbytes = 0;

    if (numbytes)
    {
        /* FIXME: do we also have to rewind the filedescriptor like in mmap? */
        char *b = malloc(numbytes);
        memcpy(b, (void *)*addr, numbytes);
        _zz_fuzz(fd, (void *)b, numbytes);
        *addr = (vm_offset_t)b;
        /* FIXME: the map is never freed; there is no such thing as unmap_fd,
         * but I suppose that kind of map should go when the filedescriptor is
         * closed (unlike mmap, which returns a persistent buffer). */
    }

    char tmp[128];
    debug_str(tmp, (uint8_t *)*addr, numbytes, 8);
    debug("%s(%i, %lli, &%p, %i, %lli) = %i %s", __func__, fd,
          (long long int)offset, (void *)*addr, (int)find_space,
          (long long int)numbytes, ret, tmp);

    return ret;
}
#endif

