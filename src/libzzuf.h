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
 *  libzzuf.h: preloaded wrapper library
 */

/* We arbitrarily split files into 1024-byte chunks. Each chunk has an
 * associated seed that can be computed from the zzuf seed, the chunk
 * index and the fuzziness density. This allows us to predictably fuzz
 * any part of the file without reading the whole file. */
#define CHUNKBYTES 1024

struct fuzz
{
    int cur;
    uint8_t *data;
};

/* Internal variables */
extern int       _zzuf_ready;
extern int       _zzuf_debug;
extern int       _zzuf_seed;
extern float     _zzuf_ratio;
extern regex_t * _zzuf_include;
extern regex_t * _zzuf_exclude;

/* Library initialisation shit */
extern void zzuf_init(void) __attribute__((constructor));
extern void zzuf_fini(void) __attribute__((destructor));

/* File descriptor handling */
extern int zzuf_fd_ismanaged(int);
extern void zzuf_fd_manage(int);
extern void zzuf_fd_unmanage(int);
extern long int zzuf_fd_getpos(int);
extern void zzuf_fd_setpos(int, long int);
extern void zzuf_fd_addpos(int, long int);
extern struct fuzz *zzuf_fd_getfuzz(int);

