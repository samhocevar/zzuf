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

struct zzuf
{
    int managed;
    uint64_t seed;
    uint64_t pos;
    int cur;
    char *data;
};

extern struct zzuf files[];

/* Internal stuff */
extern int       _zzuf_ready;
extern int       _zzuf_debug;
extern int       _zzuf_seed;
extern float     _zzuf_ratio;
extern regex_t * _zzuf_include;
extern regex_t * _zzuf_exclude;

/* Library initialisation shit */
extern void zzuf_init(void) __attribute__((constructor));
extern void zzuf_fini(void) __attribute__((destructor));

