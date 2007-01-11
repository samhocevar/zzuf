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

/* We use file descriptor 17 as the debug channel */
#define DEBUG_FILENO 17

/* We arbitrarily split files into 1024-byte chunks. Each chunk has an
 * associated seed that can be computed from the zzuf seed, the chunk
 * index and the fuzziness density. This allows us to predictably fuzz
 * any part of the file without reading the whole file. */
#define CHUNKBYTES 1024

struct fuzz
{
    int cur;
#ifdef HAVE_FGETLN
    char *tmp;
#endif
    uint8_t data[CHUNKBYTES];
};

/* Internal variables */
extern int   _zz_ready;
extern int   _zz_disabled;
extern int   _zz_hasdebug;
extern int   _zz_signal;
extern int   _zz_memory;
extern int   _zz_network;

/* Library initialisation shit */
extern void _zz_init(void) __attribute__((constructor));
extern void _zz_fini(void) __attribute__((destructor));

