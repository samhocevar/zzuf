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

/* Default seed is 0. Why not? */
#define DEFAULT_SEED 0

/* The default fuzzing ratio is, arbitrarily, 0.4% */
#define DEFAULT_RATIO 0.004
#define MIN_RATIO 0.00001
#define MAX_RATIO 5.0

struct fuzz
{
    uint32_t seed;
    double ratio;
    int64_t cur;
#ifdef HAVE_FGETLN
    char *tmp;
#endif
    int uflag; int64_t upos; uint8_t uchar; /* ungetc stuff */
    uint8_t data[CHUNKBYTES];
};

/* Internal variables */
extern int _zz_ready;
extern int _zz_disabled;
extern int _zz_debugfd;
extern int _zz_signal;
extern int _zz_memory;
extern int _zz_network;
extern int _zz_autoinc;

/* This function is needed to initialise memory functions */
extern void _zz_mem_init(void);

