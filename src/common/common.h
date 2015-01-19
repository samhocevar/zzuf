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

#pragma once

/*
 *  common.h: default fuzzing settings
 */

/* We arbitrarily split files into 1024-byte chunks. Each chunk has an
 * associated seed that can be computed from the zzuf seed, the chunk
 * index and the fuzziness density. This allows us to predictably fuzz
 * any part of the file without reading the whole file. */
#define CHUNKBYTES 1024

/* Default seed is 0. Why not? */
#define DEFAULT_SEED 0

/* The default fuzzing ratio is, arbitrarily, 0.4%. The minimal fuzzing
 * ratio is 0.000000001% (less than one bit changed on a whole DVD). */
#define DEFAULT_RATIO 0.004
#define MIN_RATIO 0.00000000001
#define MAX_RATIO 5.0

/* The default maximum memory usage is 1024 MiB. If this value is not set,
 * zzuf may bring a machine down to its knees because of I/O. */
#define DEFAULT_MEM 1024

/* We use file descriptor 17 as the debug channel on Unix */
#define DEBUG_FILENO 17

struct fuzz_context
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

typedef struct fuzz_context fuzz_context_t;

