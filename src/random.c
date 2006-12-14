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
 *  random.c: pseudorandom number generator
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>

#include "random.h"

void zzuf_srand(uint64_t seed)
{
    uint32_t a = seed & 0xffffffff;
    uint32_t b = seed >> 32;

    srand((a ^ 0x12345678) * (b ^ 0x87654321));
}

uint64_t zzuf_rand(uint64_t max)
{
    if(max <= RAND_MAX)
        return rand() % max;

    /* Could be better, but do we care? */
    return (uint64_t)((max * 1.0) * (rand() / (RAND_MAX + 1.0)));
}

