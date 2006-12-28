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

void _zz_srand(uint32_t seed)
{
    srand(seed ^ 0x12345678);
}

uint32_t _zz_rand(uint32_t max)
{
    if(max <= RAND_MAX)
        return rand() % max;

    /* Could be better, but do we care? */
    return (uint32_t)((max * 1.0) * (rand() / (RAND_MAX + 1.0)));
}

