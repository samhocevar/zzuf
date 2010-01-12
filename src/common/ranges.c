/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006-2010 Sam Hocevar <sam@hocevar.net>
 *                All Rights Reserved
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What The Fuck You Want
 *  To Public License, Version 2, as published by Sam Hocevar. See
 *  http://sam.zoy.org/wtfpl/COPYING for more details.
 */

/*
 *  ranges.c: range handling helper functions
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "ranges.h"

/* This function converts a string containing a list of ranges in the format
 * understood by cut(1) such as "1-5,8,10-" into a C array for lookup.
 * If more than 256 slots are required, new memory is allocated, otherwise
 * the static array static_ranges is used. It is the caller's duty to call
 * free() if the returned value is not static_ranges. */
int *_zz_allocrange(char const *list, int *static_ranges)
{
    char const *parser;
    int *ranges;
    unsigned int i, chunks;

    /* Count commas */
    for(parser = list, chunks = 1; *parser; parser++)
        if(*parser == ',')
            chunks++;

    if(chunks >= 256)
        ranges = malloc((chunks + 1) * 2 * sizeof(unsigned int));
    else
        ranges = static_ranges;

    /* Fill ranges list */
    for(parser = list, i = 0; i < chunks; i++)
    {
        char const *comma = strchr(parser, ',');
        char const *dash = strchr(parser, '-');

        ranges[i * 2] = (dash == parser) ? 0 : atoi(parser);
        if(dash && (dash + 1 == comma || dash[1] == '\0'))
            ranges[i * 2 + 1] = ranges[i * 2]; /* special case */
        else if(dash && (!comma || dash < comma))
            ranges[i * 2 + 1] = atoi(dash + 1) + 1;
        else
            ranges[i * 2 + 1] = ranges[i * 2] + 1;
        parser = comma + 1;
    }

    ranges[i * 2] = ranges[i * 2 + 1] = 0;

    return ranges;
}

int _zz_isinrange(int value, int const *ranges)
{
    int const *r;

    if(!ranges)
        return 1;

    for(r = ranges; r[1]; r += 2)
        if(value >= r[0] && (r[0] == r[1] || value < r[1]))
            return 1;

    return 0;
}

