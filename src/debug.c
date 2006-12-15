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
 *  debug.c: debugging support
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <regex.h>

#include "libzzuf.h"
#include "debug.h"

void zzuf_debug(const char *format, ...)
{
    va_list args;
    int saved_errno;

    if(!_zzuf_debug)
        return;

    saved_errno = errno;
    va_start(args, format);
    fprintf(stderr, "** zzuf debug ** ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
    errno = saved_errno;
}

