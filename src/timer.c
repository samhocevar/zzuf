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
 *  timer.c: timing functions
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#if defined HAVE_WINDOWS_H
#   include <windows.h>
#endif
#if defined HAVE_SYS_TIME_H
#   include <sys/time.h>
#endif
#include <stdio.h>
#include <time.h>

#include "timer.h"

int64_t _zz_time(void)
{
#if defined HAVE_GETTIMEOFDAY
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000 + tv.tv_usec;
#else
    static CRITICAL_SECTION cs;
    static unsigned long int prev;
    static int64_t tv_base = 0;
    unsigned long int tv_msec;

    if(tv_base == 0)
    {
        tv_base = 1;
        prev = 0;
        InitializeCriticalSection(&cs);
    }

    EnterCriticalSection(&cs);
    tv_msec = GetTickCount();
    if(tv_msec < prev)
        tv_base += 0x100000000LL; /* We wrapped */
    prev = tv_msec;
    LeaveCriticalSection(&cs);

    return (tv_base + tv_msec) * 1000;
#endif
}

