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
#include "util/mutex.h"

int64_t zzuf_time(void)
{
#if defined HAVE_GETTIMEOFDAY
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000 + tv.tv_usec;
#else
    static zzuf_mutex_t mutex = 0;
    static unsigned long int prev = 0;
    static uint64_t tv_base = 0;

    zzuf_mutex_lock(&mutex);
    unsigned long int tv_msec = GetTickCount();
    if (tv_msec < prev)
        tv_base += 0x100000000LL; /* We wrapped */
    prev = tv_msec;
    zzuf_mutex_unlock(&mutex);

    return (tv_base + tv_msec) * 1000;
#endif
}

