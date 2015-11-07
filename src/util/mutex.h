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
 *  mutex.h: very simple spinlock routines
 */

#if HAVE_WINDOWS_H
#   include <windows.h>
#endif

#if _WIN32
typedef volatile LONG zzuf_mutex_t;
#elif __GNUC__ || __clang__
typedef volatile int zzuf_mutex_t;
#else
#   error "No known atomic operations for this platform"
#endif

static inline void zzuf_mutex_lock(zzuf_mutex_t *l)
{
#if _WIN32
    do {}
    while (InterlockedExchange(l, 1));
#elif __GNUC__ || __clang__
    do {}
    while (__sync_lock_test_and_set(l, 1));
#endif
}

static inline void zzuf_mutex_unlock(zzuf_mutex_t *l)
{
#if _WIN32
    InterlockedExchange(l, 0);
#elif __GNUC__ || __clang__
    *l = 0;
    __sync_synchronize();
#endif
}

