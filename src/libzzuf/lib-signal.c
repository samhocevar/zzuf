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
 *  load-signal.c: loaded signal functions
 */

#include "config.h"

/* Needed for sighandler_t on glibc systems */
#define _GNU_SOURCE
/* Needed for struct sigaction on HP-UX */
#define _INCLUDE_POSIX_SOURCE
/* Needed for struct sigaction on OpenSolaris */
#define __EXTENSIONS__

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdlib.h>

#include <string.h>
#include <signal.h>

#include "libzzuf.h"
#include "lib-load.h"
#include "debug.h"
#include "fuzz.h"

#if defined HAVE_SIGHANDLER_T
#   define SIG_T sighandler_t
#elif defined HAVE_SIG_T
#   define SIG_T sig_t
#else
    typedef void (*SIG_T) (int);
#endif

/* Library functions that we divert */
static SIG_T (*ORIG(signal))    (int signum, SIG_T handler);
#if defined HAVE_SIGACTION
static int   (*ORIG(sigaction)) (int signum, const struct sigaction *act,
                                 struct sigaction *oldact);
#endif
/* Local functions */
static int isfatal(int signum);

static int isfatal(int signum)
{
    switch (signum)
    {
        case SIGABRT:
        case SIGFPE:
        case SIGILL:
#if defined SIGQUIT
        case SIGQUIT:
#endif
        case SIGSEGV:
#if defined SIGTRAP
        case SIGTRAP:
#endif
#if defined SIGSYS
        case SIGSYS:
#endif
#if defined SIGEMT
        case SIGEMT:
#endif
#if defined SIGBUS
        case SIGBUS:
#endif
#if defined SIGXCPU
        case SIGXCPU:
#endif
#if defined SIGXFSZ
        case SIGXFSZ:
#endif
            return 1;
        default:
            return 0;
    }
}

#undef signal
SIG_T NEW(signal)(int signum, SIG_T handler)
{
    LOADSYM(signal);

    if (!g_disable_sighandlers)
        return ORIG(signal)(signum, handler);

    SIG_T ret = ORIG(signal)(signum, isfatal(signum) ? SIG_DFL : handler);

    debug("%s(%i, %p) = %p", __func__, signum, handler, ret);

    return ret;
}

#if defined HAVE_SIGACTION
#undef sigaction
int NEW(sigaction)(int signum, const struct sigaction *act,
                   struct sigaction *oldact)
{
    LOADSYM(sigaction);

    if (!g_disable_sighandlers)
        return ORIG(sigaction)(signum, act, oldact);

    int ret;

    if (act && isfatal(signum))
    {
        struct sigaction newact;
        memcpy(&newact, act, sizeof(struct sigaction));
        newact.sa_handler = SIG_DFL;
        ret = ORIG(sigaction)(signum, &newact, oldact);
    }
    else
        ret = ORIG(sigaction)(signum, act, oldact);

    debug("%s(%i, %p, %p) = %i", __func__, signum, act, oldact, ret);

    return ret;
}
#endif

