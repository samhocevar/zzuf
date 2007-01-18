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
 *  load-signal.c: loaded signal functions
 */

#include "config.h"

/* needed for sighandler_t */
#define _GNU_SOURCE

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
static SIG_T (*signal_orig)    (int signum, SIG_T handler);
#if defined HAVE_SIGACTION
static int   (*sigaction_orig) (int signum, const struct sigaction *act,
                                struct sigaction *oldact);
#endif
/* Local functions */
static int isfatal(int signum);

static int isfatal(int signum)
{
    switch(signum)
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

SIG_T signal(int signum, SIG_T handler)
{
    SIG_T ret;

    LOADSYM(signal);

    if(!_zz_signal)
        return signal_orig(signum, handler);

    ret = signal_orig(signum, isfatal(signum) ? SIG_DFL : handler);

    debug("%s(%i, %p) = %p", __func__, signum, handler, ret);

    return ret;
}

#if defined HAVE_SIGACTION
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    int ret;

    LOADSYM(sigaction);

    if(!_zz_signal)
        return sigaction_orig(signum, act, oldact);

    if(act && isfatal(signum))
    {
        struct sigaction newact;
        memcpy(&newact, act, sizeof(struct sigaction));
        newact.sa_handler = SIG_DFL;
        ret = sigaction_orig(signum, &newact, oldact);
    }
    else
        ret = sigaction_orig(signum, act, oldact);

    debug("%s(%i, %p, %p) = %i", __func__, signum, act, oldact, ret);

    return ret;
}
#endif

