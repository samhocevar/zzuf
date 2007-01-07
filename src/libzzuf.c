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
 *  libzzuf.c: preloaded wrapper library
 */

#include "config.h"
#define _GNU_SOURCE

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <regex.h>

#include <stdarg.h>
#include <dlfcn.h>

#include "libzzuf.h"
#include "debug.h"
#include "load.h"
#include "fd.h"
#include "fuzz.h"

/* Global variables */
int   _zz_ready    = 0;
int   _zz_disabled = 0;
int   _zz_hasdebug = 0;
int   _zz_signal   = 0;
int   _zz_network  = 0;

/* Library initialisation shit */
void _zz_init(void)
{
    char *tmp;

    tmp = getenv("ZZUF_DEBUG");
    if(tmp && *tmp == '1')
        _zz_hasdebug = 1;

    tmp = getenv("ZZUF_SEED");
    if(tmp && *tmp)
        _zz_setseed(atol(tmp));

    tmp = getenv("ZZUF_RATIO");
    if(tmp && *tmp)
        _zz_setratio(atof(tmp));

    tmp = getenv("ZZUF_PROTECT");
    if(tmp && *tmp)
        _zz_protect(tmp);

    tmp = getenv("ZZUF_REFUSE");
    if(tmp && *tmp)
        _zz_refuse(tmp);

    tmp = getenv("ZZUF_INCLUDE");
    if(tmp && *tmp)
    {
        re_include = malloc(sizeof(*re_include));
        regcomp(re_include, tmp, REG_EXTENDED);
    }

    tmp = getenv("ZZUF_EXCLUDE");
    if(tmp && *tmp)
    {
        re_exclude = malloc(sizeof(*re_exclude));
        regcomp(re_exclude, tmp, REG_EXTENDED);
    }

    tmp = getenv("ZZUF_SIGNAL");
    if(tmp && *tmp == '1')
        _zz_signal = 1;

    tmp = getenv("ZZUF_NETWORK");
    if(tmp && *tmp == '1')
        _zz_network = 1;

    _zz_fd_init();

    tmp = getenv("ZZUF_STDIN");
    if(tmp && *tmp == '1')
        _zz_register(0);

    _zz_load_fd();
    _zz_load_signal();
    _zz_load_stream();

    _zz_ready = 1;

    debug("libzzuf initialised");
}

/* Deinitialisation */
void _zz_fini(void)
{
    _zz_fd_fini();
}

