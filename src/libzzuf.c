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
#if defined HAVE_WINDOWS_H
#   include <windows.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <stdarg.h>

#include "libzzuf.h"
#include "debug.h"
#include "fd.h"
#include "sys.h"
#include "fuzz.h"

/* Library initialisation shit */
void _zz_init(void) __attribute__((constructor));
void _zz_fini(void) __attribute__((destructor));
#if defined HAVE_WINDOWS_H
BOOL WINAPI DllMain(HINSTANCE, DWORD, PVOID);
#endif

/* Global variables */
int   _zz_ready    = 0;
int   _zz_hasdebug = 0;
int   _zz_signal   = 0;
int   _zz_memory   = 0;
int   _zz_network  = 0;

/* Library initialisation shit */
void _zz_init(void)
{
    char *tmp, *tmp2;

    tmp = getenv("ZZUF_DEBUG");
    if(tmp && *tmp == '1')
        _zz_hasdebug = 1;

    tmp = getenv("ZZUF_SEED");
    if(tmp && *tmp)
        _zz_setseed(atol(tmp));

    tmp = getenv("ZZUF_MINRATIO");
    tmp2 = getenv("ZZUF_MAXRATIO");
    if(tmp && *tmp && tmp2 && *tmp2)
        _zz_setratio(atof(tmp), atof(tmp2));

    tmp = getenv("ZZUF_AUTOINC");
    if(tmp && *tmp == '1')
        _zz_setautoinc();

    tmp = getenv("ZZUF_BYTES");
    if(tmp && *tmp)
        _zz_bytes(tmp);

    tmp = getenv("ZZUF_PROTECT");
    if(tmp && *tmp)
        _zz_protect(tmp);

    tmp = getenv("ZZUF_REFUSE");
    if(tmp && *tmp)
        _zz_refuse(tmp);

    tmp = getenv("ZZUF_INCLUDE");
    if(tmp && *tmp)
        _zz_include(tmp);

    tmp = getenv("ZZUF_EXCLUDE");
    if(tmp && *tmp)
        _zz_exclude(tmp);

    tmp = getenv("ZZUF_SIGNAL");
    if(tmp && *tmp == '1')
        _zz_signal = 1;

    tmp = getenv("ZZUF_MEMORY");
    if(tmp && *tmp == '1')
        _zz_memory = 1;

    tmp = getenv("ZZUF_NETWORK");
    if(tmp && *tmp == '1')
        _zz_network = 1;

    _zz_fd_init();
    _zz_sys_init();

    tmp = getenv("ZZUF_STDIN");
    if(tmp && *tmp == '1')
        _zz_register(0);

    _zz_ready = 1;

    debug("libzzuf initialised for PID %li", (long int)getpid());
}

/* Deinitialisation */
void _zz_fini(void)
{
    _zz_fd_fini();
}

#if defined HAVE_WINDOWS_H
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, PVOID impLoad)
{
    (void)hinst;   /* unused */
    (void)impLoad; /* unused */

    switch(reason)
    {
        case DLL_PROCESS_ATTACH:
            _zz_init();
            break;
        case DLL_PROCESS_DETACH:
            _zz_fini();
            break;
    }

    return TRUE;
}
#endif
