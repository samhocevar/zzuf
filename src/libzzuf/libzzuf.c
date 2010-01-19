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
#if defined HAVE_PROCESS_H
#   include <process.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#if defined HAVE_UNISTD_H
#   include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <stdarg.h>

#include "libzzuf.h"
#include "debug.h"
#include "fd.h"
#include "network.h"
#include "sys.h"
#include "fuzz.h"

#if defined HAVE_WINDOWS_H
BOOL WINAPI DllMain(HINSTANCE, DWORD, PVOID);
#endif

/**
 * Is libzzuf fully initialised?
 */
int _zz_ready = 0;

/**
 * The debugging level that libzzuf should use. 0 means no debugging,
 * 1 means minimal debugging, 2 means verbose debugging. Its value is set
 * by the ZZUF_DEBUG environment variable.
 */
int _zz_debuglevel = 0;

/**
 * The file descriptor used by libzzuf for communication with the main
 * zzuf program in debug mode. Its value is set by the ZZUF_DEBUGFD
 * environment variable.
 */
int _zz_debugfd = -1;

/**
 * If set to 1, this boolean variable will prevent the called application
 * from installing signal handlers that would prevent it from really crashing.
 * SDL applications often do that when not using SDL_INIT_NOPARACHUTE, for
 * instance. Its value is set by the ZZUF_SIGNAL environment variable.
 */
int _zz_signal = 0;

/**
 * If set to a positive value, this value will indicate the maximum number
 * of mebibytes (1 MiB = 1,048,576 bytes) that the called application will be
 * allowed to allocate. Its value is set by the ZZUF_MEMORY environment
 * variable.
 */
uint64_t _zz_memory = 0;

/**
 * If set to 1, this boolean will tell libzzuf to fuzz network file
 * descriptors, too. Its value is set by the ZZUF_NETWORK environment
 * variable.
 */
int _zz_network = 0;

/**
 * Library initialisation routine.
 *
 * This function reads all configuration variables put by zzuf in the
 * called process's environment and initialises diversions for the three
 * main function families: memory functions (initialised very early because
 * other functions we need such as dlsym() require them), file descriptor
 * functions and stream functions.
 */
void _zz_init(void)
{
    static int initializing = 0;
    char *tmp, *tmp2;

    /* Make sure we don't get initialised more than once */
    if (initializing++)
        return;

    tmp = getenv("ZZUF_DEBUG");
    if(tmp)
        _zz_debuglevel = atoi(tmp);

    tmp = getenv("ZZUF_DEBUGFD");
    if(tmp)
        _zz_debugfd = atoi(tmp);

    /* We need this as soon as possible */
    _zz_mem_init();

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

    tmp = getenv("ZZUF_LIST");
    if(tmp && *tmp)
        _zz_list(tmp);

    tmp = getenv("ZZUF_PORTS");
    if(tmp && *tmp)
        _zz_ports(tmp);

    tmp = getenv("ZZUF_ALLOW");
    if(tmp && *tmp)
        _zz_allow(tmp);

    tmp = getenv("ZZUF_DENY");
    if(tmp && *tmp)
        _zz_deny(tmp);

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
    if(tmp)
        _zz_memory = atoi(tmp);

    tmp = getenv("ZZUF_NETWORK");
    if(tmp && *tmp == '1')
        _zz_network = 1;

    _zz_fd_init();
    _zz_network_init();
    _zz_sys_init();

    tmp = getenv("ZZUF_STDIN");
    if(tmp && *tmp == '1')
        _zz_register(0);

    _zz_ready = 1;

    debug("libzzuf initialised for PID %li", (long int)getpid());
}

/**
 * Library deinitialisation routine.
 *
 * Free all the memory allocated by libzzuf during its lifetime.
 */
void _zz_fini(void)
{
    if (!_zz_ready)
        return;

    debug("libzzuf finishing for PID %li", (long int)getpid());

    _zz_fd_fini();
    _zz_network_fini();

    _zz_ready = 0;
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

