/*
 *  zzuf - general purpose fuzzer
 *
 *  Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
 *              2012 Kévin Szkudłapski <kszkudlapski@quarkslab.com>
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by the WTFPL Task Force.
 *  See http://www.wtfpl.net/ for more details.
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
#if defined HAVE_IO_H
#   include <io.h>
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
#include "util/mutex.h"

#if defined HAVE_WINDOWS_H
BOOL WINAPI DllMain(HINSTANCE, DWORD, PVOID);
#endif

/**
 * Is libzzuf fully initialised?
 */
int g_libzzuf_ready = 0;

/**
 * The debugging level that libzzuf should use. 0 means no debugging,
 * 1 means minimal debugging, 2 means verbose debugging. Its value is set
 * by the ZZUF_DEBUG environment variable.
 */
int g_debug_level = 0;

/**
 * The file descriptor used by libzzuf for communication with the main
 * zzuf program in debug mode. Its value is set by the ZZUF_DEBUGFD
 * environment variable.
 */
int g_debug_fd = -1;

/**
 * If set to 1, this boolean variable will prevent the called application
 * from installing signal handlers that would prevent it from really crashing.
 * SDL applications often do that when not using SDL_INIT_NOPARACHUTE, for
 * instance. Its value is set by the ZZUF_SIGNAL environment variable.
 */
int g_disable_sighandlers = 0;

/**
 * If set to a positive value, this value will indicate the maximum number
 * of mebibytes (1 MiB = 1,048,576 bytes) that the called application will be
 * allowed to allocate. Its value is set by the ZZUF_MEMORY environment
 * variable.
 */
uint64_t g_memory_limit = 0;

/**
 * If set to 1, this boolean will tell libzzuf to fuzz network file
 * descriptors, too. Its value is set by the ZZUF_NETWORK environment
 * variable.
 */
int g_network_fuzzing = 0;

/**
 * Library initialisation routine.
 *
 * This function reads all configuration variables put by zzuf in the
 * called process's environment and initialises diversions for the three
 * main function families: memory functions (initialised very early because
 * other functions we need such as dlsym() require them), file descriptor
 * functions and stream functions.
 */
void libzzuf_init(void)
{
    /* Make sure we don't get initialised more than once */
    static zzuf_mutex_t mutex = 0;
    static int initialised = 0;
    zzuf_mutex_lock(&mutex);
    if (initialised++)
    {
        zzuf_mutex_unlock(&mutex);
        return;
    }
    zzuf_mutex_unlock(&mutex);

    /* Open the debug channel */
    char *tmp = getenv("ZZUF_DEBUG");
    if (tmp)
        g_debug_level = atoi(tmp);

    tmp = getenv("ZZUF_DEBUGFD");
    if (tmp)
#if defined _WIN32
        g_debug_fd = _open_osfhandle((long)atoi(tmp), 0);
#else
        g_debug_fd = atoi(tmp);
#endif

    /* We need malloc() and a few others as soon as possible */
    _zz_mem_init();

    tmp = getenv("ZZUF_SEED");
    if (tmp && *tmp)
        zzuf_set_seed(atol(tmp));

    tmp = getenv("ZZUF_MINRATIO");
    char *tmp2 = getenv("ZZUF_MAXRATIO");
    if (tmp && *tmp && tmp2 && *tmp2)
        zzuf_set_ratio(atof(tmp), atof(tmp2));

    tmp = getenv("ZZUF_AUTOINC");
    if (tmp && *tmp == '1')
        zzuf_set_auto_increment();

    tmp = getenv("ZZUF_BYTES");
    if (tmp && *tmp)
        _zz_bytes(tmp);

    tmp = getenv("ZZUF_LIST");
    if (tmp && *tmp)
        _zz_list(tmp);

    tmp = getenv("ZZUF_PORTS");
    if (tmp && *tmp)
        _zz_ports(tmp);

    tmp = getenv("ZZUF_ALLOW");
    if (tmp && *tmp)
        _zz_allow(tmp);

    tmp = getenv("ZZUF_DENY");
    if (tmp && *tmp)
        _zz_deny(tmp);

    tmp = getenv("ZZUF_PROTECT");
    if (tmp && *tmp)
        zzuf_protect_range(tmp);

    tmp = getenv("ZZUF_REFUSE");
    if (tmp && *tmp)
        zzuf_refuse_range(tmp);

    tmp = getenv("ZZUF_INCLUDE");
    if (tmp && *tmp)
        zzuf_include_pattern(tmp);

    tmp = getenv("ZZUF_EXCLUDE");
    if (tmp && *tmp)
        zzuf_exclude_pattern(tmp);

    tmp = getenv("ZZUF_SIGNAL");
    if (tmp && *tmp == '1')
        g_disable_sighandlers = 1;

    tmp = getenv("ZZUF_MEMORY");
    if (tmp)
        g_memory_limit = atoi(tmp);

    tmp = getenv("ZZUF_NETWORK");
    if (tmp && *tmp == '1')
        g_network_fuzzing = 1;

    _zz_fd_init();
    _zz_network_init();
    _zz_sys_init();

    tmp = getenv("ZZUF_STDIN");
    if (tmp && *tmp == '1')
        _zz_register(0);

    g_libzzuf_ready = 1;

    debug("libzzuf initialised for PID %li", (long int)getpid());
}

/**
 * Library deinitialisation routine.
 *
 * Free all the memory allocated by libzzuf during its lifetime.
 */
void libzzuf_fini(void)
{
    if (!g_libzzuf_ready)
        return;

    debug("libzzuf finishing for PID %li", (long int)getpid());

    _zz_fd_fini();
    _zz_network_fini();

    g_libzzuf_ready = 0;
}

#if defined HAVE_WINDOWS_H
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, PVOID impLoad)
{
    (void)hinst;   /* unused */
    (void)impLoad; /* unused */

    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            libzzuf_init();
            break;
        case DLL_PROCESS_DETACH:
            //libzzuf_fini();
            break;
    }

    return TRUE;
}
#endif

