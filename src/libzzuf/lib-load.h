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
 *  lib-load.h: preload library functions
 */

/* Symbol loading stuff */
#define STR(x) #x
#define ORIG(x) x##_orig

#if defined HAVE_DLFCN_H
#   include <dlfcn.h>
extern void *_zz_dl_lib;
#   define NEW(x) x
#   define LOADSYM(x) \
        do { \
            if (!ORIG(x)) \
            { \
                /* XXX: we try to initialise libzzuf as soon as possible, \
                 * otherwise we may miss a lot of stuff if we wait for \
                 * the linker to load us fully. */ \
                libzzuf_init(); \
                ORIG(x) = dlsym(_zz_dl_lib, STR(x)); \
            } \
            if (!ORIG(x)) \
                abort(); \
        } while (0)
#elif defined _WIN32
#   define NEW(x) x##_new
#   define LOADSYM(x) \
        do { \
            /* Nothing to do under Windows, everything is done as soon \
             * as the process is launched. */ \
        } while (0)

typedef struct
{
    char const *lib, *name;
    void **old_sym;
    void *new_sym;
}
zzuf_table_t;

extern zzuf_table_t table_win32[];

#else
#   error "no function diversion system for this platform"
#endif

