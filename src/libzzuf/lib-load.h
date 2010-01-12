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
 *  lib-load.h: preload library functions
 */

/* Symbol loading stuff */
#define STR(x) #x
#define ORIG(x) x##_orig

#ifdef HAVE_DLFCN_H
#   include <dlfcn.h>
#   define NEW(x) x
#   define LOADSYM(x) \
        do { \
            if(!ORIG(x)) \
            { \
                /* XXX: we try to initialise libzzuf as soon as possible, \
                 * otherwise we may miss a lot of stuff if we wait for \
                 * the linker to load us fully. */ \
                _zz_init(); \
                ORIG(x) = dlsym(RTLD_NEXT, STR(x)); \
            } \
            if(!ORIG(x)) \
                abort(); \
        } while(0)
#else
#   define NEW(x) x##_new
#   define LOADSYM(x) \
        do { \
            /* Nothing to do under Windows, everything is done as soon \
             * as the process is launched. */ \
        } while(0)
#endif

