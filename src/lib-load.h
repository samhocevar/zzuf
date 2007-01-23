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
 *  lib-load.h: preloaded library functions
 */

/* The __func__ macro to get the current function name */
#if __STDC_VERSION__ < 199901L
#   if __GNUC__ >= 2
#       define __func__ __FUNCTION__
#   else
#       define __func__ "<?>"
#   endif
#endif

/* Symbol loading stuff */
#define STR(x) #x
#define ORIG(x) x##_orig
#ifdef HAVE_DLFCN_H
#   define NEW(x) x
#else
#   define NEW(x) x##_new
#endif

/* TODO: do the Win32 part */
#ifdef HAVE_DLFCN_H
#   include <dlfcn.h>
#   define LOADSYM(x) \
        do { \
            if(!ORIG(x)) \
                ORIG(x) = dlsym(RTLD_NEXT, STR(x)); \
            if(!ORIG(x)) \
                abort(); \
        } while(0)
#else
#   define LOADSYM(x) \
        do { \
            if(!ORIG(x)) \
                abort(); \
        } while(0)
#endif

