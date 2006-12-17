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
 *  preload.h: preloaded library functions
 */

#define STR(x) #x
#define ORIG(x) x##_orig

#define LOADSYM(x) \
    do { \
        ORIG(x) = dlsym(RTLD_NEXT, STR(x)); \
        if(!ORIG(x)) \
            abort(); \
    } while(0)

extern void zzuf_load_fd(void);
extern void zzuf_load_stream(void);

