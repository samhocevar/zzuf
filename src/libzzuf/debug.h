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
 *  debug.h: debugging support
 */

extern void _zz_debug(const char *format, ...) ATTRIBUTE_PRINTF(1,2);
extern void _zz_debug2(const char *format, ...) ATTRIBUTE_PRINTF(1,2);

#ifdef LIBZZUF
#   define debug _zz_debug
#   define debug2 _zz_debug2
#else
#   define debug(...) do {} while(0)
#   define debug2(...) do {} while(0)
#endif

