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
 *  debug.h: debugging support
 */

extern void zzuf_debug(char const *format, ...) ATTRIBUTE_PRINTF(1,2);
extern void zzuf_debug2(char const *format, ...) ATTRIBUTE_PRINTF(1,2);
extern void zzuf_debug_str(char *str, uint8_t const *buffer,
                           int len, int maxlen);

#ifdef LIBZZUF
#   define debug zzuf_debug
#   define debug2 zzuf_debug2
#   define debug_str zzuf_debug_str
#else
#   define debug(...) do {} while (0)
#   define debug2(...) do {} while (0)
#   define debug_str(...) do {} while (0)
#endif

