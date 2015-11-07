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
 *  fuzz.h: fuzz functions
 */

extern void _zz_fuzzing(char const *);
extern void _zz_bytes(char const *);
extern void _zz_list(char const *);
extern void zzuf_protect_range(char const *);
extern void zzuf_refuse_range(char const *);

extern void _zz_fuzz(int, volatile uint8_t *, int64_t);

