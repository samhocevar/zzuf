/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006-2010 Sam Hocevar <sam@hocevar.net>
 *                2009 Corentin Delorme <codelorme@gmail.com>
 *                All Rights Reserved
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What The Fuck You Want
 *  To Public License, Version 2, as published by Sam Hocevar. See
 *  http://sam.zoy.org/wtfpl/COPYING for more details.
 */

/*
 *  network.h: network connection helper functions
 */

extern void _zz_ports(char const *);
extern void _zz_allow(char const *);
extern void _zz_deny(char const *);
extern void _zz_network_init(void);
extern void _zz_network_fini(void);

extern int _zz_portwatched(int);
extern int _zz_hostwatched(int);

