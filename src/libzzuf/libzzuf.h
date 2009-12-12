/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006-2009 Sam Hocevar <sam@hocevar.net>
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
 *  libzzuf.h: preloaded wrapper library
 */

/* Internal variables */
extern int _zz_ready;
extern int _zz_disabled;
extern int _zz_debuglevel;
extern int _zz_debugfd;
extern int _zz_signal;
extern int _zz_memory;
extern int _zz_network;
extern int _zz_autoinc;

/* This function is needed to initialise memory functions */
extern void _zz_mem_init(void);

