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
 *  libzzuf.h: preloaded wrapper library
 */

#include "fd.h"

/* Internal variables */
extern int g_libzzuf_ready;
extern int g_debug_level;
extern int g_debug_fd;
extern int g_disable_sighandlers;
extern uint64_t g_memory_limit;
extern int g_network_fuzzing;
extern int g_auto_increment;

/* Library initialisation shit */
#if defined __GNUC__
extern void libzzuf_init(void) __attribute__((constructor));
extern void libzzuf_fini(void) __attribute__((destructor));
#elif defined HAVE_PRAGMA_INIT
#   pragma INIT "libzzuf_init"
#   pragma FINI "libzzuf_fini"
#endif

/* This function is needed to initialise memory functions */
extern void _zz_mem_init(void);

/* This function lets us know where the end of a file is. */
extern size_t _zz_bytes_until_eof(int fd, size_t offset);

static inline int must_fuzz_fd(int fd)
{
    return g_libzzuf_ready && _zz_iswatched(fd)
            && !_zz_islocked(fd) && _zz_isactive(fd);
}

