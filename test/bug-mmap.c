/*
 *  bug-mmap - regression test for a bug in zzuf
 *
 *  Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
 *            © 2015 Alexander Cherepanov <cherepan@mccme.ru>
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by the WTFPL Task Force.
 *  See http://www.wtfpl.net/ for more details.
 */

#include "config.h"

#define _BSD_SOURCE 1 /* for MAP_POPULATE */

#if HAVE_SYS_MMAN_H
#   include <sys/mman.h>
#endif
#if HAVE_SYS_TYPES_H
#   include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
#   include <sys/stat.h>
#endif
#if HAVE_UNISTD_H
#   include <unistd.h>
#endif
#include <fcntl.h>
#include <stdlib.h>

int main(void)
{
#if defined _SC_PAGE_SIZE && defined MAP_POPULATE
    int fd = open("/etc/hosts", O_RDONLY);
    mmap(0, sysconf(_SC_PAGE_SIZE) * 2, PROT_READ,
         MAP_PRIVATE | MAP_POPULATE, fd, 0);
#endif

    return EXIT_SUCCESS;
}

