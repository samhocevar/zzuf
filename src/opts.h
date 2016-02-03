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
 *  opts.h: configuration handling
 */

#include "util/hex.h"
#include "util/md5.h"

#ifdef _WIN32
#   include <windows.h>
#endif

typedef struct zzuf_opts zzuf_opts_t;
typedef struct zzuf_child zzuf_child_t;

zzuf_opts_t *zzuf_create_opts(void);
void zzuf_destroy_opts(zzuf_opts_t *);

struct zzuf_child
{
    enum status
    {
        STATUS_FREE,
        STATUS_RUNNING,
        STATUS_SIGTERM,
        STATUS_SIGKILL,
        STATUS_EOF,
    } status;

    pid_t pid;
#ifdef _WIN32
    HANDLE process_handle;
#endif
    int fd[3]; /* 0 is debug, 1 is stderr, 2 is stdout */
    int bytes, seed;
    double ratio;
    int64_t date;
    zzuf_md5sum_t *md5;
    zzuf_hexdump_t *hex;
    char **newargv;
};

struct zzuf_opts
{
    enum opmode
    {
        OPMODE_PRELOAD,
        OPMODE_COPY,
        OPMODE_NULL,
    } opmode;
    char **oldargv;
    int oldargc;
    char *fuzzing, *bytes, *list, *ports, *protect, *refuse, *allow;

    uint32_t seed;
    uint32_t endseed;

    double minratio;
    double maxratio;

    int b_md5;
    int b_hex;
    int b_checkexit;
    int b_verbose;
    int b_quiet;

    int maxbytes;
    int maxcpu;
    int maxmem;

    int64_t starttime;
    int64_t maxtime;
    int64_t maxusertime;
    int64_t delay;
    int64_t lastlaunch;

    int maxchild, nchild, maxcrashes, crashes;

    zzuf_child_t *child;
};

