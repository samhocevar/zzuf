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

/*
 *  opts.c: configuration handling
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "timer.h"
#include "opts.h"

zzuf_opts_t *zzuf_create_opts(void)
{
    zzuf_opts_t *opts = malloc(sizeof(zzuf_opts_t));

    opts->opmode = OPMODE_PRELOAD;
    opts->fuzzing = opts->bytes = opts->list = opts->ports = NULL;
    opts->allow = NULL;
    opts->protect = opts->refuse = NULL;

    opts->seed = DEFAULT_SEED;
    opts->endseed = DEFAULT_SEED + 1;
    opts->minratio = opts->maxratio = DEFAULT_RATIO;

    opts->b_quiet = 0;
    opts->b_md5 = 0;
    opts->b_hex = 0;
    opts->b_checkexit = 0;
    opts->b_verbose = 0;

    opts->maxbytes = -1;
    opts->maxmem = DEFAULT_MEM;
    opts->starttime = zzuf_time();
    opts->maxtime = 0;
    opts->maxusertime = -1;
    opts->maxcpu = -1;
    opts->delay = 0;
    opts->lastlaunch = 0;

    opts->maxchild = 1;
    opts->nchild = 0;
    opts->maxcrashes = 1;
    opts->crashes = 0;
    opts->child = NULL;

    return opts;
}

void zzuf_destroy_opts(zzuf_opts_t *opts)
{
    if (opts->child)
    {
        for (int i = 0; i < opts->maxchild; ++i)
            if (opts->child[i].newargv)
                free(opts->child[i].newargv);
        free(opts->child);
    }

    free(opts);
}

