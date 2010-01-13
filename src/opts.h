/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2002-2010 Sam Hocevar <sam@hocevar.net>
 *                All Rights Reserved
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What The Fuck You Want
 *  To Public License, Version 2, as published by Sam Hocevar. See
 *  http://sam.zoy.org/wtfpl/COPYING for more details.
 */

/*
 *  opts.h: configuration handling
 */

struct opts
{
    char **oldargv;
    char **newargv;
    char *fuzzing, *bytes, *list, *ports, *protect, *refuse, *allow;
    uint32_t seed;
    uint32_t endseed;
    double minratio;
    double maxratio;
    int quiet;
    int maxbytes;
    int maxcpu;
    int md5;
    int checkexit;
    int verbose;
    int maxmem;
    int64_t starttime;
    int64_t maxtime;
    int64_t maxusertime;
    int64_t delay;
    int64_t lastlaunch;

    int maxchild, nchild, maxcrashes, crashes;
    struct child
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
        int fd[3]; /* 0 is debug, 1 is stderr, 2 is stdout */
        int bytes, seed;
        double ratio;
        int64_t date;
        struct md5 *ctx;
    } *child;
};

void _zz_opts_init(struct opts *);
void _zz_opts_fini(struct opts *);

