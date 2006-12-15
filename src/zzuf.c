/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006 Sam Hocevar <sam@zoy.org>
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
 *  main.c: main program
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#if defined(HAVE_GETOPT_H)
#   include <getopt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "random.h"

static void set_ld_preload(char const *);
static void version(void);
#if defined(HAVE_GETOPT_H)
static void usage(void);
#endif

int main(int argc, char *argv[])
{
    char buf[BUFSIZ];
    char **newargv;
    long int seed = 0;
    float percent = 0.04;

#if defined(HAVE_GETOPT_H)
    for(;;)
    {
#   ifdef HAVE_GETOPT_LONG
#       define MOREINFO "Try `%s --help' for more information.\n"
        int option_index = 0;
        static struct option long_options[] =
            {
                /* Long option, needs arg, flag, short option */
                { "seed", 1, NULL, 's' },
                { "percent", 1, NULL, 'p' },
                { "help", 0, NULL, 'h' },
                { "version", 0, NULL, 'v' },
            };

        int c = getopt_long(argc, argv, "s:p:hv",
                            long_options, &option_index);
#   else
#       define MOREINFO "Try `%s -h' for more information.\n"
        int c = getopt(argc, argv, "s:p:hv");
#   endif
        if(c == -1)
            break;

        switch(c)
        {
        case 's': /* --seed */
            seed = atol(optarg);
            break;
        case 'p': /* --percent */
            percent = atof(optarg);
            break;
        case 'h': /* --help */
            usage();
            return 0;
        case 'v': /* --version */
            version();
            return 0;
        default:
            printf("%s: invalid option -- %c\n", argv[0], c);
            printf(MOREINFO, argv[0]);
            return 1;
        }
    }
#else
#   define MOREINFO "Usage: %s message...\n"
    int optind = 1;
#endif

    if(optind >= argc)
    {
        usage();
        return -1;
    }

    /* Create new argv */
    newargv = malloc((argc - optind + 1) * sizeof(char *));
    memcpy(newargv, argv + optind, (argc - optind) * sizeof(char *));
    newargv[argc - optind] = (char *)NULL;

    /* Preload libzzuf.so */
    set_ld_preload(argv[0]);

    /* Set environment */
    sprintf(buf, "%lu", (unsigned long int)seed);
    setenv("ZZUF_SEED", buf, 1);
    sprintf(buf, "%g", percent);
    setenv("ZZUF_PERCENT", buf, 1);

    /* Call our process */
    execvp(newargv[0], newargv);

    return 0;    
}

static void set_ld_preload(char const *progpath)
{
    char *libpath, *tmp;
    int len = strlen(progpath);

    libpath = malloc(len + strlen("/.libs/libzzuf.so") + 1);
    strcpy(libpath, progpath);
    tmp = strrchr(libpath, '/');
    strcpy(tmp ? tmp + 1 : libpath, ".libs/libzzuf.so");
    if(access(libpath, R_OK) == 0)
    {
        setenv("LD_PRELOAD", libpath, 1);
        return;
    }
    free(libpath);

    /* FIXME: use real path */
    setenv("LD_PRELOAD", "/usr/lib/zzuf/libzzuf.so", 1);
}

static void version(void)
{
    printf("zzuf %s by Sam Hocevar <sam@zoy.org>\n", VERSION);
}

#if defined(HAVE_GETOPT_H)
static void usage(void)
{
    printf("Usage: zzuf [ -vh ] [ -p percent ] [ -s seed ] PROG ARGS...\n");
#   ifdef HAVE_GETOPT_LONG
    printf("  -h, --help          display this help and exit\n");
    printf("  -v, --version       output version information and exit\n");
#   else
    printf("  -h        display this help and exit\n");
    printf("  -v        output version information and exit\n");
#   endif
}
#endif

