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
 *  libcaca       Colour ASCII-Art library
 */

/*
 *  getopt.c: getopt_long reimplementation
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#if defined HAVE_GETOPT_H && defined HAVE_GETOPT_LONG
#   include <getopt.h>
#endif
#include <stdint.h>

#include "util/getopt.h"

int   zz_optind = 1;
char *zz_optarg = NULL;

int zz_getopt(int argc, char * const _argv[], char const *optstring,
              zzuf_option_t const *longopts, int *longindex)
{
#if defined HAVE_GETOPT_LONG
    optind = zz_optind;
    optarg = zz_optarg;
    int ret = getopt_long(argc, _argv, optstring,
                          (zzuf_option_t const *)longopts, longindex);
    zz_optind = optind;
    zz_optarg = optarg;
    return ret;

#else
    /* XXX: this getopt_long implementation should not be trusted for other
     * applications without any serious peer reviewing. It “just works” with
     * zzuf and a few libcaca programs but may fail miserably in other
     * programs. */
    char **argv = (char **)(uintptr_t)_argv;

    if (zz_optind >= argc)
        return -1;

    char *flag = argv[zz_optind];

    if (flag[0] == '-' && flag[1] != '-')
    {
        int ret = flag[1];
        if (ret == '\0')
            return -1;

        char const *tmp = strchr(optstring, ret);
        if (!tmp || ret == ':')
            return '?';

        zz_optind++;
        if (tmp[1] == ':')
        {
            if (flag[2] != '\0')
                zz_optarg = flag + 2;
            else
                zz_optarg = argv[zz_optind++];
            return ret;
        }

        if (flag[2] != '\0')
        {
            flag[1] = '-';
            zz_optind--;
            argv[zz_optind]++;
        }

        return ret;
    }

    if (flag[0] == '-' && flag[1] == '-')
    {
        if (flag[2] == '\0')
            return -1;

        for (int i = 0; longopts[i].name; ++i)
        {
            size_t l = strlen(longopts[i].name);

            if (strncmp(flag + 2, longopts[i].name, l))
                continue;

            switch (flag[2 + l])
            {
            case '=':
                if (!longopts[i].has_arg)
                    goto bad_opt;
                if (longindex)
                    *longindex = i;
                zz_optind++;
                zz_optarg = flag + 2 + l + 1;
                return longopts[i].val;
            case '\0':
                if (longindex)
                    *longindex = i;
                zz_optind++;
                if (longopts[i].has_arg)
                    zz_optarg = argv[zz_optind++];
                return longopts[i].val;
            default:
                break;
            }
        }
    bad_opt:
        fprintf(stderr, "%s: unrecognized option `%s'\n", argv[0], flag);
        return '?';
    }

    return -1;
#endif
}

