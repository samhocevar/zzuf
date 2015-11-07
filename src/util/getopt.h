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
 *  getopt.h: getopt_long reimplementation
 */

struct zzuf_option
{
    char const *name;
    int has_arg;
    int *flag;
    int val;
};

typedef struct zzuf_option zzuf_option_t;

extern int zz_optind;
extern char *zz_optarg;
extern int zz_getopt(int, char * const[], char const *,
                     zzuf_option_t const *, int *);

