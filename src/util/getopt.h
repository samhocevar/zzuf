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
 *  getopt.h: getopt_long reimplementation
 */

struct zz_option
{
    char const *name;
    int has_arg;
    int *flag;
    int val;
};

extern int zz_optind;
extern char *zz_optarg;
extern int zz_getopt(int, char * const[], char const *,
                     struct zz_option const *, int *);

