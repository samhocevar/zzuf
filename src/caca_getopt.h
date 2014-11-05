/*
 *  libcaca       Colour ASCII-Art library
 *  Copyright (c) 2002-2014 Sam Hocevar <sam@hocevar.net>
 *                All Rights Reserved
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by Sam Hocevar. See
 *  http://www.wtfpl.net/ for more details.
 */

/*
 *  getopt.h: getopt_long reimplementation
 */

/** \brief Option parsing.
 *
 * This structure contains commandline parsing information for systems
 * where getopt_long() is unavailable.
 */
struct caca_option
{
    char const *name;
    int has_arg;
    int *flag;
    int val;
};

/** \defgroup caca_process libcaca process management
 *
 *  These functions help with various process handling tasks such as
 *  option parsing, DLL injection.
 *
 *  @{ */
extern int caca_optind;
extern char *caca_optarg;
extern int caca_getopt(int, char * const[], char const *,
                       struct caca_option const *, int *);

