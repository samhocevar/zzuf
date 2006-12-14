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

#include "random.h"

static void version(void);
#if defined(HAVE_GETOPT_H)
static void usage(void);
#endif

int main(int argc, char *argv[])
{
    char *input = NULL, *output = NULL;
    FILE *in, *out;
    char *data;
    long int i, todo, size, seed = -1;
    float percent = -1.0;

#if defined(HAVE_GETOPT_H)
    for(;;)
    {
#   ifdef HAVE_GETOPT_LONG
#       define MOREINFO "Try `%s --help' for more information.\n"
        int option_index = 0;
        static struct option long_options[] =
            {
                /* Long option, needs arg, flag, short option */
                { "input", 1, NULL, 'i' },
                { "output", 1, NULL, 'o' },
                { "seed", 1, NULL, 's' },
                { "percent", 1, NULL, 'p' },
                { "help", 0, NULL, 'h' },
                { "version", 0, NULL, 'v' },
            };

        int c = getopt_long(argc, argv, "i:o:s:p:hv",
                            long_options, &option_index);
#   else
#       define MOREINFO "Try `%s -h' for more information.\n"
        int c = getopt(argc, argv, "i:o:s:p:hv");
#   endif
        if(c == -1)
            break;

        switch(c)
        {
        case 'i': /* --input */
            input = optarg;
            break;
        case 'o': /* --output */
            output = optarg;
            break;
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

    /* Open the files */
    if(input)
    {
        in = fopen(input, "rb");
        if(!in)
        {
            fprintf(stderr, "could not open `%s'\n", input);
            return 1;
        }
    }
    else
        in = stdin;

    if(output)
    {
        out = fopen(output, "wb");
        if(!out)
        {
            fprintf(stderr, "could not open `%s' for writing\n", output);
            return 1;
        }
    }
    else
        out = stdout;

    /* Checking parameters */
    if(seed == -1)
    {
        unsigned long int a = getpid();
        seed = (0x7931fea7 * a) ^ (0xb7390af7 + a);
        fprintf(stderr, "no seed specified, using %lu\n", seed);
    }

    if(percent == -1.0)
    {
        percent = 0.1;
        fprintf(stderr, "no percent specified, using %g\n", percent);
    }

    /* Read file contents */
    fseek(in, 0, SEEK_END);
    size = ftell(in);
    data = malloc(size);
    fseek(in, 0, SEEK_SET);
    fread(data, size, 1, in);
    fclose(in);

    /* Randomise shit */
    zzuf_srand(seed);
    todo = percent * 0.01 * size;
    while(todo--)
    {
        i = zzuf_rand(size);
        data[i] ^= 1 << zzuf_rand(8);
    }

    /* Write result */
    fwrite(data, size, 1, out);
    fclose(out);

    return 0;    
}

static void version(void)
{
    printf("zzuf %s by Sam Hocevar <sam@zoy.org>\n", VERSION);
}

#if defined(HAVE_GETOPT_H)
static void usage(void)
{
    printf("Usage: zzuf [ -vh ] [ -i input ] [ -o output ]\n");
    printf("            [ -p percent ] [ -s seed ]\n");
#   ifdef HAVE_GETOPT_LONG
    printf("  -h, --help          display this help and exit\n");
    printf("  -v, --version       output version information and exit\n");
#   else
    printf("  -h        display this help and exit\n");
    printf("  -v        output version information and exit\n");
#   endif
}
#endif


