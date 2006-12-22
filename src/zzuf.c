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
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include "random.h"

static void spawn_child(char **);
static void set_ld_preload(char const *);
static void version(void);
#if defined(HAVE_GETOPT_H)
static void usage(void);
#endif

struct child_list
{
    pid_t pid;
    int outfd, errfd, seed;
}
*child_list;
int parallel = 1, child_count = 0;

int seed = 0;
int endseed = 1;

int main(int argc, char *argv[])
{
    char **newargv;
    char *parser;
    int i, j, quiet = 0;

#if defined(HAVE_GETOPT_H)
    for(;;)
    {
#   ifdef HAVE_GETOPT_LONG
#       define MOREINFO "Try `%s --help' for more information.\n"
        int option_index = 0;
        static struct option long_options[] =
        {
            /* Long option, needs arg, flag, short option */
            { "include", 1, NULL, 'i' },
            { "exclude", 1, NULL, 'e' },
            { "seed",    1, NULL, 's' },
            { "ratio",   1, NULL, 'r' },
            { "fork",    1, NULL, 'F' },
            { "quiet",   0, NULL, 'q' },
            { "debug",   0, NULL, 'd' },
            { "help",    0, NULL, 'h' },
            { "version", 0, NULL, 'v' },
        };
        int c = getopt_long(argc, argv, "i:e:s:r:F:qdhv",
                            long_options, &option_index);
#   else
#       define MOREINFO "Try `%s -h' for more information.\n"
        int c = getopt(argc, argv, "i:e:s:r:F:qdhv");
#   endif
        if(c == -1)
            break;

        switch(c)
        {
        case 'i': /* --include */
            setenv("ZZUF_INCLUDE", optarg, 1);
            break;
        case 'e': /* --exclude */
            setenv("ZZUF_EXCLUDE", optarg, 1);
            break;
        case 's': /* --seed */
            parser = strchr(optarg, ':');
            seed = atoi(optarg);
            endseed = parser ? atoi(parser + 1) : seed + 1;
            break;
        case 'r': /* --ratio */
            setenv("ZZUF_RATIO", optarg, 1);
            break;
        case 'F': /* --fork */
            parallel = atoi(optarg) > 1 ? atoi(optarg) : 1;
            break;
        case 'q': /* --quiet */
            quiet = 1;
            break;
        case 'd': /* --debug */
            setenv("ZZUF_DEBUG", "1", 1);
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
        printf("%s: missing argument\n", argv[0]);
        printf(MOREINFO, argv[0]);
        return EXIT_FAILURE;
    }

    /* Allocate memory for children handling */
    child_list = malloc(parallel * sizeof(struct child_list));
    for(i = 0; i < parallel; i++)
    {
        child_list[i].pid = 0;
        child_list[i].outfd = -1;
        child_list[i].errfd = -1;
    }
    child_count = 0;

    /* Preload libzzuf.so */
    set_ld_preload(argv[0]);

    /* Create new argv */
    newargv = malloc((argc - optind + 1) * sizeof(char *));
    memcpy(newargv, argv + optind, (argc - optind) * sizeof(char *));
    newargv[argc - optind] = (char *)NULL;

    /* Handle children in our way */
    signal(SIGCHLD, SIG_DFL);

    /* Main loop */
    while(child_count || seed < endseed)
    {
        struct timeval tv;
        fd_set fdset;
        int ret, maxfd = 0;

        /* Spawn a new child, if necessary */
        if(child_count < parallel && seed < endseed)
            spawn_child(newargv);

        /* Kill dead children */
        for(i = 0; i < parallel; i++)
        {
            int status;
            pid_t pid;

            if(!child_list[i].pid)
                continue;

            if(child_list[i].outfd >= 0 || child_list[i].errfd >= 0)
                continue;

            pid = waitpid(child_list[i].pid, &status, WNOHANG);
            if(pid <= 0)
                continue;

            if(WIFEXITED(status) && WEXITSTATUS(status))
                fprintf(stderr, "%i: exit %i\n",
                        child_list[i].seed, WEXITSTATUS(status));
            else if(WIFSIGNALED(status))
                fprintf(stderr, "%i: signal %i\n",
                        child_list[i].seed, WTERMSIG(status));

            child_list[i].pid = 0;
            child_list[i].outfd = -1;
            child_list[i].errfd = -1;
            child_count--;
        }
        /* Read data from all sockets */
        FD_ZERO(&fdset);
        for(i = 0; i < parallel; i++)
        {
            if(!child_list[i].pid)
                continue;

            if(child_list[i].outfd >= 0)
            {
                FD_SET(child_list[i].outfd, &fdset);
                if(child_list[i].outfd > maxfd)
                    maxfd = child_list[i].outfd;
            }

            if(child_list[i].errfd >= 0)
            {
                FD_SET(child_list[i].errfd, &fdset);
                if(child_list[i].errfd > maxfd)
                    maxfd = child_list[i].errfd;
            }
        }
        tv.tv_sec = 0;
        tv.tv_usec = 1000;

        ret = select(maxfd + 1, &fdset, NULL, NULL, &tv);
        if(ret < 0)
            perror("select");
        if(ret <= 0)
            continue;

        for(i = 0, j = 0; i < parallel; i += j, j = (j + 1) & 1)
        {
            char buf[BUFSIZ];
            int fd;

            if(!child_list[i].pid)
                continue;

            fd = j ? child_list[i].outfd : child_list[i].errfd;

            if(fd < 0 || !FD_ISSET(fd, &fdset))
                continue;

            ret = read(fd, buf, BUFSIZ - 1);
            if(ret > 0)
            {
                if(!quiet)
                {
                    buf[ret] = '\0';
                    fprintf(j ? stdout : stderr, "%s", buf);
                }
                continue;
            }
            else if(ret == 0)
            {
                close(fd);
                if(j)
                    child_list[i].outfd = -1;
                else
                    child_list[i].errfd = -1;
            }
        }
    }

    return EXIT_SUCCESS;    
}

static void spawn_child(char **argv)
{
    char buf[BUFSIZ];
    int outfd[2], errfd[2];
    pid_t pid;
    int i;

    /* Find an empty slot */
    for(i = 0; i < parallel; i++)
        if(child_list[i].pid == 0)
            break;

    /* Prepare communication pipe */
    if(pipe(outfd) == -1 || pipe(errfd) == -1)
    {
        perror("pipe");
        return;
    }

    /* Fork and launch child */
    pid = fork();
    switch(pid)
    {
        case -1:
            perror("fork");
            return;
        case 0:
            /* We’re the child */
            close(outfd[0]);
            close(errfd[0]);
            dup2(outfd[1], STDOUT_FILENO);
            dup2(errfd[1], STDERR_FILENO);
            close(outfd[1]);
            close(errfd[1]);

            /* Set environment variables */
            sprintf(buf, "%i", seed);
            setenv("ZZUF_SEED", buf, 1);

            /* Run our process */
            if(execvp(argv[0], argv))
            {
                perror(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;
        default:
            /* We’re the parent, acknowledge spawn */
            close(outfd[1]);
            close(errfd[1]);
            child_list[i].pid = pid;
            child_list[i].outfd = outfd[0];
            child_list[i].errfd = errfd[0];
            child_list[i].seed = seed;
            child_count++;
            seed++;
            break;
    }
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

    setenv("LD_PRELOAD", LIBDIR "/libzzuf.so", 1);
}

static void version(void)
{
    printf("zzuf %s\n", VERSION);
    printf("Copyright (C) 2006 Sam Hocevar <sam@zoy.org>\n");
    printf("This is free software.  You may redistribute copies of it under the\n");
    printf("terms of the Do What The Fuck You Want To Public License, Version 2\n");
    printf("<http://sam.zoy.org/wtfpl/>.\n");
    printf("There is NO WARRANTY, to the extent permitted by law.\n");
    printf("\n");
    printf("Written by Sam Hocevar. Report bugs to <sam@zoy.org>.\n");
}

#if defined(HAVE_GETOPT_H)
static void usage(void)
{
    printf("Usage: zzuf [ -vqdh ] [ -r ratio ] [ -s seed[:stop] ] [ -F forks ]\n");
    printf("                      [ -i include ] [ -e exclude ] COMMAND [ARGS]...\n");
    printf("Run COMMAND and randomly fuzz its input files.\n");
    printf("\n");
    printf("Mandatory arguments to long options are mandatory for short options too.\n");
#   ifdef HAVE_GETOPT_LONG
    printf("  -i, --include <regex>    only fuzz files matching <regex>\n");
    printf("  -e, --exclude <regex>    do not fuzz files matching <regex>\n");
    printf("  -r, --ratio <ratio>      bit fuzzing ratio (default 0.004)\n");
    printf("  -s, --seed <seed>        random seed (default 0)\n");
    printf("      --seed <start:stop>  specify a seed range\n");
    printf("  -F, --fork <count>       number of concurrent forks (default 1)\n");
    printf("  -q, --quiet              do not print the fuzzed application's messages\n");
    printf("  -d, --debug              print debug messages\n");
    printf("  -h, --help               display this help and exit\n");
    printf("  -v, --version            output version information and exit\n");
#   else
    printf("  -i <regex>       only fuzz files matching <regex>\n");
    printf("  -e <regex>       do not fuzz files matching <regex>\n");
    printf("  -r <ratio>       bit fuzzing ratio (default 0.004)\n");
    printf("  -s <seed>        random seed (default 0)\n");
    printf("     <start:stop>  specify a seed range\n");
    printf("  -F <count>       number of concurrent forks (default 1)\n");
    printf("  -q               do not print the fuzzed application's messages\n");
    printf("  -d               print debug messages\n");
    printf("  -h               display this help and exit\n");
    printf("  -v               output version information and exit\n");
#   endif
    printf("\n");
    printf("Written by Sam Hocevar. Report bugs to <sam@zoy.org>.\n");
}
#endif

