/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2002, 2007 Sam Hocevar <sam@zoy.org>
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
#include <regex.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "libzzuf.h"
#include "random.h"
#include "fd.h"
#include "fuzz.h"
#include "md5.h"
#include "timer.h"

static void loop_stdin(void);

static void spawn_children(void);
static void clean_children(void);
static void read_children(void);

static char *merge_regex(char *, char *);
static char *merge_file(char *, char *);
static void set_environment(char const *);
static void version(void);
#if defined(HAVE_GETOPT_H)
static void usage(void);
#endif

static struct child_list
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
    int64_t date;
    struct md5 *ctx;
} *child_list;
static int maxforks = 1, child_count = 0, maxcrashes = 1, crashes = 0;

static char **newargv;
static char *protect = NULL, *refuse = NULL;
static int seed = 0;
static int endseed = 1;
static int quiet = 0;
static int maxbytes = -1;
static int md5 = 0;
static int checkexit = 0;
static int maxmem = -1;
static int64_t maxtime = -1;
static int64_t delay = 0;
static int64_t lastlaunch = 0;

#define ZZUF_FD_SET(fd, p_fdset, maxfd) \
    if(fd >= 0) \
    { \
        FD_SET(fd, p_fdset); \
        if(fd > maxfd) \
            maxfd = fd; \
    }

#define ZZUF_FD_ISSET(fd, p_fdset) \
    ((fd >= 0) && (FD_ISSET(fd, p_fdset)))

int main(int argc, char *argv[])
{
    char *parser, *include, *exclude;
    int i, cmdline = 0;

    include = exclude = NULL;

#if defined(HAVE_GETOPT_H)
    for(;;)
    {
#   define OPTSTR "AB:cC:dD:E:F:iI:mM:nP:qr:R:s:ST:xhv"
#   ifdef HAVE_GETOPT_LONG
#       define MOREINFO "Try `%s --help' for more information.\n"
        int option_index = 0;
        static struct option long_options[] =
        {
            /* Long option, needs arg, flag, short option */
            { "autoinc",     0, NULL, 'A' },
            { "max-bytes",   1, NULL, 'B' },
            { "cmdline",     0, NULL, 'c' },
            { "max-crashes", 1, NULL, 'C' },
            { "debug",       0, NULL, 'd' },
            { "delay",       1, NULL, 'D' },
            { "exclude",     1, NULL, 'E' },
            { "max-forks",   1, NULL, 'F' },
            { "stdin",       0, NULL, 'i' },
            { "include",     1, NULL, 'I' },
            { "md5",         0, NULL, 'm' },
            { "max-memory",  1, NULL, 'M' },
            { "network",     0, NULL, 'n' },
            { "protect",     1, NULL, 'P' },
            { "quiet",       0, NULL, 'q' },
            { "ratio",       1, NULL, 'r' },
            { "refuse",      1, NULL, 'R' },
            { "seed",        1, NULL, 's' },
            { "signal",      0, NULL, 'S' },
            { "max-time",    1, NULL, 'T' },
            { "check-exit",  0, NULL, 'x' },
            { "help",        0, NULL, 'h' },
            { "version",     0, NULL, 'v' },
        };
        int c = getopt_long(argc, argv, OPTSTR, long_options, &option_index);
#   else
#       define MOREINFO "Try `%s -h' for more information.\n"
        int c = getopt(argc, argv, OPTSTR);
#   endif
        if(c == -1)
            break;

        switch(c)
        {
        case 'A': /* --autoinc */
            setenv("ZZUF_AUTOINC", "1", 1);
            break;
        case 'B': /* --max-bytes */
            maxbytes = atoi(optarg);
            break;
        case 'c': /* --cmdline */
            cmdline = 1;
            break;
        case 'C': /* --max-crashes */
            maxcrashes = atoi(optarg);
            if(maxcrashes <= 0)
                maxcrashes = 0;
            break;
        case 'd': /* --debug */
            setenv("ZZUF_DEBUG", "1", 1);
            break;
        case 'D': /* --delay */
            delay = (int64_t)(atof(optarg) * 1000000.0);
            break;
        case 'E': /* --exclude */
            exclude = merge_regex(exclude, optarg);
            if(!exclude)
            {
                printf("%s: invalid regex -- `%s'\n", argv[0], optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'F': /* --max-forks */
            maxforks = atoi(optarg) > 1 ? atoi(optarg) : 1;
            break;
        case 'i': /* --stdin */
            setenv("ZZUF_STDIN", "1", 1);
            break;
        case 'I': /* --include */
            include = merge_regex(include, optarg);
            if(!include)
            {
                printf("%s: invalid regex -- `%s'\n", argv[0], optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'm': /* --md5 */
            md5 = 1;
            break;
        case 'M': /* --max-memory */
            setenv("ZZUF_MEMORY", "1", 1);
            maxmem = atoi(optarg);
            break;
        case 'n': /* --network */
            setenv("ZZUF_NETWORK", "1", 1);
            break;
        case 'P': /* --protect */
            protect = optarg;
            break;
        case 'q': /* --quiet */
            quiet = 1;
            break;
        case 'r': /* --ratio */
            setenv("ZZUF_RATIO", optarg, 1);
            _zz_setratio(atof(optarg));
            break;
        case 'R': /* --refuse */
            refuse = optarg;
            break;
        case 's': /* --seed */
            parser = strchr(optarg, ':');
            _zz_setseed(seed = atol(optarg));
            endseed = parser ? atoi(parser + 1) : seed + 1;
            break;
        case 'S': /* --signal */
            setenv("ZZUF_SIGNAL", "1", 1);
            break;
        case 'T': /* --max-time */
            maxtime = (int64_t)(atof(optarg) * 1000000.0);
            break;
        case 'x': /* --check-exit */
            checkexit = 1;
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
            return EXIT_FAILURE;
        }
    }
#else
#   define MOREINFO "Usage: %s message...\n"
    int optind = 1;
#endif

    /* If asked to read from the standard input */
    if(optind >= argc)
    {
        if(endseed != seed + 1)
        {
            printf("%s: seed ranges are incompatible with stdin fuzzing\n",
                   argv[0]);
            printf(MOREINFO, argv[0]);
            return EXIT_FAILURE;
        }

        loop_stdin();

        return EXIT_SUCCESS;
    }

    /* If asked to launch programs */
    if(cmdline)
    {
        int dashdash = 0;

        for(i = optind + 1; i < argc; i++)
        {
            if(dashdash)
                include = merge_file(include, argv[i]);
            else if(!strcmp("--", argv[i]))
                dashdash = 1;
            else if(argv[i][0] != '-')
                include = merge_file(include, argv[i]);
        }
    }

    if(include)
        setenv("ZZUF_INCLUDE", include, 1);
    if(exclude)
        setenv("ZZUF_EXCLUDE", exclude, 1);
    if(protect)
        setenv("ZZUF_PROTECT", protect, 1);
    if(refuse)
        setenv("ZZUF_REFUSE", refuse, 1);

    /* Allocate memory for children handling */
    child_list = malloc(maxforks * sizeof(struct child_list));
    for(i = 0; i < maxforks; i++)
        child_list[i].status = STATUS_FREE;
    child_count = 0;

    /* Preload libzzuf.so */
    set_environment(argv[0]);

    /* Create new argv */
    newargv = malloc((argc - optind + 1) * sizeof(char *));
    memcpy(newargv, argv + optind, (argc - optind) * sizeof(char *));
    newargv[argc - optind] = (char *)NULL;

    /* Main loop */
    while(child_count || seed < endseed)
    {
        /* Spawn new children, if necessary */
        spawn_children();

        /* Cleanup dead or dying children */
        clean_children();

        /* Read data from children */
        read_children();

        if(maxcrashes && crashes >= maxcrashes && child_count == 0)
            break;
    }

    /* Clean up */
    free(newargv);
    free(child_list);

    return EXIT_SUCCESS;    
}

static void loop_stdin(void)
{
    uint8_t md5sum[16];
    struct md5 *ctx = NULL;

    if(md5)
        ctx = _zz_md5_init();

    if(protect)
        _zz_protect(protect);
    if(refuse)
        _zz_refuse(refuse);

    _zz_fd_init();
    _zz_register(0);

    for(;;)
    {
        uint8_t buf[BUFSIZ];
        int ret, off = 0, nw = 0;

        ret = read(0, buf, BUFSIZ);
        if(ret <= 0)
            break;

        _zz_fuzz(0, buf, ret);
        _zz_addpos(0, ret);

        if(md5)
            _zz_md5_add(ctx, buf, ret);
        else while(ret)
        {
            if((nw = write(1, buf + off, (size_t)ret)) < 0)
                break;
            ret -= nw;
            off += nw;
        }
    }

    if(md5)
    {
        _zz_md5_fini(md5sum, ctx);
        fprintf(stdout, "zzuf[seed=%i]: %.02x%.02x%.02x%.02x%.02x%.02x"
                "%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x\n",
                seed, md5sum[0], md5sum[1], md5sum[2], md5sum[3],
                md5sum[4], md5sum[5], md5sum[6], md5sum[7],
                md5sum[8], md5sum[9], md5sum[10], md5sum[11],
                md5sum[12], md5sum[13], md5sum[14], md5sum[15]);
        fflush(stdout);
    }

    _zz_unregister(0);
    _zz_fd_fini();
}

static char *merge_file(char *regex, char *file)
{
    char *newfile = malloc(5 + 2 * strlen(file) + 1 + 1), *tmp = newfile;

    *tmp++ = '(';
    *tmp++ = '^';
    *tmp++ = '|';
    *tmp++ = '/';
    *tmp++ = ')';
    while(*file)
    {
        if(strchr("^.[$()|*+?{\\", *file))
            *tmp++ = '\\';
        *tmp++ = *file++;
    }
    *tmp++ = '$';
    *tmp++ = '\0';

    tmp = merge_regex(regex, newfile);
    free(newfile);
    return tmp;
}

static char *merge_regex(char *regex, char *string)
{
    regex_t optre;

    if(regex)
    {
        regex = realloc(regex, strlen(regex) + strlen(string) + 1 + 1);
        sprintf(regex + strlen(regex) - 1, "|%s)", string);
    }
    else
    {
        regex = malloc(1 + strlen(string) + 1 + 1);
        sprintf(regex, "(%s)", string);
    }

    if(regcomp(&optre, regex, REG_EXTENDED) != 0)
    {
        free(regex);
        return NULL;
    }
    regfree(&optre);

    return regex;
}

static void spawn_children(void)
{
    static int const files[] = { DEBUG_FILENO, STDERR_FILENO, STDOUT_FILENO };
    char buf[BUFSIZ];
    int fd[3][2];
    int64_t now = _zz_time();
    pid_t pid;
    int i, j;

    if(child_count == maxforks)
        return; /* no slot */

    if(seed == endseed)
        return; /* job finished */

    if(maxcrashes && crashes >= maxcrashes)
        return; /* all jobs crashed */

    if(delay > 0 && lastlaunch + delay > now)
        return; /* too early */

    /* Find the empty slot */
    for(i = 0; i < maxforks; i++)
        if(child_list[i].status == STATUS_FREE)
            break;

    /* Prepare communication pipe */
    for(j = 0; j < 3; j++)
        if(pipe(fd[j]) == -1)
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
            if(maxmem >= 0)
            {
                struct rlimit rlim;
                rlim.rlim_cur = maxmem * 1000000;
                rlim.rlim_max = maxmem * 1000000;
                setrlimit(RLIMIT_AS, &rlim);
            }

            for(j = 0; j < 3; j++)
            {
                close(fd[j][0]);
                dup2(fd[j][1], files[j]);
                close(fd[j][1]);
            }

            /* Set environment variables */
            sprintf(buf, "%i", seed);
            setenv("ZZUF_SEED", buf, 1);

            /* Run our process */
            if(execvp(newargv[0], newargv))
            {
                perror(newargv[0]);
                exit(EXIT_FAILURE);
            }
            return;
    }

    /* We’re the parent, acknowledge spawn */
    child_list[i].date = now;
    child_list[i].pid = pid;
    for(j = 0; j < 3; j++)
    {
        close(fd[j][1]);
        child_list[i].fd[j] = fd[j][0];
    }
    child_list[i].bytes = 0;
    child_list[i].seed = seed;
    child_list[i].status = STATUS_RUNNING;
    if(md5)
        child_list[i].ctx = _zz_md5_init();

    lastlaunch = now;
    child_count++;
    seed++;
}

static void clean_children(void)
{
    int64_t now = _zz_time();
    int i, j;

    /* Terminate children if necessary */
    for(i = 0; i < maxforks; i++)
    {
        if(child_list[i].status == STATUS_RUNNING
            && maxbytes >= 0 && child_list[i].bytes > maxbytes)
        {
            fprintf(stdout, "zzuf[seed=%i]: data exceeded, sending SIGTERM\n",
                    child_list[i].seed);
            kill(child_list[i].pid, SIGTERM);
            child_list[i].date = now;
            child_list[i].status = STATUS_SIGTERM;
        }

        if(child_list[i].status == STATUS_RUNNING
            && maxtime >= 0
            && now > child_list[i].date + maxtime)
        {
            fprintf(stdout, "zzuf[seed=%i]: time exceeded, sending SIGTERM\n",
                    child_list[i].seed);
            kill(child_list[i].pid, SIGTERM);
            child_list[i].date = now;
            child_list[i].status = STATUS_SIGTERM;
        }
    }

    /* Kill children if necessary (still there after 2 seconds) */
    for(i = 0; i < maxforks; i++)
    {
        if(child_list[i].status == STATUS_SIGTERM
            && now > child_list[i].date + 2000000)
        {
            fprintf(stdout, "zzuf[seed=%i]: not responding, sending SIGKILL\n",
                    child_list[i].seed);
            kill(child_list[i].pid, SIGKILL);
            child_list[i].status = STATUS_SIGKILL;
        }
    }

    /* Collect dead children */
    for(i = 0; i < maxforks; i++)
    {
        uint8_t md5sum[16];
        int status;
        pid_t pid;

        if(child_list[i].status != STATUS_SIGKILL
            && child_list[i].status != STATUS_SIGTERM
            && child_list[i].status != STATUS_EOF)
            continue;

        pid = waitpid(child_list[i].pid, &status, WNOHANG);
        if(pid <= 0)
            continue;

        if(checkexit && WIFEXITED(status) && WEXITSTATUS(status))
        {
            fprintf(stdout, "zzuf[seed=%i]: exit %i\n",
                    child_list[i].seed, WEXITSTATUS(status));
            crashes++;
        }
        else if(WIFSIGNALED(status)
                 && !(WTERMSIG(status) == SIGTERM
                       && child_list[i].status == STATUS_SIGTERM))
        {
            fprintf(stdout, "zzuf[seed=%i]: signal %i%s\n",
                    child_list[i].seed, WTERMSIG(status),
                      (WTERMSIG(status) == SIGKILL && maxmem >= 0) ?
                      " (memory exceeded?)" : "");
            crashes++;
        }

        for(j = 0; j < 3; j++)
            if(child_list[i].fd[j] >= 0)
                close(child_list[i].fd[j]);

        if(md5)
        {
            _zz_md5_fini(md5sum, child_list[i].ctx);
            fprintf(stdout, "zzuf[seed=%i]: %.02x%.02x%.02x%.02x%.02x%.02x"
                    "%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x\n",
                    child_list[i].seed, md5sum[0], md5sum[1], md5sum[2],
                    md5sum[3], md5sum[4], md5sum[5], md5sum[6], md5sum[7],
                    md5sum[8], md5sum[9], md5sum[10], md5sum[11], md5sum[12],
                    md5sum[13], md5sum[14], md5sum[15]);
        }
        child_list[i].status = STATUS_FREE;
        child_count--;
    }

    fflush(stdout);
}

static void read_children(void)
{
    struct timeval tv;
    fd_set fdset;
    int i, j, ret, maxfd = 0;

    /* Read data from all sockets */
    FD_ZERO(&fdset);
    for(i = 0; i < maxforks; i++)
    {
        if(child_list[i].status != STATUS_RUNNING)
            continue;

        for(j = 0; j < 3; j++)
            ZZUF_FD_SET(child_list[i].fd[j], &fdset, maxfd);
    }
    tv.tv_sec = 0;
    tv.tv_usec = 1000;

    ret = select(maxfd + 1, &fdset, NULL, NULL, &tv);
    if(ret < 0)
        perror("select");
    if(ret <= 0)
        return;

    /* XXX: cute (i, j) iterating hack */
    for(i = 0, j = 0; i < maxforks; i += (j == 2), j = (j + 1) % 3)
    {
        uint8_t buf[BUFSIZ];

        if(child_list[i].status != STATUS_RUNNING)
            continue;

        if(!ZZUF_FD_ISSET(child_list[i].fd[j], &fdset))
            continue;

        ret = read(child_list[i].fd[j], buf, BUFSIZ - 1);
        if(ret > 0)
        {
            /* We got data */
            if(j != 0)
                child_list[i].bytes += ret;

            if(md5 && j == 2)
                _zz_md5_add(child_list[i].ctx, buf, ret);
            else if(!quiet || j == 0)
                write((j < 2) ? STDERR_FILENO : STDOUT_FILENO, buf, ret);
        }
        else if(ret == 0)
        {
            /* End of file reached */
            close(child_list[i].fd[j]);
            child_list[i].fd[j] = -1;

            if(child_list[i].fd[0] == -1 && child_list[i].fd[1] == -1
               && child_list[i].fd[2] == -1)
                child_list[i].status = STATUS_EOF;
        }
    }
}

static void set_environment(char const *progpath)
{
    char *libpath, *tmp;
    int ret, len = strlen(progpath);
#if defined __APPLE__
#   define FILENAME "libzzuf.dylib"
#   define EXTRAINFO ""
#   define PRELOAD "DYLD_INSERT_LIBRARIES"
    setenv("DYLD_FORCE_FLAT_NAMESPACE", "1", 1);
#elif defined __osf__
#   define FILENAME "libzzuf.so"
#   define EXTRAINFO ":DEFAULT"
#   define PRELOAD "_RLD_LIST"
#else
#   define FILENAME "libzzuf.so"
#   define EXTRAINFO ""
#   define PRELOAD "LD_PRELOAD"
#endif

    libpath = malloc(len + strlen("/.libs/" FILENAME EXTRAINFO) + 1);
    strcpy(libpath, progpath);

    tmp = strrchr(libpath, '/');
    strcpy(tmp ? tmp + 1 : libpath, ".libs/" FILENAME);
    ret = access(libpath, R_OK);

    strcpy(tmp ? tmp + 1 : libpath, ".libs/" FILENAME EXTRAINFO);
    if(ret == 0)
        setenv(PRELOAD, libpath, 1);
    else
        setenv(PRELOAD, LIBDIR "/" FILENAME EXTRAINFO, 1);
    free(libpath);
}

static void version(void)
{
    printf("zzuf %s\n", VERSION);
    printf("Copyright (C) 2002, 2007 Sam Hocevar <sam@zoy.org>\n");
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
    printf("Usage: zzuf [-AcdimnqSx] [-r ratio] [-s seed | -s start:stop]\n");
    printf("                         [-D delay] [-F forks] [-C crashes] [-B bytes]\n");
    printf("                         [-T seconds] [-M bytes] [-P protect] [-R refuse]\n");
    printf("                         [-I include] [-E exclude] [PROGRAM [--] [ARGS]...]\n");
#   ifdef HAVE_GETOPT_LONG
    printf("       zzuf -h | --help\n");
    printf("       zzuf -v | --version\n");
#   else
    printf("       zzuf -h\n");
    printf("       zzuf -v\n");
#   endif
    printf("Run PROGRAM with optional arguments ARGS and fuzz its input.\n");
    printf("\n");
    printf("Mandatory arguments to long options are mandatory for short options too.\n");
#   ifdef HAVE_GETOPT_LONG
    printf("  -A, --autoinc            increment seed each time a new file is opened\n");
    printf("  -B, --max-bytes <n>      kill children that output more than <n> bytes\n");
    printf("  -c, --cmdline            only fuzz files specified in the command line\n");
    printf("  -C, --max-crashes <n>    stop after <n> children have crashed (default 1)\n");
    printf("  -d, --debug              print debug messages\n");
    printf("  -D, --delay              delay between forks\n");
    printf("  -E, --exclude <regex>    do not fuzz files matching <regex>\n");
    printf("  -F, --max-forks <n>      number of concurrent children (default 1)\n");
    printf("  -i, --stdin              fuzz standard input\n");
    printf("  -I, --include <regex>    only fuzz files matching <regex>\n");
    printf("  -m, --md5                compute the output's MD5 hash\n");
    printf("  -M, --max-memory <n>     maximum child virtual memory size in MB\n");
    printf("  -n, --network            fuzz network input\n");
    printf("  -P, --protect <list>     protect bytes and characters in <list>\n");
    printf("  -q, --quiet              do not print children's messages\n");
    printf("  -r, --ratio <ratio>      bit fuzzing ratio (default 0.004)\n");
    printf("  -R, --refuse <list>      refuse bytes and characters in <list>\n");
    printf("  -s, --seed <seed>        random seed (default 0)\n");
    printf("      --seed <start:stop>  specify a seed range\n");
    printf("  -S, --signal             prevent children from diverting crashing signals\n");
    printf("  -T, --max-time <n>       kill children that run for more than <n> seconds\n");
    printf("  -x, --check-exit         report processes that exit with a non-zero status\n");
    printf("  -h, --help               display this help and exit\n");
    printf("  -v, --version            output version information and exit\n");
#   else
    printf("  -A               increment seed each time a new file is opened\n");
    printf("  -B <n>           kill children that output more than <n> bytes\n");
    printf("  -c               only fuzz files specified in the command line\n");
    printf("  -C <n>           stop after <n> children have crashed (default 1)\n");
    printf("  -d               print debug messages\n");
    printf("  -D               delay between forks\n");
    printf("  -E <regex>       do not fuzz files matching <regex>\n");
    printf("  -F <n>           number of concurrent forks (default 1)\n");
    printf("  -i               fuzz standard input\n");
    printf("  -I <regex>       only fuzz files matching <regex>\n");
    printf("  -m               compute the output's MD5 hash\n");
    printf("  -M               maximum child virtual memory size in MB\n");
    printf("  -n               fuzz network input\n");
    printf("  -P <list>        protect bytes and characters in <list>\n");
    printf("  -q               do not print the fuzzed application's messages\n");
    printf("  -r <ratio>       bit fuzzing ratio (default 0.004)\n");
    printf("  -R <list>        refuse bytes and characters in <list>\n");
    printf("  -s <seed>        random seed (default 0)\n");
    printf("     <start:stop>  specify a seed range\n");
    printf("  -S               prevent children from diverting crashing signals\n");
    printf("  -T <n>           kill children that run for more than <n> seconds\n");
    printf("  -x               report processes that exit with a non-zero status\n");
    printf("  -h               display this help and exit\n");
    printf("  -v               output version information and exit\n");
#   endif
    printf("\n");
    printf("Written by Sam Hocevar. Report bugs to <sam@zoy.org>.\n");
}
#endif

