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
 *  main.c: main program
 */

#include "config.h"

#define _INCLUDE_POSIX_SOURCE /* for STDERR_FILENO on HP-UX */

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#if !defined HAVE_GETOPT_LONG
#   include "mygetopt.h"
#elif defined HAVE_GETOPT_H
#   include <getopt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#if defined HAVE_UNISTD_H
#   include <unistd.h> /* for read(), write(), close() */
#endif
#if defined HAVE_REGEX_H
#   include <regex.h>
#endif
#if defined HAVE_WINSOCK2_H
#   include <winsock2.h> /* for fd_set */
#endif
#if defined HAVE_IO_H
#   include <io.h>
#endif
#include <string.h>
#include <errno.h>
#include <signal.h>
#if defined HAVE_SYS_TIME_H
#   include <sys/time.h>
#endif
#if defined HAVE_SYS_WAIT_H
#   include <sys/wait.h>
#endif
#if defined HAVE_SYS_RESOURCE_H
#   include <sys/resource.h> /* for RLIMIT_AS */
#endif

#include "common.h"
#include "opts.h"
#include "random.h"
#include "fd.h"
#include "fuzz.h"
#include "myfork.h"
#include "md5.h"
#include "timer.h"

#if defined HAVE_GETOPT_LONG
#   define mygetopt getopt_long
#   define myoptind optind
#   define myoptarg optarg
#   define myoption option
#endif

#if !defined SIGKILL
#   define SIGKILL 9
#endif

#if defined RLIMIT_AS
#   define ZZUF_RLIMIT_MEM RLIMIT_AS
#elif defined RLIMIT_VMEM
#   define ZZUF_RLIMIT_MEM RLIMIT_VMEM
#elif defined RLIMIT_DATA
#   define ZZUF_RLIMIT_MEM RLIMIT_DATA
#else
#   undef ZZUF_RLIMIT_MEM
#endif

#if defined RLIMIT_CPU
#   define ZZUF_RLIMIT_CPU RLIMIT_CPU
#else
#   undef ZZUF_RLIMIT_CPU
#endif

static void loop_stdin(struct opts *);

static void spawn_children(struct opts *);
static void clean_children(struct opts *);
static void read_children(struct opts *);

#if !defined HAVE_SETENV
static void setenv(char const *, char const *, int);
#endif
#if defined HAVE_WAITPID
static char const *sig2name(int);
#endif
static void finfo(FILE *, struct opts *, uint32_t);
#if defined HAVE_REGEX_H
static char *merge_regex(char *, char *);
static char *merge_file(char *, char *);
#endif
static void version(void);
static void usage(void);

#define ZZUF_FD_SET(fd, p_fdset, maxfd) \
    if(fd >= 0) \
    { \
        FD_SET((unsigned int)fd, p_fdset); \
        if(fd > maxfd) \
            maxfd = fd; \
    }

#define ZZUF_FD_ISSET(fd, p_fdset) \
    ((fd >= 0) && (FD_ISSET(fd, p_fdset)))

int main(int argc, char *argv[])
{
    struct opts _opts, *opts = &_opts;
    char *tmp;
#if defined HAVE_REGEX_H
    char *include = NULL, *exclude = NULL;
    int cmdline = 0;
#endif
    int debug = 0, network = 0;
    int i;

    _zz_opts_init(opts);

    for(;;)
    {
#if defined HAVE_REGEX_H
#   define OPTSTR_REGEX "cE:I:"
#else
#   define OPTSTR_REGEX ""
#endif
#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_MEM
#   define OPTSTR_RLIMIT_MEM "M:"
#else
#   define OPTSTR_RLIMIT_MEM ""
#endif
#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_CPU
#   define OPTSTR_RLIMIT_CPU "T:"
#else
#   define OPTSTR_RLIMIT_CPU ""
#endif
#define OPTSTR "+" OPTSTR_REGEX OPTSTR_RLIMIT_MEM OPTSTR_RLIMIT_CPU \
                "a:Ab:B:C:dD:e:f:F:ij:l:mnp:P:qr:R:s:St:U:vxhV"
#define MOREINFO "Try `%s --help' for more information.\n"
        int option_index = 0;
        static struct myoption long_options[] =
        {
            /* Long option, needs arg, flag, short option */
            { "allow",        1, NULL, 'a' },
            { "autoinc",      0, NULL, 'A' },
            { "bytes",        1, NULL, 'b' },
            { "max-bytes",    1, NULL, 'B' },
#if defined HAVE_REGEX_H
            { "cmdline",      0, NULL, 'c' },
#endif
            { "max-crashes",  1, NULL, 'C' },
            { "debug",        0, NULL, 'd' },
            { "delay",        1, NULL, 'D' },
#if defined HAVE_REGEX_H
            { "exclude",      1, NULL, 'E' },
#endif
            { "fuzzing",      1, NULL, 'f' },
            { "stdin",        0, NULL, 'i' },
#if defined HAVE_REGEX_H
            { "include",      1, NULL, 'I' },
#endif
            { "jobs",         1, NULL, 'j' },
            { "list",         1, NULL, 'l' },
            { "md5",          0, NULL, 'm' },
            { "max-memory",   1, NULL, 'M' },
            { "network",      0, NULL, 'n' },
            { "ports",        1, NULL, 'p' },
            { "protect",      1, NULL, 'P' },
            { "quiet",        0, NULL, 'q' },
            { "ratio",        1, NULL, 'r' },
            { "refuse",       1, NULL, 'R' },
            { "seed",         1, NULL, 's' },
            { "signal",       0, NULL, 'S' },
            { "max-time",     1, NULL, 't' },
            { "max-cputime",  1, NULL, 'T' },
            { "max-usertime", 1, NULL, 'U' },
            { "verbose",      0, NULL, 'v' },
            { "check-exit",   0, NULL, 'x' },
            { "help",         0, NULL, 'h' },
            { "version",      0, NULL, 'V' },
            { NULL,           0, NULL,  0  }
        };
        int c = mygetopt(argc, argv, OPTSTR, long_options, &option_index);

        if(c == -1)
            break;

        switch(c)
        {
        case 'a': /* --allow */
            opts->allow = myoptarg;
            break;
        case 'A': /* --autoinc */
            setenv("ZZUF_AUTOINC", "1", 1);
            break;
        case 'b': /* --bytes */
            opts->bytes = myoptarg;
            break;
        case 'B': /* --max-bytes */
            if(myoptarg[0] == '=')
                myoptarg++;
            opts->maxbytes = atoi(myoptarg);
            break;
#if defined HAVE_REGEX_H
        case 'c': /* --cmdline */
            cmdline = 1;
            break;
#endif
        case 'C': /* --max-crashes */
            if(myoptarg[0] == '=')
                myoptarg++;
            opts->maxcrashes = atoi(myoptarg);
            if(opts->maxcrashes <= 0)
                opts->maxcrashes = 0;
            break;
        case 'd': /* --debug */
            debug++;
            break;
        case 'D': /* --delay */
            if(myoptarg[0] == '=')
                myoptarg++;
            opts->delay = (int64_t)(atof(myoptarg) * 1000000.0);
            break;
#if defined HAVE_REGEX_H
        case 'E': /* --exclude */
            exclude = merge_regex(exclude, myoptarg);
            if(!exclude)
            {
                fprintf(stderr, "%s: invalid regex -- `%s'\n",
                        argv[0], myoptarg);
                _zz_opts_fini(opts);
                return EXIT_FAILURE;
            }
            break;
#endif
        case 'f': /* --fuzzing */
            opts->fuzzing = myoptarg;
            break;
        case 'F':
            fprintf(stderr, "%s: `-F' is deprecated, use `-j'\n", argv[0]);
            return EXIT_FAILURE;
        case 'i': /* --stdin */
            setenv("ZZUF_STDIN", "1", 1);
            break;
#if defined HAVE_REGEX_H
        case 'I': /* --include */
            include = merge_regex(include, myoptarg);
            if(!include)
            {
                fprintf(stderr, "%s: invalid regex -- `%s'\n",
                        argv[0], myoptarg);
                _zz_opts_fini(opts);
                return EXIT_FAILURE;
            }
            break;
#endif
        case 'j': /* --jobs */
            if(myoptarg[0] == '=')
                myoptarg++;
            opts->maxchild = atoi(myoptarg) > 1 ? atoi(myoptarg) : 1;
            break;
        case 'l': /* --list */
            opts->list = myoptarg;
            break;
        case 'm': /* --md5 */
            opts->md5 = 1;
            break;
#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_MEM
        case 'M': /* --max-memory */
            if(myoptarg[0] == '=')
                myoptarg++;
            opts->maxmem = atoi(myoptarg);
            break;
#endif
        case 'n': /* --network */
            setenv("ZZUF_NETWORK", "1", 1);
            network = 1;
            break;
        case 'p': /* --ports */
            opts->ports = myoptarg;
            break;
        case 'P': /* --protect */
            opts->protect = myoptarg;
            break;
        case 'q': /* --quiet */
            opts->quiet = 1;
            break;
        case 'r': /* --ratio */
            if(myoptarg[0] == '=')
                myoptarg++;
            tmp = strchr(myoptarg, ':');
            opts->minratio = atof(myoptarg);
            opts->maxratio = tmp ? atof(tmp + 1) : opts->minratio;
            break;
        case 'R': /* --refuse */
            opts->refuse = myoptarg;
            break;
        case 's': /* --seed */
            if(myoptarg[0] == '=')
                myoptarg++;
            tmp = strchr(myoptarg, ':');
            opts->seed = atol(myoptarg);
            opts->endseed = tmp ? tmp[1] ? (uint32_t)atol(tmp + 1)
                                         : (uint32_t)-1L
                                : opts->seed + 1;
            break;
        case 'S': /* --signal */
            setenv("ZZUF_SIGNAL", "1", 1);
            break;
        case 't': /* --max-time */
            if(myoptarg[0] == '=')
                myoptarg++;
            opts->maxtime = (int64_t)atoi(myoptarg) * 1000000;
            break;
#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_CPU
        case 'T': /* --max-cputime */
            if(myoptarg[0] == '=')
                myoptarg++;
            opts->maxcpu = (int)(atof(myoptarg) + 0.5);
            break;
#endif
        case 'U': /* --max-usertime */
            if(myoptarg[0] == '=')
                myoptarg++;
            opts->maxusertime = (int64_t)(atof(myoptarg) * 1000000.0);
            break;
        case 'x': /* --check-exit */
            opts->checkexit = 1;
            break;
        case 'v': /* --verbose */
            opts->verbose = 1;
            break;
        case 'h': /* --help */
            usage();
            _zz_opts_fini(opts);
            return 0;
        case 'V': /* --version */
            version();
            _zz_opts_fini(opts);
            return 0;
        default:
            fprintf(stderr, "%s: invalid option -- %c\n", argv[0], c);
            printf(MOREINFO, argv[0]);
            _zz_opts_fini(opts);
            return EXIT_FAILURE;
        }
    }

    if(opts->ports && !network)
    {
        fprintf(stderr, "%s: port option (-p) requires network fuzzing (-n)\n",
                argv[0]);
        printf(MOREINFO, argv[0]);
        _zz_opts_fini(opts);
        return EXIT_FAILURE;
    }

    if (opts->allow && !network)
    {
        fprintf(stderr, "%s: allow option (-a) requires network fuzzing (-n)\n",
                argv[0]);
        printf(MOREINFO, argv[0]);
        _zz_opts_fini(opts);
        return EXIT_FAILURE;
    }

    _zz_setratio(opts->minratio, opts->maxratio);
    _zz_setseed(opts->seed);

    /* If asked to read from the standard input */
    if(myoptind >= argc)
    {
        if(opts->verbose)
        {
            finfo(stderr, opts, opts->seed);
            fprintf(stderr, "reading from stdin\n");
        }

        if(opts->endseed != opts->seed + 1)
        {
            fprintf(stderr, "%s: seed ranges are incompatible with "
                            "stdin fuzzing\n", argv[0]);
            printf(MOREINFO, argv[0]);
            _zz_opts_fini(opts);
            return EXIT_FAILURE;
        }

        loop_stdin(opts);

        _zz_opts_fini(opts);
        return EXIT_SUCCESS;
    }

    /* If asked to launch programs */
#if defined HAVE_REGEX_H
    if(cmdline)
    {
        int dashdash = 0;

        for(i = myoptind + 1; i < argc; i++)
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
#endif

    setenv("ZZUF_DEBUG", debug ? debug > 1 ? "2" : "1" : "0", 1);
    setenv("ZZUF_DEBUGFD", DEBUG_FILENO_STR, 1);

    if(opts->fuzzing)
        setenv("ZZUF_FUZZING", opts->fuzzing, 1);
    if(opts->bytes)
        setenv("ZZUF_BYTES", opts->bytes, 1);
    if(opts->list)
        setenv("ZZUF_LIST", opts->list, 1);
    if(opts->ports)
        setenv("ZZUF_PORTS", opts->ports, 1);
    if(opts->allow && opts->allow[0] == '!')
        setenv("ZZUF_DENY", opts->allow, 1);
    else if(opts->allow)
        setenv("ZZUF_ALLOW", opts->allow, 1);
    if(opts->protect)
        setenv("ZZUF_PROTECT", opts->protect, 1);
    if(opts->refuse)
        setenv("ZZUF_REFUSE", opts->refuse, 1);
#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_MEM
    if(opts->maxmem >= 0)
    {
        char buf[32];
        snprintf(buf, 32, "%i", opts->maxmem);
        setenv("ZZUF_MEMORY", buf, 1);
    }
#endif

    /* Allocate memory for children handling */
    opts->child = malloc(opts->maxchild * sizeof(struct child));
    for(i = 0; i < opts->maxchild; i++)
        opts->child[i].status = STATUS_FREE;
    opts->nchild = 0;

    /* Create new argv */
    opts->oldargv = argv;
    opts->newargv = malloc((argc - myoptind + 1) * sizeof(char *));
    memcpy(opts->newargv, argv + myoptind, (argc - myoptind) * sizeof(char *));
    opts->newargv[argc - myoptind] = (char *)NULL;

    /* Main loop */
    while(opts->nchild || opts->seed < opts->endseed)
    {
        /* Spawn new children, if necessary */
        spawn_children(opts);

        /* Cleanup dead or dying children */
        clean_children(opts);

        /* Read data from children */
        read_children(opts);

        if(opts->maxcrashes && opts->crashes >= opts->maxcrashes
            && opts->nchild == 0)
        {
            if(opts->verbose)
                fprintf(stderr,
                        "zzuf: maximum crash count reached, exiting\n");
            break;
        }

        if(opts->maxtime && _zz_time() - opts->starttime >= opts->maxtime
            && opts->nchild == 0)
        {
            if(opts->verbose)
                fprintf(stderr,
                        "zzuf: maximum running time reached, exiting\n");
            break;
        }
    }

    /* Clean up */
    _zz_opts_fini(opts);

    return opts->crashes ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void loop_stdin(struct opts *opts)
{
    uint8_t md5sum[16];
    struct md5 *ctx = NULL;
    int total = 0;

    if(opts->md5)
        ctx = _zz_md5_init();

    if(opts->fuzzing)
        _zz_fuzzing(opts->fuzzing);
    if(opts->bytes)
        _zz_bytes(opts->bytes);
    if(opts->list)
        _zz_list(opts->list);
    if(opts->protect)
        _zz_protect(opts->protect);
    if(opts->refuse)
        _zz_refuse(opts->refuse);

    _zz_fd_init();
    _zz_register(0);

    for(;;)
    {
        uint8_t buf[BUFSIZ];
        int ret, toread = BUFSIZ, off = 0, nw = 0;

        if(opts->maxbytes >= 0)
        {
            if(total >= opts->maxbytes)
                break;
            if(total + BUFSIZ >= opts->maxbytes)
                toread = opts->maxbytes - total;
        }

        ret = read(0, buf, toread);
        if(ret <= 0)
            break;

        total += ret;

        _zz_fuzz(0, buf, ret);
        _zz_addpos(0, ret);

        if(opts->md5)
            _zz_md5_add(ctx, buf, ret);
        else while(ret)
        {
            if((nw = write(1, buf + off, (unsigned int)ret)) < 0)
                break;
            ret -= nw;
            off += nw;
        }
    }

    if(opts->md5)
    {
        _zz_md5_fini(md5sum, ctx);
        finfo(stdout, opts, opts->seed);
        fprintf(stdout, "%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x"
                "%.02x%.02x%.02x%.02x%.02x%.02x\n", md5sum[0], md5sum[1],
                md5sum[2], md5sum[3], md5sum[4], md5sum[5], md5sum[6],
                md5sum[7], md5sum[8], md5sum[9], md5sum[10], md5sum[11],
                md5sum[12], md5sum[13], md5sum[14], md5sum[15]);
        fflush(stdout);
    }

    _zz_unregister(0);
    _zz_fd_fini();
}

static void finfo(FILE *fp, struct opts *opts, uint32_t seed)
{
    if(opts->minratio == opts->maxratio)
        fprintf(fp, "zzuf[s=%i,r=%g]: ", seed, opts->minratio);
    else
        fprintf(fp, "zzuf[s=%i,r=%g:%g]: ", seed,
                opts->minratio, opts->maxratio);
}

#if defined HAVE_REGEX_H
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
#endif

static void spawn_children(struct opts *opts)
{
    int64_t now = _zz_time();
    int i;

    if(opts->nchild == opts->maxchild)
        return; /* no slot */

    if(opts->seed == opts->endseed)
        return; /* job finished */

    if(opts->maxcrashes && opts->crashes >= opts->maxcrashes)
        return; /* all jobs crashed */

    if(opts->maxtime && now - opts->starttime >= opts->maxtime)
        return; /* run time exceeded */

    if(opts->delay > 0 && opts->lastlaunch + opts->delay > now)
        return; /* too early */

    /* Find the empty slot */
    for(i = 0; i < opts->maxchild; i++)
        if(opts->child[i].status == STATUS_FREE)
            break;

    if (myfork(&opts->child[i], opts) < 0)
    {
        fprintf(stderr, "error launching `%s'\n", opts->newargv[0]);
        opts->seed++;
        return;
    }

    /* We’re the parent, acknowledge spawn */
    opts->child[i].date = now;
    opts->child[i].bytes = 0;
    opts->child[i].seed = opts->seed;
    opts->child[i].ratio = _zz_getratio();
    opts->child[i].status = STATUS_RUNNING;
    if(opts->md5)
        opts->child[i].ctx = _zz_md5_init();

    if(opts->verbose)
    {
        finfo(stderr, opts, opts->child[i].seed);
        fprintf(stderr, "launched `%s'\n", opts->newargv[0]);
    }

    opts->lastlaunch = now;
    opts->nchild++;
    opts->seed++;

    _zz_setseed(opts->seed);
}

static void clean_children(struct opts *opts)
{
#if defined HAVE_KILL
    int64_t now = _zz_time();
#endif
    int i, j;

#if defined HAVE_KILL
    /* Terminate children if necessary */
    for(i = 0; i < opts->maxchild; i++)
    {
        if(opts->child[i].status == STATUS_RUNNING
            && opts->maxbytes >= 0
            && opts->child[i].bytes > opts->maxbytes)
        {
            if(opts->verbose)
            {
                finfo(stderr, opts, opts->child[i].seed);
                fprintf(stderr, "data output exceeded, sending SIGTERM\n");
            }
            kill(opts->child[i].pid, SIGTERM);
            opts->child[i].date = now;
            opts->child[i].status = STATUS_SIGTERM;
        }

        if(opts->child[i].status == STATUS_RUNNING
            && opts->maxusertime >= 0
            && now > opts->child[i].date + opts->maxusertime)
        {
            if(opts->verbose)
            {
                finfo(stderr, opts, opts->child[i].seed);
                fprintf(stderr, "running time exceeded, sending SIGTERM\n");
            }
            kill(opts->child[i].pid, SIGTERM);
            opts->child[i].date = now;
            opts->child[i].status = STATUS_SIGTERM;
        }
    }

    /* Kill children if necessary (still there after 2 seconds) */
    for(i = 0; i < opts->maxchild; i++)
    {
        if(opts->child[i].status == STATUS_SIGTERM
            && now > opts->child[i].date + 2000000)
        {
            if(opts->verbose)
            {
                finfo(stderr, opts, opts->child[i].seed);
                fprintf(stderr, "not responding, sending SIGKILL\n");
            }
            kill(opts->child[i].pid, SIGKILL);
            opts->child[i].status = STATUS_SIGKILL;
        }
    }
#endif

    /* Collect dead children */
    for(i = 0; i < opts->maxchild; i++)
    {
        uint8_t md5sum[16];
#if defined HAVE_WAITPID
        int status;
        pid_t pid;
#endif

        if(opts->child[i].status != STATUS_SIGKILL
            && opts->child[i].status != STATUS_SIGTERM
            && opts->child[i].status != STATUS_EOF)
            continue;

#if defined HAVE_WAITPID
        pid = waitpid(opts->child[i].pid, &status, WNOHANG);
        if(pid <= 0)
            continue;

        if(opts->checkexit && WIFEXITED(status) && WEXITSTATUS(status))
        {
            finfo(stderr, opts, opts->child[i].seed);
            fprintf(stderr, "exit %i\n", WEXITSTATUS(status));
            opts->crashes++;
        }
        else if(WIFSIGNALED(status)
                 && !(WTERMSIG(status) == SIGTERM
                       && opts->child[i].status == STATUS_SIGTERM))
        {
            char const *message = "";

            if(WTERMSIG(status) == SIGKILL && opts->maxmem >= 0)
                message = " (memory exceeded?)";
#   if defined SIGXCPU
            else if(WTERMSIG(status) == SIGXCPU && opts->maxcpu >= 0)
                message = " (CPU time exceeded?)";
#   endif
            else if(WTERMSIG(status) == SIGKILL && opts->maxcpu >= 0)
                message = " (CPU time exceeded?)";

            finfo(stderr, opts, opts->child[i].seed);
            fprintf(stderr, "signal %i%s%s\n",
                    WTERMSIG(status), sig2name(WTERMSIG(status)), message);
            opts->crashes++;
        }
        else if (opts->verbose)
        {
            finfo(stderr, opts, opts->child[i].seed);
            if (WIFSIGNALED(status))
                fprintf(stderr, "signal %i%s\n",
                        WTERMSIG(status), sig2name(WTERMSIG(status)));
            else
                fprintf(stderr, "exit %i\n", WEXITSTATUS(status));
        }
#else
        /* waitpid() is not available. Don't kill the process. */
        continue;
#endif

        for(j = 0; j < 3; j++)
            if(opts->child[i].fd[j] >= 0)
                close(opts->child[i].fd[j]);

        if(opts->md5)
        {
            _zz_md5_fini(md5sum, opts->child[i].ctx);
            finfo(stdout, opts, opts->child[i].seed);
            fprintf(stdout, "%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x"
                    "%.02x%.02x%.02x%.02x%.02x%.02x%.02x\n", md5sum[0],
                    md5sum[1], md5sum[2], md5sum[3], md5sum[4], md5sum[5],
                    md5sum[6], md5sum[7], md5sum[8], md5sum[9], md5sum[10],
                    md5sum[11], md5sum[12], md5sum[13], md5sum[14], md5sum[15]);
            fflush(stdout);
        }
        opts->child[i].status = STATUS_FREE;
        opts->nchild--;
    }
}

static void read_children(struct opts *opts)
{
    struct timeval tv;
    fd_set fdset;
    int i, j, ret, maxfd = 0;

    /* Read data from all sockets */
    FD_ZERO(&fdset);
    for(i = 0; i < opts->maxchild; i++)
    {
        if(opts->child[i].status != STATUS_RUNNING)
            continue;

        for(j = 0; j < 3; j++)
            ZZUF_FD_SET(opts->child[i].fd[j], &fdset, maxfd);
    }
    tv.tv_sec = 0;
    tv.tv_usec = 1000;

    ret = select(maxfd + 1, &fdset, NULL, NULL, &tv);
    if(ret < 0 && errno)
        perror("select");
    if(ret <= 0)
        return;

    /* XXX: cute (i, j) iterating hack */
    for(i = 0, j = 0; i < opts->maxchild; i += (j == 2), j = (j + 1) % 3)
    {
        uint8_t buf[BUFSIZ];

        if(opts->child[i].status != STATUS_RUNNING)
            continue;

        if(!ZZUF_FD_ISSET(opts->child[i].fd[j], &fdset))
            continue;

        ret = read(opts->child[i].fd[j], buf, BUFSIZ - 1);
        if(ret > 0)
        {
            /* We got data */
            if(j != 0)
                opts->child[i].bytes += ret;

            if(opts->md5 && j == 2)
                _zz_md5_add(opts->child[i].ctx, buf, ret);
            else if(!opts->quiet || j == 0)
                write((j < 2) ? STDERR_FILENO : STDOUT_FILENO, buf, ret);
        }
        else if(ret == 0)
        {
            /* End of file reached */
            close(opts->child[i].fd[j]);
            opts->child[i].fd[j] = -1;

            if(opts->child[i].fd[0] == -1
                && opts->child[i].fd[1] == -1
                && opts->child[i].fd[2] == -1)
                opts->child[i].status = STATUS_EOF;
        }
    }
}

#if !defined HAVE_SETENV
static void setenv(char const *name, char const *value, int overwrite)
{
    char *str;

    if(!overwrite && getenv(name))
        return;

    str = malloc(strlen(name) + 1 + strlen(value) + 1);
    sprintf(str, "%s=%s", name, value);
    putenv(str);
}
#endif

#if defined HAVE_WAITPID
static char const *sig2name(int signum)
{
    switch(signum)
    {
#ifdef SIGQUIT
        case SIGQUIT:  return " (SIGQUIT)"; /* 3 */
#endif
        case SIGILL:   return " (SIGILL)";  /* 4 */
#ifdef SIGTRAP
        case SIGTRAP:  return " (SIGTRAP)"; /* 5 */
#endif
        case SIGABRT:  return " (SIGABRT)"; /* 6 */
#ifdef SIGBUS
        case SIGBUS:   return " (SIGBUS)";  /* 7 */
#endif
        case SIGFPE:   return " (SIGFPE)";  /* 8 */
        case SIGSEGV:  return " (SIGSEGV)"; /* 11 */
        case SIGPIPE:  return " (SIGPIPE)"; /* 13 */
#ifdef SIGEMT
        case SIGEMT:   return " (SIGEMT)";  /* ? */
#endif
#ifdef SIGXCPU
        case SIGXCPU:  return " (SIGXCPU)"; /* 24 */
#endif
#ifdef SIGXFSZ
        case SIGXFSZ:  return " (SIGXFSZ)"; /* 25 */
#endif
#ifdef SIGSYS
        case SIGSYS:   return " (SIGSYS)";  /* 31 */
#endif
    }

    return "";
}
#endif

static void version(void)
{
    printf("zzuf %s\n", PACKAGE_VERSION);
    printf("Copyright (C) 2002-2010 Sam Hocevar <sam@hocevar.net>\n");
    printf("This program is free software. It comes without any warranty, to the extent\n");
    printf("permitted by applicable law. You can redistribute it and/or modify it under\n");
    printf("the terms of the Do What The Fuck You Want To Public License, Version 2, as\n");
    printf("published by Sam Hocevar. See <http://sam.zoy.org/wtfpl/> for more details.\n");
    printf("\n");
    printf("Written by Sam Hocevar. Report bugs to <sam@hocevar.net>.\n");
}

static void usage(void)
{
#if defined HAVE_REGEX_H
    printf("Usage: zzuf [-aAcdimnqSvx] [-s seed|-s start:stop] [-r ratio|-r min:max]\n");
#else
    printf("Usage: zzuf [-aAdimnqSvx] [-s seed|-s start:stop] [-r ratio|-r min:max]\n");
#endif
    printf("              [-f mode] [-D delay] [-j jobs] [-C crashes] [-B bytes] [-a list]\n");
    printf("              [-t seconds]");
#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_CPU
    printf(                          " [-T seconds]");
#endif
#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_MEM
    printf(                                       " [-M mebibytes]");
#endif
    printf(                                                      " [-b ranges] [-p ports]\n");
    printf("              [-P protect] [-R refuse] [-l list]");
#if defined HAVE_REGEX_H
    printf(                                                " [-I include] [-E exclude]");
#endif
    printf("\n");
    printf("              [PROGRAM [--] [ARGS]...]\n");
    printf("       zzuf -h | --help\n");
    printf("       zzuf -V | --version\n");
    printf("Run PROGRAM with optional arguments ARGS and fuzz its input.\n");
    printf("\n");
    printf("Mandatory arguments to long options are mandatory for short options too.\n");
    printf("  -a, --allow <list>        only fuzz network input for IPs in <list>\n");
    printf("          ... !<list>       do not fuzz network input for IPs in <list>\n");
    printf("  -A, --autoinc             increment seed each time a new file is opened\n");
    printf("  -b, --bytes <ranges>      only fuzz bytes at offsets within <ranges>\n");
    printf("  -B, --max-bytes <n>       kill children that output more than <n> bytes\n");
#if defined HAVE_REGEX_H
    printf("  -c, --cmdline             only fuzz files specified in the command line\n");
#endif
    printf("  -C, --max-crashes <n>     stop after <n> children have crashed (default 1)\n");
    printf("  -d, --debug               print debug messages (twice for more verbosity)\n");
    printf("  -D, --delay               delay between forks\n");
#if defined HAVE_REGEX_H
    printf("  -E, --exclude <regex>     do not fuzz files matching <regex>\n");
#endif
    printf("  -f, --fuzzing <mode>      use fuzzing mode <mode> ([xor] set unset)\n");
    printf("  -i, --stdin               fuzz standard input\n");
#if defined HAVE_REGEX_H
    printf("  -I, --include <regex>     only fuzz files matching <regex>\n");
#endif
    printf("  -j, --jobs <n>            number of simultaneous jobs (default 1)\n");
    printf("  -l, --list <list>         only fuzz Nth descriptor with N in <list>\n");
    printf("  -m, --md5                 compute the output's MD5 hash\n");
#if defined HAVE_SETRLIMIT && defined ZZUF_RLIMIT_MEM
    printf("  -M, --max-memory <n>      maximum child virtual memory in MiB (default %u)\n", DEFAULT_MEM);
#endif
    printf("  -n, --network             fuzz network input\n");
    printf("  -p, --ports <list>        only fuzz network destination ports in <list>\n");
    printf("  -P, --protect <list>      protect bytes and characters in <list>\n");
    printf("  -q, --quiet               do not print children's messages\n");
    printf("  -r, --ratio <ratio>       bit fuzzing ratio (default %g)\n", DEFAULT_RATIO);
    printf("          ... <start:stop>  specify a ratio range\n");
    printf("  -R, --refuse <list>       refuse bytes and characters in <list>\n");
    printf("  -s, --seed <seed>         random seed (default %i)\n", DEFAULT_SEED);
    printf("         ... <start:stop>   specify a seed range\n");
    printf("  -S, --signal              prevent children from diverting crashing signals\n");
    printf("  -t, --max-time <n>        stop spawning children after <n> seconds\n");
    printf("  -T, --max-cputime <n>     kill children that use more than <n> CPU seconds\n");
    printf("  -U, --max-usertime <n>    kill children that run for more than <n> seconds\n");
    printf("  -v, --verbose             print information during the run\n");
    printf("  -x, --check-exit          report processes that exit with a non-zero status\n");
    printf("  -h, --help                display this help and exit\n");
    printf("  -V, --version             output version information and exit\n");
    printf("\n");
    printf("Written by Sam Hocevar. Report bugs to <sam@hocevar.net>.\n");
}

