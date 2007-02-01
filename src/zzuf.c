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
#if defined HAVE_GETOPT_H
#   include <getopt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#if defined HAVE_REGEX_H
#   include <regex.h>
#endif
#if defined HAVE_WINDOWS_H
#   include <windows.h>
#endif
#if defined HAVE_WINSOCK2_H
#   include <winsock2.h>
#endif
#if defined HAVE_IO_H
#   include <io.h>
#endif
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#if defined HAVE_SYS_WAIT_H
#   include <sys/wait.h>
#endif
#if defined HAVE_SYS_RESOURCE_H
#   include <sys/resource.h>
#endif

#include "libzzuf.h"
#include "opts.h"
#include "random.h"
#include "fd.h"
#include "fuzz.h"
#include "md5.h"
#include "timer.h"

#if !defined SIGKILL
#   define SIGKILL 9
#endif

/* We use file descriptor 17 as the debug channel */
#define DEBUG_FILENO 17
#define DEBUG_FILENO_STR "17"

static void loop_stdin(struct opts *);
static int run_process(char const *, char *[]);

static void spawn_children(struct opts *);
static void clean_children(struct opts *);
static void read_children(struct opts *);

#if !defined HAVE_SETENV
static void setenv(char const *, char const *, int);
#endif
#if defined HAVE_WAITPID
static char const *sig2str(int);
#endif
#if defined HAVE_WINDOWS_H
static int dll_inject(void *, void *);
static void *get_entry(char const *);
#endif
static void finfo(FILE *, struct opts *, uint32_t);
#if defined HAVE_REGEX_H
static char *merge_regex(char *, char *);
static char *merge_file(char *, char *);
#endif
static void version(void);
#if defined HAVE_GETOPT_H
static void usage(void);
#endif

#if defined HAVE_WINDOWS_H
static inline void addcpy(void *buf, void *x)
{
    memcpy(buf, &x, 4);
}
#endif

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
    int i;

    _zz_opts_init(opts);

#if defined HAVE_GETOPT_H
    for(;;)
    {
#   if defined HAVE_REGEX_H
#       define OPTSTR "Ab:B:cC:dD:E:f:F:iI:mM:nP:qr:R:s:ST:vxhV"
#   else
#       define OPTSTR "Ab:B:C:dD:f:F:imM:nP:qr:R:s:ST:vxhV"
#   endif
#   if defined HAVE_GETOPT_LONG
#       define MOREINFO "Try `%s --help' for more information.\n"
        int option_index = 0;
        static struct option long_options[] =
        {
            /* Long option, needs arg, flag, short option */
            { "autoinc",     0, NULL, 'A' },
            { "bytes",       1, NULL, 'b' },
            { "max-bytes",   1, NULL, 'B' },
#if defined HAVE_REGEX_H
            { "cmdline",     0, NULL, 'c' },
#endif
            { "max-crashes", 1, NULL, 'C' },
            { "debug",       0, NULL, 'd' },
            { "delay",       1, NULL, 'D' },
#if defined HAVE_REGEX_H
            { "exclude",     1, NULL, 'E' },
#endif
            { "fuzzing",     1, NULL, 'f' },
            { "max-forks",   1, NULL, 'F' },
            { "stdin",       0, NULL, 'i' },
#if defined HAVE_REGEX_H
            { "include",     1, NULL, 'I' },
#endif
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
            { "verbose",     0, NULL, 'v' },
            { "check-exit",  0, NULL, 'x' },
            { "help",        0, NULL, 'h' },
            { "version",     0, NULL, 'V' },
            { NULL,          0, NULL,  0  }
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
        case 'b': /* --bytes */
            opts->bytes = optarg;
            break;
        case 'B': /* --max-bytes */
            opts->maxbytes = atoi(optarg);
            break;
#if defined HAVE_REGEX_H
        case 'c': /* --cmdline */
            cmdline = 1;
            break;
#endif
        case 'C': /* --max-crashes */
            opts->maxcrashes = atoi(optarg);
            if(opts->maxcrashes <= 0)
                opts->maxcrashes = 0;
            break;
        case 'd': /* --debug */
            setenv("ZZUF_DEBUG", DEBUG_FILENO_STR, 1);
            break;
        case 'D': /* --delay */
            opts->delay = (int64_t)(atof(optarg) * 1000000.0);
            break;
#if defined HAVE_REGEX_H
        case 'E': /* --exclude */
            exclude = merge_regex(exclude, optarg);
            if(!exclude)
            {
                printf("%s: invalid regex -- `%s'\n", argv[0], optarg);
                _zz_opts_fini(opts);
                return EXIT_FAILURE;
            }
            break;
#endif
        case 'f': /* --fuzzing */
            opts->fuzzing = optarg;
            break;
        case 'F': /* --max-forks */
            opts->maxchild = atoi(optarg) > 1 ? atoi(optarg) : 1;
            break;
        case 'i': /* --stdin */
            setenv("ZZUF_STDIN", "1", 1);
            break;
#if defined HAVE_REGEX_H
        case 'I': /* --include */
            include = merge_regex(include, optarg);
            if(!include)
            {
                printf("%s: invalid regex -- `%s'\n", argv[0], optarg);
                _zz_opts_fini(opts);
                return EXIT_FAILURE;
            }
            break;
#endif
        case 'm': /* --md5 */
            opts->md5 = 1;
            break;
#if defined HAVE_SETRLIMIT
        case 'M': /* --max-memory */
            setenv("ZZUF_MEMORY", "1", 1);
            opts->maxmem = atoi(optarg);
            break;
#endif
        case 'n': /* --network */
            setenv("ZZUF_NETWORK", "1", 1);
            break;
        case 'P': /* --protect */
            opts->protect = optarg;
            break;
        case 'q': /* --quiet */
            opts->quiet = 1;
            break;
        case 'r': /* --ratio */
            tmp = strchr(optarg, ':');
            opts->minratio = atof(optarg);
            opts->maxratio = tmp ? atof(tmp + 1) : opts->minratio;
            break;
        case 'R': /* --refuse */
            opts->refuse = optarg;
            break;
        case 's': /* --seed */
            tmp = strchr(optarg, ':');
            opts->seed = atol(optarg);
            opts->endseed = tmp ? (uint32_t)atoi(tmp + 1) : opts->seed + 1;
            break;
        case 'S': /* --signal */
            setenv("ZZUF_SIGNAL", "1", 1);
            break;
        case 'T': /* --max-time */
            opts->maxtime = (int64_t)(atof(optarg) * 1000000.0);
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
            printf("%s: invalid option -- %c\n", argv[0], c);
            printf(MOREINFO, argv[0]);
            _zz_opts_fini(opts);
            return EXIT_FAILURE;
        }
    }
#else
#   define MOREINFO "Usage: %s message...\n"
    int optind = 1;
#endif

    _zz_setratio(opts->minratio, opts->maxratio);
    _zz_setseed(opts->seed);

    /* If asked to read from the standard input */
    if(optind >= argc)
    {
        if(opts->endseed != opts->seed + 1)
        {
            printf("%s: seed ranges are incompatible with stdin fuzzing\n",
                   argv[0]);
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
#endif

    if(opts->fuzzing)
        setenv("ZZUF_FUZZING", opts->fuzzing, 1);
    if(opts->bytes)
        setenv("ZZUF_BYTES", opts->bytes, 1);
    if(opts->protect)
        setenv("ZZUF_PROTECT", opts->protect, 1);
    if(opts->refuse)
        setenv("ZZUF_REFUSE", opts->refuse, 1);

    /* Allocate memory for children handling */
    opts->child = malloc(opts->maxchild * sizeof(struct child));
    for(i = 0; i < opts->maxchild; i++)
        opts->child[i].status = STATUS_FREE;
    opts->nchild = 0;

    /* Create new argv */
    opts->oldargv = argv;
    opts->newargv = malloc((argc - optind + 1) * sizeof(char *));
    memcpy(opts->newargv, argv + optind, (argc - optind) * sizeof(char *));
    opts->newargv[argc - optind] = (char *)NULL;

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
            break;
    }

    /* Clean up */
    _zz_opts_fini(opts);

    return opts->crashes ? EXIT_FAILURE : EXIT_SUCCESS;    
}

static void loop_stdin(struct opts *opts)
{
    uint8_t md5sum[16];
    struct md5 *ctx = NULL;

    if(opts->md5)
        ctx = _zz_md5_init();

    if(opts->fuzzing)
        _zz_fuzzing(opts->fuzzing);
    if(opts->bytes)
        _zz_bytes(opts->bytes);
    if(opts->protect)
        _zz_protect(opts->protect);
    if(opts->refuse)
        _zz_refuse(opts->refuse);

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

        if(opts->md5)
            _zz_md5_add(ctx, buf, ret);
        else while(ret)
        {
            if((nw = write(1, buf + off, (size_t)ret)) < 0)
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
    static int const files[] = { DEBUG_FILENO, STDERR_FILENO, STDOUT_FILENO };
    char buf[64];
    int fd[3][2];
    int64_t now = _zz_time();
    pid_t pid;
    int i, j;

    if(opts->nchild == opts->maxchild)
        return; /* no slot */

    if(opts->seed == opts->endseed)
        return; /* job finished */

    if(opts->maxcrashes && opts->crashes >= opts->maxcrashes)
        return; /* all jobs crashed */

    if(opts->delay > 0 && opts->lastlaunch + opts->delay > now)
        return; /* too early */

    /* Find the empty slot */
    for(i = 0; i < opts->maxchild; i++)
        if(opts->child[i].status == STATUS_FREE)
            break;

    /* Prepare communication pipe */
    for(j = 0; j < 3; j++)
    {
        int ret;
#if defined HAVE_PIPE
        ret = pipe(fd[j]);
#elif defined HAVE__PIPE
        ret = _pipe(fd[j], 256, _O_BINARY);
#endif
        if(ret < 0)
        {
            perror("pipe");
            return;
        }
    }

#if defined HAVE_FORK
    /* Fork and launch child */
    pid = fork();
    if(pid < -1)
    {
        perror("fork");
        return;
    }
#else
    pid = 0;
#endif

    if(pid == 0)
    {
#if defined HAVE_SETRLIMIT
        if(opts->maxmem >= 0)
        {
            struct rlimit rlim;
            rlim.rlim_cur = opts->maxmem * 1000000;
            rlim.rlim_max = opts->maxmem * 1000000;
            setrlimit(RLIMIT_AS, &rlim);
        }
#endif

#if defined HAVE_FORK
        /* We loop in reverse order so that files[0] is done last,
         * just in case one of the other dup2()ed fds had the value */
        for(j = 3; j--; )
        {
            close(fd[j][0]);
            if(fd[j][1] != files[j])
            {
                dup2(fd[j][1], files[j]);
                close(fd[j][1]);
            }
        }
#endif

        /* Set environment variables */
        sprintf(buf, "%i", opts->seed);
        setenv("ZZUF_SEED", buf, 1);
        sprintf(buf, "%g", opts->minratio);
        setenv("ZZUF_MINRATIO", buf, 1);
        sprintf(buf, "%g", opts->maxratio);
        setenv("ZZUF_MAXRATIO", buf, 1);

#if defined HAVE_FORK
        if(run_process(opts->oldargv[0], opts->newargv) < 0)
            exit(EXIT_FAILURE);
        exit(EXIT_SUCCESS);
#else
        if(run_process(opts->oldargv[0], opts->newargv) < 0)
            return;
#endif
    }

    /* We’re the parent, acknowledge spawn */
    opts->child[i].date = now;
    opts->child[i].pid = pid;
    for(j = 0; j < 3; j++)
    {
        close(fd[j][1]);
        opts->child[i].fd[j] = fd[j][0];
    }
    opts->child[i].bytes = 0;
    opts->child[i].seed = opts->seed;
    opts->child[i].ratio = _zz_getratio();
    opts->child[i].status = STATUS_RUNNING;
    if(opts->md5)
        opts->child[i].ctx = _zz_md5_init();

    if(opts->verbose)
    {
        finfo(stderr, opts, opts->child[i].seed);
        fprintf(stderr, "launched %s\n", opts->newargv[0]);
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
            && opts->maxtime >= 0
            && now > opts->child[i].date + opts->maxtime)
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
            finfo(stderr, opts, opts->child[i].seed);
            fprintf(stderr, "signal %i%s%s\n",
                    WTERMSIG(status), sig2str(WTERMSIG(status)),
                      (WTERMSIG(status) == SIGKILL && opts->maxmem >= 0) ?
                      " (memory exceeded?)" : "");
            opts->crashes++;
        }
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
static char const *sig2str(int signum)
{
    switch(signum)
    {
        case SIGABRT:  return " (SIGABRT)";
        case SIGFPE:   return " (SIGFPE)";
        case SIGILL:   return " (SIGILL)";
#ifdef SIGQUIT
        case SIGQUIT:  return " (SIGQUIT)";
#endif
        case SIGSEGV:  return " (SIGSEGV)";
#ifdef SIGTRAP
        case SIGTRAP:  return " (SIGTRAP)";
#endif
#ifdef SIGSYS
        case SIGSYS:   return " (SIGSYS)";
#endif
#ifdef SIGEMT
        case SIGEMT:   return " (SIGEMT)";
#endif
#ifdef SIGBUS
        case SIGBUS:   return " (SIGBUS)";
#endif
#ifdef SIGXCPU
        case SIGXCPU:  return " (SIGXCPU)";
#endif
#ifdef SIGXFSZ
        case SIGXFSZ:  return " (SIGXFSZ)";
#endif
    }

    return "";
}
#endif

static int run_process(char const *zzuf_exe, char *argv[])
{
#if defined HAVE_FORK
    char *libpath, *tmp;
    int ret, len = strlen(zzuf_exe);
#   if defined __APPLE__
#       define FILENAME "libzzuf.dylib"
#       define EXTRAINFO ""
#       define PRELOAD "DYLD_INSERT_LIBRARIES"
    setenv("DYLD_FORCE_FLAT_NAMESPACE", "1", 1);
#   elif defined __osf__
#       define FILENAME "libzzuf.so"
#       define EXTRAINFO ":DEFAULT"
#       define PRELOAD "_RLD_LIST"
#   else
#       define FILENAME "libzzuf.so"
#       define EXTRAINFO ""
#       define PRELOAD "LD_PRELOAD"
#   endif

    libpath = malloc(len + strlen("/.libs/" FILENAME EXTRAINFO) + 1);
    strcpy(libpath, zzuf_exe);

    tmp = strrchr(libpath, '/');
    strcpy(tmp ? tmp + 1 : libpath, ".libs/" FILENAME);
    ret = access(libpath, R_OK);

    strcpy(tmp ? tmp + 1 : libpath, ".libs/" FILENAME EXTRAINFO);
    if(ret == 0)
        setenv(PRELOAD, libpath, 1);
    else
        setenv(PRELOAD, LIBDIR "/" FILENAME EXTRAINFO, 1);
    free(libpath);

    if(execvp(argv[0], argv))
    {
        perror(argv[0]);
        return -1;
    }

    return 0;
#elif HAVE_WINDOWS_H
    PROCESS_INFORMATION pinfo;
    STARTUPINFO sinfo;
    void *epaddr;
    int ret;

    /* Get entry point */
    epaddr = get_entry(argv[0]);
    if(!epaddr)
        return -1;
    
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    ret = CreateProcess(NULL, argv[0], NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &sinfo, &pinfo);
    if(!ret)
        return -1;

    /* Insert the replacement code */
    ret = dll_inject(pinfo.hProcess, epaddr);
    if(ret < 0)
    {
        TerminateProcess(pinfo.hProcess, -1);
        return -1;
    }

    ret = ResumeThread(pinfo.hThread);
    if(ret < 0)
    {
        TerminateProcess(pinfo.hProcess, -1);
        return -1;
    }

    return 0;
#else
    return -1;
#endif
}

#if defined HAVE_WINDOWS_H
static int dll_inject(void *process, void *epaddr)
{
    uint8_t old_ep[7];
    uint8_t new_ep[] = "\xb8<01>\xff\xe0";
    uint8_t loader[] = "libzzuf.dll\0<0000c>\xb8<14>\x50\xb8<1a>\xff\xd0"
                       "\xb8\0\0\0\0\x50\xb8\x07\x00\x00\x00\x50\xb8<2d>"
                       "\x50\xb8<33>\x50\xb8<39>\xff\xd0\x50\xb8<41>\xff"
                       "\xd0\xb8<48>\xff\xe0";
    void *lib;
    uint8_t *loaderaddr;
    DWORD tmp;

    /* Save the old entry-point code */
    ReadProcessMemory(process, epaddr, old_ep, 7, &tmp);
    if(tmp != 7)
        return -1;

    loaderaddr = VirtualAllocEx(process, NULL, 78, MEM_COMMIT,
                                PAGE_EXECUTE_READWRITE);
    if(!loaderaddr)
        return -1;

    addcpy(new_ep + 0x01, loaderaddr + 0x0c + 7);
    WriteProcessMemory(process, epaddr, new_ep, 7, &tmp);
    if(tmp != 7)
        return -1;

    lib = LoadLibrary("kernel32.dll");
    if(!lib)
        return -1;

    memcpy(loader + 0x0c, old_ep, 7);
    addcpy(loader + 0x14, loaderaddr + 0x00); /* offset for dll string */
    addcpy(loader + 0x1a, GetProcAddress(lib, "LoadLibraryA"));
    addcpy(loader + 0x2d, loaderaddr + 0x0c);
    addcpy(loader + 0x33, epaddr);
    addcpy(loader + 0x39, GetProcAddress(lib, "GetCurrentProcess"));
    addcpy(loader + 0x41, GetProcAddress(lib, "WriteProcessMemory"));
    addcpy(loader + 0x48, epaddr);
    FreeLibrary(lib);

    WriteProcessMemory(process, loaderaddr, loader, 78, &tmp);
    if(tmp != 78)
        return -1;

    return 0;
}

static void *get_entry(char const *name)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    void *file, *map, *base;

    file = CreateFile(name, GENERIC_READ, FILE_SHARE_READ,
                      NULL, OPEN_EXISTING, 0, NULL);
    if(file == INVALID_HANDLE_VALUE)
        return NULL;

    map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if(!map)
    {
        CloseHandle(file);
        return NULL;
    }

    base = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if(!base)
    {
        CloseHandle(map);
        CloseHandle(file);
        return NULL;
    }

    /* Sanity checks */
    dos = (PIMAGE_DOS_HEADER)base;
    nt = (PIMAGE_NT_HEADERS)((char *)base + dos->e_lfanew);
    if(dos->e_magic != IMAGE_DOS_SIGNATURE
      || nt->Signature != IMAGE_NT_SIGNATURE
      || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
      || nt->OptionalHeader.Magic != 0x10b /* IMAGE_NT_OPTIONAL_HDR32_MAGIC */)
    {
        UnmapViewOfFile(base);
        CloseHandle(map);
        CloseHandle(file);
        return NULL;
    }

    return (char *)nt->OptionalHeader.ImageBase +
                           nt->OptionalHeader.AddressOfEntryPoint;
}
#endif

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

#if defined HAVE_GETOPT_H
static void usage(void)
{
#if defined HAVE_REGEX_H
    printf("Usage: zzuf [-AcdimnqSvx] [-s seed|-s start:stop] [-r ratio|-r min:max]\n");
#else
    printf("Usage: zzuf [-AdimnqSvx] [-s seed|-s start:stop] [-r ratio|-r min:max]\n");
#endif
    printf("              [-f fuzzing] [-D delay] [-F forks] [-C crashes] [-B bytes]\n");
    printf("              [-T seconds] [-M bytes] [-b ranges] [-P protect] [-R refuse]\n");
#if defined HAVE_REGEX_H
    printf("              [-I include] [-E exclude] [PROGRAM [--] [ARGS]...]\n");
#else
    printf("              [PROGRAM [--] [ARGS]...]\n");
#endif
#   if defined HAVE_GETOPT_LONG
    printf("       zzuf -h | --help\n");
    printf("       zzuf -V | --version\n");
#   else
    printf("       zzuf -h\n");
    printf("       zzuf -V\n");
#   endif
    printf("Run PROGRAM with optional arguments ARGS and fuzz its input.\n");
    printf("\n");
    printf("Mandatory arguments to long options are mandatory for short options too.\n");
#   if defined HAVE_GETOPT_LONG
    printf("  -A, --autoinc             increment seed each time a new file is opened\n");
    printf("  -b, --bytes <ranges>      only fuzz bytes at offsets within <ranges>\n");
    printf("  -B, --max-bytes <n>       kill children that output more than <n> bytes\n");
#if defined HAVE_REGEX_H
    printf("  -c, --cmdline             only fuzz files specified in the command line\n");
#endif
    printf("  -C, --max-crashes <n>     stop after <n> children have crashed (default 1)\n");
    printf("  -d, --debug               print debug messages\n");
    printf("  -D, --delay               delay between forks\n");
#if defined HAVE_REGEX_H
    printf("  -E, --exclude <regex>     do not fuzz files matching <regex>\n");
#endif
    printf("  -f, --fuzzing <mode>      use fuzzing mode <mode> ([xor] set unset)\n");
    printf("  -F, --max-forks <n>       number of concurrent children (default 1)\n");
    printf("  -i, --stdin               fuzz standard input\n");
#if defined HAVE_REGEX_H
    printf("  -I, --include <regex>     only fuzz files matching <regex>\n");
#endif
    printf("  -m, --md5                 compute the output's MD5 hash\n");
#if defined HAVE_SETRLIMIT
    printf("  -M, --max-memory <n>      maximum child virtual memory size in MB\n");
#endif
    printf("  -n, --network             fuzz network input\n");
    printf("  -P, --protect <list>      protect bytes and characters in <list>\n");
    printf("  -q, --quiet               do not print children's messages\n");
    printf("  -r, --ratio <ratio>       bit fuzzing ratio (default %g)\n", DEFAULT_RATIO);
    printf("      --ratio <start:stop>  specify a ratio range\n");
    printf("  -R, --refuse <list>       refuse bytes and characters in <list>\n");
    printf("  -s, --seed <seed>         random seed (default %i)\n", DEFAULT_SEED);
    printf("      --seed <start:stop>   specify a seed range\n");
    printf("  -S, --signal              prevent children from diverting crashing signals\n");
    printf("  -T, --max-time <n>        kill children that run for more than <n> seconds\n");
    printf("  -v, --verbose             print information during the run\n");
    printf("  -x, --check-exit          report processes that exit with a non-zero status\n");
    printf("  -h, --help                display this help and exit\n");
    printf("  -V, --version             output version information and exit\n");
#   else
    printf("  -A               increment seed each time a new file is opened\n");
    printf("  -b <ranges>      only fuzz bytes at offsets within <ranges>\n");
    printf("  -B <n>           kill children that output more than <n> bytes\n");
#if defined HAVE_REGEX_H
    printf("  -c               only fuzz files specified in the command line\n");
#endif
    printf("  -C <n>           stop after <n> children have crashed (default 1)\n");
    printf("  -d               print debug messages\n");
    printf("  -D               delay between forks\n");
#if defined HAVE_REGEX_H
    printf("  -E <regex>       do not fuzz files matching <regex>\n");
#endif
    printf("  -f <mode>        use fuzzing mode <mode>\n");
    printf("  -F <n>           number of concurrent forks (default 1)\n");
    printf("  -i               fuzz standard input\n");
#if defined HAVE_REGEX_H
    printf("  -I <regex>       only fuzz files matching <regex>\n");
#endif
    printf("  -m               compute the output's MD5 hash\n");
#if defined HAVE_SETRLIMIT
    printf("  -M               maximum child virtual memory size in MB\n");
#endif
    printf("  -n               fuzz network input\n");
    printf("  -P <list>        protect bytes and characters in <list>\n");
    printf("  -q               do not print the fuzzed application's messages\n");
    printf("  -r <ratio>       bit fuzzing ratio (default %g)\n", DEFAULT_RATIO);
    printf("     <start:stop>  specify a ratio range\n");
    printf("  -R <list>        refuse bytes and characters in <list>\n");
    printf("  -s <seed>        random seed (default %i)\n", DEFAULT_SEED);
    printf("     <start:stop>  specify a seed range\n");
    printf("  -S               prevent children from diverting crashing signals\n");
    printf("  -T <n>           kill children that run for more than <n> seconds\n");
    printf("  -v               print information during the run\n");
    printf("  -x               report processes that exit with a non-zero status\n");
    printf("  -h               display this help and exit\n");
    printf("  -V               output version information and exit\n");
#   endif
    printf("\n");
    printf("Written by Sam Hocevar. Report bugs to <sam@zoy.org>.\n");
}
#endif

