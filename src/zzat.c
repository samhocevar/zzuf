/*
 *  zzat - various cat reimplementations for testing purposes
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
 * TODO: fsetpos64, fgetln
 */

#include "config.h"

/* Needed for lseek64() */
#define _LARGEFILE64_SOURCE
/* Needed for O_RDONLY on HP-UX */
#define _INCLUDE_POSIX_SOURCE
/* Needed for fgets_unlocked() */
#define _GNU_SOURCE
/* Needed for getc_unlocked() on OpenSolaris */
#define __EXTENSIONS__

#if defined _MSC_VER
#   include <io.h>
typedef int ssize_t;
#   define snprintf sprintf_s
#   define close _close
#endif

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if defined HAVE_UNISTD_H
#   include <unistd.h>
#endif
#if defined HAVE_SYS_MMAN_H
#   include <sys/mman.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "util/getopt.h"

static int run(char const *sequence, char const *file);
static void output(char const *buf, size_t len);

static void syntax(void);
static void version(void);
static void usage(void);

/* Global parameters */
static int g_debug = 0;
static int g_repeat = 1;
static char g_escape_tabs = 0;
static char g_escape_ends = 0;
static char g_escape_other = 0;
static char g_number_lines = 0;
static char g_number_nonblank = 0;
static char g_squeeze_lines = 0;

/* Global output state */
static int g_ncrs = 0;
static int g_line = 1;
static char g_newline = 1;

/*
 * Main program.
 */

int main(int argc, char *argv[])
{
    char const *sequence = "repeat(-1, fread(1,32768), feof(1))";

    for (;;)
    {
#define OPTSTR "+AbdeEnr:stTvx:lhV"
#define MOREINFO "Try `%s --help' for more information.\n"
        int option_index = 0;
        static zzuf_option_t long_options[] =
        {
            { "show-all",         0, NULL, 'A' },
            { "number-nonblank",  0, NULL, 'b' },
            { "debug",            0, NULL, 'd' },
            { "show-ends",        0, NULL, 'E' },
            { "number",           0, NULL, 'n' },
            { "repeat",           1, NULL, 'r' },
            { "squeeze-blank",    0, NULL, 's' },
            { "show-tabs",        0, NULL, 'T' },
            { "show-nonprinting", 0, NULL, 'v' },
            { "execute",          1, NULL, 'x' },
            { "list",             0, NULL, 'l' },
            { "help",             0, NULL, 'h' },
            { "version",          0, NULL, 'V' },
            { NULL,               0, NULL,  0  }
        };
        int c = zz_getopt(argc, argv, OPTSTR, long_options, &option_index);

        if (c == -1)
            break;

        switch (c)
        {
        case 'A': /* --show-all */
            g_escape_tabs = g_escape_ends = g_escape_other = 1;
            break;
        case 'b': /* --number-nonblank */
            g_number_nonblank = 1;
            break;
        case 'd': /* --debug */
            g_debug = 1;
            break;
        case 'e':
            g_escape_ends = g_escape_other = 1;
            break;
        case 'E': /* --show-ends */
            g_escape_ends = 1;
            break;
        case 'n': /* --number */
            g_number_lines = 1;
            break;
        case 'r': /* --repeat */
            g_repeat = atoi(zz_optarg);
            break;
        case 's': /* --squeeze-blank */
            g_squeeze_lines = 1;
            break;
        case 't':
            g_escape_tabs = g_escape_other = 1;
            break;
        case 'T': /* --show-tabs */
            g_escape_tabs = 1;
            break;
        case 'v': /* --show-nonprinting */
            g_escape_tabs = 1;
            break;
        case 'x': /* --execute */
            if (zz_optarg[0] == '=')
                zz_optarg++;
            sequence = zz_optarg;
            break;
        case 'l': /* --list */
            syntax();
            return 0;
        case 'h': /* --help */
            usage();
            return 0;
        case 'V': /* --version */
            version();
            return 0;
        default:
            fprintf(stderr, "%s: invalid option -- %c\n", argv[0], c);
            printf(MOREINFO, argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (zz_optind >= argc)
    {
        fprintf(stderr, "E: zzat: too few arguments\n");
        return EXIT_FAILURE;
    }

    while (g_repeat-- > 0)
        for (int i = zz_optind; i < argc; ++i)
        {
            int ret = run(sequence, argv[i]);
            if (ret)
                return ret;
        }

    return EXIT_SUCCESS;
}

/*
 * File output method.
 */

static void output(char const *buf, size_t len)
{
    /* If no special features are requested, output directly */
    if (!(g_escape_tabs || g_escape_ends || g_escape_other
           || g_number_lines || g_number_nonblank || g_squeeze_lines))
    {
        fwrite(buf, len, 1, stdout);
        return;
    }

    /* If any special feature is active, go through every possibility */
    for (size_t i = 0; i < len; ++i)
    {
        int ch = (unsigned int)(unsigned char)buf[i];

        if (g_squeeze_lines)
        {
            if (ch == '\n')
            {
                if (++g_ncrs > 2)
                    continue;
            }
            else
                g_ncrs = 0;
        }

        if (g_number_lines || g_number_nonblank)
        {
            if (g_newline)
            {
                g_newline = 0;
                if (!g_number_nonblank || ch != '\n')
                    fprintf(stdout, "% 6i\t", g_line++);
            }

            if (ch == '\n')
                g_newline = 1;
        }

        if (g_escape_other && ch >= 0x80)
        {
            if (ch - 0x80 < 0x20 || ch - 0x80 == 0x7f)
                fprintf(stdout, "M-^%c", (ch - 0x80) ^ 0x40);
            else
                fprintf(stdout, "M-%c", ch - 0x80);
        }
        else if (g_escape_tabs && ch == '\t')
            fprintf(stdout, "^I");
        else if (g_escape_ends && ch == '\n')
            puts("$");
        else if (g_escape_other && (ch < 0x20 || ch == 0x7f))
            fprintf(stdout, "^%c", ch ^ 0x40);
        else
            putchar(ch);
    }
}

/*
 * Command intepreter
 */

#define MY_FOPEN(cmd) \
    do { \
        cmd; \
        if (!f) \
        { \
            fprintf(stderr, "E: zzat: cannot open `%s'\n", file); \
            return EXIT_FAILURE; \
        } \
        retoff = 0; \
        sequence = strchr(sequence, ')') + 1; \
    } while (0)

#define MY_FCLOSE(cmd) \
    do { \
        cmd; \
        f = NULL; \
        sequence = strchr(sequence, ')') + 1; \
    } while (0)

#define ROUNDUP(size) (((size) + 0x1000) & ~0xfff)

#define MERGE(address, cnt, off) \
    do { \
        size_t _cnt = cnt, _off = off; \
        if (_cnt && retoff + _cnt > retlen) \
        { \
            retlen = retoff + _cnt; \
            if (!retbuf || ROUNDUP(retlen) != ROUNDUP(retlen - _cnt)) \
            { \
                if (g_debug) \
                    fprintf(stderr, "D: zzat: allocating %i bytes for %i\n", \
                            (int)ROUNDUP(retlen), (int)retlen); \
                retbuf = realloc(retbuf, ROUNDUP(retlen)); \
            } \
        } \
        if (_cnt > 0) \
        { \
            if (g_debug) \
                fprintf(stderr, "D: zzat: writing %i byte%s at offset %i\n", \
                        (int)_cnt, _cnt == 1 ? "" : "s", (int)retoff); \
            memcpy(retbuf + retoff, address, _cnt); \
        } \
        retoff += _off; \
    } while (0)

#define MY_FREAD(cmd, buf, cnt) MY_FCALL(cmd, buf, cnt, cnt)
#define MY_FSEEK(cmd, off) MY_FCALL(cmd, /* unused */ "", 0, off)

#define MY_FCALL(cmd, buf, cnt, off) \
    do { \
        if (!f) \
        { \
            f = fopen(file, "r"); \
            if (!f) \
            { \
                fprintf(stderr, "E: zzat: cannot open `%s'\n", file); \
                return EXIT_FAILURE; \
            } \
        } \
        /* fprintf(stderr, "debug: %s\n", #cmd); */ \
        cmd; \
        MERGE(buf, cnt, off); \
        sequence = strchr(sequence, ')') + 1; \
    } while (0)

#define MY_FEOF() \
    do { \
        if (!f) \
        { \
            f = fopen(file, "r"); \
            if (!f) \
            { \
                fprintf(stderr, "E: zzat: cannot open `%s'\n", file); \
                return EXIT_FAILURE; \
            } \
        } \
        if (feof(f)) \
            feofs++; \
        if (feofs >= l1) \
            finish = 1; \
        sequence = strchr(sequence, ')') + 1; \
    } while (0)

/*
 * Command parser. We rewrite fmt by replacing the last character with
 * '%c' and check that the sscanf() call returns the expected number of
 * matches plus one (for the last character). We use this macro trick to
 * avoid using vsscanf() which does not exist on all platforms.
 */

struct parser
{
    char tmpfmt[1024], ch, lastch;
};

static int make_fmt(struct parser *p, char const *fmt, int *nitems)
{
    int ret = 0;

    size_t len = strlen(fmt);
    p->lastch = fmt[len - 1];

    memcpy(p->tmpfmt, fmt, len - 1);
    p->tmpfmt[len - 1] = '%';
    p->tmpfmt[len] = 'c';
    p->tmpfmt[len + 1] = '\0';

    for (char const *tmp = p->tmpfmt; *tmp; ++tmp)
        if (*tmp == '%')
            ++tmp, ++ret;

    *nitems = ret;

    return 1;
}

#define PARSECMD(fmt, ...) \
    (make_fmt(&parser, fmt, &nitems) \
         && nitems == sscanf(sequence, parser.tmpfmt, \
                             ##__VA_ARGS__, &parser.ch) \
         && parser.ch == parser.lastch)

/*
 * File reader. We parse a command line and perform all the operations it
 * contains on the specified file.
 */

static int run(char const *sequence, char const *file)
{
    struct { char const *p; int count; } loops[128];
    char *retbuf = NULL, *tmp;
    FILE *f = NULL;
    size_t retlen = 0, retoff = 0;
    int nitems, nloops = 0, fd = -1, feofs = 0, finish = 0;

    /* Initialise per-file state */
    /* TODO */

    /* Allocate 32MB for our temporary buffer. Any larger value will crash. */
    tmp = malloc(32 * 1024 * 1024);

    while (*sequence)
    {
        struct parser parser;
        long int l1, l2;
        char *s, *lineptr = NULL;
        size_t k;
        ssize_t l;
        int n;
        char ch;

        (void)k;

        /* Ignore punctuation */
        if (strchr(" \t,;\r\n", *sequence))
            ++sequence;

        /* Loop handling */
        else if (PARSECMD("repeat ( %li ,", &l1))
        {
            sequence = strchr(sequence, ',') + 1;
            loops[nloops].p = sequence;
            loops[nloops].count = l1;
            ++nloops;
        }
        else if (PARSECMD(")"))
        {
            if (nloops == 0)
            {
                fprintf(stderr, "E: zzat: ')' outside a loop\n");
                free(tmp);
                return EXIT_FAILURE;
            }
            if (loops[nloops - 1].count == 1 || finish)
            {
                nloops--;
                sequence = strchr(sequence, ')') + 1;
            }
            else
            {
                loops[nloops - 1].count--;
                sequence = loops[nloops - 1].p;
            }

            finish = 0;
        }

        /* FILE * opening functions */
        else if (PARSECMD("fopen ( )"))
            MY_FOPEN(f = fopen(file, "r"));
#if defined HAVE_FOPEN64
        else if (PARSECMD("fopen64 ( )"))
            MY_FOPEN(f = fopen64(file, "r"));
#endif
#if defined HAVE___FOPEN64
        else if (PARSECMD("__fopen64 ( )"))
            MY_FOPEN(f = __fopen64(file, "r"));
#endif
        else if (PARSECMD("freopen ( )"))
            MY_FOPEN(f = freopen(file, "r", f));
#if defined HAVE_FREOPEN64
        else if (PARSECMD("freopen64 ( )"))
            MY_FOPEN(f = freopen64(file, "r", f));
#endif
#if defined HAVE___FREOPEN64
        else if (PARSECMD("__freopen64 ( )"))
            MY_FOPEN(f = __freopen64(file, "r", f));
#endif

        /* FILE * EOF detection */
        else if (PARSECMD("feof ( %li )", &l1))
            MY_FEOF();

        /* FILE * closing functions */
        else if (PARSECMD("fclose ( )"))
            MY_FCLOSE(fclose(f));

        /* FILE * reading functions */
        else if (PARSECMD("fread ( %li , %li )", &l1, &l2))
            MY_FREAD(l = (ssize_t)fread(tmp, l1, l2, f), tmp, l > 0 ? l * l1 : 0);
        else if (PARSECMD("getc ( )"))
            MY_FREAD(ch = (n = getc(f)), &ch, (n != EOF));
        else if (PARSECMD("fgetc ( )"))
            MY_FREAD(ch = (n = fgetc(f)), &ch, (n != EOF));
        else if (PARSECMD("fgets ( %li )", &l1))
            MY_FREAD(s = fgets(tmp, l1, f), tmp, s ? strlen(tmp) : 0);
#if defined HAVE___FGETS_CHK
        else if (PARSECMD("__fgets_chk ( %li )", &l1))
            MY_FREAD(s = __fgets_chk(tmp, l1, l1, f), tmp, s ? strlen(tmp) : 0);
#endif
#if defined HAVE__IO_GETC
        else if (PARSECMD("_IO_getc ( )"))
            MY_FREAD(ch = (n = _IO_getc(f)), &ch, (n != EOF));
#endif
#if defined HAVE___FREAD_CHK
        else if (PARSECMD("__fread_chk ( %li , %li )", &l1, &l2))
            MY_FREAD(l = __fread_chk(tmp, l1 * l2, l1, l2, f), tmp, l > 0 ? l * l1 : 0);
#endif
#if defined HAVE_FREAD_UNLOCKED
        else if (PARSECMD("fread_unlocked ( %li , %li )", &l1, &l2))
            MY_FREAD(l = fread_unlocked(tmp, l1, l2, f), tmp, l > 0 ? l * l1 : 0);
#endif
#if defined HAVE___FREAD_UNLOCKED_CHK
        else if (PARSECMD("__fread_unlocked_chk ( %li , %li )", &l1, &l2))
            MY_FREAD(l = __fread_unlocked_chk(tmp, l1 * l2, l1, l2, f), tmp, l > 0 ? l * l1 : 0);
#endif
#if defined HAVE_FGETS_UNLOCKED
        else if (PARSECMD("fgets_unlocked ( %li )", &l1))
            MY_FREAD(s = fgets_unlocked(tmp, l1, f), tmp, s ? strlen(tmp) : 0);
#endif
#if defined HAVE___FGETS_UNLOCKED_CHK
        else if (PARSECMD("__fgets_unlocked_chk ( %li )", &l1))
            MY_FREAD(s = __fgets_unlocked_chk(tmp, l1, l1, f), tmp, s ? strlen(tmp) : 0);
#endif
#if defined HAVE_GETC_UNLOCKED
        else if (PARSECMD("getc_unlocked ( )"))
            MY_FREAD(ch = (n = getc_unlocked(f)), &ch, (n != EOF));
#endif
#if defined HAVE_FGETC_UNLOCKED
        else if (PARSECMD("fgetc_unlocked ( )"))
            MY_FREAD(ch = (n = fgetc_unlocked(f)), &ch, (n != EOF));
#endif

        /* FILE * getdelim functions */
#if defined HAVE_GETLINE
        else if (PARSECMD("getline ( )"))
            MY_FREAD(l = getline(&lineptr, &k, f), lineptr, l >= 0 ? l : 0);
#endif
#if defined HAVE_GETDELIM
        else if (PARSECMD("getdelim ( '%c' )", &ch))
            MY_FREAD(l = getdelim(&lineptr, &k, ch, f), lineptr, l >= 0 ? l : 0);
        else if (PARSECMD("getdelim ( %i )", &n))
            MY_FREAD(l = getdelim(&lineptr, &k, n, f), lineptr, l >= 0 ? l : 0);
#endif
#if defined HAVE___GETDELIM
        else if (PARSECMD("__getdelim ( '%c' )", &ch))
            MY_FREAD(l = __getdelim(&lineptr, &k, ch, f), lineptr, l >= 0 ? l : 0);
        else if (PARSECMD("__getdelim ( %i )", &n))
            MY_FREAD(l = __getdelim(&lineptr, &k, n, f), lineptr, l >= 0 ? l : 0);
#endif

        /* FILE * seeking functions */
        else if (PARSECMD("fseek ( %li , SEEK_CUR )", &l1))
            MY_FSEEK(l = fseek(f, l1, SEEK_CUR),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseek ( %li , SEEK_SET )", &l1))
            MY_FSEEK(l = fseek(f, l1, SEEK_SET),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseek ( %li , SEEK_END )", &l1))
            MY_FSEEK(l = fseek(f, l1, SEEK_END),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
#if defined HAVE_FSEEKO
        else if (PARSECMD("fseeko ( %li , SEEK_CUR )", &l1))
            MY_FSEEK(l = fseeko(f, l1, SEEK_CUR),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseeko ( %li , SEEK_SET )", &l1))
            MY_FSEEK(l = fseeko(f, l1, SEEK_SET),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseeko ( %li , SEEK_END )", &l1))
            MY_FSEEK(l = fseeko(f, l1, SEEK_END),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
#endif
#if defined HAVE_FSEEKO64
        else if (PARSECMD("fseeko64 ( %li , SEEK_CUR )", &l1))
            MY_FSEEK(l = fseeko64(f, l1, SEEK_CUR),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseeko64 ( %li , SEEK_SET )", &l1))
            MY_FSEEK(l = fseeko64(f, l1, SEEK_SET),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseeko64 ( %li , SEEK_END )", &l1))
            MY_FSEEK(l = fseeko64(f, l1, SEEK_END),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
#endif
#if defined HAVE___FSEEKO64
        else if (PARSECMD("__fseeko64 ( %li , SEEK_CUR )", &l1))
            MY_FSEEK(l = __fseeko64(f, l1, SEEK_CUR),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("__fseeko64 ( %li , SEEK_SET )", &l1))
            MY_FSEEK(l = __fseeko64(f, l1, SEEK_SET),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("__fseeko64 ( %li , SEEK_END )", &l1))
            MY_FSEEK(l = __fseeko64(f, l1, SEEK_END),
                     ftell(f) >= 0 ? ftell(f) - retoff : 0);
#endif
        else if (PARSECMD("rewind ( )"))
            MY_FSEEK(rewind(f), -(int)retlen);
        else if (PARSECMD("ungetc ( )"))
            MY_FSEEK(if (retoff) ungetc((unsigned char)retbuf[retoff - 1], f),
                     retoff ? -1 : 0);

        /* Unrecognised sequence */
        else
        {
            char buf[16];
            snprintf(buf, 16, strlen(sequence) < 16 ? "%s" : "%.12s...",
                     sequence);
            fprintf(stderr, "E: zzat: syntax error near `%s'\n", buf);
            return EXIT_FAILURE;
        }

        /* Clean up our mess */
        if (lineptr)
            free(lineptr);

        if (finish && !nloops)
            break;
    }

    if (f)
        fclose(f);

    if (fd >= 0)
        close(fd);

    output(retbuf, retlen);
    free(retbuf);
    free(tmp);

    return EXIT_SUCCESS;
}

#if 0
/* Only read() calls */
static int zzat_read(char const *name, unsigned char *data, int64_t len,
                      int64_t chunk)
{
    int i, fd = open(name, O_RDONLY);
    if (fd < 0)
        return EXIT_FAILURE;
    for (i = 0; i < len; i += chunk)
        read(fd, data + i, chunk);
    close(fd);
    return EXIT_SUCCESS;
}

/* Socket seeks and reads */
static int zzat_random_socket(char const *name, unsigned char *data,
                               int64_t len)
{
    int fd = open(name, O_RDONLY);
    if (fd < 0)
        return EXIT_FAILURE;
    for (int i = 0; i < 128; ++i)
    {
        lseek(fd, myrand() % len, SEEK_SET);
        for (int j = 0; j < 4; ++j)
            read(fd, data + lseek(fd, 0, SEEK_CUR), myrand() % 4096);
#ifdef HAVE_LSEEK64
        lseek64(fd, myrand() % len, SEEK_SET);
        for (int j = 0; j < 4; ++j)
            read(fd, data + lseek(fd, 0, SEEK_CUR), myrand() % 4096);
#endif
    }
    close(fd);
    return EXIT_SUCCESS;
}

/* Standard stream seeks and reads */
static int zzat_random_stream(char const *name, unsigned char *data,
                               int64_t len)
{
    FILE *stream = fopen(name, "r");
    if (!stream)
        return EXIT_FAILURE;
    for (int i = 0; i < 128; ++i)
    {
        long int now;
        fseek(stream, myrand() % len, SEEK_SET);
        for (int j = 0; j < 4; ++j)
            fread(data + ftell(stream),
                  myrand() % (len - ftell(stream)), 1, stream);
        fseek(stream, myrand() % len, SEEK_SET);
        now = ftell(stream);
        for (int j = 0; j < 16; ++j)
            data[now + j] = getc(stream);
        now = ftell(stream);
        for (int j = 0; j < 16; ++j)
            data[now + j] = fgetc(stream);
    }
    fclose(stream);
    return EXIT_SUCCESS;
}

#ifdef HAVE_MMAP
/* mmap() followed by random memory reads */
static int zzat_random_mmap(char const *name, unsigned char *data,
                            int64_t len)
{
    int fd = open(name, O_RDONLY);
    if (fd < 0)
        return EXIT_FAILURE;
    for (int i = 0; i < 128; ++i)
    {
        char *map;
        int moff, mlen, pgsz = len + 1;
#ifdef HAVE_GETPAGESIZE
        pgsz = getpagesize();
#endif
        moff = len < pgsz ? 0 : (myrand() % (len / pgsz)) * pgsz;
        mlen = 1 + (myrand() % (len - moff));
        map = mmap(NULL, mlen, PROT_READ, MAP_PRIVATE, fd, moff);
        if (map == MAP_FAILED)
            return EXIT_FAILURE;
        for (int j = 0; j < 128; ++j)
        {
            int x = myrand() % mlen;
            data[moff + x] = map[x];
        }
        munmap(map, mlen);
    }
    close(fd);
    return EXIT_SUCCESS;
}
#endif
#endif

static char const *keyword_list[] =
{
    "repeat", "(<int>,<sequence>)", "loop <int> times through <sequence>",
    "feof", "(<int>)", "break out of loop or sequence after <int> EOFs",
    NULL
};

static char const *function_list[] =
{
    "fopen", "()", "open file",
#if defined HAVE_FOPEN64
    "fopen64", "()", "same as fopen()",
#endif
#if defined HAVE___FOPEN64
    "__fopen64", "()", "same as fopen()",
#endif
    "freopen", "()", "reopen file",
#if defined HAVE_FREOPEN64
    "freopen64", "()", "same as reopen()",
#endif
#if defined HAVE___FREOPEN64
    "__freopen64", "()", "same as reopen()",
#endif
    "fclose", "()", "close file",
    "fread", "(<inta>,<intb>)", "read <intb> chunks of <inta> bytes",
    "getc", "()", "get one character (can be a macro)",
    "fgetc", "()", "get one character",
    "fgets", "(<int>)", "read one line no longer than <int> bytes",
#if defined HAVE___FGETS_CHK
    "__fgets_chk", "(<int>)", "same as fgets(), fortified version",
#endif
#if defined HAVE__IO_GETC
    "_IO_getc", "()", "get one character",
#endif
#if defined HAVE___FREAD_CHK
    "__fread_chk", "(<inta>,<intb>)", "same as fread(), fortified version",
#endif
#if defined HAVE_FREAD_UNLOCKED
    "fread_unlocked", "(<inta>,<intb>)", "same as fread(), unlocked I/O version",
#endif
#if defined HAVE___FREAD_UNLOCKED_CHK
    "__fread_unlocked_chk", "(<inta>,<intb>)", "same as fread_unlocked(), fortified version",
#endif
#if defined HAVE_FGETS_UNLOCKED
    "fgets_unlocked", "(<int>)", "same as fgets(), unlocked I/O version",
#endif
#if defined HAVE___FGETS__UNLOCKED_CHK
    "__fgets_unlocked_chk", "(<int>)", "same as fgets_unlocked(), fortified version",
#endif
#if defined HAVE_GETC_UNLOCKED
    "getc_unlocked", "()", "same as getc(), unlocked I/O version",
#endif
#if defined HAVE_FGETC_UNLOCKED
    "fgetc_unlocked", "()", "same as fgetc(), unlocked I/O version",
#endif
#if defined HAVE_GETLINE
    "getline", "()", "read one complete line of text",
#endif
#if defined HAVE_GETDELIM
    "getdelim", "('<char>')", "read all data until delimiter character <char>",
    "getdelim", "(<int>)", "read all data until delimiter character <int>",
#endif
#if defined HAVE___GETDELIM
    "__getdelim", "('<char>')", "same as getdelim()",
    "__getdelim", "(<int>)", "same as getdelim()",
#endif
    "fseek", "(<int>,<whence>)", "seek using SEEK_CUR, SEEK_SET or SEEK_END",
#if defined HAVE_FSEEKO
    "fseeko", "(<int>,<whence>)", "same as fseek()",
#endif
#if defined HAVE_FSEEKO64
    "fseeko64", "(<int>,<whence>)", "same as fseek()",
#endif
#if defined HAVE___FSEEKO64
    "__fseeko64", "(<int>,<whence>)", "same as fseek()",
#endif
    "rewind", "()", "rewind to the beginning of the stream",
    "ungetc", "()", "put one byte back in the stream",
    NULL
};

static void print_list(char const **list)
{
    static char const spaces[] = "                                ";

    while (*list)
    {
        size_t len = printf("  %s%s", list[0], list[1]);
        if (len < strlen(spaces))
            printf("%s", spaces + len);
        printf("%s\n", list[2]);
        list += 3;
    }
}

static void syntax(void)
{
    printf("Available control keywords:\n");
    print_list(keyword_list);
    printf("\n");
    printf("Available functions:\n");
    print_list(function_list);
}

static void version(void)
{
    printf("zzat %s\n", PACKAGE_VERSION);
    printf("Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>\n");
    printf("This program is free software. It comes without any warranty, to the extent\n");
    printf("permitted by applicable law. You can redistribute it and/or modify it under\n");
    printf("the terms of the Do What the Fuck You Want to Public License, Version 2, as\n");
    printf("published by the WTFPL Task Force. See http://www.wtfpl.net/ for more details.\n");
    printf("\n");
    printf("Written by Sam Hocevar. Report bugs to <sam@hocevar.net>.\n");
}

static void usage(void)
{
    printf("Usage: zzat [AbdeEntTv] [-x sequence] [FILE...]\n");
    printf("       zzat -l | --list\n");
    printf("       zzat -h | --help\n");
    printf("       zzat -V | --version\n");
    printf("Read FILE using a sequence of various I/O methods.\n");
    printf("\n");
    printf("Mandatory arguments to long options are mandatory for short options too.\n");
    printf("  -A, --show-all            equivalent to -vET\n");
    printf("  -b, --number-nonblank     number nonempty output lines\n");
    printf("  -d, --debug               print debugging information\n");
    printf("  -e                        equivalent to -vE\n");
    printf("  -E, --show-ends           display $ at end of each line\n");
    printf("  -n, --number              number all output lines\n");
    printf("  -r, --repeat=<loops>      concatenate command line files <loops> times\n");
    printf("  -t                        equivalent to -vT\n");
    printf("  -T, --show-tabs           display TAB characters as ^I\n");
    printf("  -v, --show-nonprinting    use ^ and M- notation, except for LFD and TAB\n");
    printf("  -x, --execute=<sequence>  execute commands in <sequence>\n");
    printf("  -l, --list                list available program functions\n");
    printf("  -h, --help                display this help and exit\n");
    printf("  -V, --version             output version information and exit\n");
    printf("\n");
    printf("Written by Sam Hocevar. Report bugs to <sam@hocevar.net>.\n");
}

