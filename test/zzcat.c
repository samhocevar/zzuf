/*
 *  zzcat - various cat reimplementations for testing purposes
 *  Copyright (c) 2006-2009 Sam Hocevar <sam@hocevar.net>
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
 * TODO: fsetpos64, fgetln
 */

#include "config.h"

/* Needed for lseek64() */
#define _LARGEFILE64_SOURCE
/* Needed for O_RDONLY on HP-UX */
#define _INCLUDE_POSIX_SOURCE
/* Needed for fgets_unlocked() */
#define _GNU_SOURCE

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

static inline unsigned int myrand(void)
{
    static int seed = 1;
    int x, y;
    x = (seed + 0x12345678) << 11;
    y = (seed + 0xfedcba98) >> 21;
    seed = x * 1010101 + y * 343434;
    return seed;
}

#define FOPEN(cmd) \
    do { \
        cmd; \
        if (!f) \
        { \
            fprintf(stderr, "E: zzcat: cannot open `%s'\n", file); \
            return EXIT_FAILURE; \
        } \
        retoff = 0; \
        p = strchr(p, ')') + 1; \
    } while(0)

#define FCLOSE(cmd) \
    do { \
        cmd; \
        f = NULL; \
        p = strchr(p, ')') + 1; \
    } while(0)

#define MERGE(address, cnt, off) \
    do { \
        size_t _cnt = cnt, _off = off; \
        if (_cnt && retoff + _cnt > retlen) \
        { \
            retlen = retoff + _cnt; \
            retbuf = realloc(retbuf, retlen); \
        } \
        if (_cnt > 0) \
            memcpy(retbuf + retoff, address, _cnt); \
        retoff += _off; \
    } while(0)

#define FREAD(cmd, buf, cnt) FCALL(cmd, buf, cnt, cnt)
#define FSEEK(cmd, off) FCALL(cmd, /* unused */ "", 0, off)

#define FCALL(cmd, buf, cnt, off) \
    do { \
        if (!f) \
        { \
            f = fopen(file, "r"); \
            if (!f) \
            { \
                fprintf(stderr, "E: zzcat: cannot open `%s'\n", file); \
                return EXIT_FAILURE; \
            } \
        } \
        cmd; \
        MERGE(buf, cnt, off); \
        p = strchr(p, ')') + 1; \
    } while(0)

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

static int make_fmt(struct parser *p, char const *fmt)
{
    char const *tmp;
    size_t len;
    int ret = 0;

    len = strlen(fmt);
    p->lastch = fmt[len - 1];

    memcpy(p->tmpfmt, fmt, len - 1);
    p->tmpfmt[len - 1] = '%';
    p->tmpfmt[len] = 'c';
    p->tmpfmt[len + 1] = '\0';

    for (tmp = p->tmpfmt; *tmp; tmp++)
        if (*tmp == '%')
            tmp++, ret++;

    return ret;
}

#define PARSECMD(fmt, arg...) \
    make_fmt(&parser, fmt) == sscanf(p, parser.tmpfmt, ##arg, &parser.ch) \
        && parser.ch == parser.lastch

/*
 * File reader. We parse a command line and perform all the operations it
 * contains on the specified file.
 */

static int cat_file(char const *p, char const *file)
{
    struct { char const *p; int count; } loops[128];
    char *retbuf = NULL, *tmp;
    FILE *f = NULL;
    size_t retlen = 0, retoff = 0;
    int nloops = 0, fd = -1;

    /* Allocate 32MB for our temporary buffer. Any larger value will crash. */
    tmp = malloc(32 * 1024 * 1024);

    while (*p)
    {
        struct parser parser;
        long int l1, l2;
        char *s, *lineptr = NULL;
        size_t k;
        ssize_t l;
        int n;
        char ch;

        /* Ignore punctuation */
        if (strchr(" \t,;\r\n", *p))
            p++;

        /* Loop handling */
        else if (PARSECMD("repeat ( %li ,", &l1))
        {
            p = strchr(p, ',') + 1;
            loops[nloops].p = p;
            loops[nloops].count = l1;
            nloops++;
        }
        else if (PARSECMD(")"))
        {
            if (nloops == 0)
            {
                fprintf(stderr, "E: zzcat: ')' outside a loop\n");
                return EXIT_FAILURE;
            }
            loops[nloops - 1].count--;
            if (loops[nloops - 1].count <= 0)
            {
                nloops--;
                p = strchr(p, ')') + 1;
            }
            else
            {
                p = loops[nloops - 1].p;
            }
        }

        /* FILE * opening functions */
        else if (PARSECMD("fopen ( )"))
            FOPEN(f = fopen(file, "r"));
#if defined HAVE_FOPEN64
        else if (PARSECMD("fopen64 ( )"))
            FOPEN(f = fopen64(file, "r"));
#endif
#if defined HAVE___FOPEN64
        else if (PARSECMD("__fopen64 ( )"))
            FOPEN(f = __fopen64(file, "r"));
#endif
        else if (PARSECMD("freopen ( )"))
            FOPEN(f = freopen(file, "r", f));
#if defined HAVE_FREOPEN64
        else if (PARSECMD("freopen64 ( )"))
            FOPEN(f = freopen64(file, "r", f));
#endif
#if defined HAVE___FREOPEN64
        else if (PARSECMD("__freopen64 ( )"))
            FOPEN(f = __freopen64(file, "r", f));
#endif

        /* FILE * closing functions */
        else if (PARSECMD("fclose ( )"))
            FCLOSE(fclose(f));

        /* FILE * reading functions */
        else if (PARSECMD("fread ( %li , %li )", &l1, &l2))
            FREAD(l = fread(tmp, l1, l2, f), tmp, l > 0 ? l * l1 : 0);
        else if (PARSECMD("getc ( )"))
            FREAD(ch = (n = getc(f)), &ch, (n != EOF));
        else if (PARSECMD("fgetc ( )"))
            FREAD(ch = (n = fgetc(f)), &ch, (n != EOF));
        else if (PARSECMD("fgets ( %li )", &l1))
            FREAD(s = fgets(tmp, l1, f), tmp, s ? strlen(tmp) : 0);
#if defined HAVE__IO_GETC
        else if (PARSECMD("_IO_getc ( )"))
            FREAD(ch = (n = _IO_getc(f)), &ch, (n != EOF));
#endif
#if defined HAVE_FREAD_UNLOCKED
        else if (PARSECMD("fread_unlocked ( %li , %li )", &l1, &l2))
            FREAD(l = fread_unlocked(tmp, l1, l2, f), tmp, l > 0 ? l * l1 : 0);
#endif
#if defined HAVE_FGETS_UNLOCKED
        else if (PARSECMD("fgets_unlocked ( %li )", &l1))
            FREAD(s = fgets_unlocked(tmp, l1, f), tmp, s ? strlen(tmp) : 0);
#endif
#if defined HAVE_GETC_UNLOCKED
        else if (PARSECMD("getc_unlocked ( )"))
            FREAD(ch = (n = getc_unlocked(f)), &ch, (n != EOF));
#endif
#if defined HAVE_FGETC_UNLOCKED
        else if (PARSECMD("fgetc_unlocked ( )"))
            FREAD(ch = (n = fgetc_unlocked(f)), &ch, (n != EOF));
#endif

        /* FILE * getdelim functions */
#if defined HAVE_GETLINE
        else if (PARSECMD("getline ( )"))
            FREAD(l = getline(&lineptr, &k, f), lineptr, l >= 0 ? l : 0);
#endif
#if defined HAVE_GETDELIM
        else if (PARSECMD("getdelim ( '%c' )", &ch))
            FREAD(l = getdelim(&lineptr, &k, ch, f), lineptr, l >= 0 ? l : 0);
        else if (PARSECMD("getdelim ( %i )", &n))
            FREAD(l = getdelim(&lineptr, &k, n, f), lineptr, l >= 0 ? l : 0);
#endif
#if defined HAVE___GETDELIM
        else if (PARSECMD("__getdelim ( '%c' )", &ch))
            FREAD(l = __getdelim(&lineptr, &k, ch, f), lineptr, l >= 0 ? l : 0);
        else if (PARSECMD("__getdelim ( %i )", &n))
            FREAD(l = __getdelim(&lineptr, &k, n, f), lineptr, l >= 0 ? l : 0);
#endif

        /* FILE * seeking functions */
        else if (PARSECMD("fseek ( %li , SEEK_CUR )", &l1))
            FSEEK(l = fseek(f, l1, SEEK_CUR),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseek ( %li , SEEK_SET )", &l1))
            FSEEK(l = fseek(f, l1, SEEK_SET),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseek ( %li , SEEK_END )", &l1))
            FSEEK(l = fseek(f, l1, SEEK_END),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
#if defined HAVE_FSEEKO
        else if (PARSECMD("fseeko ( %li , SEEK_CUR )", &l1))
            FSEEK(l = fseeko(f, l1, SEEK_CUR),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseeko ( %li , SEEK_SET )", &l1))
            FSEEK(l = fseeko(f, l1, SEEK_SET),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseeko ( %li , SEEK_END )", &l1))
            FSEEK(l = fseeko(f, l1, SEEK_END),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
#endif
#if defined HAVE_FSEEKO64
        else if (PARSECMD("fseeko64 ( %li , SEEK_CUR )", &l1))
            FSEEK(l = fseeko64(f, l1, SEEK_CUR),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseeko64 ( %li , SEEK_SET )", &l1))
            FSEEK(l = fseeko64(f, l1, SEEK_SET),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("fseeko64 ( %li , SEEK_END )", &l1))
            FSEEK(l = fseeko64(f, l1, SEEK_END),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
#endif
#if defined HAVE___FSEEKO64
        else if (PARSECMD("__fseeko64 ( %li , SEEK_CUR )", &l1))
            FSEEK(l = __fseeko64(f, l1, SEEK_CUR),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("__fseeko64 ( %li , SEEK_SET )", &l1))
            FSEEK(l = __fseeko64(f, l1, SEEK_SET),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
        else if (PARSECMD("__fseeko64 ( %li , SEEK_END )", &l1))
            FSEEK(l = __fseeko64(f, l1, SEEK_END),
                  ftell(f) >= 0 ? ftell(f) - retoff : 0);
#endif
        else if (PARSECMD("rewind ( )"))
            FSEEK(rewind(f), -retlen);
        else if (PARSECMD("ungetc ( )"))
            FSEEK(if(retoff) ungetc((unsigned char)retbuf[retoff - 1], f),
                  retoff ? -1 : 0);

        /* Unrecognised sequence */
        else
        {
            char buf[16];
            snprintf(buf, 16, strlen(p) < 16 ? "%s" : "%.12s...", p);
            fprintf(stderr, "E: zzcat: syntax error near `%s'\n", buf);
            return EXIT_FAILURE;
        }

        /* Clean up our mess */
        if (lineptr)
            free(lineptr);
    }

    if (f)
        fclose(f);

    if (fd >= 0)
        close(fd);

    fwrite(retbuf, retlen, 1, stdout);

    free(retbuf);
    free(tmp);

    return EXIT_SUCCESS;
}

/*
 * Main program.
 */

int main(int argc, char *argv[])
{
    int i;

    if (argc < 2)
    {
        fprintf(stderr, "E: zzcat: too few arguments\n");
        return EXIT_FAILURE;
    }

    if (argc == 2)
        return cat_file("fread(1,33554432)", argv[1]);

    for (i = 2; i < argc; i++)
    {
        int ret = cat_file(argv[1], argv[i]);
        if (ret)
            return ret;
    }

    return EXIT_SUCCESS;
}

#if 0
/* Only read() calls */
static int zzcat_read(char const *name, unsigned char *data, int64_t len,
                      int64_t chunk)
{
    int i, fd = open(name, O_RDONLY);
    if(fd < 0)
        return EXIT_FAILURE;
    for(i = 0; i < len; i += chunk)
        read(fd, data + i, chunk);
    close(fd);
    return EXIT_SUCCESS;
}

/* Socket seeks and reads */
static int zzcat_random_socket(char const *name, unsigned char *data,
                               int64_t len)
{
    int i, j, fd = open(name, O_RDONLY);
    if(fd < 0)
        return EXIT_FAILURE;
    for(i = 0; i < 128; i++)
    {
        lseek(fd, myrand() % len, SEEK_SET);
        for(j = 0; j < 4; j++)
            read(fd, data + lseek(fd, 0, SEEK_CUR), myrand() % 4096);
#ifdef HAVE_LSEEK64
        lseek64(fd, myrand() % len, SEEK_SET);
        for(j = 0; j < 4; j++)
            read(fd, data + lseek(fd, 0, SEEK_CUR), myrand() % 4096);
#endif
    }
    close(fd);
    return EXIT_SUCCESS;
}

/* Standard stream seeks and reads */
static int zzcat_random_stream(char const *name, unsigned char *data,
                               int64_t len)
{
    FILE *stream = fopen(name, "r");
    int i, j;
    if(!stream)
        return EXIT_FAILURE;
    for(i = 0; i < 128; i++)
    {
        long int now;
        fseek(stream, myrand() % len, SEEK_SET);
        for(j = 0; j < 4; j++)
            fread(data + ftell(stream),
                  myrand() % (len - ftell(stream)), 1, stream);
        fseek(stream, myrand() % len, SEEK_SET);
        now = ftell(stream);
        for(j = 0; j < 16; j++)
            data[now + j] = getc(stream);
        now = ftell(stream);
        for(j = 0; j < 16; j++)
            data[now + j] = fgetc(stream);
    }
    fclose(stream);
    return EXIT_SUCCESS;
}

#ifdef HAVE_MMAP
/* mmap() followed by random memory reads */
static int zzcat_random_mmap(char const *name, unsigned char *data,
                               int64_t len)
{
    int i, j, fd = open(name, O_RDONLY);
    if(fd < 0)
        return EXIT_FAILURE;
    for(i = 0; i < 128; i++)
    {
        char *map;
        int moff, mlen, pgsz = len + 1;
#ifdef HAVE_GETPAGESIZE
        pgsz = getpagesize();
#endif
        moff = len < pgsz ? 0 : (myrand() % (len / pgsz)) * pgsz;
        mlen = 1 + (myrand() % (len - moff));
        map = mmap(NULL, mlen, PROT_READ, MAP_PRIVATE, fd, moff);
        if(map == MAP_FAILED)
            return EXIT_FAILURE;
        for(j = 0; j < 128; j++)
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

