/*
 *  zzuf - general purpose fuzzer
 *  Copyright (c) 2006-2010 Sam Hocevar <sam@hocevar.net>
 *                All Rights Reserved
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What The Fuck You Want
 *  To Public License, Version 2, as published by Sam Hocevar. See
 *  http://sam.zoy.org/wtfpl/COPYING for more details.
 */

/*
 *  network.c: network connection helper functions
 */

#include "config.h"

#if defined HAVE_STDINT_H
#   include <stdint.h>
#elif defined HAVE_INTTYPES_H
#   include <inttypes.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined HAVE_SYS_SOCKET_H
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>
#endif

#include "libzzuf.h"
#include "debug.h"
#include "ranges.h"
#include "network.h"

#if defined HAVE_SYS_SOCKET_H
static unsigned int get_socket_ip(int);
static int host_in_list(unsigned int, unsigned int const *);
static unsigned int *create_host_list(char const *, unsigned int *);

/* Network IP cherry picking */
static unsigned int *allow = NULL;
static unsigned int static_allow[512];
static unsigned int *deny = NULL;
static unsigned int static_deny[512];

/* Network port cherry picking */
static int *ports = NULL;
static int static_ports[512];
#endif

void _zz_network_init(void)
{
    ;
}

void _zz_network_fini(void)
{
#if defined HAVE_SYS_SOCKET_H
    if(ports != static_ports)
        free(ports);
    if(allow != static_allow)
        free(allow);
    if(deny != static_deny)
        free(deny);
#endif
}

void _zz_allow(char const *allowlist)
{
#if defined HAVE_SYS_SOCKET_H
    allow = create_host_list(allowlist, static_allow);
#endif
}

void _zz_deny(char const *denylist)
{
#if defined HAVE_SYS_SOCKET_H
    deny = create_host_list(denylist, static_deny);
#endif
}

void _zz_ports(char const *portlist)
{
#if defined HAVE_SYS_SOCKET_H
    ports = _zz_allocrange(portlist, static_ports);
#endif
}

int _zz_portwatched(int port)
{
#if defined HAVE_SYS_SOCKET_H
    if(!ports)
        return 1;

    return _zz_isinrange(port, ports);
#else
    return 0;
#endif
}

int _zz_hostwatched(int sock)
{
#if defined HAVE_SYS_SOCKET_H
    int watch = 1;
    unsigned int ip;

    if(!allow && !deny)
        return 1;

    ip = get_socket_ip(sock);

    if(allow)
        watch = host_in_list(ip, allow);
    else if(deny && host_in_list(ip, deny))
        watch = 0;

    return watch;
#else
    return 0;
#endif
}

/* XXX: the following functions are local */

#if defined HAVE_SYS_SOCKET_H
static unsigned int *create_host_list(char const *list,
                                      unsigned int *static_list)
{
    char buf[BUFSIZ];
    struct in_addr addr;
    char const *parser;
    unsigned int i, chunks, *iplist;
    int ret;

    /* Count commas */
    for(parser = list, chunks = 1; *parser; parser++)
        if(*parser == ',')
            chunks++;

    if(chunks >= 512)
        iplist = malloc((chunks + 1) * sizeof(unsigned int));
    else
        iplist = static_list;

    for(i = 0, parser = list; *parser; )
    {
        char *comma = strchr(parser, ',');

        if (comma && (comma - parser) < BUFSIZ - 1)
        {
            memcpy(buf, parser, comma - parser);
            buf[comma - parser] = '\0';
            parser = comma + 1;
        }
        else if (strlen(parser) < BUFSIZ - 1)
        {
            strcpy(buf, parser);
            parser += strlen(parser);
        }
        else
        {
            buf[0] = '\0';
            parser++;
        }

        ret = inet_aton(buf, &addr);
        if (ret)
            iplist[i++] = addr.s_addr;
        else
        {
            chunks--;
            debug("create_host_list: skipping invalid address '%s'", parser);
        }
    }

    iplist[i] = 0;

    return iplist;
}

static int host_in_list(unsigned int value, unsigned int const *list)
{
    unsigned int i;

    if (!value || !list)
        return 0;

    for (i = 0; list[i]; i++)
        if (value == list[i])
            return 1;

    return 0;
}

static unsigned int get_socket_ip(int sock)
{
    struct sockaddr s;
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    int ret;

    /* Use a sockaddr instead of sockaddr_in because we don't know whether
     * their alignments are compatible. So, no cast. */
    memset(&s, 0, sizeof(sin));
    ret = getsockname(sock, &s, &len);
    if (ret)
        return 0; // TODO: error handling

    memcpy(&sin, &s, sizeof(sin));
    return sin.sin_addr.s_addr;
}
#endif /* HAVE_SYS_SOCKET_H */
