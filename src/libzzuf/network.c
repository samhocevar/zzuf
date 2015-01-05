/*
 *  zzuf - general purpose fuzzer
 *
 *  Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
 *              2012 Kévin Szkudłapski <kszkudlapski@quarkslab.com>
 *
 *  This program is free software. It comes without any warranty, to
 *  the extent permitted by applicable law. You can redistribute it
 *  and/or modify it under the terms of the Do What the Fuck You Want
 *  to Public License, Version 2, as published by the WTFPL Task Force.
 *  See http://www.wtfpl.net/ for more details.
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
#elif defined HAVE_WINSOCK2_H
#   include <winsock2.h>
#   include <ws2tcpip.h>
#endif

#include "libzzuf.h"
#include "debug.h"
#include "ranges.h"
#include "network.h"

#if defined HAVE_SYS_SOCKET_H || defined (HAVE_WINDOWS_H)
static unsigned int get_socket_ip(int);
static int host_in_list(unsigned int, unsigned int const *);
static unsigned int *create_host_list(char const *, unsigned int *);

/* Network IP cherry picking */
static unsigned int *allow = NULL;
static unsigned int static_allow[512];
static unsigned int *deny = NULL;
static unsigned int static_deny[512];

/* Network port cherry picking */
static int64_t *ports = NULL;
static int64_t static_ports[512];
#endif

void _zz_network_init(void)
{
#ifdef HAVE_WINSOCK2_H
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2,2), &wsa_data); /* LATER: handle error */
#endif
}

void _zz_network_fini(void)
{
#if defined HAVE_SYS_SOCKET_H || defined (HAVE_WINDOWS_H)
    if (ports != static_ports)
        free(ports);
    if (allow != static_allow)
        free(allow);
    if (deny != static_deny)
        free(deny);
#endif

#if defined HAVE_WINSOCK2_H
    WSACleanup(); /* LATER: handle error */
#endif
}

void _zz_allow(char const *allowlist)
{
#if defined HAVE_SYS_SOCKET_H || defined (HAVE_WINDOWS_H)
    allow = create_host_list(allowlist, static_allow);
#endif
}

void _zz_deny(char const *denylist)
{
#if defined HAVE_SYS_SOCKET_H || defined (HAVE_WINDOWS_H)
    deny = create_host_list(denylist, static_deny);
#endif
}

void _zz_ports(char const *portlist)
{
#if defined HAVE_SYS_SOCKET_H || defined (HAVE_WINDOWS_H)
    ports = _zz_allocrange(portlist, static_ports);
#endif
}

int _zz_portwatched(int port)
{
#if defined HAVE_SYS_SOCKET_H || defined (HAVE_WINDOWS_H)
    if (!ports)
        return 1;

    return _zz_isinrange(port, ports);
#else
    return 0;
#endif
}

int _zz_hostwatched(int sock)
{
#if defined HAVE_SYS_SOCKET_H || defined (HAVE_WINDOWS_H)
    int watch = 1;
    unsigned int ip;

    if (!allow && !deny)
        return 1;

    ip = get_socket_ip(sock);

    if (allow)
        watch = host_in_list(ip, allow);
    else if (deny && host_in_list(ip, deny))
        watch = 0;

    return watch;
#else
    return 0;
#endif
}

/* XXX: the following functions are local */

#if defined HAVE_SYS_SOCKET_H || defined HAVE_WINSOCK2_H
static unsigned int *create_host_list(char const *list,
                                      unsigned int *static_list)
{
    char buf[BUFSIZ];
    struct in_addr addr;
    char const *parser;
    unsigned int i, chunks, *iplist;
    int ret;

    /* Count commas */
    for (parser = list, chunks = 1; *parser; ++parser)
        if (*parser == ',')
            chunks++;

    if (chunks >= 512)
        iplist = malloc((chunks + 1) * sizeof(unsigned int));
    else
        iplist = static_list;

    for (i = 0, parser = list; *parser; )
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

        ret = inet_pton(AF_INET, buf, &addr);
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
    if (!value || !list)
        return 0;

    for (unsigned i = 0; list[i]; ++i)
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
