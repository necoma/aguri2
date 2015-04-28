/*
 * Copyright (C) 2014-2015 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <err.h>

#include "../aguri_flow.h"
#include "aguri2_xflow.h"

#define FLOWTYPE_SFLOW		1
#define FLOWTYPE_NETFLOW	2


#ifndef INFTIM	/* for linux */
#define	INFTIM		(-1)
#endif

int	verbose;
int	debug;
int	port = 0;	/* port number to reveive flow records */
int	sflow_defport   = 6343;	/* default sFlow port */
int	netflow_defport = 2055;	/* default NetFlow port */
int	flow_type = 0;	/* FLOWTYPE_SFLOW or FLOWTYPE_NETFLOW */
int	default_samprate = 1;  /* default sampling rate */
char buffer[8192];	/* buffer for flow datagram */

int	read_from_socket(void);
static void usage(void);


static	void
usage(void)
{
	fprintf(stderr,
	    "usage: aguri2_xflow -dhv [-t sflow | netflow] [-p port] [-s sampling_rate]\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int	i;
	char	*flow_typename = NULL;

	while ((i = getopt(argc, argv, "dp:s:t:v")) != -1) {
		switch (i) {
		case 'd':
			debug++;
			break;
	        case 'p':
			port = atoi(optarg);
			break;
	        case 's':
			default_samprate = atoi(optarg);
			break;
	        case 't':
			flow_typename = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}
	if (flow_typename == NULL || strcasecmp(flow_typename, "sflow") == 0) {
		flow_type = FLOWTYPE_SFLOW;
		if (port == 0)
			port = sflow_defport;
	} else if (strcasecmp(flow_typename, "netflow") == 0) {
		flow_type = FLOWTYPE_NETFLOW;
		if (port == 0)
			port = netflow_defport;
	} else
		usage();
	
	read_from_socket();

	return (0);
}

int
read_from_socket(void)
{
	struct	sockaddr_in my_addr, from_addr, agent_addr;
	int	s, nbytes;
	socklen_t	fromlen;
	int	one = 1;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family	= PF_INET;
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	my_addr.sin_port	= htons(port);
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
		       (char *)&one, sizeof(one)) < 0)
	    err(1, "SO_REUSEADDR");
	if (bind(s, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0)
		err(1, "bind");

	memset(&agent_addr, 0, sizeof(agent_addr));

	while (1) {
		struct pollfd pfds[1];
		int nfound;
		char name[INET_ADDRSTRLEN];

		pfds[0].fd = s;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;
		nfound = poll(pfds, 1, INFTIM);
		if (nfound == -1) {
			if (errno == EINTR) {
				/* interrupt occured */
				warn("poll interrupted");
				continue;
			} else {
				err(1, "poll");
				/*NOTREACHED*/
			}
		}
		if (nfound == 0 || (pfds[0].revents & POLLIN) == 0) {
			warnx("poll returns 0!");
			continue;
		}

		fromlen = sizeof(from_addr);
		if ((nbytes = recvfrom(s, buffer, sizeof(buffer), 0,
		    (struct sockaddr *)&from_addr, &fromlen)) == -1) {
			err(1, "recvfrom");
			/*NOTREACHED*/
		}

		if (agent_addr.sin_addr.s_addr == 0) {
			agent_addr = from_addr;
			if (inet_ntop(AF_INET, &from_addr.sin_addr,
			    name, sizeof(name)) != NULL)
				fprintf(stderr, "reading from agent [%s] ....\n", name);
		}

		/* is this the probe we are reading from? */
		if (from_addr.sin_addr.s_addr != agent_addr.sin_addr.s_addr) {
			if (inet_ntop(AF_INET, &from_addr.sin_addr,
			    name, sizeof(name)) != NULL)
				warnx("multiple agents: ignoring %s", name);
			continue;
		}

		if (nbytes < 24) {
			warnx("packet too short! %d bytes\n", nbytes);
			continue;
		}

		if (flow_type == FLOWTYPE_SFLOW)
			parse_sflow_datagram(buffer, nbytes);
		else
			parse_netflow_datagram(buffer, nbytes);
	}

	close(s);

	return (0);
}

int
print_flow(struct aguri_flow *afp)
{
	struct flow_spec *fs = &afp->agflow_fs;
	char srcbuf[INET6_ADDRSTRLEN];
	char dstbuf[INET6_ADDRSTRLEN];
	char timestr[64];
	int af = AF_INET;
	time_t	ts;
	struct tm *tm;

	ts = ntohl(afp->agflow_last);
	tm = localtime(&ts);
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tm);

	if (fs->fs_ipver == 6)
		af = AF_INET6;
	inet_ntop(af, &fs->fs_srcaddr, srcbuf, sizeof(srcbuf));
	inet_ntop(af, &fs->fs_dstaddr, dstbuf, sizeof(dstbuf));
	
	return printf("%s  %s %u > %s %u proto:%u bytes:%u packets:%u\n",
		timestr,
		srcbuf, ntohs(fs->fs_sport), dstbuf, ntohs(fs->fs_dport),
		fs->fs_prot, ntohl(afp->agflow_bytes), ntohl(afp->agflow_packets));
}
