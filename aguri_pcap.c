/*
 * Copyright (C) 2001-2015 WIDE Project.
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <err.h>
#include <pcap.h>

#include "aguri.h"
#include "aguri_tree.h"
#include "aguri_ip.h"
#include "aguri_pcap.h"
#include "read_pcap.h"

u_int64_t caplen_total = 0;
int caplen_max = 0;
int interval;
int reading_pcap = 0;
int summary_pending = 0;

static pcap_t *pd;
static int packet_length;	/* length of current packet */
static char errbuf[PCAP_ERRBUF_SIZE];
static int	saddr_index, daddr_index;

int
open_pcapfile(char *file, char *filter_cmd)
{
	int fd;
	struct bpf_program bprog;

	pd = pcap_open_offline(file, errbuf);
	if (pd == NULL)
		err(1, "%s", errbuf);
	if (pcap_compile(pd, &bprog, filter_cmd, 0, 0) < 0)
		err(1, "pcap_compile: %s", pcap_geterr(pd));
	else if (pcap_setfilter(pd, &bprog) < 0)
		err(1, "pcap_setfilter: %s", pcap_geterr(pd));

	net_reader = lookup_printer(pcap_datalink(pd));

	fd = fileno(pcap_file(pd));

	return (fd);
}

int
open_pcapif(char *interface, char *filter_cmd)
{
	int snaplen, fd;
	char *device;
	struct bpf_program bprog;

	if (interface == NULL) {
		device = pcap_lookupdev(errbuf);
		if (device == NULL)
			errx(1, "%s", errbuf);
	} else
		device = interface;
	fprintf(stderr, "packet filter: using device %s\n", device);
	snaplen = DEFAULT_SNAPLEN;
	pd = pcap_open_live(device, snaplen, 1, 0, errbuf);
	if (pd == NULL)
		errx(1, "%s", errbuf);
	if (pcap_compile(pd, &bprog, filter_cmd, 0, 0) < 0)
		err(1, "pcap_compile: %s", pcap_geterr(pd));
	else if (pcap_setfilter(pd, &bprog) < 0)
		err(1, "pcap_setfilter: %s", pcap_geterr(pd));

	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	net_reader = lookup_printer(pcap_datalink(pd));

	fd = pcap_fileno(pd);

#if defined(BSD) && defined(BPF_MAXBUFSIZE)
	{
		/* check the buffer size */
		u_int bufsize;

		if (ioctl(fd, BIOCGBLEN, (caddr_t)&bufsize) < 0)
			perror("BIOCGBLEN");
		else
			fprintf(stderr, "bpf buffer size is %d\n", bufsize);
	}
#endif /* BSD */

	return (fd);
}

void
close_pcap(int fd)
{
	pcap_close(pd);
	pd = NULL;
}

void
print_pcapstat(FILE *fp)
{
	struct pcap_stat stat;
	static struct pcap_stat last_stat;

	/* can't print the summary if reading from a savefile */
	if (pd != NULL && pcap_file(pd) == NULL) {
		if (pcap_stats(pd, &stat) < 0)
			fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pd));
		else {
			fprintf(fp, "%%%u packets received by filter\n",
			    stat.ps_recv - last_stat.ps_recv);
			fprintf(fp, "%%%u packets dropped by kernel\n",
			    stat.ps_drop - last_stat.ps_drop);
			last_stat = stat;
		}
	}
}

int
read_pcap(int fd)
{
	int rval;

	reading_pcap = 1;
	rval = pcap_dispatch(pd, 1, dump_reader, 0);
	reading_pcap = 0;
	if (summary_pending) {
		summary_pending = 0;
		if (wfile != NULL && freopen(wfile, "a", stdout) == NULL)
			err(1, "can't freopen %s", wfile);
	}
	if (rval < 0)
		(void)fprintf(stderr, "pcap_dispatch:%s\n", pcap_geterr(pd));
	return (rval);
}

int
do_pkthdr(const struct timeval *ts, u_int caplen, u_int len)
{
	static time_t first_interval = 0;
	static time_t next_interval = 0;

	packet_length = len;

	if (interval == 0) {
		if (start_time.tv_sec == 0)  /* first packet. initialize the start time */
			start_time = *ts;
		end_time = *ts;	/* keep the timestamp of the last packet */
		return (1);
	}

	/*
	 * interval is specified.
	 *  - align the start and end time
	 *  - print summary at the end of each interval
	 */
	if (start_time.tv_sec == 0) {
		if (first_interval == 0)
			first_interval = (ts->tv_sec + interval - 1)
			    / interval * interval;
		if (ts->tv_sec < first_interval)
			return (0);

		/* align the start time to the boundary */
		start_time.tv_sec = first_interval;
		start_time.tv_usec = 0;
		next_interval = first_interval + interval;
	}

	if (ts->tv_sec >= next_interval) {
		/*
		 * new time interval
		 */
		end_time.tv_sec = next_interval;
		end_time.tv_usec = 0;
		print_header();
		if (flow_matrix != NULL) {
			/*
			 * XXX: aguri2_summary should be called before
			 * print_summary in which trees are aggregated.
			 */
			aguri2_summary();

			/* remove nodes from the tree */
			if (agr_flows->tr_top->tn_left != NULL)
				subtree_reduce(agr_flows, agr_flows->tr_top, 0);
			tree_resetcount(agr_flows);
			if (agr_flows6 != NULL) {
				if (agr_flows6->tr_top->tn_left != NULL)
					subtree_reduce(agr_flows6, agr_flows6->tr_top, 0);
				tree_resetcount(agr_flows6);
			}
		}
		print_summary();
		
		aguri2_setup();

		if (addr_src != NULL)
			tree_resetcount(addr_src);
		if (addr6_src != NULL)
			tree_resetcount(addr6_src);
		if (addr_dst != NULL)
			tree_resetcount(addr_dst);
		if (addr6_dst != NULL)
			tree_resetcount(addr6_dst);
		if (proto_src != NULL)
			tree_resetcount(proto_src);
		if (proto_dst != NULL)
			tree_resetcount(proto_dst);

		start_time.tv_sec = next_interval;
		next_interval += interval;
	}

	end_time = *ts;	/* keep the timestamp of the last packet */
	return (1);
}

int
do_ip(const struct ip *ip)
{
	if (addr_src != NULL)
		leaf_addcount(addr_src, &ip->ip_src, packet_length, 1);
	if (addr_dst != NULL)
		leaf_addcount(addr_dst, &ip->ip_dst, packet_length, 1);

	if (flow_matrix != NULL) {
		struct tree *tp;
		struct tree_node *np, *np2;
		struct dbl_counters *dp = NULL;

		tp = addr_src;
		np = tree_matchindex(tp, &ip->ip_src, tp->tr_keylen);
		tp = addr_dst;
		np2 = tree_matchindex(tp, &ip->ip_dst, tp->tr_keylen);
#if 0
		printf("aguri2: %d %d\n", np->tn_index, np2->tn_index);
#endif
		dp = flow_matrix + np->tn_index * tp->tr_indices + np2->tn_index;
		if (dp->dc_count == 0)
			flow_num++;	/* this is a new flow entry */
		dp->dc_count += packet_length;
		dp->dc_count2 += 1;

		/* save the indices */
		saddr_index = np->tn_index;
		daddr_index = np2->tn_index;
	}
	return (1);
}

#ifdef INET6
int
do_ip6(const struct ip6_hdr *ip6)
{
	if (addr6_src != NULL)
		leaf_addcount(addr6_src, &ip6->ip6_src, packet_length, 1);
	if (addr6_dst != NULL)
		leaf_addcount(addr6_dst, &ip6->ip6_dst, packet_length, 1);

	if (flow_matrix6 != NULL) {
		struct tree *tp;
		struct tree_node *np, *np2;
		struct dbl_counters *dp = NULL;

		tp = addr6_src;
		np = tree_matchindex(tp, &ip6->ip6_src, tp->tr_keylen);
		tp = addr6_dst;
		np2 = tree_matchindex(tp, &ip6->ip6_dst, tp->tr_keylen);
#if 0
		printf("aguri2: %d %d\n", np->tn_index, np2->tn_index);
#endif
		dp = flow_matrix6 + np->tn_index * tp->tr_indices + np2->tn_index;
		if (dp->dc_count == 0)
			flow_num6++;  /* this is a new flow entry */
		dp->dc_count += packet_length;
		dp->dc_count2 += 1;

		/* save the indices */
		saddr_index = np->tn_index;
		daddr_index = np2->tn_index;
	}
	return (1);
}
#endif

int
do_ipproto(int proto, const u_char *bp, int length)
{
	struct proto pdata;
	u_short sport, dport;

	if ((xflags & CHECK_IPV4) == 0)
		return (0);

	pdata.p_ipver = 4;
	pdata.p_proto = proto;
	sport = dport = 0;

	switch (proto) {
	case IPPROTO_TCP:
		if (bp + 4 <= snapend) {
			/* long enough to get ports */
			struct tcphdr *tcp = (struct tcphdr *)bp;
			sport = tcp->th_sport;
			dport = tcp->th_dport;
		}
		break;
	case IPPROTO_UDP:
		if (bp + 4 <= snapend) {
			/* long enough to get ports */
			struct udphdr *udp = (struct udphdr *)bp;
			sport = udp->uh_sport;
			dport = udp->uh_dport;
		}
		break;
	case IPPROTO_ICMP:
		/* take icmp_type and icmp_code as port */
		if (bp + 2 <= snapend)
			sport = dport = *(u_short *)bp;
		break;
	}

	if (proto_src != NULL) {
		pdata.p_port = sport;
		leaf_addcount(proto_src, &pdata, packet_length, 1);
	}
	if (proto_dst != NULL) {
		pdata.p_port = dport;
		leaf_addcount(proto_dst, &pdata, packet_length, 1);
	}

	if (flow_matrix != NULL) {
		struct tree *tp;
		struct tree_node *np, *np2;
		u_char index_key[4];

		np = np2 = NULL;
		if (proto_src != NULL) {
			pdata.p_port = sport;
			tp = proto_src;
			np = tree_matchindex(tp, &pdata, tp->tr_keylen);
		}
		if (proto_dst != NULL) {
			pdata.p_port = dport;
			tp = proto_dst;
			np2 = tree_matchindex(tp, &pdata, tp->tr_keylen);
		}

		index_key[0] = (u_char)saddr_index;
		index_key[1] = (u_char)daddr_index;
		if (np != NULL)
			index_key[2] = (u_char)np->tn_index;
		else {
			printf("do_ipproto: np == NULL\n");
			index_key[2] = 0;
		}
		if (np2 != NULL)
			index_key[3] = (u_char)np2->tn_index;
		else
			index_key[3] = 0;

		assert(index_key[2] < (u_char)proto_src->tr_indices);
		assert(index_key[3] < (u_char)proto_dst->tr_indices);

		leaf_addcount(agr_flows, index_key, packet_length, 1);
	}

	return (1);
}

#ifdef INET6
int
do_ip6nexthdr(int proto, const u_char *bp, int length)
{
	struct proto pdata;
	u_short sport, dport;

	if ((xflags & CHECK_IPV6) == 0)
		return (0);

	pdata.p_ipver = 6;
	pdata.p_proto = proto;
	sport = dport = 0;

	switch (proto) {
	case IPPROTO_TCP:
		if (bp + 4 <= snapend) {
			/* long enough to get ports */
			struct tcphdr *tcp = (struct tcphdr *)bp;
			sport = tcp->th_sport;
			dport = tcp->th_dport;
		}
		break;
	case IPPROTO_UDP:
		if (bp + 4 <= snapend) {
			/* long enough to get ports */
			struct udphdr *udp = (struct udphdr *)bp;
			sport = udp->uh_sport;
			dport = udp->uh_dport;
		}
		break;
	case IPPROTO_ICMPV6:
		/* take icmp_type and icmp_code as port */
		if (bp + 2 <= snapend)
			sport = dport = *(u_short *)bp;
		break;
	}

	if (proto_src != NULL) {
		pdata.p_port = sport;
		leaf_addcount(proto_src, &pdata, packet_length, 1);
	}
	if (proto_dst != NULL) {
		pdata.p_port = dport;
		leaf_addcount(proto_dst, &pdata, packet_length, 1);
	}

	if (flow_matrix6 != NULL) {
		struct tree *tp;
		struct tree_node *np, *np2;
		u_char index_key[4];

		np = np2 = NULL;
		if (proto_src != NULL) {
			pdata.p_port = sport;
			tp = proto_src;
			np = tree_matchindex(tp, &pdata, tp->tr_keylen);
		}
		if (proto_dst != NULL) {
			pdata.p_port = dport;
			tp = proto_dst;
			np2 = tree_matchindex(tp, &pdata, tp->tr_keylen);
		}

		index_key[0] = (u_char)saddr_index;
		index_key[1] = (u_char)daddr_index;
		if (np != NULL)
			index_key[2] = (u_char)np->tn_index;
		else {
			printf("do_ipproto: np == NULL\n");
			index_key[2] = 0;
		}
		if (np2 != NULL)
			index_key[3] = (u_char)np2->tn_index;
		else
			index_key[3] = 0;

		assert(index_key[2] < (u_char)proto_src->tr_indices);
		assert(index_key[3] < (u_char)proto_dst->tr_indices);

		leaf_addcount(agr_flows6, index_key, packet_length, 1);
	}

	return (1);
}
#endif /* INET6 */
