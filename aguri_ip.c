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

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>
#include <err.h>
#include <inttypes.h>

#include "aguri.h"
#include "aguri_tree.h"
#include "aguri_ip.h"
#include "aguri_pcap.h"
#include "aguri_plot.h"

int xflags = CHECK_SRCADDR | CHECK_DSTADDR | CHECK_SRCPROTO | CHECK_DSTPROTO |
    	     CHECK_IPV4 | CHECK_IPV6 | CHECK_FLOWS;
int ip_thresh = 10;	/* 10/1000 (1%) */

struct tree *addr_src  = NULL;
struct tree *addr6_src = NULL;
struct tree *addr_dst  = NULL;
struct tree *addr6_dst = NULL;
struct tree *proto_src = NULL;
struct tree *proto_dst = NULL;
struct tree *agr_flows = NULL;
struct tree *agr_flows6 = NULL;
#define IP_TREES	8	/* number of trees */

extern int timeoffset;

static struct tree trees[IP_TREES];
static struct tree null_tree;

struct dbl_counters *flow_matrix = NULL;
struct dbl_counters *flow_matrix6 = NULL;

int flow_num, flow_num6;

/* threshold scaling gives bias according to the prefixlen */
static u_int64_t addr_thscale[33] =
    { 1, 64, 64, 64, 64, 64, 64, 64,
     16, 32, 32, 32, 32, 16, 16, 16,
      4,  8,  8,  8,  8,  8,  4,  4,
      1,  4,  4,  4,  2,  2,  2,  4, 1};
static u_int64_t addr6_thscale[129] =
    {  1, 64, 64, 64,  8, 16, 16, 16,  8, 16, 16, 16,  8, 16, 16, 16,
       8, 16, 16, 16,  8, 16, 16, 16,  8, 16, 16, 16,  8, 16, 16, 16,
       4, 16, 16, 16,  8, 16, 16, 16,  8, 16, 16, 16,  8, 16, 16, 16,
       2,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  2,  2,  2,  4,
       1, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 1};
static u_int64_t proto_thscale[33] =
    { 1, 64, 64, 64, 64, 64, 64, 64,
     32, 32, 32, 32, 32, 16, 16, 16,
     16, 64, 64, 64, 64, 32,  32,  16,
     16, 16,  8,  8,  8,  8,  8,  8, 1};
static u_int64_t flow_thscale[33] =
    { 1, 64, 64, 64, 64, 64, 64, 64,
     64, 64, 64, 64, 64, 64, 64, 64,
     64, 64, 64, 64, 64, 64, 64, 64,
     64, 64, 64, 64, 64, 64, 64, 64, 64};
static u_int64_t no_thscale[129] =
    {  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
       1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

static void ip_nodename(struct tree_node *np, char *buf, size_t len);
static u_int64_t ip_addrparser(char *buf, void *key,
			       size_t *prefixlen, void *arg);
static u_int64_t ip_protoparser(char *buf, void *key,
				size_t *prefixlen, void *arg);
static void ip_counter(struct tree *tp, void *key, size_t prefixlen,
		       void *arg, u_int64_t cnt);
static void ipplot_counter(struct tree *tp, void *key, size_t prefixlen,
			   void *arg, u_int64_t cnt);
static void ipplot_printnames(struct tree *tp);
static u_int64_t null_parser(char *buf, void *key, size_t *prefixlen,
			     void *arg);
static void null_counter(struct tree *tp, void *key, size_t prefixlen,
			 void *arg, u_int64_t cnt);
static void print_protos(struct tree *tp, int saddr_index, int daddr_index, u_int64_t count, u_int64_t count2, struct tree_node **rindex_sproto, struct tree_node **rindex_dproto);

static void
ip_nodename(struct tree_node *np, char *buf, size_t len)
{
	struct tree *tp;
	char prefixstr[8];

	tp = np->tn_tree;
	if (np->tn_prefixlen == 0) {
		if (tp == addr6_src || tp == addr6_dst) {
			snprintf(buf, len, "*::");
			return;
		}
		snprintf(buf, len, "*");
		return;
	}
	if (tp == addr_src || tp == addr_dst) {
		inet_ntop(AF_INET, np->tn_key, buf, len);
		if (np->tn_prefixlen < 32) {
			snprintf(prefixstr, sizeof(prefixstr), "/%u",
				 (u_int)np->tn_prefixlen);
			strncat(buf, prefixstr, len - strlen(buf));
		}
	} else if (tp == addr6_src || tp == addr6_dst) {
		inet_ntop(AF_INET6, np->tn_key, buf, len);
		if (np->tn_prefixlen < 128) {
			snprintf(prefixstr, sizeof(prefixstr), "/%u",
				 (u_int)np->tn_prefixlen);
			strncat(buf, prefixstr, len - strlen(buf));
		}
	} else if (tp == proto_src || tp == proto_dst) {
		if (np->tn_prefixlen < 8) {
			snprintf(buf, len, "%u/%d:%u:%u",
				 np->tn_key[0],
				 (int)np->tn_prefixlen,
				 np->tn_key[1],
				 ntohs(*(u_short *)&np->tn_key[2]));
		} else if (np->tn_prefixlen < 16) {
			snprintf(buf, len, "%u:%u/%d:%u",
				 np->tn_key[0],
				 np->tn_key[1],
				 (int)np->tn_prefixlen - 8,
				 ntohs(*(u_short *)&np->tn_key[2]));
		} else if (np->tn_prefixlen == 16) {
			snprintf(buf, len, "%u:%u:*",
				 np->tn_key[0],
				 np->tn_key[1]);
		} else {
			snprintf(buf, len, "%u:%u:%u",
				 np->tn_key[0], np->tn_key[1],
				 ntohs(*(u_short *)&np->tn_key[2]));
			if (np->tn_prefixlen < 16+16) {
				snprintf(prefixstr, sizeof(prefixstr), "/%d",
					 (int)np->tn_prefixlen - 16);
				strncat(buf, prefixstr, len - strlen(buf));
			}
		}
	} else
		buf[0] = '\0';
}

static int
print_ipnode(struct tree_node *np, void *arg)
{
	char buf[INET_ADDRSTRLEN + 8];
	u_int64_t cnt, *total;
	int i;

	cnt = np->tn_count;
	if (cnt == 0)
		return (0);
	total = arg;
	ip_nodename(np, buf, sizeof(buf));
	printf("[%2d]", np->tn_index);

	for (i=0; i<(int)np->tn_prefixlen; i+=2)
		printf(" ");
	printf("%s\t%"PRIu64" (%.2f%%", buf, cnt, (double)cnt/(*total)*100);
	if (np->tn_prefixlen != np->tn_tree->tr_keylen)
		printf("/%.2f%%", (double)subtree_sum(np)/(*total)*100);

	cnt = np->tn_count2;
	printf(")\t%"PRIu64" (%.2f%%", cnt, (double)cnt/(*(total + 1))*100);
	if (np->tn_prefixlen != np->tn_tree->tr_keylen)
		printf("/%.2f%%",
		       (double)subtree_sum2(np)/(*(total + 1))*100);
	printf(")\n");
	return (0);
}

static int
print_ip6node(struct tree_node *np, void *arg)
{
	char buf[INET6_ADDRSTRLEN + 8];
	u_int64_t cnt, *total;
	int i;

	cnt = np->tn_count;
	if (cnt == 0)
		return (0);
	total = arg;
	ip_nodename(np, buf, sizeof(buf));
	printf("[%2d]", np->tn_index);

	for (i=0; i<(int)np->tn_prefixlen; i+=8)
		printf(" ");
	printf("%s\t%"PRIu64" (%.2f%%", buf, cnt, (double)cnt/(*total)*100);
	if (np->tn_prefixlen != np->tn_tree->tr_keylen)
		printf("/%.2f%%", (double)subtree_sum(np)/(*total)*100);

	cnt = np->tn_count2;
	printf(")\t%"PRIu64" (%.2f%%", cnt, (double)cnt/(*(total + 1))*100);
	if (np->tn_prefixlen != np->tn_tree->tr_keylen)
		printf("/%.2f%%", (double)subtree_sum2(np)/(*(total + 1))*100);
	printf(")\n");
	return (0);
}

static int
print_protonode(struct tree_node *np, void *arg)
{
	char buf[INET6_ADDRSTRLEN + 8];
	u_int64_t cnt, *total;
	int i;

	cnt = np->tn_count;
	if (cnt == 0)
		return (0);
	total = arg;
	ip_nodename(np, buf, sizeof(buf));
	printf("[%2d]", np->tn_index);
	if (np->tn_prefixlen >= 16)
		for (i=0; i<(int)np->tn_prefixlen - 16; i++)
			printf(" ");
	printf("%s\t%"PRIu64" (%.2f%%", buf, cnt, (double)cnt/(*total)*100);
	if (np->tn_prefixlen != np->tn_tree->tr_keylen)
		printf("/%.2f%%", (double)subtree_sum(np)/(*total)*100);
	cnt = np->tn_count2;
	printf(")\t%"PRIu64" (%.2f%%", cnt, (double)cnt/(*(total + 1))*100);
	if (np->tn_prefixlen != np->tn_tree->tr_keylen)
		printf("/%.2f%%", (double)subtree_sum2(np)/(*(total + 1))*100);
	printf(")\n");
	return (0);
}

int
ipinfo_init(void)
{
	if (xflags & CHECK_SRCADDR) {
		if (xflags & CHECK_IPV4)
			addr_src  = &trees[0];
		if (xflags & CHECK_IPV6)
			addr6_src = &trees[1];
	}
	if (xflags & CHECK_DSTADDR) {
		if (xflags & CHECK_IPV4)
			addr_dst  = &trees[2];
		if (xflags & CHECK_IPV6)
			addr6_dst = &trees[3];
	}
	if (xflags & CHECK_SRCPROTO)
		proto_src = &trees[4];
	if (xflags & CHECK_DSTPROTO)
		proto_dst = &trees[5];
	if (xflags & CHECK_FLOWS) {
		agr_flows = &trees[6];
		if (xflags & CHECK_IPV6)
			agr_flows6 = &trees[7];
	}

	if (addr_src != NULL) {
		tree_init(addr_src, 32, lru_size);
		if (disable_thscale == 0)
			addr_src->tr_thscale = addr_thscale;
		else
			addr_src->tr_thscale = no_thscale;
	}
	if (addr6_src != NULL) {
		tree_init(addr6_src, 128, lru_size);
		if (disable_thscale == 0)
			addr6_src->tr_thscale = addr6_thscale;
		else
			addr6_src->tr_thscale = no_thscale;
	}
	if (addr_dst != NULL) {
		tree_init(addr_dst, 32, lru_size);
		if (disable_thscale == 0)
			addr_dst->tr_thscale = addr_thscale;
		else
			addr_dst->tr_thscale = no_thscale;
	}
	if (addr6_dst != NULL) {
		tree_init(addr6_dst, 128, lru_size);
		if (disable_thscale == 0)
			addr6_dst->tr_thscale = addr6_thscale;
		else
			addr6_dst->tr_thscale = no_thscale;
	}

	/* fix the lru_size to 512 for protocols */
	if (proto_src != NULL) {
		tree_init(proto_src, 8+8+16, 512);
		if (disable_thscale == 0)
			proto_src->tr_thscale = proto_thscale;
		else
			proto_src->tr_thscale = no_thscale;
	}
	if (proto_dst != NULL) {
		tree_init(proto_dst, 8+8+16, 512);
		if (disable_thscale == 0)
			proto_dst->tr_thscale = proto_thscale;
		else
			proto_dst->tr_thscale = no_thscale;
	}
	/* XXX: agr_flows should be large enough not to get aggregated */
	if (agr_flows != NULL) {
		tree_init(agr_flows, 32, 4096 * 4);
		if (disable_thscale == 0)
			agr_flows->tr_thscale = flow_thscale;
		else
			agr_flows->tr_thscale = no_thscale;
	}
	if (agr_flows6 != NULL) {
		tree_init(agr_flows6, 32, 4096 * 4);
		if (disable_thscale == 0)
			agr_flows6->tr_thscale = flow_thscale;
		else
			agr_flows6->tr_thscale = no_thscale;
	}
	return (0);
}

int
print_header(void)
{
	u_int64_t total[2];
	time_t t;
	double sec, avg;
	double avg2;
	char buf[128];

	printf("%s\n", fmt_string);
	t = start_time.tv_sec;
	if (t > 0) {
		t += timeoffset;	/* adjust time */
		strftime(buf, sizeof(buf), "%a %b %d %T %Y", localtime(&t));
		printf("%%%%StartTime: %s ", buf);
		strftime(buf, sizeof(buf), "%Y/%m/%d %T", localtime(&t));
		printf("(%s)\n", buf);
	}
	t = end_time.tv_sec;
	if (t > 0) {
		t += timeoffset;	/* adjust time */
		strftime(buf, sizeof(buf), "%a %b %d %T %Y", localtime(&t));
		printf("%%%%EndTime:   %s ", buf);
		strftime(buf, sizeof(buf), "%Y/%m/%d %T", localtime(&t));
		printf("(%s)\n", buf);
	}

	total[0] = total[1] = 0;
	if (addr_src != NULL || addr6_src != NULL) {
		if (addr_src != NULL) {
			total[0] += addr_src->tr_count;
			total[1] += addr_src->tr_count2;
		}
		if (addr6_src != NULL) {
			total[0] += addr6_src->tr_count;
			total[1] += addr6_src->tr_count2;
		}
	} else if (addr_dst != NULL || addr6_dst != NULL) {
		if (addr_dst != NULL) {
			total[0] += addr_dst->tr_count;
			total[1] += addr_dst->tr_count2;
		}
		if (addr6_dst != NULL) {
			total[0] += addr6_dst->tr_count;
			total[1] += addr6_dst->tr_count2;
		}
	} else if (proto_src != NULL) {
		total[0] = proto_src->tr_count;
		total[1] = proto_src->tr_count2;
	} else if (proto_dst != NULL) {
		total[0] = proto_dst->tr_count;
		total[1] = proto_dst->tr_count2;
	}

	sec = (double)end_time.tv_sec - start_time.tv_sec
	    + (end_time.tv_usec - start_time.tv_usec) / 1000000;
	if (sec != 0.0) {
		avg = (double)total[0] * 8 / sec;
		avg2 = (double)total[1] / sec;
		if (avg > 1000000.0)
			printf("%%AvgRate: %.2fMbps %.2fpps\n", avg/1000000.0, avg2);
		else
			printf("%%AvgRate: %.2fKbps %.2fpps\n", avg/1000.0, avg2);
	}
	if (addr_src != NULL && addr6_src != NULL)
		printf("%%IPv4/IPv6/total: %"PRIu64"/%"PRIu64"/%"PRIu64" bytes"
		    "  %"PRIu64"/%"PRIu64"/%"PRIu64" packets\n",
		    addr_src->tr_count, addr6_src->tr_count, total[0],
		    addr_src->tr_count2, addr6_src->tr_count2, total[1]);

	print_pcapstat(stdout);
	printf("\n");
	return (0);
}

int
print_summary(void)
{
	struct tree *tp;
	u_int64_t thresh[2];
	u_int64_t total[2];

	if (addr_src != NULL || addr6_src != NULL) {
		total[0] = total[1] = 0;
		if (addr_src != NULL) {
			total[0] += addr_src->tr_count;
			total[1] += addr_src->tr_count2;
		}
		if (addr6_src != NULL) {
			total[0] += addr6_src->tr_count;
			total[1] += addr6_src->tr_count2;
		}
		thresh[0] = total[0] * ip_thresh / 1000;
		thresh[1] = total[1] * ip_thresh / 1000;

		if (addr_src != NULL)
			tree_aggregate(addr_src, thresh);
		if (addr6_src != NULL)
			tree_aggregate(addr6_src, thresh);

		if (verbose > 0) {
			printf("[src address] %"PRIu64" (%.2f%%)\t%"PRIu64" (%.2f%%)\n",
			total[0], 100.0, total[1], 100.0);
			if (addr_src != NULL)
				tree_walk(addr_src, print_ipnode, total);
			if (addr6_src != NULL)
				tree_walk(addr6_src, print_ip6node, total);
		}

#ifdef AGURI_STATS
		if (verbose > 0) {
			u_int all = 0, hits = 0, reclaimed = 0;
			if (addr_src != NULL) {
				all += addr_src->tr_stats.total;
				hits += addr_src->tr_stats.hits;
				reclaimed += addr_src->tr_stats.reclaimed;
			}
			if (addr6_src != NULL) {
				all += addr6_src->tr_stats.total;
				hits += addr6_src->tr_stats.hits;
				reclaimed += addr6_src->tr_stats.reclaimed;
			}
			if (all > 0)
				printf("%%LRU hits: %.2f%% (%u/%u)  "
				    "reclaimed: %u\n",
				    (double)hits / all * 100, hits, all,
				    reclaimed);
		}
#endif
	}
	if (addr_dst != NULL || addr6_dst != NULL) {
		total[0] = total[1] = 0;
		if (addr_dst != NULL) {
			total[0] += addr_dst->tr_count;
			total[1] += addr_dst->tr_count2;
		}
		if (addr6_dst != NULL) {
			total[0] += addr6_dst->tr_count;
			total[1] += addr6_dst->tr_count2;
		}
		thresh[0] = total[0] * ip_thresh / 1000;
		thresh[1] = total[1] * ip_thresh / 1000;

		if (addr_dst != NULL)
			tree_aggregate(addr_dst, thresh);
		if (addr6_dst != NULL)
			tree_aggregate(addr6_dst, thresh);

		if (verbose > 0) {
			printf("[dst address] %"PRIu64" (%.2f%%)\t%"PRIu64" (%.2f%%)\n",
			total[0], 100.0, total[1], 100.0);
			if (addr_dst != NULL)
				tree_walk(addr_dst, print_ipnode, total);
			if (addr6_dst != NULL)
				tree_walk(addr6_dst, print_ip6node, total);
		}
#ifdef AGURI_STATS
		if (verbose > 0) {
			u_int all = 0, hits = 0, reclaimed = 0;
			if (addr_dst != NULL) {
				all += addr_dst->tr_stats.total;
				hits += addr_dst->tr_stats.hits;
				reclaimed += addr_dst->tr_stats.reclaimed;
			}
			if (addr6_dst != NULL) {
				all += addr6_dst->tr_stats.total;
				hits += addr6_dst->tr_stats.hits;
				reclaimed += addr6_dst->tr_stats.reclaimed;
			}
			if (all > 0)
				printf("%%LRU hits: %.2f%% (%u/%u)  "
				    "reclaimed: %u\n",
				    (double)hits / all * 100, hits, all,
				    reclaimed);
		}
#endif
	}
	if (proto_src != NULL) {
		total[0] = proto_src->tr_count;
		total[1] = proto_src->tr_count2;
		thresh[0] = total[0] * ip_thresh / 1000;
		thresh[1] = total[1] * ip_thresh / 1000;

		tree_aggregate(proto_src, thresh);
		if (verbose > 0) {
			printf("[ip:proto:srcport] %"PRIu64" (%.2f%%)\t%"PRIu64" (%.2f%%)\n",
		        total[0], 100.0, total[1], 100.0);
			tree_walk(proto_src, print_protonode, total);
		}
#ifdef AGURI_STATS
		if (verbose > 0) {
			tp = proto_src;
			if (tp->tr_stats.total > 0)
				printf("%%LRU hits: %.2f%% (%u/%u)  "
			    "reclaimed: %u\n",
			    (double)tp->tr_stats.hits /
			    tp->tr_stats.total * 100,
			    tp->tr_stats.hits, tp->tr_stats.total,
			    tp->tr_stats.reclaimed);
		}
#endif
	}
	if (proto_dst != NULL) {
		total[0] = proto_dst->tr_count;
		total[1] = proto_dst->tr_count2;
		thresh[0] = total[0] * ip_thresh / 1000;
		thresh[1] = total[1] * ip_thresh / 1000;

		tree_aggregate(proto_dst, thresh);
		if (verbose > 0) {
			printf("[ip:proto:dstport] %"PRIu64" (%.2f%%)\t%"PRIu64" (%.2f%%)\n",
		        total[0], 100.0, total[1], 100.0);
			tree_walk(proto_dst, print_protonode, total);
		}
#ifdef AGURI_STATS
		if (verbose > 0) {
			tp = proto_dst;
			if (tp->tr_stats.total > 0)
				printf("%%LRU hits: %.2f%% (%u/%u)  "
			    "reclaimed: %u\n",
			    (double)tp->tr_stats.hits /
			    tp->tr_stats.total * 100,
			    tp->tr_stats.hits, tp->tr_stats.total,
			    tp->tr_stats.reclaimed);
		}
#endif
	}
	printf("\n");
	fflush(stdout);
	return (0);
}


int
ipinfo_finish(void)
{
#ifndef AGURI2
	struct tree *tp;
#endif

	if (interval == 0)
		print_summary();

#ifdef AGURI2
	/* not yet */
#else /* !AGURI2 */

	for (tp = &trees[0]; tp < &trees[IP_TREES]; tp++)
		if (tp->tr_top != NULL)
			tree_destroy(tp);
#endif /* !AGURI2 */
	return (0);
}

struct tree *
ip_parsetype(char *buf, size_t len,
	     u_int64_t (**parser)(char *, void *, size_t *, void *),
	     void (**counter)(struct tree *, void *, size_t, void *, u_int64_t))
{
	struct tree *tp;

	if (strncmp("[src address]", buf, 13) == 0) {
		tp = addr_src;
		*parser = ip_addrparser;
	} else if (strncmp("[dst address]", buf, 13) == 0) {
		tp = addr_dst;
		*parser = ip_addrparser;
	} else if (strncmp("[ip:proto:srcport]", buf, 18) == 0) {
		tp = proto_src;
		*parser = ip_protoparser;
	} else if (strncmp("[ip:proto:dstport]", buf, 18) == 0) {
		tp = proto_dst;
		*parser = ip_protoparser;
	} else
		return (NULL);

	*counter = ip_counter;

	if (tp == NULL) {
		/* ignore lines for this type */
		tp = &null_tree;
		*parser = null_parser;
		*counter = null_counter;
	}

	return (tp);
}

static u_int64_t
ip_addrparser(char *buf, void *key, size_t *prefixlen, void *arg)
{
	int af;
	char *cp, *ap;
	size_t len;
	u_int64_t cnt;

	cp = buf;
	/* skip leading white space */
	while (isspace(*cp))
		cp++;
	if (*cp == '\0' || *cp == '%')
		return (0);
	ap = cp;

	if ((cp = strchr(ap, '/')) != NULL) {
		*cp++ = '\0';
		len = strtol(cp, NULL, 0);
	} else {
		cp = ap;
		len = 128;
	}
	cp = strpbrk(cp, " \t");  /* move to the next white space char */
	if (cp == NULL)
		return (0);
	*cp++ = '\0';
	while (isspace(*cp))	/* skip white space */
		cp++;
	cnt = strtouq(cp, NULL, 0);

	if (strchr(ap, ':') != NULL)
		af = AF_INET6;
	else if (strchr(ap, '.') != NULL) {
		af = AF_INET;
		if (len == 128)
			len = 32;
	} else {
		warnx("not ip: %s", buf);
		return (0);
	}

	if (inet_pton(af, ap, key) != 1) {
		warnx("inet_pton: %s", buf);
		return (0);
	}
	*prefixlen = len;
	if (arg != NULL) {
		if (af == AF_INET6)
			*(int *)arg = 1;
		else
			*(int *)arg = 0;
	}
	return (cnt);
}

static u_int64_t
ip_protoparser(char *buf, void *key, size_t *prefixlen, void *arg)
{
	struct proto *pdata;
	char *cp, *ap, *pp;
	size_t len;
	u_int64_t cnt;

	pdata = key;
	len = 999;
	cp = buf;
	/* skip leading white space */
	while (isspace(*cp))
		cp++;
	if (*cp == '\0' || *cp == '%')
		return(0);

	/* ip version */
	ap = cp;
	if ((cp = strchr(ap, ':')) == NULL)
		goto bad;
	*cp++ = '\0';
	if ((pp = strchr(ap, '/')) != NULL) {
		*pp++ = '\0'; 
		len = strtoul(pp, NULL, 0);
	}
	pdata->p_ipver = (u_char)strtoul(ap, NULL, 0);

	/* proto */
	while (isspace(*cp))	/* skip white space */
		cp++;
	ap = cp;
	if ((cp = strchr(ap, ':')) == NULL)
		goto bad;
	*cp++ = '\0';
	if ((pp = strchr(ap, '/')) != NULL) {
		*pp++ = '\0'; 
		len = 8 + strtoul(pp, NULL, 0);
	}
	pdata->p_proto = (u_char)strtoul(ap, NULL, 0);

	/* port */
	while (isspace(*cp))	/* skip white space */
		cp++;
	ap = cp;
	cp = strpbrk(cp, " \t");  /* move to the next white space char */
	if (cp == NULL)
		return (0);
	*cp++ = '\0';
	if ((pp = strchr(ap, '/')) != NULL) {
		*pp++ = '\0'; 
		len = 8 + 8 + strtoul(pp, NULL, 0);
	} else if (len == 999)
		len = 8 + 8 + 16;
	pdata->p_port = htons((u_short)strtoul(ap, NULL, 0));

	/* count */
	while (isspace(*cp))	/* skip white space */
		cp++;
	cnt = strtouq(cp, NULL, 0);

	*prefixlen = len;
	if (arg != NULL)
		*(int *)arg = 0;

	return (cnt);

  bad:
	warnx("parseproto: %s", buf);
	return (0);
}

static void
ip_counter(struct tree *tp, void *key, size_t prefixlen,
	   void *arg, u_int64_t cnt)
{
	/* arg points to offset of the tree array (used for addr6 trees). */
	if (arg != NULL)
		tp += *(int *)arg;

	(void)tnode_addcount(tp, key, prefixlen, cnt, 1);
}

/*
 * plot format support
 */
int
ipplot_phase1(int nentries)
{
	if (addr_src != NULL)
		plot_phase1(addr_src, 2, nentries);
	if (addr_dst != NULL)
		plot_phase1(addr_dst, 2, nentries);
	if (proto_src != NULL)
		plot_phase1(proto_src, 1, nentries);
	if (proto_dst != NULL)
		plot_phase1(proto_dst, 1, nentries);
	return (0);
}

int
ipplot_phase2(void)
{
	if (addr_src != NULL) {
		printf("#[src address]\n");
		ipplot_printnames(addr_src);
		plot_phase2(addr_src);
	}
	if (addr_dst != NULL) {
		printf("#[dst address]\n");
		ipplot_printnames(addr_dst);
		plot_phase2(addr_dst);
	}
	if (proto_src != NULL) {
		printf("#[ip:proto:srcport]\n");
		ipplot_printnames(proto_src);
		plot_phase2(proto_src);
	}
	if (proto_dst != NULL) {
		printf("#[ip:proto:dstport]\n");
		ipplot_printnames(proto_dst);
		plot_phase2(proto_dst);
	}
	return (0);
}

/*
 * plot phase1 parser is the same as normal case.
 */
struct tree *
ipplot_parse1(char *buf, size_t len,
	     u_int64_t (**parser)(char *, void *, size_t *, void *),
	     void (**counter)(struct tree *, void *, size_t, void *, u_int64_t))
{
	return (ip_parsetype(buf, len, parser, counter));
}

/*
 * plot phase2 uses a different counter
 */
struct tree *
ipplot_parse2(char *buf, size_t len,
	     u_int64_t (**parser)(char *, void *, size_t *, void *),
	     void (**counter)(struct tree *, void *, size_t, void *, u_int64_t))
{
	struct	tree *tp;

	tp = ip_parsetype(buf, len, parser, counter);

	/* override the counter */
	if (tp != NULL)
		*counter = ipplot_counter;
	return (tp);
}

static void
ipplot_counter(struct tree *tp, void *key, size_t prefixlen,
	       void *arg, u_int64_t cnt)
{
	struct tree_node *np;
	struct plot_list *pl;
	struct plot_entry *ep;

	if (plot_timestamps[time_slot] == 0)
		plot_timestamps[time_slot] = end_time.tv_sec;

	/* arg points to offset of the tree array (used for addr6 trees). */
	if (arg != NULL)
		tp += *(int *)arg;

	/* need to call tnode_addcount without cnt to maintain the tree */
	np = tnode_addcount(tp, key, prefixlen, 0, 0);

	/* add count to the plot list entry */
	pl = tree2plotlist(tp);
	while ((ep = tnode2pentry(np)) == NULL) {
		np = np->tn_parent;
		if (np == NULL)
			return;
	}
	ep->pe_counts[time_slot] += cnt;
}

static void
ipplot_printnames(struct tree *tp)
{
	struct plot_list *pl;
	struct plot_entry *ep;
	struct tree_node *np;
	char buf[INET6_ADDRSTRLEN + 8];

	if ((pl = tree2plotlist(tp)) == NULL)
		return;
	if (pl->pl_num == 0)
		/* no entries */
		return;
	printf("#time total ");
	for (ep = TAILQ_FIRST(&pl->pl_head); ep != NULL;
	     ep = TAILQ_NEXT(ep, pe_chain)) {
		np = ep->pe_node;
		ip_nodename(np, buf, sizeof(buf));
		printf("%s ", buf);
	}
	printf("\n");
}

static u_int64_t
null_parser(char *buf, void *key, size_t *prefixlen, void *arg)
{
	return (0);
}

static void
null_counter(struct tree *tp, void *key, size_t prefixlen,
	       void *arg, u_int64_t cnt)
{
}

int
aguri2_setup(void)
{
	int n;

	flow_num = flow_num6 = 0;
	if (addr_src->tr_indices > 254 || addr_dst->tr_indices > 254
#ifdef INET6
		|| addr6_src->tr_indices > 254 || addr6_dst->tr_indices > 254
#endif
		) {
		warnx("aguri2_setup: indices too large!");
		return (0);
	}
	n = addr_src->tr_indices * addr_dst->tr_indices;
	if (n > 0) {
		printf("#epoch=%d flow_matrix: %dx%d=%d ports: %dx%d\n",
			addr_src->tr_epoch, addr_src->tr_indices,
			addr_dst->tr_indices, n, 
			proto_src->tr_indices, proto_dst->tr_indices);
		flow_matrix = calloc(n, sizeof(struct dbl_counters));
	}
#ifdef INET6
	if (agr_flows6 != NULL) {
		n = addr6_src->tr_indices * addr6_dst->tr_indices;
		if (n > 0) {
			printf("#        flow_matrix6: %dx%d=%d ports: %dx%d\n",
				addr6_src->tr_indices,
				addr6_dst->tr_indices, n, 
				proto_src->tr_indices, proto_dst->tr_indices);
			flow_matrix6 = calloc(n, sizeof(struct dbl_counters));
		}
	}
#endif
	return (0);
}

struct flow_entry {
	int	fe_ipver, fe_srcindex, fe_dstindex;
	double	fe_ratio, fe_ratio2;
};

static int
flow_comp(const void *p0, const void *p1)
{
	const struct flow_entry *f0, *f1;
	double v0, v1;

	f0 = p0;
	f1 = p1;
	v0 = (f0->fe_ratio >= f0->fe_ratio2) ? f0->fe_ratio : f0->fe_ratio2;
	v1 = (f1->fe_ratio >= f1->fe_ratio2) ? f1->fe_ratio : f1->fe_ratio2;
	if (v0 > v1)
		return (-1);
	else if (v0 < v1)
		return (1);
	return (0);
}

#define RINDEX_IPV4	0
#define RINDEX_IPV6	1

int
aguri2_summary(void)
{
	int i, j, k, n, entries, ipver;
	u_int64_t	total, total2;
	struct dbl_counters *dp;
	struct tree_node **rindex_src[2] = {NULL, NULL};
	struct tree_node **rindex_dst[2] = {NULL, NULL};
	struct tree_node **rindex_sproto, **rindex_dproto, *np;
	struct flow_entry *flow_entries;
	struct tree *satp[2] = {addr_src, addr6_src};
	struct tree *datp[2] = {addr_dst, addr6_dst};
	struct tree *agtp[2] = {agr_flows, agr_flows6};
	struct dbl_counters *matrix[2] = {flow_matrix, flow_matrix6};
#ifdef DEBUG
	struct timeval t1, t2;

	gettimeofday(&t1, NULL);
#endif

	if (flow_matrix == NULL)
		/* should be the first round */
		return (0);

	total = addr_src->tr_count;
	total2 = addr_src->tr_count2;
	if (agr_flows6 != NULL) {
		total  += addr6_src->tr_count;
		total2 += addr6_src->tr_count2;
	}
	if (total == 0 || total2 == 0)
		return (0);

	/*
	 * make aggregated flow summaries for IPv4 and IPv6
	 */
	rindex_sproto = malloc(sizeof(struct tree_node *) * proto_src->tr_indices);
	if (rindex_sproto == NULL)
		err(1, "aguri2_summary: malloc");
	tree_setrindices(proto_src, rindex_sproto);
	rindex_dproto = malloc(sizeof(struct tree_node *) * proto_dst->tr_indices);
	if (rindex_dproto == NULL)
		err(1, "aguri2_summary: malloc");
	tree_setrindices(proto_dst, rindex_dproto);

	entries = flow_num + flow_num6;
	flow_entries = malloc(sizeof(struct flow_entry) * entries);
	if (flow_entries == NULL)
		err(1, "aguri2_summary: malloc");

	k = 0;  /* index of flow_entries */
	for (ipver = RINDEX_IPV4; ipver <= RINDEX_IPV6; ipver++) {
		if (ipver == RINDEX_IPV6 && agr_flows6 == NULL)
			break;

		if (verbose > 2) {
			printf("\n[flow_matrix:bytes]\n");
			dp = matrix[ipver];
			n = 0;
			for (i = 0; i < satp[ipver]->tr_indices; i++) {
				printf("[%2d] ", i);
				for (j = 0; j < datp[ipver]->tr_indices; j++) {
					printf(" %"PRIu64"", dp->dc_count);
					if (dp->dc_count != 0)
						n++;
					dp++;
				}
				printf("\n");
			}

			printf("\n[flow_matrix:packets]\n");
			dp = matrix[ipver];
			n = 0;
			for (i = 0; i < satp[ipver]->tr_indices; i++) {
				printf("[%2d] ", i);
				for (j = 0; j < datp[ipver]->tr_indices; j++) {
					printf(" %"PRIu64"", dp->dc_count2);
					if (dp->dc_count2 != 0)
						n++;
					dp++;
				}
				printf("\n");
			}
		}

		rindex_src[ipver] = malloc(sizeof(struct tree_node *) * satp[ipver]->tr_indices);
		if (rindex_src[ipver] == NULL)
			err(1, "aguri2_summary: malloc");
		tree_setrindices(satp[ipver], rindex_src[ipver]);

		rindex_dst[ipver] = malloc(sizeof(struct tree_node *) * datp[ipver]->tr_indices);
		if (rindex_dst[ipver] == NULL)
			err(1, "aguri2_summary: malloc");
		tree_setrindices(datp[ipver], rindex_dst[ipver]);

#ifdef AGURI_STATS
		if (verbose > 1) {
			struct tree *tp = agtp[ipver];
			if (tp->tr_stats.total > 0)
				printf("#[agr_flows%s] %%LRU hits: %.2f%% (%u/%u)  "
				"reclaimed: %u\n",
				(ipver == RINDEX_IPV4 ? "" : "6"),
				(double)tp->tr_stats.hits /
				tp->tr_stats.total * 100,
				tp->tr_stats.hits, tp->tr_stats.total,
				tp->tr_stats.reclaimed);
		}
#endif

		dp = matrix[ipver];
		for (i = 0; i < satp[ipver]->tr_indices; i++) {
			for (j = 0; j < datp[ipver]->tr_indices; j++) {
				if (dp->dc_count != 0) {
					assert(k < entries);
					flow_entries[k].fe_ipver = ipver;
					flow_entries[k].fe_srcindex = i;
					flow_entries[k].fe_dstindex = j;
					flow_entries[k].fe_ratio =
					    (double)dp->dc_count / total;
					flow_entries[k].fe_ratio2 =
					    (double)dp->dc_count2 / total2;
					k++;
				}
				dp++;
			}
		}
	}

	/* sort flow entries */
	qsort(flow_entries, entries, sizeof(struct flow_entry), flow_comp);

	printf("\n# aggregated flow summary: 1st line on src-dst, 2nd line on protos\n");
	printf("#  [rank] src dst: bytes (bytes%%) packets (packets%%)\n");
	printf("#     [proto:sport:dport] bytes%% packets%% ...\n");

	for (i = 0; i < entries; i++) {
		char buf[INET6_ADDRSTRLEN + 8];
		struct flow_entry *fe = &flow_entries[i];
		int srcindex, dstindex;

		printf("[%2d] ", i);
		srcindex = fe->fe_srcindex;
		np = rindex_src[fe->fe_ipver][srcindex];
		ip_nodename(np, buf, sizeof(buf));
		printf("%s ", buf);
		dstindex = fe->fe_dstindex;
		np = rindex_dst[fe->fe_ipver][dstindex];
		ip_nodename(np, buf, sizeof(buf));
		printf("%s", buf);

		dp = matrix[fe->fe_ipver] +
		    srcindex * datp[fe->fe_ipver]->tr_indices + dstindex;
		printf(": %"PRIu64" (%.2f%%)\t%"PRIu64" (%.2f%%)\n",
			dp->dc_count, fe->fe_ratio * 100,
			dp->dc_count2, fe->fe_ratio2 * 100);

		print_protos(agtp[fe->fe_ipver], srcindex, dstindex, dp->dc_count,
			dp->dc_count2, rindex_sproto, rindex_dproto);
	}
	printf("\n");

	if (rindex_src[RINDEX_IPV4] != NULL)
		free(rindex_src[RINDEX_IPV4]);
	if (rindex_dst[RINDEX_IPV4] != NULL)
		free(rindex_dst[RINDEX_IPV4]);
	if (rindex_src[RINDEX_IPV6] != NULL)
		free(rindex_src[RINDEX_IPV6]);
	if (rindex_dst[RINDEX_IPV6] != NULL)
		free(rindex_dst[RINDEX_IPV6]);

	free(flow_entries);

	free(rindex_sproto);
	free(rindex_dproto);

	free(flow_matrix);
	flow_matrix = NULL;
	if (flow_matrix6 != NULL) {
		free(flow_matrix6);
		flow_matrix6 = NULL;
	}

#ifdef DEBUG
	{
		double t;

		gettimeofday(&t2, NULL);
		t = (double)(t2.tv_sec - t1.tv_sec) +
		    (double)(t2.tv_usec - t1.tv_usec) / 1000000.0;
		printf("aguri2_summary: %.6f sec\n", t);
	}
#endif
	return (0);
}

static void print_port(struct tree_node *np);

static void
print_port(struct tree_node *np)
{
	u_short port, end;

	if (np->tn_prefixlen <= 16) {
		printf("*");
		return;
	}
	port = ntohs(*(u_short *)&np->tn_key[2]) & ~((1 << (32 - np->tn_prefixlen)) - 1);
	if (np->tn_prefixlen == 32) {
		printf("%d", port);
		return;
	}

	end = port + (1 << (32 - np->tn_prefixlen)) - 1;
	printf("%d-%d", port, end);
}

#define MAX_FE	128

static void
print_protos(struct tree *tp, int saddr_index, int daddr_index,
	u_int64_t count, u_int64_t count2,
	struct tree_node **rindex_sproto, struct tree_node **rindex_dproto)
{
	u_char index_key[4];
	int	entries, i;
	struct tree_node *top, *np, *np2;
	struct flow_entry flow_entries[MAX_FE];

	index_key[0] = (u_char)saddr_index;
	index_key[1] = (u_char)daddr_index;
	index_key[2] = 0;
	index_key[3] = 0;

	if ((np = tree_match(tp, index_key, 16)) == NULL) {
		warnx("print_protos: tree_match");
		return;
	}

	if (np->tn_prefixlen < 16) {
		/* the entry was aggregated beyond the flow level */
		if (verbose > 0)
			printf("print_protos: too short! saddr_index:%d daddr_index:%d key[%d %d %d %d] prefixlen=%lu\n",
				saddr_index, daddr_index,
				np->tn_key[0], np->tn_key[1], np->tn_key[2], np->tn_key[3],
				np->tn_prefixlen);
		printf("\n");
		return;
	}

	/* walk through the subtree */
#if 0
	printf("  [%d,%d][%d,%d,%d,%d/%d] %"PRIu64" %"PRIu64"\n",
		saddr_index, daddr_index,
		np->tn_key[0],np->tn_key[1],np->tn_key[2],np->tn_key[3], np->tn_prefixlen, 
		subtree_sum(np), subtree_sum2(np));
#endif
	entries = 0;
	top = np;
	while (1) {
		/*
		 * use the entry if the count is positive,
		 * and the node is not aggregated,
		 */
		if (np->tn_count != 0 &&
			np->tn_prefixlen == tp->tr_keylen) {
#if 0
			printf("[%d,%d] %"PRIu64" %"PRIu64" ",
				np->tn_key[2], np->tn_key[3],
				np->tn_count, np->tn_count2);
#endif
			assert(np->tn_key[0] == (u_char)saddr_index);
			assert(np->tn_key[1] == (u_char)daddr_index);
			assert(np->tn_key[2] < (u_char)proto_src->tr_indices);
			assert(np->tn_key[3] < (u_char)proto_dst->tr_indices);

			flow_entries[entries].fe_srcindex = np->tn_key[2];
			flow_entries[entries].fe_dstindex = np->tn_key[3];
			flow_entries[entries].fe_ratio = (double)np->tn_count / count;
			flow_entries[entries].fe_ratio2 = (double)np->tn_count2 / count2;
			entries++;
			if (entries == MAX_FE) {
				warnx("print_protos: exceeds MAX_FE");
				break;
			}
		}
			
		if (np->tn_left != NULL) {
			np = np->tn_left;
		} else {
			while (np != top &&
			       np == np->tn_parent->tn_right) {
				np = np->tn_parent;
			}
			if (np == top)
				break;
			np = np->tn_parent->tn_right;
		}
	}

	/* sort flow entries */
	qsort(flow_entries, entries, sizeof(struct flow_entry), flow_comp);

	printf("      ");
	for (i = 0; i < 5; i++) {
		if (i == entries)
			break;
		if (flow_entries[i].fe_ratio < 0.03 &&
		    flow_entries[i].fe_ratio2 < 0.03)
			break;
		np = rindex_sproto[flow_entries[i].fe_srcindex];
		np2 = rindex_dproto[flow_entries[i].fe_dstindex];
		if (np->tn_prefixlen >= 8)
			printf("[%d:", np->tn_key[1]);
		else if (np2->tn_prefixlen >= 8)
			printf("[%d:", np2->tn_key[1]);
		else
				printf("[*:");
		print_port(np);
		printf(":");
		print_port(np2);
		printf("]");
		printf("%.1f%% %.1f%% ", flow_entries[i].fe_ratio * 100, flow_entries[i].fe_ratio2 * 100);
	}

	printf("\n");
}


