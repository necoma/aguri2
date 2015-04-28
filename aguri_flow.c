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

#include <sys/socket.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "aguri.h"
#include "aguri_tree.h"
#include "aguri_flow.h"
#include "aguri_ip.h"
#include "aguri_pcap.h"

static int saddr_index, daddr_index;

/*
 * parse aguri flow record: returns 1 to process this packets, 0 otherwise.
 */
int agflow_doheader(const struct aguri_flow *agf)
{
	static time_t first_interval = 0;
	static time_t next_interval = 0;
	static time_t ts_max;
	time_t ts;

	ts = (time_t)ntohl(agf->agflow_last);
	if (ts > ts_max)
		ts_max = ts;	/* keep track of the max value of ts */
	ts = ts_max;  /* XXX we want ts to be monotonic */

	if (interval == 0) {
		if (start_time.tv_sec == 0)
			/* first packet. initialize the start time */
			start_time.tv_sec = ts;
		end_time.tv_sec = ts;	/* keep the timestamp of the last packet */
		return (1);
	}

	/*
	 * interval is specified.
	 *  - align the start and end time
	 *  - print summary at the end of each interval
	 */
	if (start_time.tv_sec == 0) {
		if (first_interval == 0)
			first_interval = (ts + interval - 1) / interval * interval;
		if (ts < first_interval)
			return (0);

		/* align the start time to the boundary */
		start_time.tv_sec = first_interval;
		start_time.tv_usec = 0;
		next_interval = first_interval + interval;
	}

	if (ts >= next_interval) {
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

	end_time.tv_sec = ts;	/* keep the timestamp of the last packet */
	return (1);
}

int
agflow_dov4(const struct aguri_flow *agf)
{
	u_int64_t cnt, cnt2;

	cnt = ntohl(agf->agflow_bytes);
	cnt2 = ntohl(agf->agflow_packets);
	if (addr_src != NULL)
		leaf_addcount(addr_src, &agf->agflow_fs.fs_srcaddr, cnt, cnt2);
	if (addr_dst != NULL)
		leaf_addcount(addr_dst, &agf->agflow_fs.fs_dstaddr, cnt, cnt2);

	if (flow_matrix != NULL) {
		struct tree *tp;
		struct tree_node *np, *np2;
		struct dbl_counters *dp = NULL;

		tp = addr_src;
		np = tree_matchindex(tp, &agf->agflow_fs.fs_srcaddr, tp->tr_keylen);
		tp = addr_dst;
		np2 = tree_matchindex(tp, &agf->agflow_fs.fs_dstaddr, tp->tr_keylen);
#if 0
		printf("aguri2: %d %d\n", np->tn_index, np2->tn_index);
#endif
		dp = flow_matrix + np->tn_index * tp->tr_indices + np2->tn_index;
		if (dp->dc_count == 0)
			flow_num++;	/* this is a new flow entry */
		dp->dc_count += cnt;
		dp->dc_count2 += cnt2;

		/* save the indices */
		saddr_index = np->tn_index;
		daddr_index = np2->tn_index;
	}
	agflow_doproto(agf, cnt, cnt2);
	return (1);
}

#ifdef INET6
int
agflow_dov6(const struct aguri_flow *agf)
{
	u_int64_t cnt, cnt2;

	cnt = ntohl(agf->agflow_bytes);
	cnt2 = ntohl(agf->agflow_packets);
	if (addr6_src != NULL)
		leaf_addcount(addr6_src, &agf->agflow_fs.fs_srcaddr, cnt, cnt2);
	if (addr6_dst != NULL)
		leaf_addcount(addr6_dst, &agf->agflow_fs.fs_dstaddr, cnt, cnt2);

	if (flow_matrix6 != NULL) {
		struct tree *tp;
		struct tree_node *np, *np2;
		struct dbl_counters *dp = NULL;

		tp = addr6_src;
		np = tree_matchindex(tp, &agf->agflow_fs.fs_srcaddr, tp->tr_keylen);
		tp = addr6_dst;
		np2 = tree_matchindex(tp, &agf->agflow_fs.fs_dstaddr, tp->tr_keylen);
#if 0
		printf("aguri2: %d %d\n", np->tn_index, np2->tn_index);
#endif
		dp = flow_matrix6 + np->tn_index * tp->tr_indices + np2->tn_index;
		if (dp->dc_count == 0)
			flow_num6++;  /* this is a new flow entry */
		dp->dc_count += cnt;
		dp->dc_count2 += cnt2;

		/* save the indices */
		saddr_index = np->tn_index;
		daddr_index = np2->tn_index;
	}
	agflow_doproto6(agf, cnt, cnt2);
	return (1);
}
#endif

int
agflow_doproto(const struct aguri_flow *agf, u_int64_t cnt, u_int64_t cnt2)
{
	struct proto pdata;

	pdata.p_ipver = agf->agflow_fs.fs_ipver;
	pdata.p_proto = agf->agflow_fs.fs_prot;
	if (proto_src != NULL) {
		pdata.p_port = agf->agflow_fs.fs_sport;
		leaf_addcount(proto_src, &pdata, cnt, cnt2);
	}
	if (proto_dst != NULL) {
		pdata.p_port = agf->agflow_fs.fs_dport;
		leaf_addcount(proto_dst, &pdata, cnt, cnt2);
	}

	if (flow_matrix != NULL) {
		struct tree *tp;
		struct tree_node *np, *np2;
		u_char index_key[4];

		np = np2 = NULL;
		if (proto_src != NULL) {
			pdata.p_port = agf->agflow_fs.fs_sport;
			tp = proto_src;
			np = tree_matchindex(tp, &pdata, tp->tr_keylen);
		}
		if (proto_dst != NULL) {
			pdata.p_port = agf->agflow_fs.fs_dport;
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

		leaf_addcount(agr_flows, index_key, cnt, cnt2);
	}

	return (1);
}

#ifdef INET6
int
agflow_doproto6(const struct aguri_flow *agf, u_int64_t cnt, u_int64_t cnt2)
{
	struct proto pdata;

	if ((xflags & CHECK_IPV6) == 0)
		return (0);

	pdata.p_ipver = agf->agflow_fs.fs_ipver;
	pdata.p_proto = agf->agflow_fs.fs_prot;

	if (proto_src != NULL) {
		pdata.p_port = agf->agflow_fs.fs_sport;
		leaf_addcount(proto_src, &pdata, cnt, cnt2);
	}
	if (proto_dst != NULL) {
		pdata.p_port = agf->agflow_fs.fs_dport;
		leaf_addcount(proto_dst, &pdata, cnt, cnt2);
	}

	if (flow_matrix6 != NULL) {
		struct tree *tp;
		struct tree_node *np, *np2;
		u_char index_key[4];

		np = np2 = NULL;
		if (proto_src != NULL) {
			pdata.p_port = agf->agflow_fs.fs_sport;
			tp = proto_src;
			np = tree_matchindex(tp, &pdata, tp->tr_keylen);
		}
		if (proto_dst != NULL) {
			pdata.p_port = agf->agflow_fs.fs_dport;
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

		leaf_addcount(agr_flows6, index_key, cnt, cnt2);
	}

	return (1);
}
#endif /* INET6 */
