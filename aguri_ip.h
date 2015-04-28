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

struct proto {
	u_char	p_ipver;
	u_char	p_proto;
	u_short	p_port;
};

extern int xflags;
#define	CHECK_SRCADDR		1
#define	CHECK_DSTADDR		2
#define	CHECK_SRCPROTO		4
#define	CHECK_DSTPROTO		8
#define	CHECK_IPV4	       16
#define	CHECK_IPV6	       32
#define	CHECK_FLOWS	       64

extern struct tree *addr_src, *addr6_src, *addr_dst, *addr6_dst;
extern struct tree *proto_src, *proto_dst;
extern struct tree *agr_flows, *agr_flows6;
extern int ip_thresh;
extern int flow_num, flow_num6;

int ipinfo_init(void);
int ipinfo_finish(void);
struct tree * ip_parsetype(char *buf, size_t len,
	u_int64_t (**parser)(char *, void *, size_t *, void *),
	void (**counter)(struct tree *, void *, size_t, void *, u_int64_t));
int ipplot_phase1(int nentries);
int ipplot_phase2(void);
struct tree * ipplot_parse1(char *buf, size_t len,
	u_int64_t (**parser)(char *, void *, size_t *, void *),
	void (**counter)(struct tree *, void *, size_t, void *, u_int64_t));
struct tree * ipplot_parse2(char *buf, size_t len,
	u_int64_t (**parser)(char *, void *, size_t *, void *),
	void (**counter)(struct tree *, void *, size_t, void *, u_int64_t));

int print_header(void);
int print_summary(void);

int aguri2_setup(void);
int aguri2_summary(void);
