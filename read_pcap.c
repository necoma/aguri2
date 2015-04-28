/* $Id: read_pcap.c 311 2013-10-01 06:07:36Z kjc $ */
/* read_pcap.c -- a module to read ethernet packets.
   most parts are derived from tcpdump. */
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * tcpdump - monitor tcp/ip traffic on an ethernet.
 *
 * First written in 1987 by Van Jacobson, Lawrence Berkeley Laboratory.
 * Mercilessly hacked and occasionally improved since then via the
 * combined efforts of Van, Steve McCanne and Craig Leres of LBL.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <net/if.h>
#ifdef __OpenBSD__
#include <net/if_pflog.h>
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#include <pcap.h>

#include "read_pcap.h"

#ifndef IP_V
#define IP_V(ip)	((ip)->ip_v)
#define IP_HL(ip)	((ip)->ip_hl)
#endif
#define IP4F_TABSIZE		64	/* IPv4 fragment cache size */

static void ether_if_read(u_char *user, const struct pcap_pkthdr *h,
			  const u_char *p);
static void fddi_if_read(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *p);
static void atm_if_read(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *p);
static void ppp_if_read(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *p);
static void null_if_read(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *p);
#ifdef PFLOG_HDRLEN
static void pflog_if_read(u_char *user, const struct pcap_pkthdr *h,
			  const u_char *p);
#endif
static int ether_encap_read(const u_short ethtype, const u_char *p,
			    const int length, const int caplen);
static int llc_read(const u_char *p, const int length, const int caplen);
static int ip_read(const u_char *bp, int length);
static void ip4f_cache(struct ip *, struct udphdr *);
static struct udphdr *ip4f_lookup(struct ip *);
static int ip4f_init(void);
static struct ip4_frag *ip4f_alloc(void);
static void ip4f_free(struct ip4_frag *);
#ifdef INET6
static int ip6_read(const u_char *bp, int length);
static int read_ip6hdr(struct ip6_hdr *ip6, int *proto);
#endif

const u_char *packetp;
const u_char *snapend;

/* a function switch to read different types of frames */
void (*net_reader)(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

struct ip4_frag {
    TAILQ_ENTRY(ip4_frag) ip4f_chain;
    char    ip4f_valid;
    u_char ip4f_proto;
    u_short ip4f_id;
    struct in_addr ip4f_src, ip4f_dst;
    struct udphdr ip4f_udphdr;
};

static TAILQ_HEAD(ip4f_list, ip4_frag) ip4f_list; /* IPv4 fragment cache */

struct printer {
	pcap_handler f;
	int type;
};

static struct printer printers[] = {
	{ ether_if_read,	DLT_EN10MB },
	{ fddi_if_read,	DLT_FDDI },
#ifdef DLT_ATM_RFC1483
	{ atm_if_read,	DLT_ATM_RFC1483 },
#endif
	{ ppp_if_read,	DLT_PPP },
	{ null_if_read,	DLT_NULL },
#ifdef PFLOG_HDRLEN
	{ pflog_if_read,	DLT_PFLOG },
#endif
	{ NULL,			0 },
};

pcap_handler
lookup_printer(int type)
{
	struct printer *p;

	for (p = printers; p->f; ++p)
		if (type == p->type)
			return p->f;

	errx(1, "lookup_printer: unknown data link type 0x%x", type);
	/* NOTREACHED */
	return NULL;
}

void
dump_reader(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	if (do_pkthdr((const struct timeval *)&h->ts, h->caplen, h->len))
		(*net_reader)(user, h, p);
}

static void
ether_if_read(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	int caplen = h->caplen;
	int length = h->len;
	struct ether_header *ep;
	u_short ether_type;

	if (caplen < sizeof(struct ether_header)) {
		return;
	}

	/*
	 * Some printers want to get back at the ethernet addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	packetp = p;
	snapend = p + caplen;

	ep = (struct ether_header *)p;
	ether_type = ntohs(ep->ether_type);
	p += sizeof(struct ether_header);
	length -= sizeof(struct ether_header);
	caplen -= sizeof(struct ether_header);

#ifdef ETHERTYPE_VLAN
	if (ether_type == ETHERTYPE_VLAN) {
		if (caplen < 4)
			return;
		ether_type = ntohs(*(u_int16_t *)(p + 2));
		p += 4;
		caplen -= 4;
		length -= 4;
	}
#endif

	if (ether_type < ETHERMTU) {
		if (llc_read(p, length, caplen) == 0) {
			/* ether_type not known */
		}
	} else if (ether_encap_read(ether_type, p, length, caplen) == 0) {
		/* ether_type not known */
	}
}

static int
ether_encap_read(const u_short ethtype, const u_char *p,
		 const int length, const int caplen)
{
	switch (ethtype) {
	case ETHERTYPE_IP:
		ip_read(p, length);
		break;
#ifdef INET6
	case ETHERTYPE_IPV6:
		ip6_read(p, length);
		break;
#endif
	default:
		return (0);
	}
	return (1);
}

/*
 * Length of an FDDI header; note that some compilers may pad
 * "struct fddi_header" to a multiple of 4 bytes, for example, so
 * "sizeof (struct fddi_header)" may not give the right
 * answer.
 */
#define FDDI_HDRLEN 13

static void
fddi_if_read(u_char *pcap, const struct pcap_pkthdr *h, const u_char *p)
{
	int caplen = h->caplen;
	int length = h->len;
	const struct fddi_header *fddip = (struct fddi_header *)p;

	if (p + FDDI_HDRLEN > snapend)
		return;
    
	/*
	 * Some printers want to get back at the link level addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	packetp = p;
	snapend = p + caplen;

	/* Skip over FDDI MAC header */
	length -= FDDI_HDRLEN;
	p += FDDI_HDRLEN;
	caplen -= FDDI_HDRLEN;

	/* Frame Control field determines interpretation of packet */
	if ((fddip->fddi_fc & FDDIFC_CLFF) == FDDIFC_LLC_ASYNC) {
		/* Try to print the LLC-layer header & higher layers */
		if (llc_read(p, length, caplen) == 0) {
			/*
			 * some kinds of LLC packet we cannot
			 * handle intelligently
			 */
		}
	} else {
		/* Some kinds of FDDI packet we cannot handle intelligently */
	}
}

#ifndef min
#define min(a, b)	(((a)<(b))?(a):(b))
#endif
#define	ethertype	ctl.snap_ether.snap_ethertype

static int
llc_read(const u_char *p, const int length, const int caplen)
{
	struct llc llc;
	register u_short et;
	register int ret;
    
	if (caplen < 3)
		return(0);

	/* Watch out for possible alignment problems */
	memcpy((char *)&llc, (char *)p, min(caplen, sizeof(llc)));

#if 0  /* we are not interested in these */
	if (llc.ssap == LLCSAP_GLOBAL && llc.dsap == LLCSAP_GLOBAL) {
		/* ipx */
		return (1);
	} else if (p[0] == 0xf0 && p[1] == 0xf0) {
		/* netbios */
	}
	if (llc.ssap == LLCSAP_ISONS && llc.dsap == LLCSAP_ISONS
	    && llc.llcui == LLC_UI) {
		/* iso */
	}
#endif /* 0 */

	if (llc.ssap == LLCSAP_SNAP && llc.dsap == LLCSAP_SNAP
	    && llc.llcui == LLC_UI) {
		/* snap */
		if (caplen < sizeof(llc)) {
			return (0);
		}
		/* This is an encapsulated Ethernet packet */
#ifdef ALIGN_WORD
		{
			u_short tmp;
			memcpy(&tmp, &llc.ethertype[0], sizeof(u_short));
			et = ntohs(tmp);
		}
#else
		et = ntohs(*(u_short *)&llc.ethertype[0]);
#endif
		ret = ether_encap_read(et, p + sizeof(llc),
				       length - sizeof(llc),
				       caplen - sizeof(llc));
		if (ret)
			return (ret);
	}
	/* llcsap */
	return(0);
}
#undef ethertype

static void
atm_if_read(u_char *pcap, const struct pcap_pkthdr *h, const u_char *p)
{
	int caplen = h->caplen;
	int length = h->len;
	u_short ether_type;

	if (caplen < 8)
		return;

	if (p[0] != 0xaa || p[1] != 0xaa || p[2] != 0x03) {
		/* unknown format! */
		return;
	}
	ether_type = p[6] << 8 | p[7];

	/*
	 * Some printers want to get back at the ethernet addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	packetp = p;
	snapend = p + caplen;

	length -= 8;
	caplen -= 8;
	p += 8;

	switch (ether_type) {
	case ETHERTYPE_IP:
		ip_read(p, length);
		break;
#ifdef INET6
	case ETHERTYPE_IPV6:
		ip6_read(p, length);
		break;
#endif
	}
}

/* just trim 4 byte ppp header */
static void
ppp_if_read(u_char *pcap, const struct pcap_pkthdr *h, const u_char *p)
{
	int caplen = h->caplen;
	int length = h->len;

	if (caplen < 4)
		return;

	/*
	 * Some printers want to get back at the link level addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	packetp = p;
	snapend = p + caplen;

	length -= 4;
	caplen -= 4;
	p += 4;

	ip_read(p, length);
}

#define	NULL_HDRLEN 4	/* DLT_NULL header length */

static void
null_if_read(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	int length = h->len;
	int caplen = h->caplen;
	const struct ip *ip;

	/*
	 * Some printers want to get back at the link level addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	packetp = p;
	snapend = p + caplen;

	length -= NULL_HDRLEN;
	ip = (struct ip *)(p + NULL_HDRLEN);
	switch (IP_V(ip)) {
	case 4:
		ip_read((const u_char *)ip, length);
		break;
#ifdef INET6
	case 6:
		ip6_read((const u_char *)ip, length);
		break;
#endif
	}
}

#ifdef PFLOG_HDRLEN

static void
pflog_if_read(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	int caplen = h->caplen;
	int length = h->len;
	const struct pfloghdr *pf;

	if (caplen < PFLOG_HDRLEN) {
		return;
	}

	/*
	 * Some printers want to get back at the ethernet addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	packetp = p;
	snapend = p + caplen;

	pf = (struct pfloghdr *)p;
	p += PFLOG_HDRLEN;
	length -= PFLOG_HDRLEN;
	caplen -= PFLOG_HDRLEN;
	switch (ntohl(pf->af)) {
	case AF_INET:
		ip_read((const u_char *)p, length);
		break;
#ifdef INET6
	case AF_INET6:
		ip6_read((const u_char *)p, length);
		break;
#endif
	}
}

#endif /* PFLOG_HDRLEN */

static int
ip_read(const u_char *bp, int length)
{
	struct ip *ip;
	int hlen, len, proto, off;
    
	ip = (struct ip *)bp;
	if ((u_char *)(ip + 1) > snapend)
		return (0);
#ifdef ALIGN_WORD
	/*
	 * The IP header is not word aligned, so copy into abuf.
	 * This will never happen with BPF.  It does happen raw packet
	 * dumps from -r.
	 */
	if ((int)ip & (sizeof(long)-1)) {
		static u_char *abuf;

		if (abuf == 0)
			abuf = (u_char *)malloc(DEFAULT_SNAPLEN);
		memcpy((char *)abuf, (char *)ip, caplen);
		ip = (struct ip *)abuf;
	}
#endif /* ALIGN_WORD */

	do_ip(ip);

	hlen = IP_HL(ip) * 4;
	len = min(ntohs(ip->ip_len), length);

	bp = (u_char *)ip + hlen;
	len -= hlen;

	proto = ip->ip_p;
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		/* if this is fragment zero, hand it to the next higher
		   level protocol. */
		off = ntohs(ip->ip_off);
		if (off & 0x1fff) {
			/* process fragments */
			if ((bp = (u_char *)ip4f_lookup(ip)) == NULL)
				/* lookup failed */
				return (1);
		}

		do_ipproto(ip->ip_p, bp, len);

		/* if this is a first fragment, cache it. */
		if ((off & IP_MF) && (off & 0x1fff) == 0) {
			ip4f_cache(ip, (struct udphdr *)bp);
		}
	} else {
		do_ipproto(ip->ip_p, bp, len);
	}

	return (1);
}

#ifdef INET6
/* this version doesn't handle fragments */
static int
ip6_read(const u_char *bp, int length)
{
	struct ip6_hdr *ip6;
	int hlen, len, proto;

	ip6 = (struct ip6_hdr *)bp;
	if ((u_char *)(ip6 + 1) > snapend)
		return (0);
#ifdef ALIGN_WORD
	/*
	 * The IP header is not word aligned, so copy into abuf.
	 * This will never happen with BPF.  It does happen raw packet
	 * dumps from -r.
	 */
	if ((int)ip6 & (sizeof(long)-1)) {
		static u_char *abuf;

		if (abuf == 0)
			abuf = (u_char *)malloc(DEFAULT_SNAPLEN);
		memcpy((char *)abuf, (char *)ip6, caplen);
		ip6 = (struct ip6_hdr *)abuf;
	}
#endif /* ALIGN_WORD */

	if (do_ip6(ip6) == 0)
		return (0);

	hlen = read_ip6hdr(ip6, &proto);
	len = min(ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr), length)
	    - hlen;

	bp = (u_char *)ip6 + hlen;
	length -= hlen;

	do_ip6nexthdr(proto, bp, length);

	return (1);
}

static int
read_ip6hdr(struct ip6_hdr *ip6, int *proto)
{
	int hlen, opt_len;
	struct ip6_hbh *ip6ext;
	u_char nh;

	hlen = sizeof(struct ip6_hdr);
	nh = ip6->ip6_nxt;
	ip6ext = (struct ip6_hbh *)(ip6 + 1);
	if ((u_char *)(ip6ext + 1) > snapend) {
		*proto = (int)nh;
		return (hlen);
	}
	while (nh == IPPROTO_HOPOPTS || nh == IPPROTO_ROUTING ||
	       nh == IPPROTO_AH || nh == IPPROTO_DSTOPTS) {
		if (nh == IPPROTO_AH)
			opt_len = 8 + (ip6ext->ip6h_len * 4);
		else
			opt_len = (ip6ext->ip6h_len + 1) * 8;
		hlen += opt_len;
		nh = ip6ext->ip6h_nxt;
		ip6ext = (struct ip6_hbh *)((caddr_t)ip6ext  + opt_len);
		if ((u_char *)(ip6ext + 1) > snapend)
			break;
	}
	*proto = (int)nh;
	return (hlen);
}
#endif /* INET6 */

/*
 * helper functions to handle IPv4 fragments.
 * currently only in-sequence fragments are handled.
 *	- fragment info is cached in a LRU list.
 *	- when a first fragment is found, cache its flow info.
 *	- when a non-first fragment is found, lookup the cache.
 */
static void
ip4f_cache(ip, udp)
	struct ip *ip;
	struct udphdr *udp;
{
	struct ip4_frag *fp;

	if (TAILQ_EMPTY(&ip4f_list)) {
		/* first time call, allocate fragment cache entries. */
		if (ip4f_init() < 0)
			/* allocation failed! */
			return;
	}

	fp = ip4f_alloc();
	fp->ip4f_proto = ip->ip_p;
	fp->ip4f_id = ip->ip_id;
	fp->ip4f_src = ip->ip_src;
	fp->ip4f_dst = ip->ip_dst;
	fp->ip4f_udphdr.uh_sport = udp->uh_sport;
	fp->ip4f_udphdr.uh_dport = udp->uh_dport;
}

static struct udphdr *
ip4f_lookup(ip)
	struct ip *ip;
{
	struct ip4_frag *fp;
	struct udphdr *udphdr;
    
	for (fp = TAILQ_FIRST(&ip4f_list); fp != NULL && fp->ip4f_valid;
	     fp = TAILQ_NEXT(fp, ip4f_chain))
		if (ip->ip_id == fp->ip4f_id &&
		    ip->ip_src.s_addr == fp->ip4f_src.s_addr &&
		    ip->ip_dst.s_addr == fp->ip4f_dst.s_addr &&
		    ip->ip_p == fp->ip4f_proto) {

			/* found the matching entry */
			udphdr = &fp->ip4f_udphdr;
			if ((ntohs(ip->ip_off) & IP_MF) == 0)
				/*
				 * this is the last fragment,
				 * release the entry.
				 */
				ip4f_free(fp);
			return (udphdr);
		}

	/* no matching entry found */
	return (NULL);
}

static int
ip4f_init(void)
{
	struct ip4_frag *fp;
	int i;
    
	TAILQ_INIT(&ip4f_list);
	for (i=0; i<IP4F_TABSIZE; i++) {
		fp = (struct ip4_frag *)malloc(sizeof(struct ip4_frag));
		if (fp == NULL) {
			printf("ip4f_initcache: can't alloc cache entry!\n");
			return (-1);
		}
		fp->ip4f_valid = 0;
		TAILQ_INSERT_TAIL(&ip4f_list, fp, ip4f_chain);
	}
	return (0);
}

static struct ip4_frag *
ip4f_alloc(void)
{
	struct ip4_frag *fp;
	
	/* reclaim an entry at the tail, put it at the head */
	fp = TAILQ_LAST(&ip4f_list, ip4f_list);
	TAILQ_REMOVE(&ip4f_list, fp, ip4f_chain);
	fp->ip4f_valid = 1;
	TAILQ_INSERT_HEAD(&ip4f_list, fp, ip4f_chain);
	return (fp);
}

static void
ip4f_free(fp)
	struct ip4_frag *fp;
{
	TAILQ_REMOVE(&ip4f_list, fp, ip4f_chain);
	fp->ip4f_valid = 0;
	TAILQ_INSERT_TAIL(&ip4f_list, fp, ip4f_chain);
}


