/* $Id: read_pcap.h 311 2013-10-01 06:07:36Z kjc $ */
/*
 * Copyright (c) 1993, 1994
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
 *
 */

/*
 * This stuff should come from a system header file, but there's no
 * obviously portable way to do that and it's not really going
 * to change from system to system (except for the padding business).
 */

struct fddi_header {
	u_char  fddi_fc;		/* frame control */
	u_char  fddi_dhost[6];
	u_char  fddi_shost[6];
};

#define	FDDIFC_LLC_ASYNC	0x50		/* Async. LLC frame */
#define	FDDIFC_CLFF		0xF0		/* Class/Length/Format bits */

struct llc {
	u_int8_t dsap;
	u_int8_t ssap;
	union {
		u_int8_t u_ctl;
		u_int16_t is_ctl;
		struct {
			u_int8_t snap_ui;
			u_int8_t snap_pi[5];
		} snap;
		struct {
			u_int8_t snap_ui;
			u_int8_t snap_orgcode[3];
			u_int8_t snap_ethertype[2];
		} snap_ether;
	} ctl;
};
#define	llcui		ctl.snap.snap_ui

#define	LLC_UI			0x03
#define	LLCSAP_SNAP		0xaa

#ifndef INET6
/*
 * The default snapshot length.  This value allows most printers to print
 * useful information while keeping the amount of unwanted data down.
 * In particular, it allows for an ethernet header, tcp/ip header, and
 * 14 bytes of data (assuming no ip options).
 */
#define DEFAULT_SNAPLEN 68
#else
#define DEFAULT_SNAPLEN 96
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6		0x86dd
#endif

extern const u_char *packetp;
extern const u_char *snapend;

struct ip;
struct ip6_hdr;
struct tcphdr;
struct udphdr;
struct timeval;
struct pcap_pkthdr;

void (*net_reader)(u_char *user, const struct pcap_pkthdr *h, const u_char *p);
pcap_handler lookup_printer(int type);
void dump_reader(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int do_pkthdr(const struct timeval *, u_int, u_int);
int do_ip(const struct ip *);
int do_ipproto(int proto, const u_char *bp, int length);
int do_ip6(const struct ip6_hdr *);
int do_ip6nexthdr(int proto, const u_char *bp, int length);
