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
#include <sys/socket.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#define __USE_XOPEN /* for linux */
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <err.h>

#include "aguri.h"
#include "aguri_tree.h"
#include "aguri_ip.h"
#include "aguri_pcap.h"
#include "aguri_flow.h"

char *fmt_string = "%!AGURI-2.0";

struct timeval start_time, end_time;
int timeoffset = 0;	/* for adjusting localtime */
int debug = 0;
int time_slot = 0;
char *wfile = NULL;		/* output file */
#if 0
int lru_size = 512;
#else
int lru_size = 1024;
#endif
int plot_yscale = 1;
int plot_inbps = 0;
int verbose = 0;
int disable_thscale = 0;

static char *dumpfile = NULL;		/* tcpdump output file as input */
static char *interface = NULL;
static char *pid_file = NULL;
static int read_count = 0;
static int pcap_fd = -1;
static int plot_entries = 7;
static char *filter_cmd = NULL;

struct tree *(*type_parser)(char *buf, size_t len,
	u_int64_t (**parser)(char *, void *, size_t *, void *),
	void (**counter)(struct tree *, void *, size_t, void *, u_int64_t));
static int read_file(FILE *fp);
static int read_flow(FILE *fp);
static void sig_handler(int sig);
static void usage(void);

static void
sig_handler(int sig)
{
#ifdef DEBUG
	fprintf(stderr, "got signal %d.\n", sig);
#endif

	if (sig == SIGHUP) {
		if (reading_pcap)
			summary_pending = 1;
		else if (wfile != NULL &&
			 freopen(wfile, "a", stdout) == NULL)
			err(1, "can't freopen %s", wfile);
		return;
	}

	if (sig == SIGUSR1) {
		print_pcapstat(stderr);
		return;
	}

	if (pcap_fd != -1) {
		close_pcap(pcap_fd);
		pcap_fd = -1;
	}

	print_summary();

	if (wfile)
		fclose(stdout);
	_exit(1);
}

static void
usage(void)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "  aguri2 [-dhv] [-c count] [-i interface]\n");
	fprintf(stderr, "        [-f filter_cmd] [-l nodes]\n");
	fprintf(stderr, "        [-p pid_file] [-r pcapfile] [-s interval]\n");
	fprintf(stderr, "        [-T timeoffset] [-t thresh/1000] [-w outputfile]\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int ch, len;
	char *cp;

	type_parser = ip_parsetype;

	if ((cp = strrchr(argv[0], '/')) == NULL)
		cp = argv[0];
	else
		cp++;
	if (strcmp(cp, "aguri2plot") == 0)
		type_parser = ipplot_parse1;

	while ((ch = getopt(argc, argv,
	    "46ac:Ddf:g:hi:l:n:Pp:r:s:T:t:vw:x:y:")) != EOF) {
		switch (ch) {
		case '4':
			xflags &= ~(CHECK_IPV6);
			break;
		case '6':
			xflags &= ~(CHECK_IPV4);
			break;
		case 'c':
			read_count = (int)strtol(optarg, NULL, 0);
			break;
		case 'D':
			disable_thscale = 1;
			break;
		case 'd':
			debug = 1;
			break;
		case 'f':
			filter_cmd = optarg;
			break;
		case 'h':
			usage();
			break;
		case 'i':
			interface = optarg;
			break;
		case 'l':
			lru_size = (int)strtol(optarg, NULL, 0);
			break;
		case 'n': /* plot n entries */
			plot_entries = (int)strtol(optarg, NULL, 0);
			break;
		case 'P':
			type_parser = ipplot_parse1;
			break;
		case 'p':
			pid_file = optarg;
			break;
		case 'r':
			dumpfile = optarg;
			break;
		case 's':
			interval = (int)strtol(optarg, NULL, 0);
			break;
		case 'T':
			timeoffset = (int)strtol(optarg, NULL, 0) * 3600;
			break;
		case 't': /* thresh: (n/1000) */
			ip_thresh = (int)strtol(optarg, NULL, 0);
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			wfile = optarg;
			break;
		case 'x':
			xflags &= ~(CHECK_SRCADDR | CHECK_DSTADDR |
				    CHECK_SRCPROTO | CHECK_DSTPROTO);
			if (isalpha(optarg[0])) {
				if (strchr(optarg,'s'))
				    xflags |= CHECK_SRCADDR;
				if (strchr(optarg,'d'))
				    xflags |= CHECK_DSTADDR;
				if (strchr(optarg,'S'))
				    xflags |= CHECK_SRCPROTO;
				if (strchr(optarg,'D'))
				    xflags |= CHECK_DSTPROTO;
			} else if (isdigit(optarg[0]))
				xflags = (int)strtol(optarg, NULL, 0);
			break;
		case 'y':  /* y scale for plot */
			if (isalpha(optarg[0])) {
				if (toupper(optarg[0]) == 'M')
					plot_yscale = 1000000;
				else if (toupper(optarg[0]) == 'K')
					plot_yscale = 1000;
				plot_inbps = 1;
			} else if (isdigit(optarg[0]))
				   plot_yscale = (int)strtol(optarg, NULL, 0);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGHUP,  sig_handler);
	signal(SIGUSR1,  sig_handler);

	if (pid_file != NULL) {
		FILE *fp;

		/* save pid to the pid file */
		if ((fp = fopen(pid_file, "w")) != NULL) {
			fprintf(fp, "%d\n", getpid());
			fclose(fp);
		}
		else
			warn("can't open pid file: %s", pid_file);
	}

	if (wfile != NULL && freopen(wfile, "w", stdout) == NULL)
		err(1, "can't freopen %s", wfile);

	ipinfo_init();

	if (dumpfile != NULL || interface != NULL) {
		int cnt = 0;

		if (dumpfile != NULL)
			pcap_fd = open_pcapfile(dumpfile, filter_cmd);
		else
			pcap_fd = open_pcapif(interface, filter_cmd);
		
		while (1) {
			len = read_pcap(pcap_fd);
			if (len < 0)
				break;
			if (dumpfile != NULL && len == 0)
				/* EOF */
				break;
			if (read_count != 0 && read_count == ++cnt)
				break;
		}
		close_pcap(pcap_fd);

	} else if (argc > 0) {
		int n;
		char **files;
	again:
		n = argc;
		files = argv;
			
		while (n > 0) {
			FILE *fp;

			if ((fp = fopen(*files, "r")) == NULL)
				err(1, "can't open %s", *files);
			read_file(fp);
			(void)fclose(fp);
			time_slot++;
			--n;
			++files;
		}
		if (type_parser == ipplot_parse1) {
			ipplot_phase1(plot_entries);
			type_parser = ipplot_parse2;
			time_slot = 0;
			goto again;
		}
	} else  {
			/* read from stdin */
			read_flow(stdin);
	}

	if (type_parser == ipplot_parse2)
		ipplot_phase2();
	else
		ipinfo_finish();

	if (wfile)
		fclose(stdout);

#ifdef AGURI2
	/* XXX only works with '-r' */
	if (interval == 0) {
		aguri2_setup();

		if (dumpfile != NULL) {
			pcap_fd = open_pcapfile(dumpfile, filter_cmd);
			while (1) {
				len = read_pcap(pcap_fd);
				if (len < 0)
					break;
				if (dumpfile != NULL && len == 0)
					/* EOF */
					break;
			}
			close_pcap(pcap_fd);
		} else
			read_flow(stdin);
		print_header();
		aguri2_summary();
	}
#endif
	return (0);
}

static int
read_file(FILE *fp)
{
	char buf[256], *cp;
	u_char	key[MAX_KEYBYTES];
	struct tree *tp;
	time_t t;
	struct tm tm;
	size_t prefixlen;
	u_int64_t cnt;
	int line_no, arg;
	u_int64_t (*parser)(char *, void *, size_t *, void *);
	void (*counter)(struct tree *, void *, size_t, void *, u_int64_t);

	tp = NULL;
	line_no = 0;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		++line_no;
		if (line_no == 1) {
			if (strncmp(fmt_string, buf, strlen(fmt_string)) != 0)
				errx(1, "isn't an aguri file!");
			continue;
		}

		if (buf[0] == '%' && buf[1] == '%') {
			/* predefined comments */
			if (strncmp("StartTime:", &buf[2], 10) == 0) {
				cp = strchr(&buf[2], ':');
				cp++;
				cp += strspn(cp, " \t");
				memset(&tm, 0, sizeof(tm));
				if (strptime(cp, "%a %b %d %T %Y", &tm) == NULL)
					err(1, "strptime");
				if (start_time.tv_sec == 0) {
					if ((t = mktime(&tm)) != -1)
						start_time.tv_sec = t;
					else
						warnx("mktime failed");
				}
			} else if (strncmp("EndTime:", &buf[2], 8) == 0) {
				cp = strchr(&buf[2], ':');
				cp++;
				cp += strspn(cp, " \t");
				memset(&tm, 0, sizeof(tm));
				if (strptime(cp, "%a %b %d %T %Y", &tm) == NULL)
					err(1, "strptime");
				if ((t = mktime(&tm)) != -1)
					end_time.tv_sec = t;
				else
					warnx("mktime failed");
			}	
			continue;
		}

		if (buf[0] == '%' || buf[0] == '\n') {
			if (strncmp(fmt_string, buf, strlen(fmt_string)) == 0)
				/* new record within the file */
				time_slot++;

			/* skip comment and blank lines */
			continue;
		}

		if (buf[0] == '[') {
			/* if new type, lookup the corresponding tree */
			tp = (*type_parser)(buf, sizeof(buf),
					    &parser, &counter);
			if (tp == NULL) {
				fprintf(stderr, "unknown type %s\n", buf);
				return (-1);
			}
			continue;
		}

		/* convert the line to key, prefixlen, count */
		cnt = (*parser)(buf, key, &prefixlen, &arg);
		if (cnt > 0)
			(*counter)(tp, key, prefixlen, &arg, cnt);
	}

	if (!feof(fp))
		perror("aguri_read");

	return (0);
}

static int read_flow(FILE *fp)
{
	struct aguri_flow agflow;

	fprintf(stderr, "aguri2: reading flow info from stdin...\n");
	while (1) {
		if (fread(&agflow, sizeof(agflow), 1, fp) != 1) {
			warn("fread failed!");
			return (-1);
		}

		if (agflow_doheader(&agflow) > 0) {
			if (agflow.agflow_fs.fs_ipver == 4)
				agflow_dov4(&agflow);
			else if (agflow.agflow_fs.fs_ipver == 6)
				agflow_dov6(&agflow);
			else
				fprintf(stderr, "unknown flow type!\n");
		}
	}
	return (0);
}
