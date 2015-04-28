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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <err.h>
#include <inttypes.h>

#include "aguri.h"
#include "aguri_tree.h"
#include "aguri_plot.h"

static struct plot_list *plot_lists = NULL;
time_t *plot_timestamps = NULL;

static struct plot_list *list_create(struct tree *tp, int ntree);
static void list_destroy(struct plot_list *pl);
static int list_add(struct tree_node *np, void *arg);
static void list_reduce(struct plot_list *pl, int n);

struct plot_list *
tree2plotlist(struct tree *tp)
{
	struct plot_list *pl;

	for (pl = plot_lists; pl != NULL; pl = pl->pl_next)
		if (pl->pl_tree == tp)
			return (pl);
#if 1	/* ick! needed for ipv6 */
	tp--;
	for (pl = plot_lists; pl != NULL; pl = pl->pl_next)
		if (pl->pl_tree == tp)
			return (pl);
#endif
	return (NULL);
}

struct plot_entry *
tnode2pentry(struct tree_node *np)
{
	struct plot_list *pl;
	struct plot_entry *ep;

	if ((pl = tree2plotlist(np->tn_tree)) == NULL)
		return (NULL);
	for (ep = TAILQ_FIRST(&pl->pl_head); ep != NULL;
	     ep = TAILQ_NEXT(ep, pe_chain))
		if (ep->pe_node == np)
			return (ep);
	return (NULL);
}

/*
 * plot_phase1 is called at the end of the 1st round, and creates
 * a list of entries to plot.
 */
struct plot_list *
plot_phase1(struct tree *tp, int ntree, int nentries)
{
	struct plot_list *pl;
	struct plot_entry *ep;

	/* create a list of nodes */
	pl = list_create(tp, ntree);

	/* reduce the number of nodes to nentries */
	list_reduce(pl, nentries);

	/* allocate counter buffers for the remaining nodes */
	pl->pl_timeslots = time_slot;
	for (ep = TAILQ_FIRST(&pl->pl_head); ep != NULL;
	     ep = TAILQ_NEXT(ep, pe_chain)) {
		ep->pe_counts = calloc(pl->pl_timeslots, sizeof(u_int64_t));
	}

	/* allocate time buffers */
	if (plot_timestamps == NULL)
		plot_timestamps = calloc(pl->pl_timeslots, sizeof(time_t));

	return (0);
}

/*
 * plot_phase2 is called at the end of the 2nd round, and outputs
 * the counter values in the plot format.
 */
int
plot_phase2(struct tree *tp)
{
	struct plot_list *pl;
	struct plot_entry *ep;
	u_int64_t total;
	double sec = 1.0;
	int i;
	char buf[128];

	if ((pl = tree2plotlist(tp)) == NULL)
		return (-1);
	if (pl->pl_num == 0)
		/* no entries */
		return (0);
	for (i = 0; i < pl->pl_timeslots; i++) {
#if 1 /* workaround timestamp of 0 */
		if (plot_timestamps[i] == 0) {
			if (i == 0)
				plot_timestamps[i] = start_time.tv_sec;
			else
				plot_timestamps[i] = plot_timestamps[i-1];
			continue;
		}
#endif
		strftime(buf, sizeof(buf), "%Y/%m/%d:%T",
			 localtime(&plot_timestamps[i]));
		printf("%s ", buf);

		if (plot_inbps) {
			if (i == 0)
				sec = (double)(plot_timestamps[i] -
					       start_time.tv_sec);
			else
				sec = (double)(plot_timestamps[i] -
					       plot_timestamps[i-1]);
		}

		/* output total */
		total = 0;
		for (ep = TAILQ_FIRST(&pl->pl_head); ep != NULL;
		     ep = TAILQ_NEXT(ep, pe_chain))
			total += ep->pe_counts[i];
		if (plot_inbps) {
			printf("%.2f ", (double)total * 8 / sec / plot_yscale);
		} else {
			if (plot_yscale == 1)
				printf("%"PRIu64" ", total);
			else
				printf("%.2f ", (double)total / plot_yscale);
		}

		/* output each entry */
		for (ep = TAILQ_FIRST(&pl->pl_head); ep != NULL;
		     ep = TAILQ_NEXT(ep, pe_chain)) {
			if (plot_inbps) {
				printf("%.2f ",
				       (double)ep->pe_counts[i] * 8 / sec /
				       plot_yscale);
			} else {
				if (plot_yscale == 1)
					printf("%"PRIu64" ", ep->pe_counts[i]);
				else
					printf("%.2f ",
					       (double)ep->pe_counts[i] /
					       plot_yscale);
			}
		}
		printf("\n");
	}

	list_destroy(pl);

	if (plot_lists == NULL)
		free(plot_timestamps);
	return (0);
}

static struct plot_list *
list_create(struct tree *tp, int ntree)
{
	static struct plot_list *pl;

	if ((pl = malloc(sizeof(*pl))) == NULL)
		err(1, "malloc");

	TAILQ_INIT(&pl->pl_head);
	pl->pl_tree = tp;
	pl->pl_num = 0;
	pl->pl_timeslots = 0;
	pl->pl_next = plot_lists;
	plot_lists = pl;

	while (ntree-- > 0) {
		tree_walk(tp, list_add, (void *)pl);
		tp++;
	}
	return (pl);
}

static void
list_destroy(struct plot_list *pl)
{
	struct plot_entry *ep;
	struct plot_list *pl2;

	while (!TAILQ_EMPTY(&pl->pl_head)) {
		ep = TAILQ_FIRST(&pl->pl_head);
		TAILQ_REMOVE(&pl->pl_head, ep, pe_chain);
		if (ep->pe_counts != NULL)
			free(ep->pe_counts);
		free(ep);
	}

	if (plot_lists == pl)
		plot_lists = pl->pl_next;
	else {
		for (pl2 = plot_lists; pl2 != NULL; pl2 = pl2->pl_next)
			if (pl2->pl_next == pl)
				pl2->pl_next = pl->pl_next;
	}
	free(pl);
}

static int
list_add(struct tree_node *np, void *arg)
{
	struct plot_list *pl = (struct plot_list *)arg;
	struct plot_entry *ep, *ep2;
	struct tree_node *np2;

	/* if count isn't 0, create an entry */
	if (np->tn_count == 0)
		return (0);

	if ((ep = malloc(sizeof(*ep))) == NULL)
		err(1, "malloc");

	ep->pe_node = np;
	ep->pe_counts = NULL;

	/* add the entry to the ordered list */
	ep2 = TAILQ_FIRST(&pl->pl_head);
	while (ep2 != NULL) {
		np2 = ep2->pe_node;
		if (np->tn_count >= np2->tn_count)
			break;
		ep2 = TAILQ_NEXT(ep2, pe_chain);
	}
	if (ep2 != NULL)
		TAILQ_INSERT_BEFORE(ep2, ep, pe_chain);
	else
		TAILQ_INSERT_TAIL(&pl->pl_head, ep, pe_chain);
	pl->pl_num++;
	return (0);
}

static void
list_reduce(struct plot_list *pl, int n)
{
	struct	plot_entry *ep, *ep2;
	struct	tree_node *np, *np2;

	while (pl->pl_num > n) {
		/*
		 * grab the node with the smallest count.
		 * aggregate the count to the first ancestor whose
		 * count is non-zero.
		 * then, remove this entry from the list.
		 */
		ep = TAILQ_LAST(&pl->pl_head, _list);
		np = ep->pe_node;

		if ((np2 = np->tn_parent) != NULL) {
			while (np2->tn_count == 0 && np2->tn_parent != NULL)
				np2 = np2->tn_parent;
			np2->tn_count += np->tn_count;
			np->tn_count = 0;
		}
		TAILQ_REMOVE(&pl->pl_head, ep, pe_chain);
		free(ep);
		pl->pl_num--;

		/*
		 * the counter value of the ancestor has been changed.
		 * move the position, if necessary.
		 */
		if (np2 != NULL)
			ep2 = tnode2pentry(np2);
		else
			ep2 = NULL;
		if (ep2 == NULL)
			/* in case of root node and it isn't in the list */
			continue;

		ep = TAILQ_PREV(ep2, _list, pe_chain);
		while (ep != NULL) {
			np = ep->pe_node;
			if (np2->tn_count <= np->tn_count)
				break;
			ep = TAILQ_PREV(ep, _list, pe_chain);
		}
		if (ep != NULL) {
			if (TAILQ_NEXT(ep, pe_chain) != ep2) {
				TAILQ_REMOVE(&pl->pl_head, ep2, pe_chain);
				TAILQ_INSERT_AFTER(&pl->pl_head, ep, ep2, pe_chain);
			}
		} else if (TAILQ_FIRST(&pl->pl_head) != ep2) {
			TAILQ_REMOVE(&pl->pl_head, ep2, pe_chain);
			TAILQ_INSERT_HEAD(&pl->pl_head, ep2, pe_chain);
		}
	}
}
