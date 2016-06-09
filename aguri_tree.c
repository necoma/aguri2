/*
 * Copyright (C) 2001-2016 WIDE Project.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <err.h>
#include <inttypes.h>

#include "aguri_tree.h"

extern int disable_heuristics;

static struct tree_node *leaf_alloc(struct tree *tp, const void *key,
			     struct tree_node *np);
static void leaf_free(struct tree *tp, struct tree_node *leaf);
static void leaf_reclaim(struct tree *tp, int n);

static void tnode_reset(struct tree_node *np);
static int tnode_resetcount(struct tree_node *np, void *arg);
static int tnode_sum(struct tree_node *np, void *arg);
static int tnode_sum2(struct tree_node *np, void *arg);
static int tnode_setrindex(struct tree_node *np, void *arg);
static int tnode_countindices(struct tree_node *np, void *arg);
static struct tree_node *tnode_find(struct tree *tp, const void *key, size_t len);
static struct tree_node *tnode_match(struct tree *tp, const void *key, size_t len);
static struct tree_node *tnode_matchindex(struct tree *tp, const void *key, size_t len);
static int tnode_aggregate(struct tree_node *np, void *arg);
static int tnode_print(struct tree_node *np, void *arg);
static int key_print(u_char *key, size_t len, size_t prefixlen);
static __inline__ int prefix_cmp(const void *p1, const void *p2, size_t len);
static size_t prefix_common(const void *p1, const void *p2, size_t len,
			    void *p3);
static __inline__ int bit_test(const void *p, size_t pos);
static void bit_set(void *p, size_t pos);
#if 0
static void bit_clear(void *p, size_t pos);
#endif
#if 1
static void check_nfree(struct tree *tp);
#endif

/*
 * radix (or patricia) tree implementation for aguri
 */

/*
 * initialize a tree.
 * the lru list contains free nodes and leaf nodes, but not internal nodes.
 */
void
tree_init(struct tree *tp, size_t keylen, size_t maxnodes)
{
	struct tree_node *np;
	int i;

	tp->tr_keylen = keylen;
	TAILQ_INIT(&tp->tr_lru);

	for (i = 0; i < maxnodes; i++) {
		if ((np = malloc(sizeof(*np))) == NULL)
			err(1, "tree_init: can't alloc nodes!");
		TAILQ_INSERT_TAIL(&tp->tr_lru, np, tn_chain);
		tnode_reset(np);
		np->tn_tree = tp;
		np->tn_intree = 0;
		tp->tr_nfree++;
	}

	/* allocate the top node */
	np = TAILQ_FIRST(&tp->tr_lru);
	tnode_reset(np);
	memset(&np->tn_key, 0, sizeof(np->tn_key));
	np->tn_prefixlen = 0;
	tp->tr_top = np;
	np->tn_intree = 1;
	tp->tr_nfree--;
#if 0
	/* don't remove the top node from the LRU list, which
	 * triggered a bug to try to remove the top node from the list
	 * in leaf_alloc()
	 */
	TAILQ_REMOVE(&tp->tr_lru, np, tn_chain);
#endif
}

void
tree_destroy(struct tree *tp)
{
	struct tree_node *np;

	/* first, remove nodes from the tree */
	if (tp->tr_top->tn_left != NULL)
		subtree_reduce(tp, tp->tr_top, 0);

	/*
	 * at this point, only top is remaining in the tree,
	 * and all nodes are in the LRU list.
	 */
	assert(tp->tr_top->tn_left == NULL && tp->tr_top->tn_right == NULL);
	while ((np = TAILQ_FIRST(&tp->tr_lru)) != NULL) {
		TAILQ_REMOVE(&tp->tr_lru, np, tn_chain);
		free(np);
	}

#if 1
	free(tp->tr_top);
#endif
	tp->tr_top = NULL;
	tp->tr_nfree = 0;
}

/*
 * preorder tree walk
 */
int
tree_walk(struct tree *tp,
	  int (*func)(struct tree_node *, void *),
	  void *arg)
{
	return (subtree_walk(tp->tr_top, func, arg));
}

/*
 * postorder tree walk
 */
int
tree_postorderwalk(struct tree *tp,
		   int (*func)(struct tree_node *, void *),
		   void *arg)
{
	return (subtree_postorderwalk(tp->tr_top, func, arg));
}

void
tree_resetcount(struct tree *tp)
{
	tree_walk(tp, tnode_resetcount, 0);
	tp->tr_count = 0;
	tp->tr_count2 = 0;
	tp->tr_epoch++;
#ifdef AGURI_STATS
	tp->tr_stats.hits = 0;
	tp->tr_stats.total = 0;
	tp->tr_stats.reclaimed = 0;
#endif
}

int
tree_aggregate(struct tree *tp, u_int64_t *thresh)
{
	/* reset index that is to be set in tnode_aggregate */
	tp->tr_indices = 0;
	tree_postorderwalk(tp, tnode_aggregate, (void *)thresh);
#if 0
	printf("#tree_aggregate: indices=%d\n", tp->tr_indices);
#endif
#if 0
	check_nfree(tp);
#endif
	return (0);
}

int
tree_setrindices(struct tree *tp, struct tree_node **tn)
{
	tree_walk(tp, tnode_setrindex, (void *)tn);
	return (0);
}


void
tree_print(struct tree *tp)
{
	tree_walk(tp, tnode_print, 0);
}

/*
 * preorder tree walk
 */
int
subtree_walk(struct tree_node *top,
	  int (*func)(struct tree_node *, void *),
	  void *arg)
{
	struct tree_node *np;
	int error, depth;

	depth = 0;
	np = top;
	while (1) {

		assert((np->tn_left == NULL && np->tn_right == NULL)
			|| (np->tn_left != NULL && np->tn_right != NULL));

		np->tn_depth = depth;
		if ((error = (*func)(np, arg)) != 0)
			return (error);

		if (np->tn_left != NULL) {
			np = np->tn_left;
			depth++;
		} else {
			while (np != top &&
			       np == np->tn_parent->tn_right) {
				np = np->tn_parent;
				depth--;
			}
			if (np == top)
				break;
			np = np->tn_parent->tn_right;
		}
	}
	return (0);
}

/*
 * postorder tree walk
 */
int
subtree_postorderwalk(struct tree_node *top,
		   int (*func)(struct tree_node *, void *),
		   void *arg)
{
	struct tree_node *np;
	int error, depth;

	depth = 0;
	np = top;
	while (np->tn_left != NULL) {
		np = np->tn_left;
		depth++;
	}
	while (1) {
		np->tn_depth = depth;
		if ((error = (*func)(np, arg)) != 0)
			return (error);

		if (np == top)
			break;

		/*
		 * move on to the next node
		 */
		if (np == np->tn_parent->tn_right) {
			/* at right child, go up */
			np = np->tn_parent;
			depth--;
		} else {
			/*
			 * at left child. move to its sibling, then
			 * go down to the left most child.
			 */
			np = np->tn_parent->tn_right;
			while (np->tn_left != NULL) {
				np = np->tn_left;
				depth++;
			}
		}
	}
	return (0);
}

u_int64_t
subtree_sum(struct tree_node *np)
{
	u_int64_t cnt = 0;

	subtree_walk(np, tnode_sum, &cnt);
	return (cnt);
}

u_int64_t
subtree_sum2(struct tree_node *np)
{
	u_int64_t cnt = 0;

	subtree_walk(np, tnode_sum2, &cnt);
	return (cnt);
}

int
subtree_countindices(struct tree_node *np)
{
	int cnt = 0;

	subtree_walk(np, tnode_countindices, &cnt);
	return (cnt);
}

/*
 * reduce a subtree into a single leaf node
 */
void
subtree_reduce(struct tree *tp, struct tree_node *np, int depth)
{
	if (depth > 0) {
		/* nodes to be deleted */
		if (np->tn_left == NULL) {
			/* leaf node */
			assert(np->tn_right == NULL);
			TAILQ_REMOVE(&tp->tr_lru, np, tn_chain);
		} else {
			/* internal node */
			assert(np->tn_right != NULL);
			subtree_reduce(tp, np->tn_left, depth + 1);
			subtree_reduce(tp, np->tn_right, depth + 1);
		}

		np->tn_parent->tn_count += np->tn_count;
		np->tn_parent->tn_count2 += np->tn_count2;
#if 1  /* debug */
		if (np->tn_index >= 0)
			printf("##subtree_reduce recleaim index=%d\n", np->tn_index);
#endif

		if (np->tn_parent->tn_left == np)
			np->tn_parent->tn_left = NULL;
		else
			np->tn_parent->tn_right = NULL;
		np->tn_intree = 0;
		TAILQ_INSERT_TAIL(&tp->tr_lru, np, tn_chain);
		tp->tr_nfree++;
#ifdef AGURI_STATS
		tp->tr_stats.reclaimed++;
#endif
		return;
	}

	/* remaining node, converted from an internal node to a leaf */
#if 1
	if (np->tn_left == NULL)
		/* this is a leaf, nothing to do */
		return;
#else
	assert(np->tn_left != NULL && np->tn_right != NULL);
#endif
	subtree_reduce(tp, np->tn_left, depth + 1);
	subtree_reduce(tp, np->tn_right, depth + 1);
	assert(np->tn_left == NULL && np->tn_right == NULL);
	TAILQ_INSERT_HEAD(&tp->tr_lru, np, tn_chain);
}

/*
 * creat a leaf node and its branch point.
 * then, insert the branch point as the parent of the specified node.
 */
static struct tree_node *
leaf_alloc(struct tree *tp, const void *key, struct tree_node *np)
{
	struct tree_node *bp, *leaf;

	/* reclaim two nodes from the LRU list */
	leaf = TAILQ_LAST(&tp->tr_lru, _lru);
	while (leaf->tn_intree)
		leaf = TAILQ_PREV(leaf, _lru, tn_chain);
	TAILQ_REMOVE(&tp->tr_lru, leaf, tn_chain);
	TAILQ_INSERT_HEAD(&tp->tr_lru, leaf, tn_chain);
	leaf->tn_intree = 1;
	tp->tr_nfree--;
	tnode_reset(leaf);
	memcpy(leaf->tn_key, key, tp->tr_keylen/8);
	leaf->tn_prefixlen = tp->tr_keylen;

	assert(tp->tr_nfree > 0);
	bp = TAILQ_LAST(&tp->tr_lru, _lru);
	while (bp->tn_intree)
		bp = TAILQ_PREV(bp, _lru, tn_chain);
	TAILQ_REMOVE(&tp->tr_lru, bp, tn_chain);
	bp->tn_intree = 1;
	tp->tr_nfree--;
	tnode_reset(bp);
	bp->tn_prefixlen =
	    prefix_common(np->tn_key, key, tp->tr_keylen, bp->tn_key);

	if (bp->tn_prefixlen >= np->tn_prefixlen) {
		/*
		 * leaf should be a child of np, create 2 leaves
		 */
		assert(np->tn_left == NULL && np->tn_right == NULL);
		TAILQ_REMOVE(&tp->tr_lru, np, tn_chain);
		TAILQ_INSERT_HEAD(&tp->tr_lru, bp, tn_chain);
#if 1
		if (bp->tn_prefixlen == np->tn_prefixlen) {
			/* leaf has 1 at np->tn_prefixlen+1 */
			np->tn_left = bp;
			np->tn_right = leaf;
		} else {
			bit_set(bp->tn_key, np->tn_prefixlen + 1);
			np->tn_left = leaf;
			np->tn_right = bp;
		}
		bp->tn_prefixlen = tp->tr_keylen; /* full prefixlen */
#else
		if (bp->tn_prefixlen != np->tn_prefixlen) {
			bit_set(bp->tn_key, np->tn_prefixlen + 1);
			np->tn_left = leaf;
			np->tn_right = bp;
		} else {
			if (np->tn_parent == NULL && bp->tn_prefixlen == 0) {
				/*
				 * special case for the top node
				 * do not add another 0/0 node
				 */
				bp->tn_prefixlen = tp->tr_keylen;
			}
			np->tn_left = bp;
			np->tn_right = leaf;
		}
#endif
		bp->tn_parent = np;
		leaf->tn_parent = np;
		return (leaf);
	}

	assert(np->tn_parent->tn_prefixlen < bp->tn_prefixlen);
	if (np->tn_parent->tn_left == np)
		np->tn_parent->tn_left = bp;
	else
		np->tn_parent->tn_right = bp;
	bp->tn_parent = np->tn_parent;
	if (bit_test(key, bp->tn_prefixlen + 1)) {
		bp->tn_left = np;
		bp->tn_right = leaf;
	} else {
		bp->tn_left = leaf;
		bp->tn_right = np;
	}
	np->tn_parent = bp;
	leaf->tn_parent = bp;

	return (leaf);
}

static void
leaf_free(struct tree *tp, struct tree_node *leaf)
{
	struct tree_node *bp, *np, *parent;

	assert(leaf->tn_intree);
	assert(leaf->tn_left == NULL && leaf->tn_right == NULL);
	bp = leaf->tn_parent;
	assert(bp->tn_left != NULL && bp->tn_right != NULL);
	parent = bp->tn_parent;
	assert(parent != NULL);

	/*
	 * aggregate the counter values of the nodes to be deleted
	 * into their parent node
	 */
	parent->tn_count += bp->tn_count + leaf->tn_count;
	parent->tn_count2 += bp->tn_count2 + leaf->tn_count2;
#if 1 /* debug */
	if (leaf->tn_index >= 0)
		printf("##leaf_free: recleaim index=%d\n", leaf->tn_index);
	if (bp->tn_index >= 0)
		printf("##leaf_free: recleaim index=%d\n", bp->tn_index);
#endif

	if (bp->tn_left == leaf)
		np = bp->tn_right;
	else
		np = bp->tn_left;
	if (parent->tn_left == bp)
		parent->tn_left = np;
	else
		parent->tn_right = np;
	np->tn_parent = parent;

	leaf->tn_intree = 0;
	bp->tn_intree = 0;
	TAILQ_REMOVE(&tp->tr_lru, leaf, tn_chain);
	TAILQ_INSERT_TAIL(&tp->tr_lru, leaf, tn_chain);
	TAILQ_INSERT_TAIL(&tp->tr_lru, bp, tn_chain);
	tp->tr_nfree += 2;
#ifdef AGURI_STATS
	tp->tr_stats.reclaimed += 2;
#endif
}

/*
 * reclaim leaf nodes using the LRU replacement algorithm.
 * we don't select a node as a possible victim if the node is
 *  - already reclaimed
 *  - the counter value is larger than the threshold
 *  - both of its parent and sibling's subtree are larger than the threshold
 * then, we compare parent's count with sibling's subtree sum.
 * - if parent is larger, reduce the subtree into parent.
 * - otherwise, reclaim this node and parent, and leave the sibling's subtree.
 */
static void
leaf_reclaim(struct tree *tp, int n)
{
	struct tree_node *np, *after, *parent, *sibling;
	u_int64_t thresh, sum;
	u_int64_t thresh2, sum2;
	int	moved_to_head, indices, need_parent, need_sibling;

	thresh = tp->tr_count / 64;
	thresh2 = tp->tr_count2 / 64;

	if (thresh == 0)
		thresh = 1;
	if (thresh2 == 0)
		thresh2 = 1;
	while (tp->tr_nfree < n) {
		/*
		 * select a victim from the LRU list.
		 * exclude nodes whose count is more than the threshold.
		 */
		moved_to_head = 0;
		np = TAILQ_LAST(&tp->tr_lru, _lru);
		while (np != NULL) {
			if (np->tn_intree == 0) {
				/* free node */
				np =  TAILQ_PREV(np, _lru, tn_chain);
				continue;
			} else if (np->tn_count > thresh ||
				np->tn_count2 > thresh2 || np->tn_index >= 0) {
				/* if bigger than thresh, move it to head */
				after = np;
				np = TAILQ_PREV(np, _lru, tn_chain);
				if (moved_to_head > 3)
					continue;
				TAILQ_REMOVE(&tp->tr_lru, after, tn_chain);
				TAILQ_INSERT_HEAD(&tp->tr_lru, after, tn_chain);
				moved_to_head++;
				continue;
			}
			/*
			 * a possible victim found.
			 * see if either its parent or sibling's subtree is
			 * smaller than the threshold.
			 * also check if parent is not the top node.
			 */
			parent = np->tn_parent;
			if (parent->tn_left == np)
				sibling = parent->tn_right;
			else
				sibling = parent->tn_left;
			sum = subtree_sum(sibling);
			sum2 = subtree_sum2(sibling);
			indices = subtree_countindices(sibling);
#if 1
			assert(indices <= tp->tr_indices);
#endif

			need_parent = parent->tn_count > thresh
			    || parent->tn_count2 > thresh2 || parent->tn_index >= 0
			    || parent == tp->tr_top;
			need_sibling = sum > thresh || sum2 > thresh2 || indices > 0;
			
			if (need_parent && need_sibling) {
				/* we cannot remove this node */
				after = np;
				np =  TAILQ_PREV(np, _lru, tn_chain);
				if (moved_to_head > 3)
					continue;
				TAILQ_REMOVE(&tp->tr_lru, after, tn_chain);
				TAILQ_INSERT_HEAD(&tp->tr_lru, after, tn_chain);
				moved_to_head++;
				continue;
			}

			/*
			 * at this point, we are about to reclaim this victim.
			 * compare parent's count with sibling's subtree sum.
			 * if sibling is larger, reclaim this node and parent.
			 * otherwise, reduce the subtree into parent.
			 */
#if 1
			if (need_sibling)
				leaf_free(tp, np);
			else
				subtree_reduce(tp, np->tn_parent, 0);
#else
			if (need_parent)
				subtree_reduce(tp, np->tn_parent, 0);
			else
				leaf_free(tp, np);
#endif
			break;
		}

		if (np == NULL) {
			thresh *= 2;
			thresh2 *= 2;
#if 1
#if 0
			fprintf(stderr, "thresh increased to %"PRIu64"/%"PRIu64" %"PRIu64"/%"PRIu64"\n",
			thresh, tp->tr_count, thresh2, tp->tr_count2);
#endif
			if (thresh2 > tp->tr_count2 * 2) {
				tree_print(tp);
				check_nfree(tp);
				errx(1, "leaf_reclaim: loop!");
			}
#endif
		}
	}
}

void
leaf_addcount(struct tree *tp, const void *key, u_int64_t cnt, u_int64_t cnt2)
{
	(void)tnode_addcount(tp, key, tp->tr_keylen, cnt, cnt2);
}

struct tree_node *
tnode_addcount(struct tree *tp, const void *key, size_t len, u_int64_t cnt, u_int64_t cnt2)
{
	struct tree_node *np;

#ifdef AGURI_STATS
	tp->tr_stats.total++;
#endif
	np = tnode_find(tp, key, len);

	np->tn_count += cnt;
	tp->tr_count += cnt;
	np->tn_count2 += cnt2;
	tp->tr_count2 += cnt2;

	/* if this is a leaf, place this node at the head of the LRU list */
	if (np->tn_left == NULL)
		if (np != TAILQ_FIRST(&tp->tr_lru)) {
			TAILQ_REMOVE(&tp->tr_lru, np, tn_chain);
			TAILQ_INSERT_HEAD(&tp->tr_lru, np, tn_chain);
		}
	return (np);
}

static void
tnode_reset(struct tree_node *np)
{
	np->tn_parent = np->tn_left = np->tn_right = NULL;
	np->tn_count = 0;
	np->tn_count2 = 0;
	np->tn_index = -1;
	np->tn_prefixlen = 0;
}

static int
tnode_resetcount(struct tree_node *np, void *arg)
{
	np->tn_count = 0;
	np->tn_count2 = 0;
	return (0);
}

static int
tnode_sum(struct tree_node *np, void *arg)
{
	u_int64_t *p = arg;

	*p += np->tn_count;
	return (0);
}

static int
tnode_sum2(struct tree_node *np, void *arg)
{
	u_int64_t *p = arg;

	*p += np->tn_count2;
	return (0);
}

static int
tnode_setrindex(struct tree_node *np, void *arg)
{
	struct tree_node **p = arg;

	if (np->tn_index >= 0)
		p[np->tn_index] = np;
	return (0);
}

static int
tnode_countindices(struct tree_node *np, void *arg)
{
	int *p = arg;

	if (np->tn_index >= 0)
		*p += 1;
	return (0);
}

static struct tree_node *
tnode_find(struct tree *tp, const void *key, size_t len)
{
	struct tree_node *np;
	int needfree;

	/*
	 * before starting a search, make sure at least two free nodes
	 * are available at the tail of the LRU list, since two nodes
	 * are required to allocate a new leaf during the search.
	 * for an internal node, we may need 4 free nodes.
	 */
	if (len == tp->tr_keylen)
		needfree = 2;	/* leaf node */
	else
		needfree = 4;	/* internal node */
	if (tp->tr_nfree < needfree)
		leaf_reclaim(tp, needfree);

	np = tp->tr_top;
	while (1) {
		if (len < np->tn_prefixlen) {
			/*
			 * a special case for looking for a non-existent
			 * internal node.  we need to create dummy
			 * leaves to make this branch point.
			 *  first case: np is a child of the target
			 *    create a dummy leaf to make the target
			 *  second case: np isn't a child of the target
			 *    we need 4 nodes.  first create
			 *    a branch point by the target key with full
			 *    prefixlen.  then, go on to the first case.
			 */
			u_char	leafkey[MAX_KEYBYTES];

			memcpy(leafkey, key, tp->tr_keylen/8);
			if (prefix_cmp(np->tn_key, key, len) == 0) {
				if (bit_test(np->tn_key, len + 1) == 0)
					bit_set(leafkey, len + 1);
				(void)leaf_alloc(tp, leafkey, np);
				assert(len == np->tn_parent->tn_prefixlen);
				assert(prefix_cmp(np->tn_parent->tn_key,
						  key, len) == 0);
				return (np->tn_parent);
			} else {
				np = leaf_alloc(tp, leafkey, np);
				continue;
			}
		}

		if (prefix_cmp(np->tn_key, key, np->tn_prefixlen) != 0) {
			/*
			 * the prefix doesn't match, we need to
			 * insert new nodes here
			 */
			np = leaf_alloc(tp, key, np);
			if (len != tp->tr_keylen)
				continue;
			return (np);
		}

		/*
		 * the prefix matched.
		 * if len is equal to the prefixlen, we have a match.
		 * otherwise, we have to go down the tree.
		 * since the node holds the common prefix of the
		 * two children, the bit value at prefixlen + 1
		 * shows which way to take.
		 */
		if (len == np->tn_prefixlen) {
#ifdef AGURI_STATS
			tp->tr_stats.hits++;
#endif
			return (np);
		}

		/* if np has no child, create 2 leaves */
		if (np->tn_right == NULL) {
			np = leaf_alloc(tp, key, np);
			if (len != tp->tr_keylen)
				continue;
			return (np);
		}

		if (bit_test(key, np->tn_prefixlen + 1))
			np = np->tn_right;
		else
			np = np->tn_left;
	}
	/* NOTREACHED */
}

struct tree_node *
tree_match(struct tree *tp, const void *key, size_t len)
{
	return tnode_match(tp, key, len);
}


/*
 * tnode_match returns the longest match node.
 * note: this is not exact "longest match", and may return the node
 * with longer prefixlen than specified.
 * currently used only for the agr_flow tree.
 */
static struct tree_node *
tnode_match(struct tree *tp, const void *key, size_t len)
{
	struct tree_node *np, *prev = NULL;

	np = tp->tr_top;
	while (1) {
		size_t l = (len < np->tn_prefixlen) ? len : np->tn_prefixlen;
		if (prefix_cmp(np->tn_key, key, l) != 0) {
			if (prev != NULL)
				return (prev);
			/* the prefix doesn't match (should not happen) */
			return (tp->tr_top);
		}

		/*
		 * the prefix matched.
		 * if len is equal to the prefixlen, we have a match.
		 * otherwise, we have to go down the tree.
		 * since the node holds the common prefix of the
		 * two children, the bit value at prefixlen + 1
		 * shows which way to take.
		 */
		if (len <= np->tn_prefixlen)
			return (np);

		/* if np has no child, this is the longest match */
		if (np->tn_right == NULL)
				return (np);

		prev = np;
		if (bit_test(key, np->tn_prefixlen + 1))
			np = np->tn_right;
		else
			np = np->tn_left;
	}
	/* NOTREACHED */
}

/*
 * tree_matchindex() is similar to tree_match(), but only matches
 * nodes with a positive index.
 */
struct tree_node *
tree_matchindex(struct tree *tp, const void *key, size_t len)
{
	return tnode_matchindex(tp, key, len);
}

static struct tree_node *
tnode_matchindex(struct tree *tp, const void *key, size_t len)
{
	struct tree_node *np, *prev = NULL;

	np = tp->tr_top;
	while (1) {
		size_t l = (len < np->tn_prefixlen) ? len : np->tn_prefixlen;
		if (prefix_cmp(np->tn_key, key, l) != 0) {
			if (prev != NULL)
				return (prev);
			/* the prefix doesn't match */
			return (tp->tr_top);
		}

		/*
		 * the prefix matched.
		 * if len is equal to the prefixlen, we have a match.
		 * otherwise, we have to go down the tree.
		 * since the node holds the common prefix of the
		 * two children, the bit value at prefixlen + 1
		 * shows which way to take.
		 */
		if (len <= np->tn_prefixlen) {
			if (np->tn_index >= 0)
				return (np);
			if (prev != NULL)
				return (prev);
			return (tp->tr_top);
		}

		/* if np has no child, this is the longest match */
		if (np->tn_right == NULL) {
			if (np->tn_index >= 0)
				return (np);
			if (prev != NULL)
				return (prev);
			return (tp->tr_top);
		}

		if (np->tn_index >= 0)
			prev = np;
		if (bit_test(key, np->tn_prefixlen + 1))
			np = np->tn_right;
		else
			np = np->tn_left;
	}
	/* NOTREACHED */
}

/*
 * are_similar() compares 2 nodes, and returns 1 if their counts
 * differ less than 12.5% (diff < mean / 8)
 * XXX only byte counts are used at the moment
 */
static int
are_similar(struct tree_node *np, struct tree_node *np2)
{
	u_int64_t diff;

	if (np->tn_count > np2->tn_count)
		diff = np->tn_count - np2->tn_count;
	else
		diff = np2->tn_count - np->tn_count;
	if (diff < ((np->tn_count + np2->tn_count) >> 4))
		return 1;
	return 0;
}

static inline int
tnode_aggregate(struct tree_node *np, void *arg)
{
	u_int64_t thresh = *(u_int64_t *)arg;
	u_int64_t thresh2 = *((u_int64_t *)arg + 1);

	if (thresh == 0)
		thresh = 1;
	if (thresh2 == 0)
		thresh2 = 1;
	if ((disable_heuristics & 1) == 0) {
		int scale = np->tn_tree->tr_thscale[np->tn_prefixlen];
		thresh  <<= scale;
		thresh2 <<= scale;
	}

#if 1  /* experimental */
	if ((disable_heuristics & 2) == 0 && np->tn_right != NULL) {
		int merge_right = 0, merge_left = 0;
		/*
		 * heuristics to mitigate threshold sensitivity.
		 * when children have similar counts, merge them.
		 */
		if (np->tn_right->tn_count > 0 &&
		    np->tn_left->tn_count > 0 &&
		    np->tn_right->tn_prefixlen ==
		    np->tn_left->tn_prefixlen &&
		    are_similar(np->tn_right, np->tn_left)) {
			/* both children have same prefixlen and 
			 * similar counts */
			merge_right = merge_left = 1;
		} else {
			/* when one child is just below the threshold,
			 * it's been already merged to this node.
			 * so, check if this is the case */
			if (np->tn_right->tn_count > 0 &&
			    np->tn_left->tn_prefixlen == 
			    np->tn_prefixlen + 1 &&
			    are_similar(np, np->tn_right))
				merge_right = 1;
			else if (np->tn_left->tn_count > 0 &&
			    np->tn_right->tn_prefixlen == 
			    np->tn_prefixlen + 1 &&
			    are_similar(np, np->tn_left))
				merge_left = 1;
		}
		if (merge_right) {
			np->tn_count += np->tn_right->tn_count;
			np->tn_right->tn_count = 0;
			np->tn_count2 += np->tn_right->tn_count2;
			np->tn_right->tn_count2 = 0;
			np->tn_right->tn_index = -1;
		}
		if (merge_left) {
			np->tn_count += np->tn_left->tn_count;
			np->tn_left->tn_count = 0;
			np->tn_count2 += np->tn_left->tn_count2;
			np->tn_left->tn_count2 = 0;
			np->tn_left->tn_index = -1;
		}
	}
#endif
	/* if count is less than thresh, aggregate */
	if (np->tn_parent != NULL
		&& np->tn_count < thresh && np->tn_count2 < thresh2) {
		if (np->tn_count > 0) {
			np->tn_parent->tn_count += np->tn_count;
			np->tn_count = 0;
			np->tn_parent->tn_count2 += np->tn_count2;
			np->tn_count2 = 0;
		}
		np->tn_index = -1;
	} else {
		np->tn_index = np->tn_tree->tr_indices++;
	}
	return (0);
}

static int
key_print(u_char *key, size_t len, size_t prefixlen)
{
	int i;

	printf("0x");
	for (i=0; i<len/8; i++)
		printf("%02x", key[i]);
	printf("/%u", (u_int)prefixlen);
	return (0);
}

static int
tnode_print(struct tree_node *np, void *arg)
{
	int i;
#if 0
	if (np->tn_count == 0)
		return (0);
#endif
	for (i=0; i<np->tn_depth; i++)
		printf(" ");
	key_print(np->tn_key, np->tn_tree->tr_keylen, np->tn_prefixlen);
#if 1
	printf(" (%d)", np->tn_index);
#endif
	printf(": %"PRIu64" %"PRIu64"\n", np->tn_count, np->tn_count2);
	return (0);
}

static unsigned char prefixmask[8] =
	{ 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };

/*
 * compare prefixes of p1 and p2
 */
static __inline__ int
prefix_cmp(const void *p1, const void *p2, size_t len)
{
	const unsigned char *c1, *c2;
	unsigned char mask;
	size_t bytes, bits;

	if (len == 0)
		return (0);

	c1 = p1;
	c2 = p2;
	bytes = len / 8;
	bits = len & 7;

	while (bytes-- != 0)
		if (*c1++ != *c2++)
			return (*--c1 - *--c2);
	if ((mask = prefixmask[bits]) == 0)
		return (0);
	return ((*c1 & mask) - (*c2 & mask));
}

/*
 * extract a common prefix from p1 and p2 to p3, return the common prefixlen
 */
static size_t
prefix_common(const void *p1, const void *p2, size_t len, void *p3)
{
	const unsigned char *c1, *c2, *end;
	unsigned char val, *c3;
	size_t bytes, bits, n;

	c1 = p1;
	c2 = p2;
	c3 = p3;
	end = p3 + ((len + 7) / 8);
	n = 0;
	bytes = len / 8;
	bits = len & 7;

	while (bytes-- != 0) {
		if (*c1 != *c2) {
			bits = 7; /* at most 7 bits can be common */
			break;
		}
		*c3++ = *c1++;
		c2++;
		n += 8;
	}
	if (bits != 0) {
		val = *c1 ^ *c2;
		do {
			if (val & 0x80)
				break;
			n++;
			val <<= 1;
		} while (--bits != 0);
		*c3++ = *c1 & prefixmask[n & 7];
	}
	/* clear the remaining bytes */
	while (c3 < end)
		*c3++ = 0;
	return (n);
}

/*
 * return the bit value at the specified position
 */
static unsigned char bitpos[8] =
	{ 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };

static __inline__ int
bit_test(const void *p, size_t pos)
{
	const unsigned char *cp;
	size_t off;

	cp = p;
	off = (pos - 1) / 8;
	return (cp[off] & bitpos[(pos - 1) & 7]);
}

static void
bit_set(void *p, size_t pos)
{
	unsigned char *cp;
	size_t off;

	cp = p;
	off = (pos - 1) / 8;
	cp[off] |= bitpos[(pos - 1) & 7];
}

#if 0
static void
bit_clear(void *p, size_t pos)
{
	unsigned char *cp;
	size_t off;

	cp = p;
	off = (pos - 1) / 8;
	cp[off] &= ~bitpos[(pos - 1) & 7];
}
#endif

#if 1
static void
check_nfree(struct tree *tp)
{
	struct tree_node *np;
	int i, n, l;

	i = n = l = 0;
	TAILQ_FOREACH(np, &tp->tr_lru, tn_chain) {
		if (np->tn_intree == 0)
			i++;
		else if (np->tn_left == NULL)
			l++;
		n++;
	}
	fprintf(stderr, "#nfree:%u free:%d leaf:%d in_lru:%d\n",
		tp->tr_nfree, i, l, n);
	assert(i == tp->tr_nfree);
}
#endif
