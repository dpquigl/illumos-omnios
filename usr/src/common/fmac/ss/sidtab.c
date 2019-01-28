/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Original files contributed to OpenSolaris.org under license by the
 * United States Government (NSA) to Sun Microsystems, Inc.
 */

/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/*
 * Implementation of the SID table type.
 */

#include <sys/types.h>

#if defined(_KERNEL)
#include <sys/inttypes.h>
#include <sys/ksynch.h>
#else
#include <inttypes.h>
#include <thread.h>
#include <synch.h>
#include <limits.h>
#endif /* defined(_KERNEL) */

#include "ss_impl.h"
#include <sys/fmac/flask.h>
#include "sidtab.h"

#define	SIDTAB_HASH(sid)	(sid & SIDTAB_HASH_MASK)

#if defined(_KERNEL)
#define	INIT_SIDTAB_LOCK(s) mutex_init(&s->lock, NULL, MUTEX_DEFAULT, NULL)
#define	SIDTAB_LOCK(s) mutex_enter(&s->lock)
#define	SIDTAB_UNLOCK(s) mutex_exit(&s->lock)
#else
#define	INIT_SIDTAB_LOCK(s) mutex_init(&s->lock, USYNC_THREAD, NULL)
#define	SIDTAB_LOCK(s) mutex_lock(&s->lock)
#define	SIDTAB_UNLOCK(s) mutex_unlock(&s->lock)
#endif

int
sidtab_init(sidtab_t *s)
{
	int i;

	s->htable = SS_ALLOC_NOSLEEP(sizeof (sidtab_ptr_t)*SIDTAB_SIZE);
	if (!s->htable)
		return (ENOMEM);
	for (i = 0; i < SIDTAB_SIZE; i++)
		s->htable[i] = (sidtab_ptr_t) NULL;
	s->nel = 0;
	s->next_sid = 1;
	s->shutdown = 0;
	INIT_SIDTAB_LOCK(s);
	return (0);
}

int
sidtab_insert(sidtab_t *s, security_id_t sid, context_struct_t *context)
{
	int hvalue;
	sidtab_node_t *prev, *cur, *newnode;


	if (!s)
		return (ENOMEM);

	hvalue = SIDTAB_HASH(sid);
	prev = NULL;
	cur = s->htable[hvalue];
	while (cur != NULL && sid > cur->sid) {
		prev = cur;
		cur = cur->next;
	}

	if (cur && sid == cur->sid)
		return (EEXIST);

	newnode = (sidtab_node_t *) SS_ALLOC_NOSLEEP(sizeof (sidtab_node_t));
	if (newnode == NULL)
		return (ENOMEM);
	newnode->sid = sid;
	if (context_cpy(&newnode->context, context)) {
		SS_FREE(newnode, sizeof (sidtab_node_t));
		return (ENOMEM);
	}

	if (prev) {
		newnode->next = prev->next;
		prev->next = newnode;
	} else {
		newnode->next = s->htable[hvalue];
		s->htable[hvalue] = newnode;
	}

	s->nel++;
	if (sid >= s->next_sid)
		s->next_sid = sid + 1;
	return (0);
}

int
sidtab_remove(sidtab_t *s, security_id_t sid)
{
	int hvalue;
	sidtab_node_t *cur, *last;


	if (!s)
		return (ENOENT);

	hvalue = SIDTAB_HASH(sid);
	last = NULL;
	cur = s->htable[hvalue];
	while (cur != NULL && sid > cur->sid) {
		last = cur;
		cur = cur->next;
	}

	if (cur == NULL || sid != cur->sid)
		return (ENOENT);

	if (last == NULL)
		s->htable[hvalue] = cur->next;
	else
		last->next = cur->next;

	context_destroy(&cur->context);

	SS_FREE(cur, sizeof (sidtab_node_t));
	s->nel--;
	return (0);
}

context_struct_t *
sidtab_search(sidtab_t *s, security_id_t sid)
{
	int hvalue;
	sidtab_node_t *cur;

	if (!s)
		return (NULL);

	hvalue = SIDTAB_HASH(sid);
	cur = s->htable[hvalue];
	while (cur != NULL && sid > cur->sid)
		cur = cur->next;

	if (cur == NULL || sid != cur->sid) {
		/* Remap invalid SIDs to the unlabeled SID. */
		sid = SECINITSID_UNLABELED;
		hvalue = SIDTAB_HASH(sid);
		cur = s->htable[hvalue];
		while (cur != NULL && sid > cur->sid)
			cur = cur->next;
		if (!cur || sid != cur->sid)
			return (NULL);
	}

	return (&cur->context);
}

int
sidtab_map(sidtab_t *s, int (*apply) (security_id_t sid,
    context_struct_t *context, void *args), void *args)
{
	int i, ret;
	sidtab_node_t *cur;


	if (!s)
		return (0);

	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = s->htable[i];
		while (cur != NULL) {
			ret = apply(cur->sid, &cur->context, args);
			if (ret)
				return (ret);
			cur = cur->next;
		}
	}
	return (0);
}

void
sidtab_map_remove_on_error(sidtab_t *s, int (*apply) (security_id_t sid,
    context_struct_t *context, void *args), void *args)
{
	int i, ret;
	sidtab_node_t *last, *cur, *temp;


	if (!s)
		return;

	for (i = 0; i < SIDTAB_SIZE; i++) {
		last = NULL;
		cur = s->htable[i];
		while (cur != NULL) {
			ret = apply(cur->sid, &cur->context, args);
			if (ret) {
				if (last) {
					last->next = cur->next;
				} else {
					s->htable[i] = cur->next;
				}

				temp = cur;
				cur = cur->next;
				context_destroy(&temp->context);
				SS_FREE(temp, sizeof (sidtab_node_t));
				s->nel--;
			} else {
				last = cur;
				cur = cur->next;
			}
		}
	}
}

static inline security_id_t
sidtab_search_context(sidtab_t *s, context_struct_t *context)
{
	int i;
	sidtab_node_t *cur;

	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = s->htable[i];
		while (cur != NULL) {
			if (context_cmp(&cur->context, context))
				return (cur->sid);
			cur = cur->next;
		}
	}
	return (0);
}

int
sidtab_context_to_sid(sidtab_t *s, context_struct_t *context,
    security_id_t *out_sid)
{
	security_id_t sid;
	int ret = 0;

	*out_sid = SECSID_NULL;

	sid = sidtab_search_context(s, context);
	if (!sid) {
		SIDTAB_LOCK(s);
		/* Rescan now that we hold the lock. */
		sid = sidtab_search_context(s, context);
		if (sid)
			goto unlock_out;
		/* No SID exists for the context.  Allocate a new one. */
		if (s->next_sid == UINT_MAX || s->shutdown) {
			ret = ENOMEM;
			goto unlock_out;
		}
		sid = s->next_sid++;
		ret = sidtab_insert(s, sid, context);
		if (ret)
			s->next_sid--;
unlock_out:
		SIDTAB_UNLOCK(s);
	}

	if (ret)
		return (ret);

	*out_sid = sid;
	return (0);
}

void
sidtab_hash_eval(sidtab_t *h, char *tag)
{
	int i, chain_len, slots_used, max_chain_len;
	sidtab_node_t *cur;


	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = h->htable[i];
		if (cur) {
			slots_used++;
			chain_len = 0;
			while (cur) {
				chain_len++;
				cur = cur->next;
			}

			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
	}

	(void) printf("%s:  %d entries and %d/%d buckets used, longest chain "
	    "length %d\n",
	    tag, h->nel, slots_used, SIDTAB_SIZE, max_chain_len);
}

void
sidtab_destroy(sidtab_t *s)
{
	int i;
	sidtab_ptr_t cur, temp;


	if (!s)
		return;

	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = s->htable[i];
		while (cur != NULL) {
			temp = cur;
			cur = cur->next;
			context_destroy(&temp->context);
			SS_FREE(temp, sizeof (sidtab_node_t));
		}
		s->htable[i] = NULL;
	}
	SS_FREE(s->htable, sizeof (sidtab_ptr_t) * SIDTAB_SIZE);
	s->htable = NULL;
	s->nel = 0;
	s->next_sid = 1;
}

void
sidtab_set(sidtab_t *dst, sidtab_t *src)
{
	SIDTAB_LOCK(src);
	dst->htable = src->htable;
	dst->nel = src->nel;
	dst->next_sid = src->next_sid;
	dst->shutdown = 0;
	SIDTAB_UNLOCK(src);
}

void
sidtab_shutdown(sidtab_t *s)
{
	SIDTAB_LOCK(s);
	s->shutdown = 1;
	SIDTAB_UNLOCK(s);
}

int
sidtab_get_sids(sidtab_t *s,
		    security_id_t **sids,
		    uint32_t *nel)
{
	int rc = 0;
	security_id_t *mysids;
	uint32_t mynel;
	int i, j;
	sidtab_node_t *cur;

	SIDTAB_LOCK(s);
	mynel = s->nel;
	mysids = SS_ALLOC_NOSLEEP(sizeof (security_id_t)*mynel);
	if (!mysids) {
		rc = ENOMEM;
		goto out;
	}
	j = 0;
	for (i = 0; i < SIDTAB_SIZE && j < mynel; i++) {
		cur = s->htable[i];
		while (cur != NULL && j < mynel) {
			mysids[j++] = cur->sid;
			cur = cur->next;
		}
	}
	*nel = mynel;
	*sids = mysids;

out:
	SIDTAB_UNLOCK(s);
	return (rc);
}
