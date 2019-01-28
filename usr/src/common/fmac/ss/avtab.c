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
 * Implementation of the access vector table type.
 */

#include <sys/note.h>

#if defined(_KERNEL)
#include <sys/inttypes.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#else
#include <inttypes.h>
#include <stdio.h>
#endif /* defined(_KERNEL) */

#include "ss_impl.h"
#include "avtab.h"
#include "policydb.h"

#define	AVTAB_HASH(keyp)						\
	((keyp->target_class +						\
	    (keyp->target_type << 2) + (keyp->source_type << 9)) &	\
	    AVTAB_HASH_MASK)

int
avtab_insert(avtab_t *h, avtab_key_t *key, avtab_datum_t *datum)
{
	int hvalue;
	avtab_ptr_t prev, cur, newnode;

	if (!h)
		return (ENOMEM);

	hvalue = AVTAB_HASH(key);
	for (prev = NULL, cur = h->htable[hvalue]; cur; prev = cur,
		cur = cur->next) {
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (datum->specified & cur->datum.specified))
			return (EEXIST);
		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}

	newnode = (avtab_ptr_t) SS_ALLOC_SLEEP(sizeof (struct avtab_node));
	if (newnode == NULL)
		return (ENOMEM);
	(void) memset(newnode, 0, sizeof (struct avtab_node));
	newnode->key = *key;
	newnode->datum = *datum;
	if (prev) {
		newnode->next = prev->next;
		prev->next = newnode;
	} else {
		newnode->next = h->htable[hvalue];
		h->htable[hvalue] = newnode;
	}

	h->nel++;
	return (0);
}


avtab_datum_t *
avtab_search(avtab_t *h, avtab_key_t *key, int specified)
{
	int hvalue;
	avtab_ptr_t cur;


	if (!h)
		return (NULL);

	hvalue = AVTAB_HASH(key);
	for (cur = h->htable[hvalue]; cur; cur = cur->next) {
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->datum.specified))
			return (&cur->datum);

		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}

	return (NULL);
}


void
avtab_destroy(avtab_t *h)
{
	int i;
	avtab_ptr_t cur, temp;


	if (!h)
		return;

	for (i = 0; i < AVTAB_SIZE; i++) {
		cur = h->htable[i];
		while (cur != NULL) {
			temp = cur;
			cur = cur->next;
			SS_FREE(temp, sizeof (struct avtab_node));
		}
		h->htable[i] = NULL;
	}
	SS_FREE(h->htable, sizeof (avtab_ptr_t)*AVTAB_SIZE);
}


int
avtab_map(avtab_t *h, int (*apply) (avtab_key_t *k, avtab_datum_t *d,
    void *args), void *args)
{
	int i, ret;
	avtab_ptr_t cur;


	if (!h)
		return (0);

	for (i = 0; i < AVTAB_SIZE; i++) {
		cur = h->htable[i];
		while (cur != NULL) {
			ret = apply(&cur->key, &cur->datum, args);
			if (ret)
				return (ret);
			cur = cur->next;
		}
	}
	return (0);
}

int
avtab_init(avtab_t *h)
{
	int i;

	h->htable = SS_ALLOC_SLEEP(sizeof (avtab_ptr_t)*AVTAB_SIZE);
	if (!h->htable)
		return (-1);
	for (i = 0; i < AVTAB_SIZE; i++)
		h->htable[i] = (avtab_ptr_t) NULL;
	h->nel = 0;
	return (0);
}


void
avtab_hash_eval(avtab_t *h, char *tag)
{
	int i, chain_len, slots_used, max_chain_len;
	avtab_ptr_t cur;


	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < AVTAB_SIZE; i++) {
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

	(void) printf("%s:  %d entries and %d/%d buckets used, longest "
		"chain length %d\n",
		tag,
		h->nel,
		slots_used,
		AVTAB_SIZE,
		max_chain_len);
}

int
avtab_read(avtab_t *a, void *fp, uint32_t config)
{
	int i, rc;
	avtab_key_t avkey;
	avtab_datum_t avdatum;
	uint32_t buf[7];
	uint32_t nel;
	size_t items, items2;

	_NOTE(ARGUNUSED(config));

	items = next_entry(&nel, sizeof (uint32_t), 1, fp);
	if (items != 1) {
		(void) printf("security: avtab: truncated table\n");
		goto bad;
	}
	nel = SS_LE32_TO_CPU(nel);
	if (!nel) {
		(void) printf("security: avtab: table is empty\n");
		goto bad;
	}
	for (i = 0; i < nel; i++) {
		(void) memset(&avkey, 0, sizeof (avtab_key_t));
		(void) memset(&avdatum, 0, sizeof (avtab_datum_t));

		items = next_entry(buf, sizeof (uint32_t), 1, fp);
		if (items != 1) {
			(void) printf("security: avtab: truncated entry\n");
			goto bad;
		}
		items2 = SS_LE32_TO_CPU(buf[0]);
		if (items2 > (sizeof (buf) / sizeof (uint32_t))) {
			(void) printf("security: avtab: entry too large\n");
			goto bad;
		}
		items = next_entry(buf, sizeof (uint32_t), items2, fp);
		if (items != items2) {
			(void) printf("security: avtab: truncated entry\n");
			goto bad;
		}
		items = 0;
		avkey.source_type = SS_LE32_TO_CPU(buf[items++]);
		avkey.target_type = SS_LE32_TO_CPU(buf[items++]);
		avkey.target_class = SS_LE32_TO_CPU(buf[items++]);
		avdatum.specified = SS_LE32_TO_CPU(buf[items++]);
		if (!(avdatum.specified & (AVTAB_AV | AVTAB_TYPE))) {
			(void) printf("security: avtab: null entry\n");
			goto bad;
		}
		if ((avdatum.specified & AVTAB_AV) &&
		    (avdatum.specified & AVTAB_TYPE)) {
			(void) printf("security: avtab: entry has both "
				"access vectors and types\n");
			goto bad;
		}
		if (avdatum.specified & AVTAB_AV) {
			if (avdatum.specified & AVTAB_ALLOWED)
				avtab_allowed(&avdatum) =
				    SS_LE32_TO_CPU(buf[items++]);
			if (avdatum.specified & AVTAB_AUDITDENY)
				avtab_auditdeny(&avdatum) =
				    SS_LE32_TO_CPU(buf[items++]);
			if (avdatum.specified & AVTAB_AUDITALLOW)
				avtab_auditallow(&avdatum) =
				    SS_LE32_TO_CPU(buf[items++]);
		} else {
			if (avdatum.specified & AVTAB_TRANSITION)
				avtab_transition(&avdatum) =
				    SS_LE32_TO_CPU(buf[items++]);
			if (avdatum.specified & AVTAB_CHANGE)
				avtab_change(&avdatum) =
				    SS_LE32_TO_CPU(buf[items++]);
			if (avdatum.specified & AVTAB_MEMBER)
				avtab_member(&avdatum) =
				    SS_LE32_TO_CPU(buf[items++]);
		}
		if (items != items2) {
			(void) printf("security: avtab: entry only had %lu "
			    "items, expected %lu\n", items2, items);
			goto bad;
		}
		rc = avtab_insert(a, &avkey, &avdatum);
		if (rc) {
			if (rc == ENOMEM)
				(void) printf("security: avtab: out of "
				    "memory\n");
			if (rc == EEXIST)
				(void) printf("security: avtab: duplicate "
				    "entry\n");
			goto bad;
		}
	}

	return (0);

bad:
	avtab_destroy(a);
	return (-1);
}
