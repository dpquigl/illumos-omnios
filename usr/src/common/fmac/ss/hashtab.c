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
 * Implementation of the hash table type.
 */


#if defined(_KERNEL)
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/systm.h>
#else
#include <errno.h>
#include <stdio.h>
#include <string.h>
#endif /* defined(_KERNEL) */

#include "ss_impl.h"
#include "hashtab.h"

hashtab_t
hashtab_create(unsigned int (*hash_value) (hashtab_t h, hashtab_key_t key),
    int (*keycmp) (hashtab_t h, hashtab_key_t key1, hashtab_key_t key2),
    unsigned int size)
{
	hashtab_t p;
	int i;


	p = (hashtab_t) SS_ALLOC_SLEEP(sizeof (hashtab_val_t));
	if (p == NULL)
		return (p);

	(void) memset(p, 0, sizeof (hashtab_val_t));
	p->size = size;
	p->nel = 0;
	p->hash_value = hash_value;
	p->keycmp = keycmp;
	p->htable =
	    (hashtab_ptr_t *) SS_ALLOC_SLEEP(sizeof (hashtab_ptr_t) * size);
	if (p->htable == NULL) {
		SS_FREE(p, sizeof (hashtab_val_t));
		return (NULL);
	}
	for (i = 0; i < size; i++)
		p->htable[i] = (hashtab_ptr_t) NULL;

	return (p);
}

int
hashtab_insert(hashtab_t h, hashtab_key_t key, hashtab_datum_t datum)
{
	int hvalue;
	hashtab_ptr_t prev, cur, newnode;


	if (!h)
		return (HASHTAB_OVERFLOW);

	hvalue = h->hash_value(h, key);
	prev = NULL;
	cur = h->htable[hvalue];
	while (cur && h->keycmp(h, key, cur->key) > 0) {
		prev = cur;
		cur = cur->next;
	}

	if (cur && (h->keycmp(h, key, cur->key) == 0))
		return (HASHTAB_PRESENT);

	newnode = (hashtab_ptr_t) SS_ALLOC_SLEEP(sizeof (hashtab_node_t));
	if (newnode == NULL)
		return (HASHTAB_OVERFLOW);
	(void) memset(newnode, 0, sizeof (struct hashtab_node));
	newnode->key = key;
	newnode->datum = datum;
	if (prev) {
		newnode->next = prev->next;
		prev->next = newnode;
	} else {
		newnode->next = h->htable[hvalue];
		h->htable[hvalue] = newnode;
	}

	h->nel++;
	return (HASHTAB_SUCCESS);
}

int
hashtab_remove(hashtab_t h, hashtab_key_t key,
    void (*destroy) (hashtab_key_t k, hashtab_datum_t d, void *args),
    void *args)
{
	int hvalue;
	hashtab_ptr_t cur, last;


	if (!h)
		return (HASHTAB_MISSING);

	hvalue = h->hash_value(h, key);
	last = NULL;
	cur = h->htable[hvalue];
	while (cur != NULL && h->keycmp(h, key, cur->key) > 0) {
		last = cur;
		cur = cur->next;
	}

	if (cur == NULL || (h->keycmp(h, key, cur->key) != 0))
		return (HASHTAB_MISSING);

	if (last == NULL)
		h->htable[hvalue] = cur->next;
	else
		last->next = cur->next;

	if (destroy)
		destroy(cur->key, cur->datum, args);
	SS_FREE(cur, sizeof (struct hashtab_node));
	h->nel--;
	return (HASHTAB_SUCCESS);
}

int
hashtab_replace(hashtab_t h, hashtab_key_t key, hashtab_datum_t datum,
    void (*destroy) (hashtab_key_t k, hashtab_datum_t d, void *args),
    void *args)
{
	int hvalue;
	hashtab_ptr_t prev, cur, newnode;


	if (!h)
		return (HASHTAB_OVERFLOW);

	hvalue = h->hash_value(h, key);
	prev = NULL;
	cur = h->htable[hvalue];
	while (cur != NULL && h->keycmp(h, key, cur->key) > 0) {
		prev = cur;
		cur = cur->next;
	}

	if (cur && (h->keycmp(h, key, cur->key) == 0)) {
		if (destroy)
			destroy(cur->key, cur->datum, args);
		cur->key = key;
		cur->datum = datum;
	} else {
		newnode =
		    (hashtab_ptr_t) SS_ALLOC_SLEEP(sizeof (hashtab_node_t));
		if (newnode == NULL)
			return (HASHTAB_OVERFLOW);
		(void) memset(newnode, 0, sizeof (struct hashtab_node));
		newnode->key = key;
		newnode->datum = datum;
		if (prev) {
			newnode->next = prev->next;
			prev->next = newnode;
		} else {
			newnode->next = h->htable[hvalue];
			h->htable[hvalue] = newnode;
		}
	}

	return (HASHTAB_SUCCESS);
}

hashtab_datum_t
hashtab_search(hashtab_t h, hashtab_key_t key)
{
	int hvalue;
	hashtab_ptr_t cur;


	if (!h)
		return (NULL);

	hvalue = h->hash_value(h, key);
	cur = h->htable[hvalue];
	while (cur != NULL && h->keycmp(h, key, cur->key) > 0)
		cur = cur->next;

	if (cur == NULL || (h->keycmp(h, key, cur->key) != 0))
		return (NULL);

	return (cur->datum);
}

void
hashtab_destroy(hashtab_t h)
{
	int i;
	hashtab_ptr_t cur, temp;


	if (!h)
		return;

	for (i = 0; i < h->size; i++) {
		cur = h->htable[i];
		while (cur != NULL) {
			temp = cur;
			cur = cur->next;
			SS_FREE(temp, sizeof (hashtab_node_t));
		}
		h->htable[i] = NULL;
	}

	SS_FREE(h->htable, sizeof (hashtab_ptr_t) * h->size);
	h->htable = NULL;

	SS_FREE(h, sizeof (hashtab_val_t));
}

int
hashtab_map(
	hashtab_t h,
	int (*apply) (
		hashtab_key_t k,
		hashtab_datum_t d,
		void *args),
	void *args)
{
	int i, ret;
	hashtab_ptr_t cur;


	if (!h)
		return (HASHTAB_SUCCESS);

	for (i = 0; i < h->size; i++) {
		cur = h->htable[i];
		while (cur != NULL) {
			ret = apply(cur->key, cur->datum, args);
			if (ret)
				return (ret);
			cur = cur->next;
		}
	}
	return (HASHTAB_SUCCESS);
}

void
hashtab_map_remove_on_error(hashtab_t h, int (*apply) (hashtab_key_t k,
    hashtab_datum_t d, void *args), void (*destroy) (hashtab_key_t k,
    hashtab_datum_t d, void *args), void *args)
{
	int i, ret;
	hashtab_ptr_t last, cur, temp;


	if (!h)
		return;

	for (i = 0; i < h->size; i++) {
		last = NULL;
		cur = h->htable[i];
		while (cur != NULL) {
			ret = apply(cur->key, cur->datum, args);
			if (ret) {
				if (last) {
					last->next = cur->next;
				} else {
					h->htable[i] = cur->next;
				}

				temp = cur;
				cur = cur->next;
				if (destroy)
					destroy(temp->key, temp->datum, args);
				SS_FREE(temp, sizeof (hashtab_node_t));
				h->nel--;
			} else {
				last = cur;
				cur = cur->next;
			}
		}
	}
}

void
hashtab_hash_eval(hashtab_t h, char *tag)
{
	int i, chain_len, slots_used, max_chain_len;
	hashtab_ptr_t cur;


	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < h->size; i++) {
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
		h->size,
		max_chain_len);
}
