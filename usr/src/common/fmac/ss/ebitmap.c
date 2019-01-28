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
 * Implementation of the extensible bitmap type.
 */

#if defined(_KERNEL)
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#else
#include <inttypes.h>
#include <stdio.h>
#endif /* defined(_KERNEL) */

#include "ss_impl.h"
#include "ebitmap.h"
#include "policydb.h"

int
ebitmap_or(ebitmap_t *dst, ebitmap_t *e1, ebitmap_t *e2)
{
	ebitmap_node_t *n1, *n2, *new, *prev;

	ebitmap_init(dst);

	n1 = e1->node;
	n2 = e2->node;
	prev = 0;
	while (n1 || n2) {
		new = (ebitmap_node_t *) SS_ALLOC_NOSLEEP(
		    sizeof (ebitmap_node_t));
		if (!new) {
			ebitmap_destroy(dst);
			return (FALSE);
		}
		(void) memset(new, 0, sizeof (ebitmap_node_t));
		if (n1 && n2 && n1->startbit == n2->startbit) {
			new->startbit = n1->startbit;
			new->map = n1->map | n2->map;
			n1 = n1->next;
			n2 = n2->next;
		} else if (!n2 || (n1 && n1->startbit < n2->startbit)) {
			new->startbit = n1->startbit;
			new->map = n1->map;
			n1 = n1->next;
		} else {
			new->startbit = n2->startbit;
			new->map = n2->map;
			n2 = n2->next;
		}

		new->next = 0;
		if (prev)
			prev->next = new;
		else
			dst->node = new;
		prev = new;
	}

	dst->highbit = (e1->highbit > e2->highbit) ? e1->highbit : e2->highbit;
	return (TRUE);
}

int
ebitmap_cmp(ebitmap_t *e1, ebitmap_t *e2)
{
	ebitmap_node_t *n1, *n2;


	if (e1->highbit != e2->highbit)
		return (FALSE);

	n1 = e1->node;
	n2 = e2->node;
	while (n1 && n2 && (n1->startbit == n2->startbit) &&
	    (n1->map == n2->map)) {
		n1 = n1->next;
		n2 = n2->next;
	}

	if (n1 || n2)
		return (FALSE);

	return (TRUE);
}

int
ebitmap_cpy(ebitmap_t *dst, ebitmap_t *src)
{
	ebitmap_node_t *n, *new, *prev;


	ebitmap_init(dst);
	n = src->node;
	prev = 0;
	while (n) {
		new = (ebitmap_node_t *) SS_ALLOC_NOSLEEP(
		    sizeof (ebitmap_node_t));
		if (!new) {
			ebitmap_destroy(dst);
			return (FALSE);
		}
		(void) memset(new, 0, sizeof (ebitmap_node_t));
		new->startbit = n->startbit;
		new->map = n->map;
		new->next = 0;
		if (prev)
			prev->next = new;
		else
			dst->node = new;
		prev = new;
		n = n->next;
	}

	dst->highbit = src->highbit;
	return (TRUE);
}

int
ebitmap_contains(ebitmap_t *e1, ebitmap_t *e2)
{
	ebitmap_node_t *n1, *n2;


	if (e1->highbit < e2->highbit)
		return (FALSE);

	n1 = e1->node;
	n2 = e2->node;
	while (n1 && n2 && (n1->startbit <= n2->startbit)) {
		if (n1->startbit < n2->startbit) {
			n1 = n1->next;
			continue;
		}
		if ((n1->map & n2->map) != n2->map)
			return (FALSE);

		n1 = n1->next;
		n2 = n2->next;
	}

	if (n2)
		return (FALSE);

	return (TRUE);
}

int
ebitmap_get_bit(ebitmap_t *e, unsigned long bit)
{
	ebitmap_node_t *n;

	if (e->highbit < bit)
		return (FALSE);

	n = e->node;
	while (n && (n->startbit <= bit)) {
		if ((n->startbit + MAPSIZE) > bit) {
			if (n->map & (MAPBIT << (bit - n->startbit)))
				return (TRUE);
			else
				return (FALSE);
		}
		n = n->next;
	}

	return (FALSE);
}

int
ebitmap_set_bit(ebitmap_t *e, unsigned long bit, int value)
{
	ebitmap_node_t *n, *prev, *new;


	prev = 0;
	n = e->node;
	while (n && n->startbit <= bit) {
		if ((n->startbit + MAPSIZE) > bit) {
			if (value) {
				n->map |= (MAPBIT << (bit - n->startbit));
			} else {
				n->map &= ~(MAPBIT << (bit - n->startbit));
				if (!n->map) {
					/* drop this node from the bitmap */

					if (!n->next) {
						/*
						 * this was the highest map
						 * within the bitmap
						 */
						if (prev)
							e->highbit =
							    prev->startbit +
							    MAPSIZE;
						else
							e->highbit = 0;
					}
					if (prev)
						prev->next = n->next;
					else
						e->node = n->next;

					SS_FREE(n, sizeof (ebitmap_node_t));
				}
			}
			return (TRUE);
		}
		prev = n;
		n = n->next;
	}

	if (!value)
		return (TRUE);

	new = (ebitmap_node_t *) SS_ALLOC_NOSLEEP(sizeof (ebitmap_node_t));
	if (!new)
		return (FALSE);
	(void) memset(new, 0, sizeof (ebitmap_node_t));

	new->startbit = bit & ~(MAPSIZE - 1);
	new->map = (MAPBIT << (bit - new->startbit));

	if (!n)
		/* this node will be the highest map within the bitmap */
		e->highbit = new->startbit + MAPSIZE;

	if (prev) {
		new->next = prev->next;
		prev->next = new;
	} else {
		new->next = e->node;
		e->node = new;
	}

	return (TRUE);
}

void
ebitmap_destroy(ebitmap_t *e)
{
	ebitmap_node_t *n, *temp;

	if (!e)
		return;

	n = e->node;
	while (n) {
		temp = n;
		n = n->next;
		SS_FREE(temp, sizeof (ebitmap_node_t));
	}

	e->highbit = 0;
	e->node = 0;
}

int
ebitmap_read(ebitmap_t *e, void *fp)
{
	ebitmap_node_t *n, *l;
	uint32_t buf[3], mapsize, count, i;
	uint64_t map;
	size_t items;

	ebitmap_init(e);

	items = next_entry(buf, sizeof (uint32_t), 3, fp);
	if (items != 3)
		return (FALSE);
	mapsize = SS_LE32_TO_CPU(buf[0]);
	e->highbit = SS_LE32_TO_CPU(buf[1]);
	count = SS_LE32_TO_CPU(buf[2]);

	if (mapsize != MAPSIZE) {
		(void) printf("security: ebitmap: map size %u does not match "
		    "my size %u (high bit was %u)\n", mapsize,
		    (uint32_t)MAPSIZE, e->highbit);
		return (FALSE);
	}
	if (!e->highbit) {
		e->node = NULL;
		return (TRUE);
	}
	if (e->highbit & (MAPSIZE - 1)) {
		(void) printf("security: ebitmap: high bit (%u) is not "
		    "a multiple of the map size (%u)\n",
		    e->highbit, (uint32_t)MAPSIZE);
		goto bad;
	}
	l = NULL;
	for (i = 0; i < count; i++) {
		items = next_entry(buf, sizeof (uint32_t), 1, fp);
		if (items != 1) {
			(void) printf("security: ebitmap: truncated map\n");
			goto bad;
		}
		n = (ebitmap_node_t *) SS_ALLOC_NOSLEEP(
		    sizeof (ebitmap_node_t));
		if (!n) {
			(void) printf("security: ebitmap: out of memory\n");
			goto bad;
		}
		(void) memset(n, 0, sizeof (ebitmap_node_t));

		n->startbit = SS_LE32_TO_CPU(buf[0]);

		if (n->startbit & (MAPSIZE - 1)) {
			(void) printf("security: ebitmap start bit (%u) is "
			    "not a multiple of the map size (%u)\n",
			    n->startbit, (uint32_t)MAPSIZE);
			goto bad_free;
		}
		if (n->startbit > (e->highbit - MAPSIZE)) {
			(void) printf("security: ebitmap start bit (%u) is "
			    "beyond the end of the bitmap (%u)\n",
			    n->startbit, (uint32_t)(e->highbit - MAPSIZE));
			goto bad_free;
		}
		items = next_entry(&map, sizeof (uint64_t), 1, fp);
		if (items != 1) {
			(void) printf("security: ebitmap: truncated map\n");
			goto bad_free;
		}
		n->map = SS_LE64_TO_CPU(map);

		if (!n->map) {
			(void) printf("security: ebitmap: null map in ebitmap "
			    "(startbit %d)\n",
			    n->startbit);
			goto bad_free;
		}
		if (l) {
			if (n->startbit <= l->startbit) {
				(void) printf("security: ebitmap: start bit "
				    "%d comes after start bit %d\n",
				    n->startbit, l->startbit);
				goto bad_free;
			}
			l->next = n;
		} else
			e->node = n;

		l = n;
	}

	return (TRUE);

bad_free:
	SS_FREE(n, sizeof (ebitmap_node_t));
bad:
	ebitmap_destroy(e);
	return (FALSE);
}
