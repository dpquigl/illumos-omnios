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
 * Original files contributed to OpenSolaris.org under license by the
 * United States Government (NSA) to Sun Microsystems, Inc.
 */

/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/*
 * An extensible bitmap is a bitmap that supports an
 * arbitrary number of bits.  Extensible bitmaps are
 * used to represent sets of values, such as types,
 * roles, categories, and classes.
 *
 * Each extensible bitmap is implemented as a linked
 * list of bitmap nodes, where each bitmap node has
 * an explicitly specified starting bit position within
 * the total bitmap.
 */

#ifndef _EBITMAP_H
#define	_EBITMAP_H

#if defined(_KERNEL)
#include <sys/inttypes.h>
#include <sys/systm.h>
#else
#include <inttypes.h>
#include <string.h>
#endif /* defined(_KERNEL) */

#define	MAPTYPE uint64_t		/* portion of bitmap in each node */
#define	MAPSIZE (sizeof (MAPTYPE) * 8)	/* number of bits in node bitmap */
#define	MAPBIT  1ULL			/* a bit in the node bitmap */

typedef struct ebitmap_node {
	uint32_t startbit;	/* starting position in the total bitmap */
	MAPTYPE map;		/* this node's portion of the bitmap */
	struct ebitmap_node *next;
} ebitmap_node_t;

typedef struct ebitmap {
	ebitmap_node_t *node;	/* first node in the bitmap */
	uint32_t highbit;	/* highest position in the total bitmap */
} ebitmap_t;


#define	ebitmap_length(e) ((e)->highbit)
#define	ebitmap_startbit(e) ((e)->node ? (e)->node->startbit : 0)

#define	ebitmap_init(e) (void) memset(e, 0, sizeof (ebitmap_t))

/*
 * All of the non-void functions return TRUE or FALSE.
 * Contrary to typical usage, nonzero (TRUE) is returned
 * on success and zero (FALSE) is returned on failure.
 * These functions should be changed to use more conventional
 * return codes.  TBD.
 */
#define	FALSE	0
#define	TRUE	1

int ebitmap_cmp(ebitmap_t *e1, ebitmap_t *e2);
int ebitmap_or(ebitmap_t *dst, ebitmap_t *e1, ebitmap_t *e2);
int ebitmap_cpy(ebitmap_t *dst, ebitmap_t *src);
int ebitmap_contains(ebitmap_t *e1, ebitmap_t *e2);
int ebitmap_get_bit(ebitmap_t *e, unsigned long bit);
int ebitmap_set_bit(ebitmap_t *e, unsigned long bit, int value);
void ebitmap_destroy(ebitmap_t *e);
int ebitmap_read(ebitmap_t *e, void *fp);

#endif	/* _EBITMAP_H */
