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
 * Type definitions for the multi-level security (MLS) policy.
 */

#ifndef _MLS_TYPES_H
#define	_MLS_TYPES_H

#if defined(_KERNEL)
#include <sys/inttypes.h>
#else
#include <inttypes.h>
#endif /* defined(_KERNEL) */

#include <sys/fmac/flask_types.h>

typedef struct mls_level {
	uint32_t sens;	/* sensitivity */
	ebitmap_t cat;	/* category set */
} mls_level_t;

typedef struct mls_range {
	mls_level_t level[2]; /* low == level[0], high == level[1] */
} mls_range_t;

typedef struct mls_range_list {
	mls_range_t range;
	struct mls_range_list *next;
} mls_range_list_t;

#define	MLS_RELATION_DOM	1 /* source dominates */
#define	MLS_RELATION_DOMBY	2 /* target dominates */
#define	MLS_RELATION_EQ		4 /* source and target are equivalent */
#define	MLS_RELATION_INCOMP	8 /* source and target are incomparable */

#define	mls_level_eq(l1, l2)						\
	(((l1).sens == (l2).sens) && ebitmap_cmp(&(l1).cat, &(l2).cat))	\

#define	mls_level_relation(l1, l2) (					\
	(((l1).sens == (l2).sens) && ebitmap_cmp(&(l1).cat,		\
	    &(l2).cat)) ? MLS_RELATION_EQ :				\
	    (((l1).sens >= (l2).sens) && ebitmap_contains(&(l1).cat,	\
	    &(l2).cat)) ? MLS_RELATION_DOM :				\
	    (((l2).sens >= (l1).sens) && ebitmap_contains(&(l2).cat,	\
	    &(l1).cat)) ? MLS_RELATION_DOMBY : MLS_RELATION_INCOMP)

#define	mls_range_contains(r1, r2) \
	((mls_level_relation((r1).level[0], (r2).level[0]) &		\
	    (MLS_RELATION_EQ | MLS_RELATION_DOMBY)) &&			\
	    (mls_level_relation((r1).level[1], (r2).level[1]) &		\
	    (MLS_RELATION_EQ | MLS_RELATION_DOM)))

/*
 * Every access vector permission is mapped to a set of MLS base
 * permissions, based on the flow properties of the corresponding
 * operation.
 */
typedef struct mls_perms {
	access_vector_t read;		/* permissions that map to `read' */
	access_vector_t readby;		/* permissions that map to `readby' */
	access_vector_t write;		/* permissions that map to `write' */
	access_vector_t writeby;	/* permissions that map to `writeby' */
} mls_perms_t;

#endif /* _MLS_TYPES_H */
