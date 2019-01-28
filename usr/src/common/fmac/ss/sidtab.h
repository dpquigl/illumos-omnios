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
 * A security identifier table (sidtab) is a hash table
 * of security context structures indexed by SID value.
 */

#ifndef _SIDTAB_H
#define	_SIDTAB_H

#if defined(_KERNEL)
#include <sys/inttypes.h>
#include <sys/ksynch.h>
#else
#include <inttypes.h>
#include <synch.h>
#endif /* defined(_KERNEL) */

#include "context.h"

typedef struct sidtab_node {
	security_id_t sid;		/* security identifier */
	context_struct_t context;	/* security context structure */
	struct sidtab_node *next;
} sidtab_node_t;

typedef struct sidtab_node *sidtab_ptr_t;

#define	SIDTAB_HASH_BITS 7
#define	SIDTAB_HASH_BUCKETS (1 << SIDTAB_HASH_BITS)
#define	SIDTAB_HASH_MASK (SIDTAB_HASH_BUCKETS-1)

#define	SIDTAB_SIZE SIDTAB_HASH_BUCKETS

typedef struct {
	sidtab_ptr_t *htable;
	unsigned int nel;	/* number of elements */
	unsigned int next_sid;	/* next SID to allocate */
	unsigned char shutdown;
#if defined(_KERNEL)
	kmutex_t lock;
#else
	mutex_t lock;
#endif
} sidtab_t;

int sidtab_init(sidtab_t *s);

int sidtab_insert(sidtab_t * s, security_id_t sid, context_struct_t * context);

context_struct_t *sidtab_search(sidtab_t * s, security_id_t sid);

int sidtab_map(sidtab_t *s, int (*apply) (security_id_t sid,
    context_struct_t *context, void *args), void *args);

void sidtab_map_remove_on_error(sidtab_t *s, int (*apply) (security_id_t sid,
    context_struct_t *context, void *args), void *args);

int sidtab_context_to_sid(
	sidtab_t *s,			/* IN */
	context_struct_t *context,	/* IN */
	security_id_t *sid);		/* OUT */

void sidtab_hash_eval(sidtab_t *h, char *tag);

void sidtab_destroy(sidtab_t *s);

void sidtab_set(sidtab_t *dst, sidtab_t *src);

void sidtab_shutdown(sidtab_t *s);

int sidtab_get_sids(sidtab_t *s, security_id_t **sids, uint32_t *nel);

#endif	/* _SIDTAB_H */
