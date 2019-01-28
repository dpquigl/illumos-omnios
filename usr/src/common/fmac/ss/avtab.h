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
 * An access vector table (avtab) is a hash table
 * of access vectors and transition types indexed
 * by a type pair and a class.  An access vector
 * table is used to represent the type enforcement
 * tables.
 */

#ifndef _AVTAB_H
#define	_AVTAB_H

#if defined(_KERNEL)
#include <sys/inttypes.h>
#else
#include <inttypes.h>
#endif /* defined(_KERNEL) */

typedef struct avtab_key {
	uint32_t source_type;	/* source type */
	uint32_t target_type;	/* target type */
	uint32_t target_class;	/* target object class */
} avtab_key_t;

typedef struct avtab_datum {
#define	AVTAB_ALLOWED		1
#define	AVTAB_AUDITALLOW	2
#define	AVTAB_AUDITDENY		4
#define	AVTAB_AV	(AVTAB_ALLOWED | AVTAB_AUDITALLOW | AVTAB_AUDITDENY)
#define	AVTAB_TRANSITION	16
#define	AVTAB_MEMBER		32
#define	AVTAB_CHANGE		64
#define	AVTAB_TYPE		(AVTAB_TRANSITION | AVTAB_MEMBER | AVTAB_CHANGE)
	uint32_t specified;	/* what fields are specified */
	uint32_t data[3];	/* access vectors or types */
#define	avtab_allowed(x) (x)->data[0]
#define	avtab_auditdeny(x) (x)->data[1]
#define	avtab_auditallow(x) (x)->data[2]
#define	avtab_transition(x) (x)->data[0]
#define	avtab_change(x) (x)->data[1]
#define	avtab_member(x) (x)->data[2]
} avtab_datum_t;

typedef struct avtab_node *avtab_ptr_t;

struct avtab_node {
	avtab_key_t key;
	avtab_datum_t datum;
	avtab_ptr_t next;
};

typedef struct avtab {
	avtab_ptr_t *htable;
	uint32_t nel;	/* number of elements */
} avtab_t;

int avtab_init(avtab_t *);

int avtab_insert(avtab_t * h, avtab_key_t * k, avtab_datum_t * d);

avtab_datum_t *avtab_search(avtab_t * h, avtab_key_t * k, int specified);

void avtab_destroy(avtab_t * h);

int avtab_map(avtab_t * h, int (*apply) (avtab_key_t *k, avtab_datum_t *d,
    void *args), void *args);

void avtab_hash_eval(avtab_t * h, char *tag);

int avtab_read(avtab_t *a, void *fp, uint32_t config);

#define	AVTAB_HASH_BITS		15
#define	AVTAB_HASH_BUCKETS	(1 << AVTAB_HASH_BITS)
#define	AVTAB_HASH_MASK		(AVTAB_HASH_BUCKETS-1)

#define	AVTAB_SIZE		AVTAB_HASH_BUCKETS

#endif	/* _AVTAB_H */
