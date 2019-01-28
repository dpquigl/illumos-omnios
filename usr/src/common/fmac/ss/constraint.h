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
 * A constraint is a condition that must be satisfied in
 * order for one or more permissions to be granted.
 * Constraints are used to impose additional restrictions
 * beyond the type-based rules in `te' or the role-based
 * transition rules in `rbac'.  Constraints are typically
 * used to prevent a process from transitioning to a new user
 * identity or role unless it is in a privileged type.
 * Constraints are likewise typically used to prevent a
 * process from labeling an object with a different user
 * identity.
 */

#ifndef _CONSTRAINT_H
#define	_CONSTRAINT_H

#if defined(_KERNEL)
#include <sys/inttypes.h>
#else
#include <inttypes.h>
#endif /* defined(_KERNEL) */

#include "ebitmap.h"

#define	CEXPR_MAXDEPTH		5

typedef struct constraint_expr {
#define	CEXPR_NOT		1	/* not expr */
#define	CEXPR_AND		2 	/* expr and expr */
#define	CEXPR_OR		3 	/* expr or expr */
#define	CEXPR_ATTR		4	/* attr op attr */
#define	CEXPR_NAMES		5 	/* attr op names */
	uint32_t expr_type;		/* expression type */

#define	CEXPR_USER		 1	/* user */
#define	CEXPR_ROLE		 2	/* role */
#define	CEXPR_TYPE		 4	/* type */
#define	CEXPR_TARGET		 8	/* target if set, source otherwise */
	uint32_t attr;			/* attribute */

#define	CEXPR_EQ		1	/* == or eq */
#define	CEXPR_NEQ		2	/* != */
#define	CEXPR_DOM		3	/* dom */
#define	CEXPR_DOMBY		4	/* domby  */
#define	CEXPR_INCOMP		5	/* incomp */
	uint32_t op;			/* operator */
	ebitmap_t names;		/* names */
	struct constraint_expr *next;   /* next expression */
} constraint_expr_t;


typedef struct constraint_node {
	access_vector_t permissions;	/* constrained permissions */
	constraint_expr_t *expr;	/* constraint on permissions */
	struct constraint_node *next;	/* next constraint */
} constraint_node_t;

#endif	/* _CONSTRAINT_H */
