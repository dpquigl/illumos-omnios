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
 * A security context is a set of security attributes
 * associated with each subject and object controlled
 * by the security policy.  Security contexts are
 * externally represented as variable-length strings
 * that can be interpreted by a user or application
 * with an understanding of the security policy.
 * Internally, the security server uses a simple
 * structure.  This structure is private to the
 * security server and can be changed without affecting
 * clients of the security server.
 */

#ifndef _CONTEXT_H
#define	_CONTEXT_H

#if defined(_KERNEL)
#include <sys/inttypes.h>
#include <sys/errno.h>
#include <sys/systm.h>
#else
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#endif /* defined(_KERNEL) */

#include "ss_impl.h"
#include "ebitmap.h"
#include "mls_types.h"

/*
 * A security context consists of an authenticated user
 * identity, a role, a type and a MLS range.
 */
typedef struct context_struct {
	uint32_t user;
	uint32_t role;
	uint32_t type;
#ifdef CONFIG_FLASK_MLS
	mls_range_t range;
#endif
} context_struct_t;


#ifdef CONFIG_FLASK_MLS

#define	mls_context_init(c) (void) memset(c, 0, sizeof (mls_range_t))

static inline int mls_context_cpy(context_struct_t *dst, context_struct_t *src)
{
	(dst)->range.level[0].sens = (src)->range.level[0].sens;
	if (!ebitmap_cpy(&(dst)->range.level[0].cat,
	    &(src)->range.level[0].cat))
		return (ENOMEM);
	(dst)->range.level[1].sens = (src)->range.level[1].sens;
	if (!ebitmap_cpy(&(dst)->range.level[1].cat,
	    &(src)->range.level[1].cat)) {
		ebitmap_destroy(&(dst)->range.level[0].cat);
		return (ENOMEM);
	}
	return (0);
}

#define	mls_context_cmp(c1, c2)						\
	(((c1)->range.level[0].sens == (c2)->range.level[0].sens) &&	\
	ebitmap_cmp(&(c1)->range.level[0].cat,				\
	    &(c2)->range.level[0].cat) &&				\
	((c1)->range.level[1].sens == (c2)->range.level[1].sens) &&	\
	ebitmap_cmp(&(c1)->range.level[1].cat, &(c2)->range.level[1].cat))

#define	mls_context_destroy(c)						\
	{								\
		ebitmap_destroy(&(c)->range.level[0].cat);		\
		ebitmap_destroy(&(c)->range.level[1].cat);		\
		(void) memset(c, 0, sizeof (mls_range_t));		\
	}
#else

#define	mls_context_init(c)
#define	mls_context_cpy(dst, src)	0
#define	mls_context_destroy(c)
#define	mls_context_cmp(c1, c2)		1

#endif


#define	context_init(c)	(void) memset(c, 0, sizeof (context_struct_t))

static inline int
context_cpy(context_struct_t *dst, context_struct_t *src)
{
	(dst)->user = (src)->user;
	(dst)->role = (src)->role;
	(dst)->type = (src)->type;
	return (mls_context_cpy(dst, src));
}


#define	context_destroy(c)						\
	{								\
		(c)->user = 0;						\
		(c)->role = 0;						\
		(c)->type = 0;						\
		mls_context_destroy(c);					\
	}

static inline int
context_cmp(context_struct_t *c1, context_struct_t *c2)
{
	return (((c1)->user == (c2)->user) &&
		((c1)->role == (c2)->role) &&
		((c1)->type == (c2)->type) &&
		mls_context_cmp(c1, c2));
}

#endif	/* _CONTEXT_H */
