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

#ifndef _CHECKPOLICY_H
#define	_CHECKPOLICY_H

#include "ebitmap.h"
#include <sys/fmac/flask_types.h>

typedef struct te_assert {
	ebitmap_t		stypes;
	ebitmap_t		ttypes;
	ebitmap_t		tclasses;
	int			self;
	access_vector_t		*avp;
	unsigned long		line;
	struct te_assert	*next;
} te_assert_t;

te_assert_t *te_assertions;

#endif /* _CHECKPOLICY_H */
