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
 * A symbol table (symtab) maintains associations between symbol
 * strings and datum values.  The type of the datum values
 * is arbitrary.  The symbol table type is implemented
 * using the hash table type (hashtab).
 */

#ifndef _SYMTAB_H
#define	_SYMTAB_H

#if defined(_KERNEL)
#include <sys/inttypes.h>
#else
#include <inttypes.h>
#endif /* defined(_KERNEL) */

#include "hashtab.h"

typedef struct {
	hashtab_t table;	/* hash table (keyed on a string) */
	uint32_t nprim;		/* number of primary names in table */
} symtab_t;

int symtab_init(symtab_t *, unsigned int size);

#endif	/* _SYMTAB_H */
