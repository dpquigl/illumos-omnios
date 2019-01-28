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
 * Implementation of the symbol table type.
 */

#include <sys/note.h>

#if defined(_KERNEL)
#include <sys/systm.h>
#else
#include <strings.h>
#endif /* defined(_KERNEL) */

#include "symtab.h"

static unsigned int
symhash(hashtab_t h, hashtab_key_t key)
{
	char *p, *keyp;
	unsigned int size;
	unsigned int val;


	val = 0;
	keyp = (char *) key;
	size = strlen(keyp);
	for (p = keyp; (p - keyp) < size; p++)
		val = (val << 4 | (val >> (8*sizeof (unsigned int)-4))) ^ (*p);
	return (val & (h->size - 1));
}

static int
symcmp(hashtab_t h, hashtab_key_t key1, hashtab_key_t key2)
{
	char *keyp1, *keyp2;

	_NOTE(ARGUNUSED(h));

	keyp1 = (char *) key1;
	keyp2 = (char *) key2;
	return (strcmp(keyp1, keyp2));
}

int
symtab_init(symtab_t *s, unsigned int size)
{
	s->table = hashtab_create(symhash, symcmp, size);
	if (!s->table)
		return (-1);
	s->nprim = 0;
	return (0);
}
