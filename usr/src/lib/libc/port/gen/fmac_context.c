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
 * This source code originated from
 * http://www.nsa.gov/selinux/archives/libselinux-2.0.65.tgz
 * with the following LICENSE file in the top-level of the tar archive:
 *
 * This library (libselinux) is public domain software, i.e. not copyrighted.
 *
 * Warranty Exclusion
 * ------------------
 * You agree that this software is a
 * non-commercially developed program that may contain "bugs" (as that
 * term is used in the industry) and that it may not function as intended.
 * The software is licensed "as is". NSA makes no, and hereby expressly
 * disclaims all, warranties, express, implied, statutory, or otherwise
 * with respect to the software, including noninfringement and the implied
 * warranties of merchantability and fitness for a particular purpose.
 *
 * Limitation of Liability
 * -----------------------
 * In no event will NSA be liable for any damages, including loss of data,
 * lost profits, cost of cover, or other special, incidental,
 * consequential, direct or indirect damages arising from the software or
 * the use thereof, however caused and on any theory of liability. This
 * limitation will apply even if NSA has been advised of the possibility
 * of such damage. You acknowledge that this is a reasonable allocation of
 * risk.
 */

#include "lint.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fmac/fmac_context.h>

#define	COMP_USER  0
#define	COMP_ROLE  1
#define	COMP_TYPE  2
#define	COMP_RANGE 3

typedef struct {
	char *current_str;	/* This is made up-to-date only when needed */
	char *(component[4]);
} fmac_context_private_t;

/*
 * Allocate a new context, initialized from str.  There must be 3 or
 * 4 colon-separated components and no whitespace in any component other
 * than the MLS component.
 */
fmac_context_t
fmac_context_new(const char *str)
{
	int i, count;
	fmac_context_private_t *n =
	    (fmac_context_private_t *)malloc(sizeof (fmac_context_private_t));
	fmac_context_t result =
	    (fmac_context_t)malloc(sizeof (fmac_context_s_t));
	const char *p, *tok;

	if (result)
		result->ptr = n;
	else
		free(n);
	if (n == 0 || result == 0) {
		goto err;
	}
	n->current_str = n->component[0] = n->component[1] = n->component[2] =
	    n->component[3] = 0;
	for (i = count = 0, p = str; *p; p++) {
		switch (*p) {
		case ':':
			count++;
			break;
		case '\n':
		case '\t':
		case '\r':
			goto err;	/* sanity check */
		case ' ':
			if (count < 3)
				goto err;	/* sanity check */
		}
	}
	/*
	 * Could be anywhere from 2 - 5
	 * e.g user:role:type to user:role:type:sens1:cata-sens2:catb
	 */
	if (count < 2 || count > 5) {	/* might not have a range */
		goto err;
	}

	n->component[3] = 0;
	for (i = 0, tok = str; *tok; i++) {
		if (i < 3)
			for (p = tok; *p && *p != ':'; p++) {	/* empty */
		} else {
			/* MLS range is one component */
			for (p = tok; *p; p++) {	/* empty */
			}
		}
		n->component[i] = (char *)malloc(p - tok + 1);
		if (n->component[i] == 0)
			goto err;
		strncpy(n->component[i], tok, p - tok);
		n->component[i][p - tok] = '\0';
		tok = *p ? p + 1 : p;
	}
	return (result);
err:
	fmac_context_free(result);
	return (0);
}

static void
fmac_conditional_free(char **v)
{
	if (*v) {
		free(*v);
	}
	*v = 0;
}

/*
 * free all storage used by a context.  Safe to call with
 * null pointer.
 */
void
fmac_context_free(fmac_context_t context)
{
	fmac_context_private_t *n;
	int i;
	if (context) {
		n = context->ptr;
		if (n) {
			fmac_conditional_free(&n->current_str);
			for (i = 0; i < 4; i++) {
				fmac_conditional_free(&n->component[i]);
			}
			free(n);
		}
		free(context);
	}
}

/*
 * Return a pointer to the string value of the context.
 */
char *
fmac_context_str(fmac_context_t context)
{
	fmac_context_private_t *n = context->ptr;
	int i;
	size_t total = 0;
	fmac_conditional_free(&n->current_str);
	for (i = 0; i < 4; i++) {
		if (n->component[i]) {
			total += strlen(n->component[i]) + 1;
		}
	}
	n->current_str = malloc(total);
	if (n->current_str != 0) {
		char *cp = n->current_str;

		strcpy(cp, n->component[0]);
		for (i = 1; i < 4; i++) {
			if (n->component[i]) {
				strcat(cp, ":");
				strcat(cp, n->component[i]);
			}
		}
	}
	return (n->current_str);
}

/*
 * Returns nonzero on failure.
 */
static int
fmac_set_comp(fmac_context_private_t *n, int idx, const char *str)
{
	char *t = NULL;
	const char *p;
	if (str) {
		t = (char *)malloc(strlen(str) + 1);
		if (!t) {
			return (1);
		}
		for (p = str; *p; p++) {
			if (*p == '\t' || *p == '\n' || *p == '\r' ||
			    ((*p == ':' || *p == ' ') && idx != COMP_RANGE)) {
				free(t);
				errno = EINVAL;
				return (1);
			}
		}
		strcpy(t, str);
	}
	fmac_conditional_free(&n->component[idx]);
	n->component[idx] = t;
	return (0);
}

#define	def_get(name, tag) \
const char * \
fmac_context_ ## name ## _get(fmac_context_t context) \
{ \
	fmac_context_private_t *n = context->ptr; \
	return (n->component[tag]); \
}

def_get(type, COMP_TYPE)
def_get(user, COMP_USER)
def_get(range, COMP_RANGE)
def_get(role, COMP_ROLE)

#define	def_set(name, tag) \
int \
fmac_context_ ## name ## _set(fmac_context_t context, const char *str) \
{ \
	return (fmac_set_comp(context->ptr, tag, str)); \
}

def_set(type, COMP_TYPE)
def_set(role, COMP_ROLE)
def_set(user, COMP_USER)
def_set(range, COMP_RANGE)
