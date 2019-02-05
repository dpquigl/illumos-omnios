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
 * Set FMAC enforcing status to permissive or enforcing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <libintl.h>
#include <fmac/fmac.h>

int
main(int argc, char *argv[])
{
	char *status;
	int errflg = 0;
	int c;
	int mode;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "")) != EOF) {
		switch (c) {
			case '?':
				errflg++;
				break;
		}
	}

	if (errflg || argc != 2) {
		(void) fprintf(stderr,
		gettext("usage: setenforce [0|1|permissive|enforcing]\n"));
		return (1);
	}

	status = *++argv;
	if (strcasecmp(status, "permissive") == 0 || strcmp(status, "0") == 0)
		mode = 0;
	else if (strcasecmp(status, "enforcing") == 0 ||
			strcmp(status, "1") == 0)
		mode = 1;
	else {
		(void) fprintf(stderr,
		gettext("usage: setenforce [0|1|permissive|enforcing]\n"));
		return (1);
	}

	if (security_setenforce(mode)) {
		(void) fprintf(stderr,
		    gettext("setenforce: setting status to %s failed: %s\n"),
		    status, strerror(errno));
		return (1);
	}

	return (0);
}
