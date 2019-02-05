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
 * Get and display FMAC enforcing status.
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

	if (errflg || argc != 1) {
		(void) fprintf(stderr,
		gettext("usage: getenforce\n"));
		return (1);
	}

	mode = security_getenforce();
	if (mode == 1)
		(void) printf(gettext("enforcing\n"));
	else if (mode == 0)
		(void) printf(gettext("permissive\n"));
	else if (mode < 0 && errno == ENOSYS)
		(void) printf(gettext("disabled\n"));
	else {
		(void) fprintf(stderr,
		    gettext("getenforce: getting status failed: %s\n"),
		    strerror(errno));
	}

	return (mode);
}
