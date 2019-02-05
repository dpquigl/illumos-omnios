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
 * Display context for current or specified PIDs
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <libintl.h>
#include <fmac/fmac.h>

static char *command;

static pid_t
str2pid(const char *s)
{
	pid_t pid;
	char *endptr = 0;

	errno = 0;

	pid = strtoul(s, &endptr, 10);

	if (endptr == s || *endptr != '\0' || errno || pid < 0)
		return (-1);
	else
		return (pid);
}

static int
show_context(const char *s)
{
	security_context_t context;
	pid_t pid;

	if (s == NULL)
		pid = getpid();
	else if ((pid = str2pid(s)) == -1) {
		(void) fprintf(stderr, gettext("%s: invalid argument: %s\n"),
		    command, s);
		return (1);
	}

	if (getpidcon(pid, &context) == -1) {
		(void) fprintf(stderr,
		    gettext("%s: can't get context for %d: %s\n"),
		    command, (int)pid, strerror(errno));
			return (1);
	} else {
		(void) printf("%d: %s\n", (int)pid, context);
		freecon(context);
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	int rc = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	if (argc <= 1) {
		rc += show_context(NULL);
	} else {
		while (--argc >= 1) {
			rc += show_context(*++argv);
		}
	}

	return (rc > 255 ? 255 : rc);
}
