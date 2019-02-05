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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Start a shell in the requested context
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <libintl.h>
#include <fmac/fmac.h>
#include <fmac/fmac_context.h>
#include <pwd.h>

int
main(int argc, char **argv)
{
	int i;
	int c;
	char *prog = argv[0];
	int errflg =  0;
	struct passwd *pw;
	fmac_context_t fcon;
	security_context_t pcontext, ncontext;
	const char *p_role;
	const char *p_type;
	const char *p_level;
	const char *n_role = NULL;
	const char *n_type = NULL;
	const char *n_level = NULL;
	char *shell;
	char **nargv;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "r:t:l:")) != -1) {
		switch (c) {
		case 'r':
			n_role = optarg;
			break;
		case 't':
			n_type = optarg;
			break;
		case 'l':
			n_level = optarg;
			break;
		case ':':
			(void) fprintf(stderr,
			    gettext("%s: option -%c requires an operand\n"),
			    prog, optopt);
			errflg++;
			break;
		case '?':
			(void) fprintf(stderr,
			    gettext("%s: unrecognized option: -%c\n"),
			    prog, optopt);
			errflg++;
			break;
		}
	}

	if (!n_role && !n_type && !n_level)
		errflg++;

	if (errflg) {
		(void) fprintf(stderr,
		    gettext("usage: %s [-r role] [-t type] [-l level] "
		    "command...\n"), prog);
		exit(1);
	}

	argc -= optind;
	argv += optind;

	if ((pw = getpwuid(getuid())) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: can't get user shell entry: %s\n"),
		    prog, strerror(errno));
		exit(1);
	}

	if ((shell = strdup(pw->pw_shell)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: allocation for passwd shell failed: %s\n"),
		    prog, strerror(errno));
		exit(1);

	}

	/* Get and parse previous process context */
	if (getprevcon(&pcontext)) {
		(void) fprintf(stderr,
		    gettext("%s: can't get previous context: %s\n"),
		    prog, strerror(errno));
		exit(1);
	}

	fcon = fmac_context_new(pcontext);
	if (!fcon) {
		(void) fprintf(stderr,
		    gettext("%s: can't split previous context: %s\n"),
		    prog, strerror(errno));
		exit(1);
	}

	p_role = fmac_context_role_get(fcon);
	p_type = fmac_context_type_get(fcon);
	p_level = fmac_context_range_get(fcon);

	/* Merge process and requested context fields */
	if (n_role == NULL)
		n_role = p_role;
	if (n_type == NULL) {
		if (get_default_type(n_role, (char **)&n_type) != 0)
			n_type = p_type;
	}
	if (n_level == NULL && p_level != NULL)
		n_level = p_level;

	if (fmac_context_role_set(fcon, n_role)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to set role\n"), prog);
			exit(1);
	}
	if (fmac_context_type_set(fcon, n_type)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to set type\n"), prog);
			exit(1);
	}
	if (fmac_context_range_set(fcon, n_level)) {
		(void) fprintf(stderr,
		    gettext("%s: unable to set level\n"), prog);
			exit(1);
	}

	ncontext = fmac_context_str(fcon);
	if (!ncontext) {
		(void) fprintf(stderr,
		    gettext("%s: unable to set up new context\n"), prog);
			exit(1);
	}

	if (security_check_context(ncontext) != 0) {
		(void) fprintf(stderr,
		    gettext("%s: invalid context %s failed: %s\n"),
		    prog, ncontext, strerror(errno));
		exit(1);
	}

	if ((nargv = calloc(argc+2, sizeof (char **))) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: allocation of argument array failed: %s\n"),
		    prog, strerror(errno));
		exit(1);

	}

	nargv[0] = shell;

	for (i = 1; i <= argc; i++)
		nargv[i] = argv[i-1];

	nargv[i] = NULL;

	if (setexeccon(ncontext)) {
		(void) fprintf(stderr,
		    gettext("%s: secexeccon of %s failed: %s\n"),
		    prog, ncontext, strerror(errno));
		exit(1);
	}

	(void) execvp(nargv[0], nargv);

	(void) fprintf(stderr, gettext("%s: execvp failed: %s\n"), prog,
	    strerror(errno));

	return (1);
}
