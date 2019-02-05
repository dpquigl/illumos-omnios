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

#pragma weak _get_default_context_with_role = get_default_context_with_role
#pragma weak _get_default_context_with_rolelevel = \
    get_default_context_with_rolelevel
#pragma weak _get_default_context = get_default_context
#pragma weak _get_ordered_context_list_with_level = \
    get_ordered_context_list_with_level
#pragma weak _get_default_context_with_level = get_default_context_with_level
#pragma weak _get_ordered_context_list = get_ordered_context_list

#include "lint.h"
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <pwd.h>
#include <fmac/fmac.h>
#include <fmac/fmac_context.h>
#include "fmac_private.h"

#define	FMAC_DEFAULTUSER "user_u"

int
get_default_context_with_role(const char *user, const char *role,
    security_context_t fromcon, security_context_t *newcon)
{
	security_context_t *conary;
	char **ptr;
	fmac_context_t con;
	const char *role2;
	int rc;

	rc = get_ordered_context_list(user, fromcon, &conary);
	if (rc <= 0)
		return (-1);

	for (ptr = conary; *ptr; ptr++) {
		con = fmac_context_new(*ptr);
		if (!con)
			continue;
		role2 = fmac_context_role_get(con);
		if (role2 && strcmp(role, role2) == 0) {
			fmac_context_free(con);
			break;
		}
		fmac_context_free(con);
	}

	rc = -1;
	if (!(*ptr))
		goto out;
	*newcon = strdup(*ptr);
	if (!(*newcon))
		goto out;
	rc = 0;
out:
	freeconary(conary);
	return (rc);
}

int
get_default_context_with_rolelevel(const char *user, const char *role,
    const char *level, security_context_t fromcon, security_context_t *newcon)
{

	int rc = 0;
	int freefrom = 0;
	fmac_context_t con;
	char *newfromcon;
	if (!level)
		return (get_default_context_with_role(user, role, fromcon,
		    newcon));

	if (!fromcon) {
		rc = getcon(&fromcon);
		if (rc < 0)
			return (rc);
		freefrom = 1;
	}

	rc = -1;
	con = fmac_context_new(fromcon);
	if (!con)
		goto out;

	if (fmac_context_range_set(con, level))
		goto out;

	newfromcon = fmac_context_str(con);
	if (!newfromcon)
		goto out;

	rc = get_default_context_with_role(user, role, newfromcon, newcon);

out:
	fmac_context_free(con);
	if (freefrom)
		freecon(fromcon);
	return (rc);

}

int
get_default_context(const char *user, security_context_t fromcon,
    security_context_t *newcon)
{
	security_context_t *conary;
	int rc;

	rc = get_ordered_context_list(user, fromcon, &conary);
	if (rc <= 0)
		return (-1);

	*newcon = strdup(conary[0]);
	freeconary(conary);
	if (!(*newcon))
		return (-1);
	return (0);
}

static int
find_partialcon(security_context_t *list, unsigned int nreach, char *part)
{
	const char *conrole, *contype;
	char *partrole, *parttype, *ptr;
	fmac_context_t con;
	unsigned int i;

	partrole = part;
	ptr = part;
	while (*ptr && !isspace(*ptr) && *ptr != ':')
		ptr++;
	if (*ptr != ':')
		return (-1);
	*ptr++ = 0;
	parttype = ptr;
	while (*ptr && !isspace(*ptr) && *ptr != ':')
		ptr++;
	*ptr = 0;

	for (i = 0; i < nreach; i++) {
		con = fmac_context_new(list[i]);
		if (!con)
			return (-1);
		conrole = fmac_context_role_get(con);
		contype = fmac_context_type_get(con);
		if (!conrole || !contype) {
			fmac_context_free(con);
			return (-1);
		}
		if (strcmp(conrole, partrole) == 0 &&
		    strcmp(contype, parttype) == 0) {
			fmac_context_free(con);
			return (i);
		}
		fmac_context_free(con);
	}

	return (-1);
}

static int
get_context_order(FILE *fp, security_context_t fromcon,
    security_context_t *reachable, unsigned int nreach,
    unsigned int *ordering, unsigned int *nordered)
{
	char *start, *end = NULL;
	char *line = NULL;
	int len;
	int found = 0;
	const char *fromrole, *fromtype;
	char *linerole, *linetype;
	unsigned int i;
	fmac_context_t con;
	int rc;

	errno = -EINVAL;

	/*
	 * Extract the role and type of the fromcon for matching.
	 * User identity and MLS range can be variable.
	 */
	con = fmac_context_new(fromcon);
	if (!con)
		return (-1);
	fromrole = fmac_context_role_get(con);
	fromtype = fmac_context_type_get(con);
	if (!fromrole || !fromtype) {
		fmac_context_free(con);
		return (-1);
	}

	if ((line = malloc(1024)) == NULL) {
		fmac_context_free(con);
		return (-1);
	}

	while (fgets(line, 1024, fp) != NULL) {
		len = strlen(line);
		if (line[len - 1] == '\n')
			line[len - 1] = 0;

		/* Skip leading whitespace. */
		start = line;
		while (*start && isspace(*start))
			start++;
		if (!(*start))
			continue;

		/* Find the end of the (partial) fromcon in the line. */
		end = start;
		while (*end && !isspace(*end))
			end++;
		if (!(*end))
			continue;

		/* Check for a match. */
		linerole = start;
		while (*start && !isspace(*start) && *start != ':')
			start++;
		if (*start != ':')
			continue;
		*start = 0;
		linetype = ++start;
		while (*start && !isspace(*start) && *start != ':')
			start++;
		if (!(*start))
			continue;
		*start = 0;
		if (strcmp(fromrole, linerole) == 0 &&
		    strcmp(fromtype, linetype) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		errno = ENOENT;
		rc = -1;
		goto out;
	}

	start = ++end;
	while (*start) {
		/* Skip leading whitespace */
		while (*start && isspace(*start))
			start++;
		if (!(*start))
			break;

		/* Find the end of this partial context. */
		end = start;
		while (*end && !isspace(*end))
			end++;
		if (*end)
			*end++ = 0;

		/* Check for a match in the reachable list. */
		rc = find_partialcon(reachable, nreach, start);
		if (rc < 0) {
			/* No match, skip it. */
			start = end;
			continue;
		}

		/*
		 * If a match is found and the entry is not already ordered
		 * (e.g. due to prior match in prior config file), then set
		 * the ordering for it.
		 */
		i = rc;
		if (ordering[i] == nreach)
			ordering[i] = (*nordered)++;
		start = end;
	}

	rc = 0;

out:
	fmac_context_free(con);
	free(line);
	return (rc);
}

static int
get_failsafe_context(const char *user, security_context_t *newcon)
{
	FILE *fp;
	char buf[255], *ptr;
	size_t plen, nlen;
	int found = 0;
	int rc;

	fp = fopen(fmac_failsafe_context_path(), "r");
	if (!fp)
		return (-1);

	while (fgets(buf, sizeof (buf), fp) != NULL) {
		plen = strlen(buf);

		if (buf[plen - 1] == '\n')
			buf[plen - 1] = 0;

		/* Skip leading whitespace. */
		ptr = buf;
		while (*ptr && isspace(*ptr))
			ptr++;
		if (!(*ptr) || *ptr == '#')
			continue;
		plen = strlen(ptr);

		found = 1;
		break;
	}

	(void) fclose(fp);

	if (!found) {
		*newcon = 0;
		return (-1);
	}
retry:
	nlen = strlen(user) + 1 + plen + 1;
	*newcon = malloc(nlen);
	if (!(*newcon))
		return (-1);
	rc = snprintf(*newcon, nlen, "%s:%s", user, ptr);
	if (rc < 0 || (size_t)rc >= nlen) {
		free(*newcon);
		*newcon = 0;
		return (-1);
	}

	/*
	 * If possible, check the context to catch
	 * errors early rather than waiting until the
	 * caller tries to use setexeccon on the context.
	 * But this may not always be possible, e.g. if
	 * selinuxfs isn't mounted.
	 */
	if (security_check_context(*newcon) && errno != ENOENT) {
		free(*newcon);
		*newcon = 0;
		if (strcmp(user, FMAC_DEFAULTUSER)) {
			user = FMAC_DEFAULTUSER;
			goto retry;
		}
		return (-1);
	}

	return (0);
}

struct context_order {
	security_context_t con;
	unsigned int order;
};

static int
order_compare(const void *A, const void *B)
{
	const struct context_order *c1 = A, *c2 = B;
	if (c1->order < c2->order)
		return (-1);
	else if (c1->order > c2->order)
		return (1);
	return (strcmp(c1->con, c2->con));
}

int
get_ordered_context_list_with_level(const char *user, const char *level,
    security_context_t fromcon, security_context_t **list)
{
	int rc;
	int freefrom = 0;
	fmac_context_t con;
	char *newfromcon;

	if (!level)
		return (get_ordered_context_list(user, fromcon, list));

	if (!fromcon) {
		rc = getcon(&fromcon);
		if (rc < 0)
			return (rc);
		freefrom = 1;
	}

	rc = -1;
	con = fmac_context_new(fromcon);
	if (!con)
		goto out;

	if (fmac_context_range_set(con, level))
		goto out;

	newfromcon = fmac_context_str(con);
	if (!newfromcon)
		goto out;

	rc = get_ordered_context_list(user, newfromcon, list);

out:
	fmac_context_free(con);
	if (freefrom)
		freecon(fromcon);
	return (rc);
}

int
get_default_context_with_level(const char *user, const char *level,
    security_context_t fromcon, security_context_t *newcon)
{
	security_context_t *conary;
	int rc;

	rc = get_ordered_context_list_with_level(user, level, fromcon, &conary);
	if (rc <= 0)
		return (-1);

	*newcon = strdup(conary[0]);
	freeconary(conary);
	if (!(*newcon))
		return (-1);
	return (0);
}

int
get_ordered_context_list(const char *user, security_context_t fromcon,
    security_context_t **list)
{
	security_context_t *reachable = NULL;
	unsigned int *ordering = NULL;
	struct context_order *co = NULL;
	char **ptr;
	int rc = 0;
	unsigned int nreach = 0, nordered = 0, freefrom = 0, i;
	FILE *fp;
	char *fname = NULL;
	size_t fname_len;
	const char *user_contexts_path = fmac_user_contexts_path();

	if (!fromcon) {
		/*
		 * Get the current context and use it for the starting context
		 */
		rc = getcon(&fromcon);
		if (rc < 0)
			return (rc);
		freefrom = 1;
	}

	/* Determine the set of reachable contexts for the user. */
	rc = security_compute_user(fromcon, user, &reachable);
	if (rc < 0) {
		/* Retry with the default SELinux user identity. */
		user = FMAC_DEFAULTUSER;
		rc = security_compute_user(fromcon, user, &reachable);
		if (rc < 0)
			goto failsafe;
	}
	nreach = 0;
	for (ptr = reachable; *ptr; ptr++)
		nreach++;
	if (!nreach)
		goto failsafe;

	/* Initialize ordering array. */
	ordering = malloc(nreach * sizeof (unsigned int));
	if (!ordering)
		goto oom_order;
	for (i = 0; i < nreach; i++)
		ordering[i] = nreach;

	/*
	 * Determine the ordering to apply from the optional per-user config
	 * and from the global config.
	 */
	fname_len = strlen(user_contexts_path) + strlen(user) + 2;
	fname = malloc(fname_len);
	if (!fname)
		goto oom_order;
	(void) snprintf(fname, fname_len, "%s%s", user_contexts_path, user);
	fp = fopen(fname, "r");
	if (fp) {
		(void) get_context_order(fp, fromcon, reachable, nreach,
		    ordering, &nordered);
		(void) fclose(fp);
		if (rc < 0 && errno != ENOENT) {
			syslog(LOG_NOTICE,
			    "%s:  error in processing configuration file %s\n",
			    __func__, fname);
			/* Fall through, try global config */
		}
	}
	free(fname);
	fp = fopen(fmac_default_context_path(), "r");
	if (fp) {
		(void) get_context_order(fp, fromcon, reachable, nreach,
		    ordering, &nordered);
		(void) fclose(fp);
		if (rc < 0 && errno != ENOENT) {
			/* Fall through */
			syslog(LOG_NOTICE,
			    "%s:  error in processing configuration file %s\n",
			    __func__, fmac_default_context_path());
		}
	}

	/* Apply the ordering. */
	if (nordered) {
		co = malloc(nreach * sizeof (struct context_order));
		if (!co)
			goto oom_order;
		for (i = 0; i < nreach; i++) {
			co[i].con = reachable[i];
			co[i].order = ordering[i];
		}
		qsort(co, nreach, sizeof (struct context_order), order_compare);
		for (i = 0; i < nreach; i++)
			reachable[i] = co[i].con;
		free(co);
	}

	/*
	 * Return the ordered list.
	 * If we successfully ordered it, then only report the ordered entries
	 * to the caller.  Otherwise, fall back to the entire reachable list.
	 */
	if (nordered && nordered < nreach) {
		for (i = nordered; i < nreach; i++)
			free(reachable[i]);
		reachable[nordered] = NULL;
		rc = nordered;
	} else {
		rc = nreach;
	}

out:
	*list = reachable;

	free(ordering);
	if (freefrom)
		freecon(fromcon);

	return (rc);

failsafe:
	/*
	 * Unable to determine a reachable context list, try to fall back to
	 * the "failsafe" context to at least permit root login
	 * for emergency recovery if possible.
	 */
	freeconary(reachable);
	reachable = malloc(2 * sizeof (security_context_t));
	if (!reachable) {
		rc = -1;
		goto out;
	}
	reachable[0] = reachable[1] = 0;
	rc = get_failsafe_context(user, &reachable[0]);
	if (rc < 0) {
		freeconary(reachable);
		reachable = NULL;
		goto out;
	}
	rc = 1;			/* one context in the list */
	goto out;

oom_order:
	/*
	 * Unable to order context list due to OOM condition.
	 * Fall back to unordered reachable context list.
	 */
	rc = nreach;
	goto out;
}
