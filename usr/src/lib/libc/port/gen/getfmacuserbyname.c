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

#pragma weak _getfmacuserbyname = getfmacuserbyname

#include "lint.h"

#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>
#include <user_attr.h>
#include <dlfcn.h>
#include <fmac/fmac.h>
#include "fmac_private.h"

typedef userattr_t *(*real_getusernam_t)(const char *);
typedef void (*real_free_userattr_t)(userattr_t *);
typedef char *(*real_kva_match_t)(kva_t *, char *);

static real_getusernam_t real_getusernam = NULL;
static real_free_userattr_t real_free_userattr;
static real_kva_match_t real_kva_match;

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>

static int
get_default_user(char **user, char **level)
{
	FILE *fp;
	char *linebuf;
	char *user_p = NULL;
	char *level_p = NULL;
	char *user_c = NULL;
	char *level_c = NULL;

	if ((fp = fopen(fmac_default_user_path(), "r")) == NULL)
		return (-1);

	if ((linebuf = (char *)malloc(FMAC_MAX_CONTEXT_LEN)) == NULL) {
		(void) fclose(fp);
		return (-1);
	}

	while (fgets(linebuf, FMAC_MAX_CONTEXT_LEN, fp) != NULL) {
		char *p = linebuf;
		char *lasts;

		p[strcspn(p, "\n")] = 0;

		while (isspace(*p))
			p++;

		if (strlen(p) == 0 || *p == '#')
			continue;

		user_p = strtok_r(p, ":", &lasts);
		level_p = strtok_r(NULL, "", &lasts);

		if (user_p)
			break;
	}

	if (user_p) {
		if (user_c = strdup(user_p)) {
			if (level_p) {
				if (level_c = strdup(level_p)) {
					*user = user_c;
					*level = level_c;
				} else {
					free(user_c);
					user_c = NULL;
				}
			} else {
				*user = user_c;
			}
		}
	}

	free(linebuf);
	(void) fclose(fp);

	if (user_c)
		return (0);
	else {
		errno = ENOENT;
		return (-1);
	}
}

int
getfmacuserbyname(const char *name, char **fmacuser, char **level)
{
	userattr_t	*ua;
	char		*ua_fmacuser;
	char		*ua_level;
	int		err = 0;

	if (real_getusernam == NULL) {
		void *handle = dlopen("libsecdb.so.1", RTLD_LAZY);

		if (handle == NULL)
			return (-1);

		if ((real_getusernam = (real_getusernam_t)dlsym(handle,
		    "getusernam")) == NULL ||
		    (real_kva_match = (real_kva_match_t)dlsym(handle,
		    "kva_match")) == NULL ||
		    (real_free_userattr = (real_free_userattr_t)dlsym(handle,
		    "free_userattr")) == NULL) {
			dlclose(handle);
			return (-1);
		}
	}

	if (((ua = real_getusernam(name)) == NULL) ||
	    ((ua_fmacuser = real_kva_match(ua->attr, "fmac_user")) == NULL)) {
		/*
		 * Use the default_user entry if it exists.
		 */
		err = get_default_user(fmacuser, level);
		goto done;
	}

	if ((*fmacuser = strdup(ua_fmacuser)) == NULL) {
		err = -1;
		goto done;
	}

	if ((ua_level = real_kva_match(ua->attr, "fmac_level")) != NULL) {
		if ((*level = strdup(ua_level)) == NULL) {
			free(*fmacuser);
			*fmacuser = NULL;
			err = -1;
			goto done;
		}
	} else
		*level = NULL;

done:
	real_free_userattr(ua);

	return (err);
}
