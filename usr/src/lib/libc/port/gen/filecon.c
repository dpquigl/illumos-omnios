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

#pragma weak _getfilecon = getfilecon
#pragma weak _setfilecon = setfilecon

#include "lint.h"
#include "libc.h"
#include <sys/types.h>
#include <sys/nvpair.h>
#include <fcntl.h>
#include <attr.h>
#include <string.h>
#include <errno.h>
#include <fmac/fmac.h>

#ifndef A_SECCTX
#define	A_SECCTX	"secctx"
#endif

int
getfilecon(const char *path, char **secctxp)
{
	nvlist_t *nvp;
	int error;
	char *secctx;

	error = getattrat(AT_FDCWD, XATTR_VIEW_READWRITE, path, &nvp);
	if (error)
		return (-1);
	error = libc_nvlist_lookup_string(nvp, A_SECCTX, &secctx);
	if (error) {
		errno = ENODATA;
		libc_nvlist_free(nvp);
		return (-1);
	}
	*secctxp = strdup(secctx);
	libc_nvlist_free(nvp);
	if (!(*secctxp))
		return (-1);
	return (0);
}

int
setfilecon(const char *path, char *secctx)
{
	nvlist_t *nvp;
	int error;

	error = libc_nvlist_alloc(&nvp, NV_UNIQUE_NAME, 0);
	if (error) {
		errno = error;
		return (-1);
	}

	error = libc_nvlist_add_string(nvp, A_SECCTX, secctx);
	if (error) {
		errno = error;
		error = -1;
		goto out;
	}

	error = setattrat(AT_FDCWD, XATTR_VIEW_READWRITE, path, nvp);
out:
	libc_nvlist_free(nvp);
	return (error);
}
