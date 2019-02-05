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

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include <fmac/fmac.h>

#pragma weak _security_compute_user = security_compute_user

/*
 * Since the number of contexts returned from the kernel is unknown,
 * allocate a large buffer. In the future, this could be changed to
 * retry with a larger buffer if ENOMEM is returned.
 */
#define	SCU_SIZE	(1024*32)

int
security_compute_user(security_context_t scontext, const char *user,
    security_context_t **context)
{
	char **ary;
	char *buf, *ptr;
	size_t size;
	int ret;
	unsigned int i, nel;

	size = SCU_SIZE;
	buf = malloc(size);

	if (!buf) {
		ret = -1;
		goto out;
	}

	memset(buf, 0, size);

	ret = syscall(SYS_fmacsys, FMACSYS_SECURITYCOMPUTEUSER, scontext, user,
	    buf, size);

	if (ret < 0)
		goto out2;

	nel = ret;

	ary = malloc((nel + 1) * sizeof (char *));

	if (!ary) {
		ret = -1;
		goto out2;
	}

	ptr = buf;

	for (i = 0; i < nel; i++) {
		ary[i] = strdup(ptr);
		if (!ary[i]) {
			freeconary(ary);
			ret = -1;
			goto out2;
		}
		ptr += strlen(ptr) + 1;
	}

	ary[nel] = NULL;
	*context = ary;
	ret = 0;
out2:
	free(buf);
out:
	return (ret);
}
