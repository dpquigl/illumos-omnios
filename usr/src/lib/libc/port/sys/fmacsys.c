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

#pragma weak _security_load_policy = security_load_policy
#pragma weak _security_compute_av = security_compute_av
#pragma weak _security_check_context = security_check_context
#pragma weak _security_getenforce = security_getenforce
#pragma weak _security_setenforce = security_setenforce
#pragma weak _is_fmac_enabled = is_fmac_enabled
#pragma weak _getcon = getcon
#pragma weak _getpidcon = getpidcon
#pragma weak _getexeccon = getexeccon
#pragma weak _setexeccon = setexeccon
#pragma weak _getprevcon = getprevcon

#include <fmac/fmac.h>
#include <sys/fmac/flask_types.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <errno.h>
#include <strings.h>
#include <alloca.h>

int
security_load_policy(char *path)
{
	return (syscall(SYS_fmacsys, FMACSYS_SECURITYLOADPOLICY, path));
}

int
security_compute_av(security_context_t scontext, security_context_t tcontext,
    security_class_t tclass, access_vector_t request, struct av_decision *avd)
{
	return (syscall(SYS_fmacsys, FMACSYS_SECURITYCOMPUTEAV, scontext,
	    tcontext, tclass, request, avd));
}

int
security_check_context(security_context_t context)
{
	return (syscall(SYS_fmacsys, FMACSYS_SECURITYCHECKCONTEXT, context));
}

int
security_getenforce()
{
	return (syscall(SYS_fmacsys, FMACSYS_SECURITYGETENFORCE));
}

int
security_setenforce(int mode)
{
	return (syscall(SYS_fmacsys, FMACSYS_SECURITYSETENFORCE, mode));
}

int
is_fmac_enabled()
{
	return (syscall(SYS_fmacsys, FMACSYS_ISFMACENABLED));
}

int
getcon(security_context_t *context)
{
	security_context_t	acontext;
	security_context_t	dcontext;

	if (context == NULL) {
		errno = EINVAL;
		return (-1);
	}

	acontext = alloca(FMAC_MAX_CONTEXT_LEN);

	if (syscall(SYS_fmacsys, FMACSYS_GETCON, acontext) < 0) {
		return (-1);
	}

	if (dcontext = strdup(acontext)) {
		*context = dcontext;
		return (0);
	} else
		return (-1);
}

int
getpidcon(pid_t pid, security_context_t *context)
{
	security_context_t	acontext;
	security_context_t	dcontext;

	if (context == NULL) {
		errno = EINVAL;
		return (-1);
	}

	acontext = alloca(FMAC_MAX_CONTEXT_LEN);

	if (syscall(SYS_fmacsys, FMACSYS_GETPIDCON, pid, acontext) < 0) {
		return (-1);
	}

	if (dcontext = strdup(acontext)) {
		*context = dcontext;
		return (0);
	} else
		return (-1);
}

int
getexeccon(security_context_t *context)
{
	security_context_t	acontext;
	security_context_t	dcontext;

	if (context == NULL) {
		errno = EINVAL;
		return (-1);
	}

	acontext = alloca(FMAC_MAX_CONTEXT_LEN);

	if (syscall(SYS_fmacsys, FMACSYS_GETEXECCON, acontext) < 0) {
		return (-1);
	}

	if (*acontext == 0) {
		*context = 0;
		return (0);
	}

	if (dcontext = strdup(acontext)) {
		*context = dcontext;
		return (0);
	} else
		return (-1);
}

int
setexeccon(security_context_t context)
{
	return (syscall(SYS_fmacsys, FMACSYS_SETEXECCON, context));
}

int
getprevcon(security_context_t *context)
{
	security_context_t	acontext;
	security_context_t	dcontext;

	if (context == NULL) {
		errno = EINVAL;
		return (-1);
	}

	acontext = alloca(FMAC_MAX_CONTEXT_LEN);

	if (syscall(SYS_fmacsys, FMACSYS_GETPREVCON, acontext) < 0) {
		return (-1);
	}

	if (*acontext == 0) {
		*context = 0;
		return (0);
	}

	if (dcontext = strdup(acontext)) {
		*context = dcontext;
		return (0);
	} else
		return (-1);
}
