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
 * Original files contributed to OpenSolaris.org under license by the
 * United States Government (NSA) to Sun Microsystems, Inc.
 */

/*
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */

#ifndef _SYS_FMAC_AVC_SS_H
#define	_SYS_FMAC_AVC_SS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Access vector cache interface for the security server
 */

#include <sys/fmac/flask_types.h>
#include <sys/fmac/flask.h>

/*
 * Any of the SID parameters may be wildcarded,
 * in which case the operation is applied to all
 * matching entries in the AVC.
 */

/* Grant previously denied permissions */
int avc_ss_grant(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno);		/* IN */

/*
 * Try to revoke previously granted permissions, but
 * only if they are not retained as migrated permissions.
 * Return the subset of permissions that are retained.
 */
int avc_ss_try_revoke(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno,			/* IN */
	access_vector_t *out_retained);	/* OUT */

/*
 * Revoke previously granted permissions, even if
 * they are retained as migrated permissions.
 */
int avc_ss_revoke(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno);		/* IN */

/*
 * Flush the cache and revalidate all migrated permissions.
 */
int avc_ss_reset(uint32_t seqno);


/* Enable or disable auditing of granted permissions */
int avc_ss_set_auditallow(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno,			/* IN */
	uint32_t enable);

/* Enable or disable auditing of denied permissions */
int avc_ss_set_auditdeny(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno,			/* IN */
	uint32_t enable);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FMAC_AVC_SS_H */

