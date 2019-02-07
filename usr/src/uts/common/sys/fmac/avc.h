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

#ifndef _SYS_FMAC_AVC_H
#define	_SYS_FMAC_AVC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Access vector cache interface for object managers
 */

#include <sys/systm.h>
#include <sys/fmac/flask_types.h>
#include <sys/fmac/flask.h>
#include <sys/fmac/av_permissions.h>
#include <sys/fmac/security.h>

struct vnode;

typedef struct avc_audit_data {
	char    type;
#define	AVC_AUDIT_DATA_FS   1
#define	AVC_AUDIT_DATA_NET  2
#define	AVC_AUDIT_DATA_PRIV 3
#define	AVC_AUDIT_DATA_IPC  4
#define	AVC_AUDIT_DATA_DONTAUDIT 5 /* never audit this permission check */
	union 	{
		struct {
			struct vnode *vp;
			char *name;
		} fs;
		struct {
			int priv;
		} priv;
	} u;

} avc_audit_data_t;

/* Initialize an AVC audit data structure. */
#define	AVC_AUDIT_DATA_INIT(_d, _t) {					\
	(void) memset((_d), 0, sizeof (struct avc_audit_data));		\
	(_d)->type = AVC_AUDIT_DATA_##_t;				\
}

/*
 * AVC operations
 */

/* Initialize the AVC */
void avc_init(void);

/*
 * Compute an entire access vector.
 */
extern int avc_compute_av(security_id_t ssid, security_id_t tsid,
    security_class_t tclass, access_vector_t requested,
    struct av_decision *avd);

/* Check requested permissions. */
extern int avc_has_perm(security_id_t ssid, security_id_t tsid,
    security_class_t tclass, access_vector_t requested,
    avc_audit_data_t *auditdata);

/* Check requested permissions without considering permissive mode/domains. */
extern int avc_has_perm_strict(security_id_t ssid, security_id_t tsid,
    security_class_t tclass, access_vector_t requested,
    avc_audit_data_t *auditdata);

#define	AVC_CALLBACK_GRANT		1
#define	AVC_CALLBACK_TRY_REVOKE		2
#define	AVC_CALLBACK_REVOKE		4
#define	AVC_CALLBACK_RESET		8
#define	AVC_CALLBACK_AUDITALLOW_ENABLE	16
#define	AVC_CALLBACK_AUDITALLOW_DISABLE	32
#define	AVC_CALLBACK_AUDITDENY_ENABLE	64
#define	AVC_CALLBACK_AUDITDENY_DISABLE	128

/*
 * Register a callback for events in the set `events'
 * related to the SID pair (`ssid', `tsid') and
 * and the permissions `perms', interpreting
 * `perms' based on `tclass'.
 */
int avc_add_callback(int (*callback)(
	    uint32_t event,
	    security_id_t ssid,
	    security_id_t tsid,
	    security_class_t tclass,
	    access_vector_t perms,
	    access_vector_t *out_retained),
	uint32_t events,
	security_id_t ssid,
	security_id_t tsid,
	security_class_t tclass,
	access_vector_t perms);

/* Dump cache contents. */
extern void avc_dump_cache(char *tag);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FMAC_AVC_H */

