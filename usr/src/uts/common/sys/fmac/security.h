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
 * Original files contributed to OpenSolaris.org under license by the
 * United States Government (NSA) to Sun Microsystems, Inc.
 */

/*
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */

#ifndef _SYS_FMAC_SECURITY_H
#define	_SYS_FMAC_SECURITY_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Security server interface.
 */

#include <sys/fmac/fmac.h>
#include <sys/fmac/flask_types.h>
#include <sys/fmac/flask.h>
#include <sys/types.h>

/* Initialize the security server */
int security_init(void);

/* Load the security policy. */
int security_load_policy(void *data, size_t len);

/*
 * Compute access vectors based on a SID pair for
 * the permissions in a particular class.
 */
int security_compute_av(
	security_id_t ssid,			/* IN */
	security_id_t tsid,			/* IN */
	security_class_t tclass,		/* IN */
	access_vector_t requested,		/* IN */
	struct av_decision *avd);		/* OUT */

/*
 * Compute a SID to use for labeling a new object in the
 * class `tclass' based on a SID pair.
 */
int security_transition_sid(
	security_id_t ssid,			/* IN */
	security_id_t tsid,			/* IN */
	security_class_t tclass,		/* IN */
	security_id_t *out_sid);		/* OUT */

/*
 * Compute a SID to use when selecting a member of a
 * polyinstantiated object of class `tclass' based on
 * a SID pair.
 */
int security_member_sid(
	security_id_t ssid,			/* IN */
	security_id_t tsid,			/* IN */
	security_class_t tclass,		/* IN */
	security_id_t *out_sid);		/* OUT */

/*
 * Compute a SID to use for relabeling an object in the
 * class `tclass' based on a SID pair.
 */
int security_change_sid(
	security_id_t ssid,			/* IN */
	security_id_t tsid,			/* IN */
	security_class_t tclass,		/* IN */
	security_id_t *out_sid);		/* OUT */

/*
 * Write the security context string representation of
 * the context associated with `sid' into a dynamically
 * allocated string of the correct size.  Set `*scontext'
 * to point to this string and set `*scontext_len' to
 * the length of the string.
 */
int security_sid_to_context(
	security_id_t  sid,			/* IN */
	security_context_t *scontext,		/* OUT */
	uint32_t *scontext_len);		/* OUT */

/*
 * Free a security context.
 */
void security_context_free(security_context_t scontext);

/*
 * Return a SID associated with the security context that
 * has the string representation specified by `scontext'.
 */
int security_context_to_sid(
	security_context_t scontext,		/* IN */
	uint32_t scontext_len,			/* IN */
	security_id_t *out_sid);		/* OUT */

/*
 * Generate the set of SIDs for legal security contexts
 * for a given user that can be reached by `fromsid'.
 * Set `*sids' to point to a dynamically allocated
 * array containing the set of SIDs.  Set `*nel' to the
 * number of elements in the array.
 */
int security_get_user_sids(
	security_id_t callsid,
	char *username,
	security_id_t **sids,
	uint32_t *nel);

/*
 * Free the set of SIDs allocated by security_get_user_sids()
 */
void security_free_user_sids(security_id_t *sids, uint32_t nel);

/*
 * Return the SIDs to use for an unlabeled file system
 * that is being mounted from the device with the
 * the kdevname `name'.  The `fs_sid' SID is returned for
 * the file system and the `file_sid' SID is returned
 * for all files within that file system.
 */
int security_fs_sid(
	char *dev,				/* IN */
	security_id_t *fs_sid,			/* OUT  */
	security_id_t *file_sid);		/* OUT */

/*
 * Return the SID of the port specified by
 * `domain', `type', `protocol', and `port'.
 */
int security_port_sid(
	uint16_t domain,
	uint16_t type,
	uint8_t protocol,
	uint16_t port,
	security_id_t *out_sid);

/*
 * Return the SIDs to use for a network interface
 * with the name `name'.  The `if_sid' SID is returned for
 * the interface and the `msg_sid' SID is returned as
 * the default SID for messages received on the
 * interface.
 */
int security_netif_sid(
	char *name,
	security_id_t *if_sid,
	security_id_t *msg_sid);

/*
 * Return the SID of the node specified by the address
 * `addr' where `addrlen' is the length of the address
 * in bytes and `domain' is the communications domain or
 * address family in which the address should be interpreted.
 */
int security_node_sid(
	uint16_t domain,
	void *addr,
	uint32_t addrlen,
	security_id_t *out_sid);

/*
 * Return a value indicating how to handle labeling for the
 * the specified filesystem type, and optionally return a SID
 * for the filesystem object.
 */
#define	SECURITY_FS_USE_XATTR	1 /* use xattr */
#define	SECURITY_FS_USE_TRANS	2 /* use transition SIDs, e.g. devpts/tmpfs */
#define	SECURITY_FS_USE_TASK	3 /* use task SIDs, e.g. pipefs/sockfs */
#define	SECURITY_FS_USE_GENFS	4 /* use the genfs support */
#define	SECURITY_FS_USE_NONE	5 /* no labeling support */
int security_fs_use(
	const char *fstype,			/* IN */
	unsigned int *behavior,			/* OUT */
	security_id_t *sid);			/* OUT  */

/*
 * Return the SID to use for a file in a filesystem
 * that cannot support a persistent label mapping or use another
 * fixed labeling behavior like transition SIDs or task SIDs.
 */
int security_genfs_sid(
	const char *fstype,			/* IN */
	char *name,				/* IN */
	security_class_t sclass,		/* IN */
	security_id_t *sid);			/* OUT  */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FMAC_SECURITY_H */

