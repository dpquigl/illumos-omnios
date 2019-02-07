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

#ifndef _SYS_FMAC_FLASK_TYPES_H
#define	_SYS_FMAC_FLASK_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif
/*
 * The basic Flask types and constants.
 */

/*
 * A security context is a set of security attributes
 * associated with each subject and object controlled
 * by the security policy.  The security context type
 * is defined as a variable-length string that can be
 * interpreted by any application or user with an
 * understanding of the security policy.
 */
typedef char *security_context_t;

/*
 * An access vector (AV) is a collection of related permissions
 * for a pair of SIDs.  The bits within an access vector
 * are interpreted differently depending on the class of
 * the object.  The access vector interpretations are specified
 * in flask/access_vectors, and the corresponding constants
 * for permissions are defined in the automatically generated
 * header file av_permissions.h.
 */
typedef uint32_t access_vector_t;

/*
 * Each object class is identified by a fixed-size value.
 * The set of security classes is specified in flask/security_classes,
 * with the corresponding constants defined in the automatically
 * generated header file flask.h.
 */
typedef uint16_t security_class_t;
#define	SECCLASS_NULL			0x0000 /* no class */

/* Private kernel definitions */

/*
 * A kernel security identifier (SID) is a fixed-size value
 * that is mapped by the security server to a
 * particular security context.  The SID mapping
 * cannot be assumed to be consistent either across
 * executions (reboots) of the security server or
 * across security servers on different nodes.
 *
 * Certain SIDs (specified in flask/initial_sids) are
 * predefined for system initialization. The corresponding
 * constants are defined in the automatically generated
 * header file flask.h.
 */
typedef uint32_t security_id_t;
#define	SECSID_NULL			0x00000000 /* unspecified SID */
#define	SECSID_WILD			0xFFFFFFFF /* wildcard SID */

#define	SEMAGIC 0xf97cff8c

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FMAC_FLASK_TYPES_H */

