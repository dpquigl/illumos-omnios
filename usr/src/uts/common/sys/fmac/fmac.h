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

#ifndef _SYS_FMAC_FMAC_H
#define	_SYS_FMAC_FMAC_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_KERNEL)
#include <sys/inttypes.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/priv.h>
#else
#include <inttypes.h>
#endif /* _KERNEL */

#include <sys/fmac/flask_types.h>

#define	FMAC_MAX_CONTEXT_LEN	4096
#define	FMAC_POLICY_FILE	"/etc/security/fmac/ss_policy"
#define	FMAC_CONTEXT_ATTR	"SUNW.fmac.security"

/*
 * FMAC system calls subcodes
 */
#define	FMACSYS_SECURITYGETENFORCE	0
#define	FMACSYS_SECURITYSETENFORCE	1
#define	FMACSYS_SECURITYLOADPOLICY	2
#define	FMACSYS_ISFMACENABLED		3
#define	FMACSYS_SECURITYCOMPUTEAV	4
#define	FMACSYS_SECURITYCHECKCONTEXT	5
#define	FMACSYS_GETCON			6
#define	FMACSYS_GETPIDCON		7
#define	FMACSYS_GETEXECCON		8
#define	FMACSYS_SETEXECCON		9
#define	FMACSYS_GETPREVCON		10
#define	FMACSYS_GETFILECON		11
#define	FMACSYS_SETFILECON		12
#define	FMACSYS_LGETFILECON		13
#define	FMACSYS_LSETFILECON		14
#define	FMACSYS_FGETFILECON		15
#define	FMACSYS_FSETFILECON		16
#define	FMACSYS_SECURITYCOMPUTEUSER	17

#if defined(_KERNEL)
extern int fmac_enabled;
extern int fmac_enforcing;
#else
#define	fmac_enforcing 1
#endif /* _KERNEL */

struct av_decision {
	access_vector_t allowed;
	access_vector_t decided;
	access_vector_t auditallow;
	access_vector_t auditdeny;
	uint32_t seqno;
};

#if defined(_KERNEL)
extern char *fmac_default_policy_file;
void fmac_init(void);
int fmac_load_policy(char *file);
int fmac_vnode_lookup(vnode_t *, cred_t *, caller_context_t *);
void fmac_vnode_init_secid(vnode_t *vp, char *secctx);
int fmac_vfs_root(vfs_t *, vnode_t *);
int fmac_vnode_set_secctx(char *, cred_t *, vtype_t, vnode_t *);
int fmac_vnode_get_secctx(vnode_t *vp, vattr_t *vap);
int fmac_vnode_create(vnode_t *, char *, xvattr_t *, vattr_t **, cred_t *,
    security_id_t *);
void fmac_vnode_post_create(vnode_t *, security_id_t);
int fmac_vnode_link(vnode_t *tdvp, vnode_t *svp, char *name, cred_t *cr);
int fmac_vnode_remove(vnode_t *dvp, vnode_t *vp, char *name, cred_t *cr);
int fmac_vnode_rename(vnode_t *sdvp, vnode_t *svp, vnode_t *tdvp, vnode_t *tvp,
    cred_t *cr);
int fmac_vnode_setattr(vnode_t *, cred_t *);
int fmac_exec(cred_t *cr, vnode_t *vp, boolean_t *setsecid,
    boolean_t *setprivinc, security_id_t *prev_secidp, security_id_t *secidp);
int fmac_vnode_access(vnode_t *, int, int, cred_t *, boolean_t);
int fmac_priv_proc_cred_perm(const cred_t *scr, cred_t *tcr, int mode);
access_vector_t fmac_sigtoav(int sig);
int fmac_hasprocperm(const cred_t *tcrp, const cred_t *scrp,
    access_vector_t perms);
int fmac_vnode_priv_access(const cred_t *, vnode_t *, int, int);
int fmac_priv_restrict(const cred_t *cr, int priv);
int fmac_priv_require_set(const cred_t *cr, const priv_set_t *req);
int fmac_xvattr(cred_t *cr, vnode_t *vp, int priv, int err);
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FMAC_FMAC_H */

