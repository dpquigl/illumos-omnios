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

/*
 * FMAC
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/param.h>
#include <sys/kobj.h>
#include <sys/vfs.h>
#include <sys/acl.h>
#include <sys/priv_impl.h>
#include <sys/fmac/security.h>
#include <sys/fmac/fmac.h>
#include <sys/fmac/avc.h>
#include <sys/cred_impl.h>
#include <sys/note.h>

/* Tunables */
int fmac_enabled = 1;		/* policy enabled */
int fmac_enforcing = 0;		/* permissive or enforcing */

char *fmac_default_policy_file = FMAC_POLICY_FILE;

/*
 * Parse boot arguments. Boot arguments take priority over
 * defaults and /etc/system specifications.
 */
static void
fmac_parse_bootargs(const char *cp)
{
	const char *ncp;

	while (*cp != '\0') {

		/* Skip white spaces */
		while (*cp == ' ')
			cp++;

		if (strncmp(cp, "enabled", sizeof ("enabled") -1) == 0) {
			fmac_enabled = 1;
			cp += sizeof ("enabled") - 1;
		} else if (strncmp(cp, "disabled",
		    sizeof ("disabled")-1) == 0) {
			fmac_enabled = 0;
			cp += sizeof ("disabled") - 1;
		} else if (strncmp(cp, "enforcing",
		    sizeof ("enforcing")-1) == 0) {
			fmac_enabled = 1;
			fmac_enforcing = 1;
			cp += sizeof ("enforcing") - 1;
		} else if (strncmp(cp, "permissive",
		    sizeof ("permissive")-1) == 0) {
			fmac_enabled = 1;
			fmac_enforcing = 0;
			cp += sizeof ("permissive") - 1;
		}

		/* Check for additional arguments */
		if (*cp != '\0' && (ncp = strchr(cp, ',')) != '\0') {
			cp = ncp + 1;
		} else
			break;
	}
}

void
fmac_init()
{
	fmac_parse_bootargs(policyargs);

	if (fmac_enabled)
		if (fmac_load_policy(fmac_default_policy_file))
			if (fmac_enforcing)
				cmn_err(CE_PANIC,
				    "security: Policy load failed");
}

int
fmac_load_policy(char *file)
{
	struct _buf *policy_handle;
	int ret;

	cmn_err(CE_CONT, "security: Loading policy %s\n", file);

	if ((policy_handle = kobj_open_file(file)) ==
	    (struct _buf *)-1) {
		cmn_err(CE_WARN, "security: Unable to open %s\n", file);
		return (ENOENT);
	}

	if ((ret = security_load_policy(policy_handle, 0))) {
		cmn_err(CE_WARN, "security: Policy load failed %s\n", file);
		kobj_close_file(policy_handle);
		return (ret);
	}

	kobj_close_file(policy_handle);

	cmn_err(CE_CONT, "security: Policy loaded from %s\n", file);
	cmn_err(CE_CONT, "security: mode is %s\n",
	    fmac_enforcing == 0 ? "permissive" : "enforcing");

	return (0);
}

security_class_t
fmac_vtype_to_sclass(vtype_t vtype)
{
	switch (vtype) {
	case VREG:
		return (SECCLASS_FILE);
	case VDIR:
		return (SECCLASS_DIR);
#if notyet
	/* Wait until we have labeling support for all file types. */
	case VBLK:
		return (SECCLASS_BLK_FILE);
	case VCHR:
		return (SECCLASS_CHR_FILE);
	case VLNK:
		return (SECCLASS_LNK_FILE);
	case VFIFO:
		return (SECCLASS_FIFO_FILE);
	case VSOCK:
		return (SECCLASS_SOCK_FILE);
#endif
	case VDOOR:
		/* TBD */
	case VPROC:
		/* TBD */
	case VPORT:
		/* TBD */
	case VNON:
		return (SECCLASS_NULL);
	}
	return (SECCLASS_NULL);
}

int
fmac_vnode_lookup(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	int error;
	xvattr_t xvattr;
	xoptattr_t *xoap;
	security_id_t secid;

	if (!fmac_enabled)
		return (0);
	if (vp->v_secid != SECINITSID_UNLABELED)
		return (0); /* already set */
	if (vfs_has_feature(vp->v_vfsp, VFSFT_XVATTR) == 0)
		return (0);

	xva_init(&xvattr);
	if ((xoap = xva_getxoptattr(&xvattr)) == NULL)
		return (EINVAL);
	XVA_SET_REQ(&xvattr, XAT_SECCTX);

	error = VOP_GETATTR(vp, &xvattr.xva_vattr, 0, cr, ct);
	if (error)
		return (error);

	if (XVA_ISSET_RTN(&xvattr, XAT_SECCTX)) {
		error = security_context_to_sid(xoap->xoa_secctx,
		    strlen(xoap->xoa_secctx), &secid);
		if (error)
			return (error);
	} else {
		/* default SID for files without a secctx. */
		secid = SECINITSID_FILE;
	}

	mutex_enter(&(vp->v_lock));
	if (vp->v_secid == SECINITSID_UNLABELED)
		vp->v_secid = secid;
	mutex_exit(&(vp->v_lock));

	return (0);
}

void
fmac_vnode_init_secid(vnode_t *vp, char *secctx)
{
	security_id_t secid;

	if (!fmac_enabled)
		return;

	/*
	 * Called before vp is put in dnlc, so no need to hold v_lock.
	 */
	if (security_context_to_sid(secctx, strlen(secctx), &secid))
		vp->v_secid = SECINITSID_UNLABELED;
	else
		vp->v_secid = secid;
}

int
fmac_vfs_root(vfs_t *vfsp, vnode_t *vp)
{
	_NOTE(ARGUNUSED(vfsp));	/* future use for context mounts? */
	return (fmac_vnode_lookup(vp, CRED(), NULL));
}

int
fmac_vnode_set_secctx(char *secctx, cred_t *cr, vtype_t vtype, vnode_t *vp)
{
	security_id_t cr_secid, old_secid, new_secid;
	security_class_t sclass;
	int error;
	avc_audit_data_t ad;

	if (!fmac_enabled)
		return (EINVAL);

	cr_secid = cr->cr_secid;

	sclass = fmac_vtype_to_sclass(vtype);
	if (!sclass)
		return (EINVAL);

	error = security_context_to_sid(secctx, strlen(secctx), &new_secid);
	if (error)
		return (error);

	if (vp) {
		/*
		 * Relabeling an existing file.
		 */
		mutex_enter(&(vp->v_lock));
		old_secid = vp->v_secid;
		AVC_AUDIT_DATA_INIT(&ad, FS);
		ad.u.fs.vp = vp;
		error = avc_has_perm(cr_secid, old_secid, sclass,
		    FILE__RELABELFROM, &ad);
		if (!error)
			error = avc_has_perm(cr_secid, new_secid, sclass,
			    FILE__RELABELTO, &ad);
		if (!error)
			vp->v_secid = new_secid;
		mutex_exit(&(vp->v_lock));
	} else {
		/* Creating a new file. */
		error = avc_has_perm(cr_secid, new_secid, sclass,
		    FILE__CREATE, NULL);
	}

	return (error);
}

int
fmac_vnode_get_secctx(vnode_t *vp, vattr_t *vap)
{
	xvattr_t *xvap = (xvattr_t *)vap;
	xoptattr_t *xoap;
	security_context_t scontext;
	uint32_t scontext_len;
	int error;

	if (!fmac_enabled)
		return (0);

	xoap = xva_getxoptattr(xvap);
	if (!xoap)
		return (0);

	if (!XVA_ISSET_REQ(xvap, XAT_SECCTX))
		return (0);

	error = security_sid_to_context(vp->v_secid, &scontext, &scontext_len);
	if (error)
		return (error);

	if (scontext_len > sizeof (xoap->xoa_secctx)) {
		security_context_free(scontext);
		return (EINVAL);
	}

	(void) strncpy(xoap->xoa_secctx, scontext, sizeof (xoap->xoa_secctx));
	XVA_SET_RTN(xvap, XAT_SECCTX);
	security_context_free(scontext);
	return (0);
}

int
fmac_vnode_create(vnode_t *dvp, char *name, xvattr_t *xvap, vattr_t **vapp,
    cred_t *cr, security_id_t *secidp)
{
	security_id_t cr_secid, secid;
	security_class_t sclass;
	security_context_t scontext;
	uint32_t scontext_len;
	vattr_t *vap = *vapp;
	xoptattr_t *xoap;
	int error;
	avc_audit_data_t ad;

	if (!fmac_enabled)
		return (0);

	/*
	 * Make sure we define a default secid for use by
	 * fmac_vnode_post_create even if the fs does not
	 * support xvattrs.
	 */
	*secidp = SECINITSID_FILE;

	if (vfs_has_feature(dvp->v_vfsp, VFSFT_XVATTR) == 0)
		return (0);

	sclass = fmac_vtype_to_sclass(vap->va_type);
	if (!sclass)
		return (0);

	cr_secid = cr->cr_secid;

	error = security_transition_sid(cr_secid, dvp->v_secid, sclass,
	    &secid);
	if (error)
		return (error);

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = dvp;
	ad.u.fs.name = name;

	error = avc_has_perm(cr_secid, dvp->v_secid, SECCLASS_DIR,
	    DIR__ADD_NAME, &ad);
	if (error)
		return (error);

	error = avc_has_perm(cr_secid, secid, sclass, FILE__CREATE, &ad);
	if (error)
		return (error);

	if (!xvap) {
		/*
		 * Caller only wants the secid, not an xvattr w/ secctx.
		 * tmpfs is one such example.
		 */
		*secidp = secid;
		return (0);
	}

	if (!(vap->va_mask & AT_XVATTR)) {
		/*
		 * If the vattr is not already an xvattr, then wrap the
		 * vattr with an xvattr so we can pass the secctx to
		 * the fs code.
		 */
		xva_from_va(xvap, vap);
		*vapp = &xvap->xva_vattr;
	} else {
		xvap = (xvattr_t *)vap;
	}

	error = security_sid_to_context(secid, &scontext, &scontext_len);
	if (error)
		return (error);

	xoap = xva_getxoptattr(xvap);
	if (!xoap || scontext_len > sizeof (xoap->xoa_secctx))
		goto inval;
	(void) strncpy(xoap->xoa_secctx, scontext, sizeof (xoap->xoa_secctx));
	XVA_SET_REQ(xvap, XAT_SECCTX);

	*secidp = secid;
	security_context_free(scontext);
	return (0);
inval:
	security_context_free(scontext);
	return (EINVAL);
}

void
fmac_vnode_post_create(vnode_t *vp, security_id_t secid)
{
	if (!fmac_enabled)
		return;
	mutex_enter(&(vp->v_lock));
	vp->v_secid = secid;
	mutex_exit(&(vp->v_lock));
}

int
fmac_vnode_link(vnode_t *tdvp, vnode_t *svp, char *name, cred_t *cr)
{
	security_id_t cr_secid;
	security_class_t sclass;
	int error;
	avc_audit_data_t ad;

	if (!fmac_enabled)
		return (0);

	sclass = fmac_vtype_to_sclass(svp->v_type);
	if (!sclass)
		return (0);

	cr_secid = cr->cr_secid;

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = tdvp;
	ad.u.fs.name = name;
	error = avc_has_perm(cr_secid, tdvp->v_secid, SECCLASS_DIR,
	    DIR__ADD_NAME, &ad);
	if (error)
		return (error);

	ad.u.fs.vp = svp;
	return (avc_has_perm(cr_secid, svp->v_secid, sclass,
	    FILE__LINK, &ad));
}

int
fmac_vnode_remove(vnode_t *dvp, vnode_t *vp, char *name, cred_t *cr)
{
	security_id_t cr_secid;
	security_class_t sclass;
	access_vector_t av;
	int error;
	avc_audit_data_t ad;

	if (!fmac_enabled)
		return (0);

	sclass = fmac_vtype_to_sclass(vp->v_type);
	if (!sclass)
		return (0);

	cr_secid = cr->cr_secid;

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = dvp;
	ad.u.fs.name = name;
	error = avc_has_perm(cr_secid, dvp->v_secid, SECCLASS_DIR,
	    DIR__REMOVE_NAME, &ad);
	if (error)
		return (error);

	ad.u.fs.vp = vp;
	if (sclass == SECCLASS_DIR)
		av = DIR__RMDIR;
	else
		av = FILE__UNLINK;
	return (avc_has_perm(cr_secid, vp->v_secid, sclass, av, &ad));
}

int
fmac_vnode_rename(vnode_t *sdvp, vnode_t *svp, vnode_t *tdvp, vnode_t *tvp,
    cred_t *cr)
{
	security_id_t cr_secid;
	security_class_t sclass, tclass;
	access_vector_t av;
	int error;
	avc_audit_data_t ad;

	if (!fmac_enabled)
		return (0);

	sclass = fmac_vtype_to_sclass(svp->v_type);
	if (!sclass)
		return (0);

	cr_secid = cr->cr_secid;

	AVC_AUDIT_DATA_INIT(&ad, FS);

	ad.u.fs.vp = sdvp;
	error = avc_has_perm(cr_secid, sdvp->v_secid, SECCLASS_DIR,
	    DIR__REMOVE_NAME, &ad);
	if (error)
		return (error);

	ad.u.fs.vp = svp;
	error = avc_has_perm(cr_secid, svp->v_secid, sclass,
	    FILE__RENAME, &ad);
	if (error)
		return (error);

	ad.u.fs.vp = tdvp;
	error = avc_has_perm(cr_secid, tdvp->v_secid, SECCLASS_DIR,
	    DIR__ADD_NAME, &ad);
	if (error)
		return (error);

	if (tvp) {
		tclass = fmac_vtype_to_sclass(tvp->v_type);
		if (!tclass)
			return (0);

		if (tclass == SECCLASS_DIR)
			av = DIR__RMDIR;
		else
			av = FILE__UNLINK;

		ad.u.fs.vp = tvp;
		error = avc_has_perm(cr_secid, tvp->v_secid, tclass, av,
		    &ad);
		if (error)
			return (error);
	}

	return (0);
}

int
fmac_vnode_setattr(vnode_t *vp, cred_t *cr)
{
	security_id_t cr_secid;
	security_class_t sclass;
	avc_audit_data_t ad;

	if (!fmac_enabled)
		return (0);

	sclass = fmac_vtype_to_sclass(vp->v_type);
	if (!sclass)
		return (0);

	cr_secid = cr->cr_secid;

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = vp;
	return (avc_has_perm(cr_secid, vp->v_secid, sclass,
	    FILE__SETATTR, &ad));
}

int
fmac_exec(cred_t *cr, vnode_t *vp, boolean_t *setsecid,
    boolean_t *setprivinc, security_id_t *prev_secidp, security_id_t *secidp)
{
	security_id_t prev_secid, secid;
	int error;
	avc_audit_data_t ad;

	if (!fmac_enabled)
		return (0);

	prev_secid = cr->cr_secid;
	secid = cr->cr_exec_secid;
	if (!secid) {
		error = security_transition_sid(prev_secid, vp->v_secid,
		    SECCLASS_PROCESS, &secid);
		if (error)
			return (error);
	}

	if (vp->v_vfsp->vfs_flag & VFS_NOSETUID)
		secid = prev_secid;

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = vp;

	if (prev_secid == secid) {
		error = avc_has_perm(prev_secid, vp->v_secid,
		    SECCLASS_FILE, FILE__EXECUTE_NO_TRANS, &ad);
		if (error)
			return (error);
		*setprivinc = B_FALSE;
		*setsecid = B_FALSE;
		*prev_secidp = *secidp = secid;
		return (0);
	}

	error = avc_has_perm(prev_secid, secid, SECCLASS_PROCESS,
	    PROCESS__TRANSITION, &ad);
	if (error)
		return (error);

	error = avc_has_perm(secid, vp->v_secid, SECCLASS_FILE,
	    FILE__ENTRYPOINT, &ad);
	if (error)
		return (error);

	error = avc_has_perm(prev_secid, secid, SECCLASS_PROCESS,
	    PROCESS__NOPRIVINC, &ad);
	if (error)
		*setprivinc = B_TRUE;
	else
		*setprivinc = B_FALSE;

	*setsecid = B_TRUE;
	*prev_secidp = prev_secid;
	*secidp = secid;
	return (0);
}

#define	fmac_ace_to_av(mask, perm) \
	if (mode & (mask)) { \
		mode &= ~(mask); \
		av |= (perm); \
	}

#define	ACE_GETATTR_MASK (ACE_READ_NAMED_ATTRS | ACE_READ_ATTRIBUTES | \
    ACE_READ_ACL)
#define	ACE_SETATTR_MASK (ACE_WRITE_NAMED_ATTRS | ACE_WRITE_ATTRIBUTES | \
    ACE_WRITE_ACL | ACE_WRITE_OWNER)

int
fmac_vnode_access(vnode_t *vp, int mode, int flags, cred_t *cr,
    boolean_t audit)
{
	security_id_t cr_secid;
	security_class_t sclass;
	access_vector_t av;
	avc_audit_data_t ad;

	if (!fmac_enabled)
		return (0);

	cr_secid = cr->cr_secid;

	sclass = fmac_vtype_to_sclass(vp->v_type);
	if (!sclass)
		return (0);

	av = 0;

	if (flags & V_ACE_MASK) {
		mode &= ~ACE_SYNCHRONIZE; /* ignore synchronize bit */
		fmac_ace_to_av(ACE_READ_DATA, FILE__READ);
		fmac_ace_to_av(ACE_GETATTR_MASK, FILE__GETATTR);
		fmac_ace_to_av(ACE_SETATTR_MASK, FILE__SETATTR);
		if (sclass == SECCLASS_DIR) {
			fmac_ace_to_av((ACE_ADD_FILE | ACE_ADD_SUBDIRECTORY),
			    DIR__ADD_NAME);
			fmac_ace_to_av(ACE_DELETE_CHILD, DIR__REMOVE_NAME);
			fmac_ace_to_av(ACE_DELETE, DIR__RMDIR);
			fmac_ace_to_av(ACE_EXECUTE, DIR__SEARCH);
		} else {
			fmac_ace_to_av(ACE_APPEND_DATA, FILE__APPEND);
			fmac_ace_to_av(ACE_WRITE_DATA, (flags & V_APPEND) ?
			    FILE__APPEND : FILE__WRITE);
			fmac_ace_to_av(ACE_EXECUTE, FILE__EXECUTE);
			fmac_ace_to_av(ACE_DELETE, FILE__UNLINK);
		}
		if (mode) {
			cmn_err(CE_WARN, "FMAC:  Unknown ACE mask 0x%x\n",
			    mode);
			return (EACCES);
		}
	} else {
		if (mode & VREAD)
			av |= FILE__READ;
		if (flags & V_APPEND)
			av |= FILE__APPEND;
		else if (mode & VWRITE)
			av |= FILE__WRITE;
		if (mode & VEXEC) {
			if (sclass == SECCLASS_DIR)
				av |= DIR__SEARCH;
			else
				av |= FILE__EXECUTE;
		}
	}

	if (!av)
		return (0);

	if (audit) {
		AVC_AUDIT_DATA_INIT(&ad, FS);
		ad.u.fs.vp = vp;
	} else
		AVC_AUDIT_DATA_INIT(&ad, DONTAUDIT);
	return (avc_has_perm(cr_secid, vp->v_secid, sclass, av, &ad));
}

int
fmac_priv_proc_cred_perm(const cred_t *scr, cred_t *tcr, int mode)
{
	_NOTE(ARGUNUSED(mode));	/* todo:  distinguish read vs. write? */

	if (!fmac_enabled)
		return (0);
	return (avc_has_perm(scr->cr_secid, tcr->cr_secid,
	    SECCLASS_PROCESS, PROCESS__PTRACE, NULL));
}

access_vector_t
fmac_sigtoav(int sig)
{
	switch (sig) {
	case SIGCHLD:
		return (PROCESS__SIGCHLD);
	case SIGKILL:
		return (PROCESS__SIGKILL);
	case SIGSTOP:
		return (PROCESS__SIGSTOP);
	}
	return (PROCESS__SIGNAL);
}

int
fmac_hasprocperm(const cred_t *tcrp, const cred_t *scrp, access_vector_t perms)
{
	security_id_t tsecid;
	security_id_t ssecid;

	if (!fmac_enabled)
		return (0);

	tsecid = tcrp->cr_secid;
	ssecid = scrp->cr_secid;
	return (avc_has_perm(ssecid, tsecid, SECCLASS_PROCESS, perms, NULL));
}

static int
fmac_vnode_priv_common(cred_t *cr, vnode_t *vp, security_class_t sclass,
    access_vector_t av, priv_set_t *privs, int err)
{
	avc_audit_data_t ad;

	/*
	 * If privilege aware, then honor any legacy policy denial
	 * since the program may have reduced its own privileges.
	 */
	if (err && (CR_FLAGS(cr) & PRIV_AWARE))
		return (err);

	/*
	 * Do not allow FMAC to override the limit set.
	 */
	if (err && !priv_issubset(privs, &CR_LPRIV(cr)))
		return (err);

	AVC_AUDIT_DATA_INIT(&ad, FS);
	ad.u.fs.vp = vp;
	return (avc_has_perm_strict(cr->cr_secid, vp->v_secid, sclass,
	    av, &ad) ? EPERM : 0);
}

int
fmac_vnode_priv_access(const cred_t *cr, vnode_t *vp, int mode, int err)
{
	security_class_t sclass;
	access_vector_t av;
	priv_set_t privs;

	/* If not enabled, just return the legacy policy decision. */
	if (!fmac_enabled)
		return (err);

	sclass = fmac_vtype_to_sclass(vp->v_type);
	if (!sclass)
		return (err);

	av = 0;
	priv_emptyset(&privs);
	if (mode & VREAD) {
		av |= FILE__FILE_DAC_READ;
		priv_addset(&privs, PRIV_FILE_DAC_READ);
	}
	if (mode & VWRITE) {
		av |= FILE__FILE_DAC_WRITE;
		priv_addset(&privs, PRIV_FILE_DAC_WRITE);
	}

	if (mode & VEXEC) {
		if (sclass == SECCLASS_DIR) {
			av |= DIR__FILE_DAC_SEARCH;
			priv_addset(&privs, PRIV_FILE_DAC_SEARCH);
		} else {
			av |= FILE__FILE_DAC_EXECUTE;
			priv_addset(&privs, PRIV_FILE_DAC_EXECUTE);
		}
	}

	if (!av)
		return (err);

	return (fmac_vnode_priv_common((cred_t *)cr, vp, sclass, av,
	    &privs, err));
}

int
fmac_xvattr(cred_t *cr, vnode_t *vp, int priv, int err)
{
	security_class_t sclass;
	access_vector_t av;
	priv_set_t privs;

	/* If not enabled, just return the legacy policy decision. */
	if (!fmac_enabled)
		return (err);

	/* Only go further if the base privilege check failed. */
	if (err == 0)
		return (0);

	sclass = fmac_vtype_to_sclass(vp->v_type);
	if (!sclass)
		return (err);

	av = 0;
	priv_emptyset(&privs);
	priv_addset(&privs, priv);
	if (priv == PRIV_FILE_FLAG_SET)
		av |= FILE__FILE_FLAG_SET;
	else {
		ASSERT(priv == PRIV_FILE_FLAG_CLR);
		av |= FILE__FILE_FLAG_CLR;
	}

	return (fmac_vnode_priv_common(cr, vp, sclass, av, &privs, err));
}

int
fmac_priv_restrict(const cred_t *cr, int priv)
{
	security_id_t cr_secid;
	security_class_t sclass;
	access_vector_t av;
	avc_audit_data_t ad;
	const char *name;

	if (!fmac_enabled)
		return (0);

	if (priv < 0) {
		/*
		 * Need to handle special privileges like PRIV_ALL
		 * in the callers where we can map the operation to a
		 * specific FMAC permission.
		 */
		return (0);
	}

	cr_secid = cr->cr_secid;

	switch (priv >> 5) {
	case 0:
		sclass = SECCLASS_PRIV0;
		break;
	case 1:
		sclass = SECCLASS_PRIV1;
		break;
	case 2:
		sclass = SECCLASS_PRIV2;
		break;
	default:
		name = priv_getbynum(priv);
		cmn_err(CE_WARN, "FMAC:  Out of range privilege %d (%s)\n",
		    priv, name ? name : "undefined");
		if (fmac_enforcing)
			return (EACCES);
		else
			return (0);
	}

	/* Note:  The access vector representation != privmask(priv). */
	av = 1 << (priv & 31);

	AVC_AUDIT_DATA_INIT(&ad, PRIV);
	ad.u.priv.priv = priv;
	return (avc_has_perm(cr_secid, cr_secid, sclass, av, &ad));
}

int
fmac_priv_require_set(const cred_t *cr, const priv_set_t *req)
{
	int priv;

	for (priv = 0; priv < nprivs; priv++)
		if (priv_ismember(req, priv))
			if (fmac_priv_restrict(cr, priv))
				return (EACCES);
	return (0);
}
