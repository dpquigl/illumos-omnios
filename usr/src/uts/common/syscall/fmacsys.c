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

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/zone.h>
#include <sys/note.h>
#include <sys/policy.h>
#include <sys/priv.h>
#include <sys/fmac/fmac.h>
#include <sys/fmac/flask.h>
#include <sys/fmac/flask_types.h>
#include <sys/fmac/security.h>
#include <sys/fmac/avc.h>
#include <sys/fmac/avc_ss.h>

static int
fmacsys_getenforce()
{
	if (fmac_enforcing)
		return (1);
	else
		return (0);
}

static int
fmacsys_setenforce(int mode)
{
	int err = 0;

	if (!INGLOBALZONE(curproc))
		return (set_errno(EINVAL));

	if (err = avc_has_perm(crgetsecid(CRED()), SECINITSID_SECURITY,
	    SECCLASS_SECURITY, SECURITY__SETENFORCE, NULL))
		return (set_errno(err));

	switch (mode) {

	case 0:
	case 1:
		fmac_enforcing = mode;
		if (fmac_enforcing)
			(void) avc_ss_reset(0);
		break;
	default:
		err = EINVAL;
		break;
	}

out:
	if (err)
		return (set_errno(err));
	else
		return (0);
}

static int
fmacsys_security_load_policy(char *path)
{
	char	*kpath = 0;
	int	err;

	if (!INGLOBALZONE(curproc))
		return (set_errno(EINVAL));

	if (err = avc_has_perm(crgetsecid(CRED()), SECINITSID_SECURITY,
	    SECCLASS_SECURITY, SECURITY__LOAD_POLICY, NULL))
		return (set_errno(err));

	kpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if ((err = copyinstr(path, kpath, MAXPATHLEN, NULL)) == 0)
		err = fmac_load_policy(kpath);

	kmem_free(kpath, MAXPATHLEN);

	if (err)
		return (set_errno(err));
	else
		return (0);
}

static int
fmacsys_is_fmac_enabled()
{
	if (fmac_enabled)
		return (1);
	else
		return (0);
}


static int
fmacsys_security_compute_av(
    security_context_t scontext,
    security_context_t tcontext,
    security_class_t tclass,
    access_vector_t request,
    struct av_decision *avd)
{
	security_context_t	kscontext;
	security_context_t	ktcontext;
	security_id_t		ssid;
	security_id_t		tsid;
	struct av_decision	kavd;
	size_t			slen;
	size_t			tlen;
	int			err;

	if (err = avc_has_perm(crgetsecid(CRED()), SECINITSID_SECURITY,
	    SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL))
		return (set_errno(err));

	kscontext = kmem_alloc(FMAC_MAX_CONTEXT_LEN, KM_SLEEP);
	ktcontext = kmem_alloc(FMAC_MAX_CONTEXT_LEN, KM_SLEEP);

	if ((err = copyinstr(scontext, kscontext, FMAC_MAX_CONTEXT_LEN,
	    &slen)) != 0)
		goto out;

	if ((err = copyinstr(tcontext, ktcontext, FMAC_MAX_CONTEXT_LEN,
	    &tlen)) != 0)
		goto out;

	if ((err = security_context_to_sid(kscontext, slen, &ssid)))
		goto out;

	if ((err = security_context_to_sid(ktcontext, tlen, &tsid)))
		goto out;

	if ((err = security_compute_av(ssid, tsid, tclass, request, &kavd)))
		goto out;

	if (copyout(&kavd, avd, sizeof (struct av_decision))) {
		err = EFAULT;
		goto out;
	}

out:
	kmem_free(kscontext, FMAC_MAX_CONTEXT_LEN);
	kmem_free(ktcontext, FMAC_MAX_CONTEXT_LEN);

	if (err)
		return (set_errno(err));
	else
		return (0);
}

static int
fmacsys_security_check_context(security_context_t scontext)
{
	security_context_t	kscontext;
	security_id_t		ssid;
	size_t			slen;
	int			err;

	if (err = avc_has_perm(crgetsecid(CRED()), SECINITSID_SECURITY,
	    SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL))
		return (set_errno(err));

	kscontext = kmem_alloc(FMAC_MAX_CONTEXT_LEN, KM_SLEEP);

	if ((err = copyinstr(scontext, kscontext, FMAC_MAX_CONTEXT_LEN,
	    &slen)) == 0)
		err = security_context_to_sid(kscontext, slen, &ssid);

	kmem_free(kscontext, FMAC_MAX_CONTEXT_LEN);

	if (err)
		return (set_errno(err));
	else
		return (0);
}

static int
fmacsys_getcon(pid_t pid, security_context_t scontext)
{
	security_context_t	pcontext;
	uint32_t		pcontext_len;
	security_id_t		sid;
	proc_t			*p;
	int			err = 0;

	if (pid == P_MYID || pid == curproc->p_pid) {
		sid = crgetsecid(CRED());
	} else {
		mutex_enter(&pidlock);
		if ((p = prfind(pid)) == NULL ||
		    (secpolicy_basic_procinfo(CRED(), p, curproc) != 0)) {
			mutex_exit(&pidlock);
			return (set_errno(ESRCH));
		}
		mutex_enter(&p->p_lock);
		mutex_exit(&pidlock);
		mutex_enter(&p->p_crlock);
		sid = crgetsecid(p->p_cred);
		mutex_exit(&p->p_crlock);
		mutex_exit(&p->p_lock);
	}

	if (err = avc_has_perm(crgetsecid(CRED()), sid, SECCLASS_PROCESS,
	    PROCESS__GETATTR, NULL))
		return (set_errno(err));

	if ((err = security_sid_to_context(sid, &pcontext,
	    &pcontext_len)) == 0) {
		if (copyout(pcontext, scontext, pcontext_len))
			err = EFAULT;
		security_context_free(pcontext);
	}

	if (err)
		return (set_errno(err));
	else
		return (0);
}

static int
fmacsys_getexeccon(security_context_t scontext)
{
	security_context_t	pcontext;
	uint32_t		pcontext_len;
	int			err = 0;

	/* If exec context not set, return null string */
	if (crgetexecsecid(CRED()) == SECSID_NULL) {
		if (subyte(scontext, 0) < 0)
			return (set_errno(EFAULT));
		else
			return (0);
	}

	if (err = security_sid_to_context(crgetexecsecid(CRED()), &pcontext,
	    &pcontext_len))
		return (set_errno(err));

	if (copyout(pcontext, scontext, pcontext_len))
		err = EFAULT;

	security_context_free(pcontext);

	if (err)
		return (set_errno(err));
	else
		return (0);
}

static int
fmacsys_setexeccon(security_context_t scontext)
{
	security_context_t	kscontext;
	security_id_t		sid;
	size_t			slen;
	proc_t			*p;
	cred_t			*cr;
	cred_t			*newcr;
	int			err;

	if (err = avc_has_perm(crgetsecid(CRED()), crgetsecid(CRED()),
	    SECCLASS_PROCESS, PROCESS__SETEXEC, NULL))
		return (set_errno(err));

	if (scontext == 0) {
		sid = SECSID_NULL;
	} else {

		kscontext = kmem_alloc(FMAC_MAX_CONTEXT_LEN, KM_SLEEP);

		err = copyinstr(scontext, kscontext, FMAC_MAX_CONTEXT_LEN,
		    &slen);

		if (!err)
			err = security_context_to_sid(kscontext, slen, &sid);

		kmem_free(kscontext, FMAC_MAX_CONTEXT_LEN);

		if (err)
			return (set_errno(err));
	}

	newcr = cralloc_ksid();
	p = ttoproc(curthread);
	mutex_enter(&p->p_crlock);
	cr = p->p_cred;
	crdup_to(cr, newcr);
	crsetexecsecid(newcr, sid);
	p->p_cred = newcr;
	crhold(newcr);
	crfree(cr);
	mutex_exit(&p->p_crlock);
	crset(p, newcr);

	if (err)
		return (set_errno(err));
	else
		return (0);
}

static int
fmacsys_getprevcon(security_context_t scontext)
{
	security_context_t	pcontext;
	uint32_t		pcontext_len;
	int			err = 0;

	/* If previous context not set, return null string */
	if (crgetprevsecid(CRED()) == SECSID_NULL) {
		if (subyte(scontext, 0) < 0)
			return (set_errno(EFAULT));
		else
			return (0);
	}

	if (err = security_sid_to_context(crgetprevsecid(CRED()), &pcontext,
	    &pcontext_len))
		return (set_errno(err));

	if (copyout(pcontext, scontext, pcontext_len))
		err = EFAULT;

	security_context_free(pcontext);

	if (err)
		return (set_errno(err));
	else
		return (0);
}

static int
fmacsys_getfilecon(char *path, security_context_t scontext)
{
	_NOTE(ARGUNUSED(path, scontext));

	return (set_errno(ENOSYS));
}

static int
fmacsys_setfilecon(char *path, security_context_t scontext)
{
	_NOTE(ARGUNUSED(path, scontext));

	return (set_errno(ENOSYS));
}

static int
fmacsys_lgetfilecon(char *path, security_context_t scontext)
{
	_NOTE(ARGUNUSED(path, scontext));

	return (set_errno(ENOSYS));
}

static int
fmacsys_lsetfilecon(char *path, security_context_t scontext)
{
	_NOTE(ARGUNUSED(path, scontext));

	return (set_errno(ENOSYS));
}

static int
fmacsys_fgetfilecon(int fd, security_context_t scontext)
{
	_NOTE(ARGUNUSED(fd, scontext));

	return (set_errno(ENOSYS));
}

static int
fmacsys_fsetfilecon(int fd, security_context_t scontext)
{
	_NOTE(ARGUNUSED(fd, scontext));

	return (set_errno(ENOSYS));
}

static int
fmac_securitycomputeuser(security_context_t scontext, const char *username,
    void *buf, size_t buf_len)
{
	char		*kbuf;
	size_t		kcontext_len;
	security_id_t	*sids;
	security_id_t	fromsid;
	uint32_t	nel = 0;
	int		err;
	char		*toptr;

	if (err = avc_has_perm(crgetsecid(CRED()), SECINITSID_SECURITY,
	    SECCLASS_SECURITY, SECURITY__COMPUTE_USER, NULL))
		return (set_errno(err));

	kbuf = kmem_alloc(FMAC_MAX_CONTEXT_LEN, KM_SLEEP);

	if (err = copyinstr(scontext, kbuf, FMAC_MAX_CONTEXT_LEN,
	    &kcontext_len))
		goto out;

	if (err = security_context_to_sid(kbuf, kcontext_len, &fromsid)) {
		goto out;
	}

	if (err = copyinstr(username, kbuf, FMAC_MAX_CONTEXT_LEN, NULL)) {
		goto out;
	}

	if ((err = security_get_user_sids(fromsid, kbuf, &sids, &nel)) == 0) {
		int i;

		kmem_free(kbuf, FMAC_MAX_CONTEXT_LEN);
		kbuf = NULL;

		toptr = buf;

		for (i = 0; i < nel; i++) {
			security_context_t context;
			uint32_t context_len;
			int count = 0;

			if ((err = security_sid_to_context(sids[i], &context,
			    &context_len)) == 0) {
				if (count + context_len > buf_len) {
					err = ENOMEM;
					security_context_free(context);
					goto out;
				}
				if (copyout(context, toptr, context_len)) {
					err = EFAULT;
					security_context_free(context);
					goto out;
				}
				toptr += context_len;
				count += context_len;
				security_context_free(context);
			} else
				goto out;
		}
	}
out:
	if (kbuf)
		kmem_free(kbuf, FMAC_MAX_CONTEXT_LEN);

	if (nel)
		security_free_user_sids(sids, nel);

	if (err)
		return (set_errno(err));
	else
		return (nel);
}

int
fmacsys(int op, void *a1, void *a2, void *a3, void *a4, void *a5)
{
	if (op == FMACSYS_ISFMACENABLED)
		return (fmacsys_is_fmac_enabled());

	if (!fmac_enabled)
		return (set_errno(ENOSYS));

	switch (op) {
	case FMACSYS_SECURITYGETENFORCE:
		return (fmacsys_getenforce());
	case FMACSYS_SECURITYSETENFORCE:
		return (fmacsys_setenforce((int)(uintptr_t)a1));
	case FMACSYS_SECURITYLOADPOLICY:
		return (fmacsys_security_load_policy((char *)a1));
	case FMACSYS_SECURITYCOMPUTEAV:
		return (fmacsys_security_compute_av((security_context_t)a1,
		    (security_context_t)a2,
		    (security_class_t)(uintptr_t)a3,
		    (access_vector_t)(unsigned long)a4,
		    (struct av_decision *)a5));
	case FMACSYS_SECURITYCHECKCONTEXT:
		return (fmacsys_security_check_context((security_context_t)a1));
	case FMACSYS_GETCON:
		return (fmacsys_getcon(P_MYID, (security_context_t)a1));
	case FMACSYS_GETPIDCON:
		return (fmacsys_getcon((pid_t)(uintptr_t)a1,
		    (security_context_t)a2));
	case FMACSYS_GETEXECCON:
		return (fmacsys_getexeccon((security_context_t)a1));
	case FMACSYS_SETEXECCON:
		return (fmacsys_setexeccon((security_context_t)a1));
	case FMACSYS_GETPREVCON:
		return (fmacsys_getprevcon((security_context_t)a1));
	case FMACSYS_GETFILECON:
		return (fmacsys_getfilecon((char *)a1, (security_context_t)a2));
	case FMACSYS_SETFILECON:
		return (fmacsys_setfilecon((char *)a1, (security_context_t)a2));
	case FMACSYS_LGETFILECON:
		return (fmacsys_lgetfilecon((char *)a1,
		    (security_context_t)a2));
	case FMACSYS_LSETFILECON:
		return (fmacsys_lsetfilecon((char *)a1,
		    (security_context_t)a2));
	case FMACSYS_FGETFILECON:
		return (fmacsys_fgetfilecon((int)(uintptr_t)a1,
		    (security_context_t)a2));
	case FMACSYS_FSETFILECON:
		return (fmacsys_fsetfilecon((int)(uintptr_t)a1,
		    (security_context_t)a2));
	case FMACSYS_SECURITYCOMPUTEUSER:
		return (fmac_securitycomputeuser((security_context_t)a1,
		    (const char *)a2, (void *)a3, (size_t)a4));
	default:
		return (set_errno(ENOSYS));
	}
	/* NOTREACHED */
}

