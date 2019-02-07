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
 * Original files contributed to OpenSolaris.org under license by the
 * United States Government (NSA) to Sun Microsystems, Inc.
 */

/*
 * Author:  Stephen Smalley, <sds@epoch.ncsc.mil>
 */

/*
 * Implementation of the kernel access vector cache (AVC).
 */

/* include system headers from the OS here */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/inttypes.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/systm.h>
#include <sys/kstat.h>
#include <sys/atomic.h>
#include <sys/priv.h>
#include <sys/note.h>
#include <sys/fmac/fmac.h>
#include <sys/fmac/avc.h>
#include <sys/fmac/avc_ss.h>
#include <sys/fmac/class_to_string.h>
#include <sys/fmac/common_perm_to_string.h>
#include <sys/fmac/av_inherit.h>
#include <sys/fmac/av_perm_to_string.h>

static krwlock_t avc_lock;
static kmutex_t avc_audit_lock;

/*
 * An entry in the AVC.
 */
typedef struct avc_entry {
	security_id_t		ssid;
	security_id_t		tsid;
	security_class_t	tclass;
	struct av_decision	avd;
	int			used;	 /* used recently */
} avc_entry_t;

typedef struct avc_node {
	struct avc_entry ae;
	struct avc_node *next;
} avc_node_t;

static struct avc_node *avc_node_freelist = NULL;

#define	AVC_CACHE_SLOTS		512
#define	AVC_CACHE_MAXNODES	410

typedef struct {
	avc_node_t	*slots[AVC_CACHE_SLOTS];
	uint32_t	lru_hint;	/* LRU hint for reclaim scan */
	uint32_t	activeNodes;
	uint32_t	latest_notif;	/* latest revocation notification */
} avc_cache_t;

static avc_cache_t avc_cache;


#define	AVC_HASH(ssid, tsid, tclass) \
		((ssid ^ (tsid<<2) ^ (tclass<<4)) & (AVC_CACHE_SLOTS - 1))

static char *avc_audit_buffer = NULL;

/*
 * AVC statistics
 */
static struct {
	kstat_named_t avclookups;
	kstat_named_t avchits;
	kstat_named_t avcprobes;
	kstat_named_t avcmisses;
} avcstats = {
	{ "avclookups", KSTAT_DATA_UINT64 },
	{ "avchits", KSTAT_DATA_UINT64 },
	{ "avcprobes", KSTAT_DATA_UINT64 },
	{ "avcmisses", KSTAT_DATA_UINT64 }
};

kstat_named_t *avcstats_ptr = (kstat_named_t *)&avcstats;
uint_t avcstats_ndata = sizeof (avcstats) / sizeof (kstat_named_t);

#define	avc_cache_stats_incr(stat) atomic_inc_64(&avcstats.stat.value.ui64)
#define	avc_cache_stats_add(stat, x) atomic_add_64(&avcstats.stat.value.ui64, x)

static void avc_audit_start(void)
{
	mutex_enter(&avc_audit_lock);
	(void) memset(avc_audit_buffer, 0, PAGESIZE);
}

/*PRINTFLIKE1*/
static void avc_audit_append(const char *fmt, ...)
{
	va_list ap;
	size_t len;

	len = strlen(avc_audit_buffer);
	va_start(ap, fmt);
	(void) vsnprintf(avc_audit_buffer + len, PAGESIZE - len, fmt, ap);
	va_end(ap);
}

static void avc_audit_end(void)
{
	(void) printf("%s\n", avc_audit_buffer);
	mutex_exit(&avc_audit_lock);
}

/*
 * Display an access vector in human-readable form.
 */
static void
avc_dump_av(security_class_t tclass, access_vector_t av)
{
	char		**common_pts = 0;
	access_vector_t	common_base = 0;
	int		i;
	int		i2;
	int		perm;

	if (av == 0) {
		avc_audit_append(" null");
		return;
	}

	for (i = 0; i < AV_INHERIT_SIZE; i++) {
		if (av_inherit[i].tclass == tclass) {
			common_pts = av_inherit[i].common_pts;
			common_base = av_inherit[i].common_base;
			break;
		}
	}

	avc_audit_append(" {");
	i = 0;
	perm = 1;
	while (perm < common_base) {
		if (perm & av)
			avc_audit_append(" %s", common_pts[i]);
		i++;
		perm <<= 1;
	}

	while (i < sizeof (access_vector_t) * 8) {
		if (perm & av) {
			for (i2 = 0; i2 < AV_PERM_TO_STRING_SIZE; i2++) {
				if ((av_perm_to_string[i2].tclass == tclass) &&
				    (av_perm_to_string[i2].value == perm))
					break;
			}
			if (i2 < AV_PERM_TO_STRING_SIZE)
				avc_audit_append(" %s",
				    av_perm_to_string[i2].name);
		}
		i++;
		perm <<= 1;
	}

	avc_audit_append(" }");
}

/*
 * Display a SID pair and a class in human-readable form.
 */
static void
avc_dump_query(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass)	/* IN */
{
	int			rc;
	security_context_t	scontext;
	uint32_t		scontext_len;

	rc = security_sid_to_context(ssid, &scontext, &scontext_len);
	if (rc)
		avc_audit_append("ssid=%d", ssid);
	else {
		avc_audit_append("scontext=%s", scontext);
		security_context_free(scontext);
	}

	rc = security_sid_to_context(tsid, &scontext, &scontext_len);
	if (rc)
		avc_audit_append(" tsid=%d", tsid);
	else {
		avc_audit_append(" tcontext=%s", scontext);
		security_context_free(scontext);
	}
	avc_audit_append(" tclass=%s", class_to_string[tclass]);
}

/*
 * Initialize the cache.
 */
void
avc_init(void)
{
	kstat_t *ksp;
	avc_node_t	*new;
	int		i;

	if (!fmac_enabled)
		return;

	rw_init(&avc_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&avc_audit_lock, NULL, MUTEX_DEFAULT, NULL);

	ksp = kstat_create("avc", 0, "avcstats", "misc", KSTAT_TYPE_NAMED,
	    avcstats_ndata, KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE);

	if (ksp) {
		ksp->ks_data = avcstats_ptr;
		kstat_install(ksp);
	}

	for (i = 0; i < AVC_CACHE_SLOTS; i++)
		avc_cache.slots[i] = 0;
	avc_cache.lru_hint = 0;
	avc_cache.activeNodes = 0;
	avc_cache.latest_notif = 0;

	for (i = 0; i < AVC_CACHE_MAXNODES; i++) {
		new = (avc_node_t *)kmem_zalloc(sizeof (avc_node_t), KM_SLEEP);
		if (!new) {
			cmn_err(CE_WARN,
			    "avc:  only able to allocate %d entries\n", i);
			break;
		}
		new->next = avc_node_freelist;
		avc_node_freelist = new;
	}

	avc_audit_buffer = (char *)kmem_zalloc(PAGESIZE, KM_SLEEP);
	if (!avc_audit_buffer)
		panic("AVC:  unable to allocate audit buffer\n");

	cmn_err(CE_CONT, "AVC: Initialized\n");
}

#if 0
static void
avc_hash_eval(char *tag)
{
	int		i;
	int		chain_len;
	int		max_chain_len;
	int		slots_used;
	avc_node_t	*node;

	rw_enter(&avc_lock, RW_READER);

	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		node = avc_cache.slots[i];
		if (node) {
			slots_used++;
			chain_len = 0;
			while (node) {
				chain_len++;
				node = node->next;
			}
			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
	}

	rw_exit(&avc_lock);

	printf("\n%s avc:  %d entries and %d/%d buckets used, longest "
	    "chain length %d\n",
	    tag, avc_cache.activeNodes, slots_used, AVC_CACHE_SLOTS,
	    max_chain_len);
}
#else
#define	avc_hash_eval(t)
#endif

/*
 * Display the contents of the cache in human-readable form.
 */
void
avc_dump_cache(char *tag)
{
	int		i;
	int		chain_len;
	int		max_chain_len;
	int		slots_used;
	avc_node_t	*node;

	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		node = avc_cache.slots[i];
		if (node) {
			printf("\n%s avc:  slot %d:\n", tag, i);
			slots_used++;
			chain_len = 0;
			while (node) {
				avc_audit_start();
				avc_dump_query(node->ae.ssid, node->ae.tsid,
				    node->ae.tclass);
				avc_audit_append(" allowed");
				avc_dump_av(node->ae.tclass,
				    node->ae.avd.allowed);
				avc_audit_end();

				chain_len++;
				node = node->next;
			}

			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
	}

	printf("\n%s avc:  %d entries and %d/%d buckets used, longest "
	    "chain length %d\n",
	    tag, avc_cache.activeNodes, slots_used, AVC_CACHE_SLOTS,
	    max_chain_len);

	printf("%s avc:  latest_notif=%d\n", tag, avc_cache.latest_notif);
}

/*
 * Reclaim a node from the cache for use.
 */
static inline avc_node_t *
avc_reclaim_node(void)
{
	avc_node_t	*prev;
	avc_node_t	*cur;
	int		hvalue;
	int		try;

	hvalue = avc_cache.lru_hint;
	for (try = 0; try < 2; try++) {
		do {
			prev = NULL;
			cur = avc_cache.slots[hvalue];
			while (cur) {
				if (!cur->ae.used)
					goto found;

				cur->ae.used = 0;

				prev = cur;
				cur = cur->next;
			}
			hvalue = (hvalue + 1) & (AVC_CACHE_SLOTS - 1);
		} while (hvalue != avc_cache.lru_hint);
	}

	panic("avc_reclaim_node");

found:
	avc_cache.lru_hint = hvalue;

	if (prev == NULL)
		avc_cache.slots[hvalue] = cur->next;
	else
		prev->next = cur->next;

	return (cur);
}

/*
 * Claim a node for use for a particular
 * SID pair and class.
 */
static inline avc_node_t *
avc_claim_node(security_id_t ssid, security_id_t tsid,
    security_class_t tclass)
{
	avc_node_t	*new;
	int		hvalue;

	hvalue = AVC_HASH(ssid, tsid, tclass);
	if (avc_node_freelist) {
		new = avc_node_freelist;
		avc_node_freelist = avc_node_freelist->next;
		avc_cache.activeNodes++;
	} else {
		new = avc_reclaim_node();
		if (!new)
			return (NULL);
	}

	new->ae.used = 1;
	new->ae.ssid = ssid;
	new->ae.tsid = tsid;
	new->ae.tclass = tclass;
	new->next = avc_cache.slots[hvalue];
	avc_cache.slots[hvalue] = new;

	return (new);
}

/*
 * Search for a node that has the specified
 * SID pair and class.
 */
static inline avc_node_t *
avc_search_node(security_id_t ssid, security_id_t tsid,
    security_class_t tclass, int *probes)
{
	avc_node_t	*cur;
	int		hvalue;
	int		tprobes = 1;

	hvalue = AVC_HASH(ssid, tsid, tclass);
	cur = avc_cache.slots[hvalue];
	while (cur != NULL &&
	    (ssid != cur->ae.ssid ||
	    tclass != cur->ae.tclass ||
	    tsid != cur->ae.tsid)) {
		tprobes++;
		cur = cur->next;
	}

	if (cur == NULL) {
		/* cache miss */
		return (NULL);
	}

	/* cache hit */
	if (probes)
		*probes = tprobes;

	cur->ae.used = 1;

	return (cur);
}

/*
 * Look up an AVC entry that is valid for the
 * `requested' permissions between the SID pair
 * (`ssid', `tsid'), interpreting the permissions
 * based on `tclass'.  If a valid AVC entry exists,
 * then this function copies the av_decision into `avd'
 * and returns 0. Otherwise, this function
 * returns ENOENT.
 */
static int
avc_lookup(security_id_t ssid, security_id_t tsid, security_class_t tclass,
    access_vector_t requested, struct av_decision *avd)
{
	avc_node_t	*node;
	int		probes;

	avc_cache_stats_incr(avclookups);

	rw_enter(&avc_lock, RW_READER);
	node = avc_search_node(ssid, tsid, tclass, &probes);
	if (node && ((node->ae.avd.decided & requested) == requested)) {
		(void) memcpy(avd, &node->ae.avd, sizeof (*avd));
		rw_exit(&avc_lock);
		avc_cache_stats_incr(avchits);
		avc_cache_stats_add(avcprobes, probes);
		return (0);
	}
	rw_exit(&avc_lock);

	avc_cache_stats_incr(avcmisses);
	return (ENOENT);
}

/*
 * Insert an AVC entry for the SID pair
 * (`ssid', `tsid') and class `tclass'.
 * The access vectors and the sequence number are
 * normally provided by the security server in
 * response to a security_compute_av call.  If the
 * sequence number `ae->avd.seqno' is not less than the latest
 * revocation notification, then the function copies
 * the access vectors into a cache entry, updates
 * `aeref' to refer to the entry, and returns 0.
 * Otherwise, this function returns EAGAIN.
 */
static int
avc_insert(security_id_t ssid, security_id_t tsid, security_class_t tclass,
    struct av_decision *avd)
{
	avc_node_t	*node;

	rw_enter(&avc_lock, RW_WRITER);
	if (avd->seqno < avc_cache.latest_notif) {
		printf("avc:  seqno %d < latest_notif %d\n", avd->seqno,
		    avc_cache.latest_notif);
		rw_exit(&avc_lock);
		return (EAGAIN);
	}

	node = avc_claim_node(ssid, tsid, tclass);
	if (!node) {
		rw_exit(&avc_lock);
		return (ENOMEM);
	}

	(void) memcpy(&node->ae.avd, avd, sizeof (*avd));
	rw_exit(&avc_lock);
	return (0);
}

/*
 * Audit the granting or denial of permissions.
 */
#define	AVC_AUDITALLOW	0
#define	AVC_AUDITDENY	1
static void
avc_audit(security_id_t ssid, security_id_t tsid, security_class_t tclass,
    access_vector_t audited, uint32_t denied, avc_audit_data_t *a)
{
	struct proc *p = curproc;
	struct vnode *vp;
	const char *name;

	if (a && a->type == AVC_AUDIT_DATA_DONTAUDIT)
		return;

	avc_audit_start();
	avc_audit_append("avc:  %s ", denied ? "denied" : "granted");
	avc_dump_av(tclass, audited);
	avc_audit_append(" for ");
	avc_dump_query(ssid, tsid, tclass);
	avc_audit_append(" pid=%d comm=%s", p->p_pid, p->p_user.u_comm);
	if (a) {
		switch (a->type) {
		case AVC_AUDIT_DATA_FS:
			vp = a->u.fs.vp;
			if (vp && vp->v_path)
				avc_audit_append(" path=%s", vp->v_path);
			if (a->u.fs.name)
				avc_audit_append(" name=%s", a->u.fs.name);
			break;
		case AVC_AUDIT_DATA_PRIV:
			avc_audit_append(" priv=%d", a->u.priv.priv);
			name = priv_getbynum(a->u.priv.priv);
			if (name)
				avc_audit_append(" priv_name=%s", name);
			break;
		}
	}
	avc_audit_end();
}

typedef struct avc_callback_node
{
	int (*callback)(uint32_t event,
	    security_id_t ssid,
	    security_id_t tsid,
	    security_class_t tclass,
	    access_vector_t perms,
	    access_vector_t *out_retained);
	uint32_t events;
	security_id_t ssid;
	security_id_t tsid;
	security_class_t tclass;
	access_vector_t perms;
	struct avc_callback_node *next;
} avc_callback_node_t;

static avc_callback_node_t *avc_callbacks = NULL;

/*
 * Register a callback for events in the set `events'
 * related to the SID pair (`ssid', `tsid') and
 * and the permissions `perms', interpreting
 * `perms' based on `tclass'.
 */

int
avc_add_callback(int (*callback)(uint32_t event, security_id_t ssid,
    security_id_t tsid, security_class_t tclass, access_vector_t perms,
    access_vector_t *out_retained), uint32_t events, security_id_t ssid,
    security_id_t tsid, security_class_t tclass, access_vector_t perms)
{
	avc_callback_node_t *c;

	c = (avc_callback_node_t *)kmem_alloc(sizeof (avc_callback_node_t),
	    KM_SLEEP);

	c->callback = callback;
	c->events = events;
	c->ssid = ssid;
	c->tsid = tsid;
	c->tclass = tclass;
	c->perms = perms;
	c->next = avc_callbacks;
	avc_callbacks = c;

	return (0);
}


#define	AVC_SIDCMP(x, y) \
		((x) == (y) || (x) == SECSID_WILD || (y) == SECSID_WILD)

/*
 * Update the cache entry `node' based on the
 * event `event' and permissions `perms'.
 */
static inline void
avc_update_node(uint32_t event, avc_node_t *node, access_vector_t perms)
{
	switch (event) {
	case AVC_CALLBACK_GRANT:
		node->ae.avd.allowed |= perms;
		break;
	case AVC_CALLBACK_TRY_REVOKE:
	case AVC_CALLBACK_REVOKE:
		node->ae.avd.allowed &= ~perms;
		break;
	case AVC_CALLBACK_AUDITALLOW_ENABLE:
		node->ae.avd.auditallow |= perms;
		break;
	case AVC_CALLBACK_AUDITALLOW_DISABLE:
		node->ae.avd.auditallow &= ~perms;
		break;
	case AVC_CALLBACK_AUDITDENY_ENABLE:
		node->ae.avd.auditdeny |= perms;
		break;
	case AVC_CALLBACK_AUDITDENY_DISABLE:
		node->ae.avd.auditdeny &= ~perms;
		break;
	}
}

/*
 * Update any cache entries that match the
 * SID pair (`ssid', `tsid') and class `tclass'
 * based on the event `event' and permissions
 * `perms'.
 */
static int
avc_update_cache(uint32_t event, security_id_t ssid, security_id_t tsid,
    security_class_t tclass, access_vector_t perms)
{
	avc_node_t	*node;
	int		i;

	rw_enter(&avc_lock, RW_WRITER);

	if (ssid == SECSID_WILD || tsid == SECSID_WILD) {
		/* apply to all matching nodes */
		for (i = 0; i < AVC_CACHE_SLOTS; i++) {
			for (node = avc_cache.slots[i]; node;
			    node = node->next) {
				if (AVC_SIDCMP(ssid, node->ae.ssid) &&
				    AVC_SIDCMP(tsid, node->ae.tsid) &&
				    tclass == node->ae.tclass) {
					avc_update_node(event, node, perms);
				}
			}
		}
	} else {
		/* apply to one node */
		node = avc_search_node(ssid, tsid, tclass, 0);
		if (node) {
			avc_update_node(event, node, perms);
		}
	}

	rw_exit(&avc_lock);

	return (0);
}

/*
 * Update the cache state and invoke any
 * registered callbacks that match the
 * SID pair (`ssid', `tsid') and class `tclass'
 * based on the event `event' and permissions
 * `perms'.  Increase the latest revocation
 * notification sequence number if appropriate.
 */
static int
avc_control(
	uint32_t event,			/* IN */
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno,			/* IN */
	access_vector_t *out_retained)	/* OUT */
{
	avc_callback_node_t *c;
	access_vector_t tretained = 0, cretained = 0;
	int rc;

	/*
	 * try_revoke only removes permissions from the cache
	 * state if they are not retained by the object manager.
	 * Hence, try_revoke must wait until after the callbacks have
	 * been invoked to update the cache state.
	 */
	if (event != AVC_CALLBACK_TRY_REVOKE)
		(void) avc_update_cache(event, ssid, tsid, tclass, perms);

	for (c = avc_callbacks; c; c = c->next) {
		if ((c->events & event) &&
		    AVC_SIDCMP(c->ssid, ssid) &&
		    AVC_SIDCMP(c->tsid, tsid) &&
		    c->tclass == tclass &&
		    (c->perms & perms)) {
			cretained = 0;
			rc = c->callback(event, ssid, tsid, tclass,
			    (c->perms & perms), &cretained);
			if (rc)
				return (rc);
			tretained |= cretained;
		}
	}

	if (event == AVC_CALLBACK_TRY_REVOKE) {
		/* revoke any unretained permissions */
		perms &= ~tretained;
		(void) avc_update_cache(event, ssid, tsid, tclass, perms);
		*out_retained = tretained;
	}

	rw_enter(&avc_lock, RW_WRITER);
	if (seqno > avc_cache.latest_notif)
		avc_cache.latest_notif = seqno;
	rw_exit(&avc_lock);

	return (0);
}

/* Grant previously denied permissions */
int
avc_ss_grant(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno)			/* IN */
{
	return avc_control(AVC_CALLBACK_GRANT, ssid, tsid, tclass, perms,
	    seqno, 0);
}

/*
 * Try to revoke previously granted permissions, but
 * only if they are not retained as migrated permissions.
 * Return the subset of permissions that are retained.
 */
int
avc_ss_try_revoke(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno,			/* IN */
	access_vector_t *out_retained)	/* OUT */
{
	return avc_control(AVC_CALLBACK_TRY_REVOKE, ssid, tsid, tclass, perms,
	    seqno, out_retained);
}

/*
 * Revoke previously granted permissions, even if
 * they are retained as migrated permissions.
 */
int
avc_ss_revoke(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno)			/* IN */
{
	return avc_control(AVC_CALLBACK_REVOKE,
	    ssid, tsid, tclass, perms, seqno, 0);
}

/*
 * Flush the cache and revalidate all migrated permissions.
 */
int
avc_ss_reset(uint32_t seqno)
{
	avc_callback_node_t	*c;
	int			rc;
	avc_node_t		*node;
	avc_node_t		*tmp;
	int			i;

	avc_hash_eval("reset");

	rw_enter(&avc_lock, RW_WRITER);

	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		node = avc_cache.slots[i];
		while (node) {
			tmp = node;
			node = node->next;
			tmp->ae.ssid = tmp->ae.tsid = SECSID_NULL;
			tmp->ae.tclass = SECCLASS_NULL;
			tmp->ae.avd.allowed = tmp->ae.avd.decided = 0;
			tmp->ae.avd.auditallow = tmp->ae.avd.auditdeny = 0;
			tmp->ae.used = 0;
			tmp->next = avc_node_freelist;
			avc_node_freelist = tmp;
			avc_cache.activeNodes--;
		}
		avc_cache.slots[i] = 0;
	}
	avc_cache.lru_hint = 0;

	rw_exit(&avc_lock);

	for (c = avc_callbacks; c; c = c->next) {
		if (c->events & AVC_CALLBACK_RESET) {
			rc = c->callback(AVC_CALLBACK_RESET,
			    0, 0, 0, 0, 0);
			if (rc)
				return (rc);
		}
	}

	rw_enter(&avc_lock, RW_WRITER);
	if (seqno > avc_cache.latest_notif)
		avc_cache.latest_notif = seqno;
	rw_exit(&avc_lock);

	return (0);
}

/* Enable or disable auditing of granted permissions */
int
avc_ss_set_auditallow(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno,			/* IN */
	uint32_t enable)
{
	if (enable)
		return avc_control(AVC_CALLBACK_AUDITALLOW_ENABLE,
		    ssid, tsid, tclass, perms, seqno, 0);
	else
		return avc_control(AVC_CALLBACK_AUDITALLOW_DISABLE,
		    ssid, tsid, tclass, perms, seqno, 0);
}

/* Enable or disable auditing of denied permissions */
int
avc_ss_set_auditdeny(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t perms,		/* IN */
	uint32_t seqno,			/* IN */
	uint32_t enable)
{
	if (enable)
		return avc_control(AVC_CALLBACK_AUDITDENY_ENABLE,
		    ssid, tsid, tclass, perms, seqno, 0);
	else
		return avc_control(AVC_CALLBACK_AUDITDENY_DISABLE,
		    ssid, tsid, tclass, perms, seqno, 0);
}

/*
 * Compute an entire access vector.
 */
int
avc_compute_av(security_id_t ssid, security_id_t tsid, security_class_t tclass,
    access_vector_t requested, struct av_decision *avd)
{
	int			rc;

	if (!fmac_enabled)
		return (0);

	rc = avc_lookup(ssid, tsid, tclass, requested, avd);
	if (rc) {
		rc = security_compute_av(ssid, tsid, tclass, requested, avd);
		if (rc)
			return (rc);
		rc = avc_insert(ssid, tsid, tclass, avd);
		if (rc)
			return (rc);
	}

	return (0);
}

static int
avc_has_perm_common(security_id_t ssid, security_id_t tsid,
    security_class_t tclass, access_vector_t requested,
    avc_audit_data_t *auditdata, boolean_t strict)
{
	struct av_decision avd;
	access_vector_t	denied;
	int rc;

	ASSERT(requested);

	rc = avc_compute_av(ssid, tsid, tclass, requested, &avd);
	if (rc)
		return (rc);

	denied = requested & ~avd.allowed;

	if (denied) {
		if (denied & avd.auditdeny)
			avc_audit(ssid, tsid, tclass, denied, AVC_AUDITDENY,
			    auditdata);
		if (strict || fmac_enforcing) {
			return (EACCES);
		} else {
			(void) avc_update_cache(AVC_CALLBACK_GRANT, ssid, tsid,
			    tclass, requested);
			return (0);
		}
	}

	if (requested & avd.auditallow)
		avc_audit(ssid, tsid, tclass, requested, AVC_AUDITALLOW,
		    auditdata);

	return (0);
}

int
avc_has_perm(security_id_t ssid, security_id_t tsid, security_class_t tclass,
    access_vector_t requested, avc_audit_data_t *auditdata)
{
	return avc_has_perm_common(ssid, tsid, tclass, requested, auditdata,
	    B_FALSE);
}

int
avc_has_perm_strict(security_id_t ssid, security_id_t tsid,
    security_class_t tclass, access_vector_t requested,
    avc_audit_data_t *auditdata)
{
	return avc_has_perm_common(ssid, tsid, tclass, requested, auditdata,
	    B_TRUE);
}
