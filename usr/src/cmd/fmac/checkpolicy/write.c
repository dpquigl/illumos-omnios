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

#include "ss_impl.h"
#include <ebitmap.h>
#include <avtab.h>
#include <mls.h>
#include <policydb.h>

int
ebitmap_write(ebitmap_t *e, FILE *fp)
{
	ebitmap_node_t *n;
	uint32_t buf[32], bit, count;
	uint64_t map;
	size_t items;

	buf[0] = SS_CPU_TO_LE32(MAPSIZE);
	buf[1] = SS_CPU_TO_LE32(e->highbit);

	count = 0;
	for (n = e->node; n; n = n->next)
		count++;
	buf[2] = SS_CPU_TO_LE32(count);

	items = fwrite(buf, sizeof (uint32_t), 3, fp);
	if (items != 3)
		return (FALSE);

	for (n = e->node; n; n = n->next) {
		bit = SS_CPU_TO_LE32(n->startbit);
		items = fwrite(&bit, sizeof (uint32_t), 1, fp);
		if (items != 1)
			return (FALSE);
		map = SS_CPU_TO_LE64(n->map);
		items = fwrite(&map, sizeof (uint64_t), 1, fp);
		if (items != 1)
			return (FALSE);

	}

	return (TRUE);
}

int
avtab_write(avtab_t *a, FILE *fp)
{
	int i;
	avtab_ptr_t cur;
	uint32_t buf[32];
	uint32_t nel;
	size_t items, items2;

	nel = SS_CPU_TO_LE32(a->nel);
	items = fwrite(&nel, sizeof (uint32_t), 1, fp);
	if (items != 1)
		return (-1);

	for (i = 0; i < AVTAB_SIZE; i++) {
		for (cur = a->htable[i]; cur; cur = cur->next) {
			items = 1;	/* item 0 is used for the item count */
			buf[items++] = SS_CPU_TO_LE32(cur->key.source_type);
			buf[items++] = SS_CPU_TO_LE32(cur->key.target_type);
			buf[items++] = SS_CPU_TO_LE32(cur->key.target_class);
			buf[items++] = SS_CPU_TO_LE32(cur->datum.specified);
			if (!(cur->datum.specified & (AVTAB_AV | AVTAB_TYPE))) {
				printf("security: avtab: null entry\n");
				return (-1);
			}
			if ((cur->datum.specified & AVTAB_AV) &&
			    (cur->datum.specified & AVTAB_TYPE)) {
				printf("security: avtab: entry has both "
					"access vectors and types\n");
				return (-1);
			}
			if (cur->datum.specified & AVTAB_AV) {
				if (cur->datum.specified & AVTAB_ALLOWED)
					buf[items++] = SS_CPU_TO_LE32(
						avtab_allowed(&cur->datum));
				if (cur->datum.specified & AVTAB_AUDITDENY)
					buf[items++] = SS_CPU_TO_LE32(
						avtab_auditdeny(&cur->datum));
				if (cur->datum.specified & AVTAB_AUDITALLOW)
					buf[items++] = SS_CPU_TO_LE32(
						avtab_auditallow(&cur->datum));
			} else {
				if (cur->datum.specified & AVTAB_TRANSITION)
					buf[items++] = SS_CPU_TO_LE32(
						avtab_transition(&cur->datum));
				if (cur->datum.specified & AVTAB_CHANGE)
					buf[items++] = SS_CPU_TO_LE32(
						avtab_change(&cur->datum));
				if (cur->datum.specified & AVTAB_MEMBER)
					buf[items++] = SS_CPU_TO_LE32(
						avtab_member(&cur->datum));
			}
			buf[0] = SS_CPU_TO_LE32(items - 1);

			items2 = fwrite(buf, sizeof (uint32_t), items, fp);
			if (items != items2)
				return (-1);
		}
	}

	return (0);
}

#ifdef CONFIG_FLASK_MLS
/*
 * Write a MLS level structure to a policydb binary
 * representation file.
 */
int
mls_write_level(mls_level_t *l, FILE *fp)
{
	uint32_t sens;
	int items;

	sens = SS_CPU_TO_LE32(l->sens);
	items = fwrite(&sens, sizeof (uint32_t), 1, fp);
	if (items != 1)
		return (-1);

	if (!ebitmap_write(&l->cat, fp))
		return (-1);

	return (0);
}


/*
 * Write a MLS range structure to a policydb binary
 * representation file.
 */
static int
mls_write_range_helper(mls_range_t *r, FILE *fp)
{
	uint32_t buf[3];
	int items, items2;
	int rel;

	rel = mls_level_relation(r->level[1], r->level[0]);

	items = 1;		/* item 0 is used for the item count */
	buf[items++] = SS_CPU_TO_LE32(r->level[0].sens);
	if (rel != MLS_RELATION_EQ)
		buf[items++] = SS_CPU_TO_LE32(r->level[1].sens);
	buf[0] = SS_CPU_TO_LE32(items - 1);

	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items2 != items)
		return (-1);

	if (!ebitmap_write(&r->level[0].cat, fp))
		return (-1);
	if (rel != MLS_RELATION_EQ)
		if (!ebitmap_write(&r->level[1].cat, fp))
			return (-1);

	return (0);
}

int
mls_write_range(context_struct_t *c, FILE *fp)
{
	return (mls_write_range_helper(&c->range, fp));
}


/*
 * Write a MLS perms structure to a policydb binary
 * representation file.
 */
int
mls_write_class(class_datum_t *cladatum, FILE *fp)
{
	mls_perms_t *p = &cladatum->mlsperms;
	uint32_t buf[32];
	int items, items2;

	items = 0;
	buf[items++] = SS_CPU_TO_LE32(p->read);
	buf[items++] = SS_CPU_TO_LE32(p->readby);
	buf[items++] = SS_CPU_TO_LE32(p->write);
	buf[items++] = SS_CPU_TO_LE32(p->writeby);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items2 != items)
		return (-1);

	return (0);
}

#define	mls_write_perm(buf, items, perdatum) \
	buf[items++] = SS_CPU_TO_LE32(perdatum->base_perms);

int
mls_write_user(user_datum_t *usrdatum, FILE *fp)
{
	mls_range_list_t *r;
	uint32_t nel;
	uint32_t buf[32];
	int items;

	nel = 0;
	for (r = usrdatum->ranges; r; r = r->next)
		nel++;
	buf[0] = SS_CPU_TO_LE32(nel);
	items = fwrite(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		return (-1);
	for (r = usrdatum->ranges; r; r = r->next) {
		if (mls_write_range_helper(&r->range, fp))
			return (-1);
	}
	return (0);
}

int
mls_write_nlevels(policydb_t *p, FILE *fp)
{
	uint32_t buf[32];
	size_t items;

	buf[0] = SS_CPU_TO_LE32(p->nlevels);
	items = fwrite(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		return (-1);
	return (0);
}

int
mls_write_trusted(policydb_t *p, FILE *fp)
{
	if (!ebitmap_write(&p->trustedreaders, fp))
		return (-1);
	if (!ebitmap_write(&p->trustedwriters, fp))
		return (-1);
	if (!ebitmap_write(&p->trustedobjects, fp))
		return (-1);
	return (0);
}

int
sens_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	level_datum_t *levdatum;
	uint32_t buf[32], len;
	int items, items2;
	FILE *fp = p;

	levdatum = (level_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = SS_CPU_TO_LE32(len);
	buf[items++] = SS_CPU_TO_LE32(levdatum->isalias);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		return (-1);

	items = fwrite(key, 1, len, fp);
	if (items != len)
		return (-1);

	if (mls_write_level(levdatum->level, fp))
		return (-1);

	return (0);
}

int
cat_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	cat_datum_t *catdatum;
	uint32_t buf[32], len;
	int items, items2;
	FILE *fp = p;


	catdatum = (cat_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = SS_CPU_TO_LE32(len);
	buf[items++] = SS_CPU_TO_LE32(catdatum->value);
	buf[items++] = SS_CPU_TO_LE32(catdatum->isalias);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		return (-1);

	items = fwrite(key, 1, len, fp);
	if (items != len)
		return (-1);

	return (0);
}
#else
#define	mls_write_range(c, fp) 0
#define	mls_write_class(c, fp) 0
#define	mls_write_perm(buf, items, perdatum)
#define	mls_write_user(u, fp) 0
#define	mls_write_nlevels(p, fp) 0
#define	mls_write_trusted(p, fp) 0
#endif

/*
 * Write a security context structure
 * to a policydb binary representation file.
 */
static int
context_write(context_struct_t *c, FILE *fp)
{
	uint32_t buf[32];
	size_t items, items2;

	items = 0;
	buf[items++] = SS_CPU_TO_LE32(c->user);
	buf[items++] = SS_CPU_TO_LE32(c->role);
	buf[items++] = SS_CPU_TO_LE32(c->type);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items2 != items)
		return (-1);
	if (mls_write_range(c, fp))
		return (-1);

	return (0);
}


/*
 * The following *_write functions are used to
 * write the symbol data to a policy database
 * binary representation file.
 */

static int
perm_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	perm_datum_t *perdatum;
	uint32_t buf[32], len;
	int items, items2;
	FILE *fp = p;

	perdatum = (perm_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = SS_CPU_TO_LE32(len);
	buf[items++] = SS_CPU_TO_LE32(perdatum->value);
	mls_write_perm(buf, items, perdatum);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		return (-1);

	items = fwrite(key, 1, len, fp);
	if (items != len)
		return (-1);

	return (0);
}


static int
common_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	common_datum_t *comdatum;
	uint32_t buf[32], len;
	int items, items2;
	FILE *fp = p;

	comdatum = (common_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = SS_CPU_TO_LE32(len);
	buf[items++] = SS_CPU_TO_LE32(comdatum->value);
	buf[items++] = SS_CPU_TO_LE32(comdatum->permissions.nprim);
	buf[items++] = SS_CPU_TO_LE32(comdatum->permissions.table->nel);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		return (-1);

	items = fwrite(key, 1, len, fp);
	if (items != len)
		return (-1);

	if (hashtab_map(comdatum->permissions.table, perm_write, fp))
		return (-1);

	return (0);
}


static int
class_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	class_datum_t *cladatum;
	constraint_node_t *c;
	constraint_expr_t *e;
	uint32_t buf[32], len, len2, ncons, nexpr;
	int items, items2;
	FILE *fp = p;

	cladatum = (class_datum_t *) datum;

	len = strlen(key);
	if (cladatum->comkey)
		len2 = strlen(cladatum->comkey);
	else
		len2 = 0;

	ncons = 0;
	for (c = cladatum->constraints; c; c = c->next) {
		ncons++;
	}

	items = 0;
	buf[items++] = SS_CPU_TO_LE32(len);
	buf[items++] = SS_CPU_TO_LE32(len2);
	buf[items++] = SS_CPU_TO_LE32(cladatum->value);
	buf[items++] = SS_CPU_TO_LE32(cladatum->permissions.nprim);
	if (cladatum->permissions.table)
		buf[items++] = SS_CPU_TO_LE32(
			cladatum->permissions.table->nel);
	else
		buf[items++] = 0;
	buf[items++] = SS_CPU_TO_LE32(ncons);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		return (-1);

	items = fwrite(key, 1, len, fp);
	if (items != len)
		return (-1);

	if (cladatum->comkey) {
		items = fwrite(cladatum->comkey, 1, len2, fp);
		if (items != len2)
			return (-1);
	}
	if (hashtab_map(cladatum->permissions.table, perm_write, fp))
		return (-1);

	for (c = cladatum->constraints; c; c = c->next) {
		nexpr = 0;
		for (e = c->expr; e; e = e->next) {
			nexpr++;
		}
		buf[0] = SS_CPU_TO_LE32(c->permissions);
		buf[1] = SS_CPU_TO_LE32(nexpr);
		items = fwrite(buf, sizeof (uint32_t), 2, fp);
		if (items != 2)
			return (-1);
		for (e = c->expr; e; e = e->next) {
			items = 0;
			buf[items++] = SS_CPU_TO_LE32(e->expr_type);
			buf[items++] = SS_CPU_TO_LE32(e->attr);
			buf[items++] = SS_CPU_TO_LE32(e->op);
			items2 = fwrite(buf, sizeof (uint32_t), items, fp);
			if (items != items2)
				return (-1);

			switch (e->expr_type) {
			case CEXPR_NAMES:
				if (!ebitmap_write(&e->names, fp))
					return (-1);
				break;
			default:
				break;
			}
		}
	}

	if (mls_write_class(cladatum, fp))
		return (-1);

	return (0);
}

static int
role_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	role_datum_t *role;
	uint32_t buf[32], len;
	int items, items2;
	FILE *fp = p;

	role = (role_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = SS_CPU_TO_LE32(len);
	buf[items++] = SS_CPU_TO_LE32(role->value);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		return (-1);

	items = fwrite(key, 1, len, fp);
	if (items != len)
		return (-1);

	if (!ebitmap_write(&role->dominates, fp))
		return (-1);

	if (!ebitmap_write(&role->types, fp))
		return (-1);

	return (0);
}

static int
type_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	type_datum_t *typdatum;
	uint32_t buf[32], len;
	int items, items2;
	FILE *fp = p;

	typdatum = (type_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = SS_CPU_TO_LE32(len);
	buf[items++] = SS_CPU_TO_LE32(typdatum->value);
	buf[items++] = SS_CPU_TO_LE32(typdatum->primary);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		return (-1);

	items = fwrite(key, 1, len, fp);
	if (items != len)
		return (-1);

	return (0);
}

static int
user_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	user_datum_t *usrdatum;
	uint32_t buf[32], len;
	int items, items2;
	FILE *fp = p;


	usrdatum = (user_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = SS_CPU_TO_LE32(len);
	buf[items++] = SS_CPU_TO_LE32(usrdatum->value);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		return (-1);

	items = fwrite(key, 1, len, fp);
	if (items != len)
		return (-1);

	if (!ebitmap_write(&usrdatum->roles, fp))
		return (-1);

	return (mls_write_user(usrdatum, fp));
}


static int (*write_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum,
    void *datap) =
{
	common_write,
	class_write,
	role_write,
	type_write,
	user_write
	mls_write_f
};


/*
 * Write the configuration data in a policy database
 * structure to a policy database binary representation
 * file.
 */
int
policydb_write(policydb_t *p, FILE *fp)
{
	struct role_allow *ra;
	struct role_trans *tr;
	ocontext_t *c;
	genfs_t *genfs;
	int i, j;
	uint32_t buf[32], len, config, nel;
	size_t items, items2;
	char *policydb_str = POLICYDB_STRING;

	config = 0;
	mls_set_config(config);

	/* Write the magic number and string identifiers. */
	items = 0;
	buf[items++] = SS_CPU_TO_LE32(POLICYDB_MAGIC);
	len = strlen(POLICYDB_STRING);
	buf[items++] = SS_CPU_TO_LE32(len);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		return (-1);
	items = fwrite(policydb_str, 1, len, fp);
	if (items != len)
		return (-1);

	/* Write the version, config, and table sizes. */
	items = 0;
	buf[items++] = SS_CPU_TO_LE32(POLICYDB_VERSION);
	buf[items++] = SS_CPU_TO_LE32(config);
	buf[items++] = SS_CPU_TO_LE32(SYM_NUM);
	buf[items++] = SS_CPU_TO_LE32(OCON_NUM);
	items2 = fwrite(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		return (-1);

	if (mls_write_nlevels(p, fp))
		return (-1);

	for (i = 0; i < SYM_NUM; i++) {
		buf[0] = SS_CPU_TO_LE32(p->symtab[i].nprim);
		buf[1] = SS_CPU_TO_LE32(p->symtab[i].table->nel);
		items = fwrite(buf, sizeof (uint32_t), 2, fp);
		if (items != 2)
			return (-1);
		if (hashtab_map(p->symtab[i].table, write_f[i], fp))
			return (-1);
	}

	if (avtab_write(&p->te_avtab, fp))
		return (-1);

	nel = 0;
	for (tr = p->role_tr; tr; tr = tr->next)
		nel++;
	buf[0] = SS_CPU_TO_LE32(nel);
	items = fwrite(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		return (-1);
	for (tr = p->role_tr; tr; tr = tr->next) {
		buf[0] = SS_CPU_TO_LE32(tr->role);
		buf[1] = SS_CPU_TO_LE32(tr->type);
		buf[2] = SS_CPU_TO_LE32(tr->new_role);
		items = fwrite(buf, sizeof (uint32_t), 3, fp);
		if (items != 3)
			return (-1);
	}

	nel = 0;
	for (ra = p->role_allow; ra; ra = ra->next)
		nel++;
	buf[0] = SS_CPU_TO_LE32(nel);
	items = fwrite(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		return (-1);
	for (ra = p->role_allow; ra; ra = ra->next) {
		buf[0] = SS_CPU_TO_LE32(ra->role);
		buf[1] = SS_CPU_TO_LE32(ra->new_role);
		items = fwrite(buf, sizeof (uint32_t), 2, fp);
		if (items != 2)
			return (-1);
	}

	for (i = 0; i < OCON_NUM; i++) {
		nel = 0;
		for (c = p->ocontexts[i]; c; c = c->next)
			nel++;
		buf[0] = SS_CPU_TO_LE32(nel);
		items = fwrite(buf, sizeof (uint32_t), 1, fp);
		if (items != 1)
			return (-1);
		for (c = p->ocontexts[i]; c; c = c->next) {
			switch (i) {
			case OCON_ISID:
				buf[0] = SS_CPU_TO_LE32(c->sid[0]);
				items = fwrite(buf, sizeof (uint32_t), 1, fp);
				if (items != 1)
					return (-1);
				if (context_write(&c->context[0], fp))
					return (-1);
				break;
			case OCON_FS:
			case OCON_NETIF:
				len = strlen(c->u.name);
				buf[0] = SS_CPU_TO_LE32(len);
				items = fwrite(buf, sizeof (uint32_t), 1, fp);
				if (items != 1)
					return (-1);
				items = fwrite(c->u.name, 1, len, fp);
				if (items != len)
					return (-1);
				if (context_write(&c->context[0], fp))
					return (-1);
				if (context_write(&c->context[1], fp))
					return (-1);
				break;
			case OCON_PORT:
				buf[0] = c->u.port.protocol;
				buf[1] = c->u.port.low_port;
				buf[2] = c->u.port.high_port;
				for (j = 0; j < 3; j++) {
					buf[j] = SS_CPU_TO_LE32(buf[j]);
				}
				items = fwrite(buf, sizeof (uint32_t), 3, fp);
				if (items != 3)
					return (-1);
				if (context_write(&c->context[0], fp))
					return (-1);
				break;
			case OCON_NODE:
				/* store in network order */
				buf[0] = c->u.node.addr;
				buf[1] = c->u.node.mask;
				items = fwrite(buf, sizeof (uint32_t), 2, fp);
				if (items != 2)
					return (-1);
				if (context_write(&c->context[0], fp))
					return (-1);
				break;
			case OCON_FSUSE:
				buf[0] = SS_CPU_TO_LE32(c->v.behavior);
				len = strlen(c->u.name);
				buf[1] = SS_CPU_TO_LE32(len);
				items = fwrite(buf, sizeof (uint32_t), 2, fp);
				if (items != 2)
					return (-1);
				items = fwrite(c->u.name, 1, len, fp);
				if (items != len)
					return (-1);
				if (context_write(&c->context[0], fp))
					return (-1);
				break;
			}
		}
	}

	nel = 0;
	for (genfs = p->genfs; genfs; genfs = genfs->next)
		nel++;
	buf[0] = SS_CPU_TO_LE32(nel);
	items = fwrite(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		return (-1);
	for (genfs = p->genfs; genfs; genfs = genfs->next) {
		len = strlen(genfs->fstype);
		buf[0] = SS_CPU_TO_LE32(len);
		items = fwrite(buf, sizeof (uint32_t), 1, fp);
		if (items != 1)
			return (-1);
		items = fwrite(genfs->fstype, 1, len, fp);
		if (items != len)
			return (-1);
		nel = 0;
		for (c = genfs->head; c; c = c->next)
			nel++;
		buf[0] = SS_CPU_TO_LE32(nel);
		items = fwrite(buf, sizeof (uint32_t), 1, fp);
		if (items != 1)
			return (-1);
		for (c = genfs->head; c; c = c->next) {
			len = strlen(c->u.name);
			buf[0] = SS_CPU_TO_LE32(len);
			items = fwrite(buf, sizeof (uint32_t), 1, fp);
			if (items != 1)
				return (-1);
			items = fwrite(c->u.name, 1, len, fp);
			if (items != len)
				return (-1);
			buf[0] = SS_CPU_TO_LE32(c->v.sclass);
			items = fwrite(buf, sizeof (uint32_t), 1, fp);
			if (items != 1)
				return (-1);
			if (context_write(&c->context[0], fp))
				return (-1);
		}
	}

	if (mls_write_trusted(p, fp))
		return (-1);

	return (0);
}
