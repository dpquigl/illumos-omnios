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

/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/*
 * Implementation of the policy database.
 */

#include <sys/types.h>
#include <sys/note.h>

#if defined(_KERNEL)
#include <sys/inttypes.h>
#include <sys/systm.h>
#else
#include <inttypes.h>
#include <stdio.h>
#endif /* defined(_KERNEL) */

#include "ss_impl.h"
#include "policydb.h"
#include "mls.h"

#if 0
static char *symtab_name[SYM_NUM] = {
	"common prefixes",
	"classes",
	"roles",
	"types",
	"users"
	mls_symtab_names
};
#endif

static unsigned int symtab_sizes[SYM_NUM] = {
	2,
	32,
	16,
	512,
	128
	mls_symtab_sizes
};

/*
 * Initialize the role table.
 */
int
roles_init(policydb_t *p)
{
	char *key = 0;
	role_datum_t *role;

	role = SS_ALLOC_SLEEP(sizeof (role_datum_t));
	if (!role)
		return (-1);
	(void) memset(role, 0, sizeof (role_datum_t));
	role->value = ++p->p_roles.nprim;
	if (role->value != OBJECT_R_VAL)
		return (-1);
	key = SS_ALLOC_SLEEP(strlen(OBJECT_R)+1);
	if (!key)
		return (-1);
	(void) strcpy(key, OBJECT_R);

	if (hashtab_insert(p->p_roles.table, key, role))
		return (-1);

	return (0);
}

/*
 * Initialize a policy database structure.
 */
int
policydb_init(policydb_t *p)
{
	int i;

	(void) memset(p, 0, sizeof (policydb_t));

	for (i = 0; i < SYM_NUM; i++) {
		if (symtab_init(&p->symtab[i], symtab_sizes[i]))
			return (-1);
	}

	if (avtab_init(&p->te_avtab))
		return (-1);

	if (roles_init(p))
		return (-1);

	return (0);
}

/*
 * The following *_index functions are used to
 * define the val_to_name and val_to_struct arrays
 * in a policy database structure.  The val_to_name
 * arrays are used when converting security context
 * structures into string representations.  The
 * val_to_struct arrays are used when the attributes
 * of a class, role, or user are needed.
 */
static int
common_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	common_datum_t *comdatum;


	comdatum = (common_datum_t *) datum;
	p = (policydb_t *) datap;

	p->p_common_val_to_name[comdatum->value - 1] = (char *) key;

	return (0);
}

static int
class_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	class_datum_t *cladatum;


	cladatum = (class_datum_t *) datum;
	p = (policydb_t *) datap;

	p->p_class_val_to_name[cladatum->value - 1] = (char *) key;
	p->class_val_to_struct[cladatum->value - 1] = cladatum;

	return (0);
}

static int
role_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	role_datum_t *role;


	role = (role_datum_t *) datum;
	p = (policydb_t *) datap;

	p->p_role_val_to_name[role->value - 1] = (char *) key;
	p->role_val_to_struct[role->value - 1] = role;

	return (0);
}

static int
type_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	type_datum_t *typdatum;


	typdatum = (type_datum_t *) datum;
	p = (policydb_t *) datap;

	if (typdatum->primary)
		p->p_type_val_to_name[typdatum->value - 1] = (char *) key;

	return (0);
}

static int
user_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	user_datum_t *usrdatum;


	usrdatum = (user_datum_t *) datum;
	p = (policydb_t *) datap;

	p->p_user_val_to_name[usrdatum->value - 1] = (char *) key;
	p->user_val_to_struct[usrdatum->value - 1] = usrdatum;

	return (0);
}

static int
(*index_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum, void *datap) =
{
	common_index,
	class_index,
	role_index,
	type_index,
	user_index
	mls_index_f
};

/*
 * Define the common val_to_name array and the class
 * val_to_name and val_to_struct arrays in a policy
 * database structure.
 */
int
policydb_index_classes(policydb_t *p)
{
	p->p_common_val_to_name = (char **)
	    SS_ALLOC_SLEEP(p->p_commons.nprim * sizeof (char *));
	if (!p->p_common_val_to_name)
		return (-1);

	if (hashtab_map(p->p_commons.table, common_index, p))
		return (-1);

	p->class_val_to_struct = (class_datum_t **)
	    SS_ALLOC_SLEEP(p->p_classes.nprim * sizeof (class_datum_t *));
	if (!p->class_val_to_struct)
		return (-1);

	p->p_class_val_to_name = (char **)
	    SS_ALLOC_SLEEP(p->p_classes.nprim * sizeof (char *));
	if (!p->p_class_val_to_name)
		return (-1);

	if (hashtab_map(p->p_classes.table, class_index, p))
		return (-1);
	return (0);
}

/*
 * Define the other val_to_name and val_to_struct arrays
 * in a policy database structure.
 */
int
policydb_index_others(policydb_t *p)
{
	int i;


	(void) printf("security:  %d users, %d roles, %d types",
	    p->p_users.nprim, p->p_roles.nprim, p->p_types.nprim);
	mls_policydb_index_others(p);
	(void) printf("\n");

	(void) printf("security:  %d classes, %d rules\n",
	    p->p_classes.nprim, p->te_avtab.nel);

#if 0
	avtab_hash_eval(&p->te_avtab, "rules");
	for (i = 0; i < SYM_NUM; i++)
		hashtab_hash_eval(p->symtab[i].table, symtab_name[i]);
#endif

	p->role_val_to_struct = (role_datum_t **)
	    SS_ALLOC_SLEEP(p->p_roles.nprim * sizeof (role_datum_t *));
	if (!p->role_val_to_struct)
		return (-1);

	p->user_val_to_struct = (user_datum_t **)
	    SS_ALLOC_SLEEP(p->p_users.nprim * sizeof (user_datum_t *));
	if (!p->user_val_to_struct)
		return (-1);

	for (i = SYM_ROLES; i < SYM_NUM; i++) {
		p->sym_val_to_name[i] = (char **)
		    SS_ALLOC_SLEEP(p->symtab[i].nprim * sizeof (char *));
		if (!p->sym_val_to_name[i])
			return (-1);
		if (hashtab_map(p->symtab[i].table, index_f[i], p))
			return (-1);
	}

	return (0);
}

/*
 * The following *_destroy functions are used to
 * free any memory allocated for each kind of
 * symbol data in the policy database.
 */
static int
perm_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	_NOTE(ARGUNUSED(p));

	if (key)
		SS_FREE(key, strlen(key) + 1);
	SS_FREE(datum, sizeof (perm_datum_t));
	return (0);
}

static int
common_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	common_datum_t *comdatum;

	_NOTE(ARGUNUSED(p));

	if (key)
		SS_FREE(key, strlen(key) + 1);
	comdatum = (common_datum_t *) datum;
	(void) hashtab_map(comdatum->permissions.table, perm_destroy, 0);
	hashtab_destroy(comdatum->permissions.table);
	SS_FREE(datum, sizeof (common_datum_t));
	return (0);
}

static int
class_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	class_datum_t *cladatum;
	constraint_node_t *constraint, *ctemp;
	constraint_expr_t *e, *etmp;

	_NOTE(ARGUNUSED(p));

	if (key)
		SS_FREE(key, strlen(key) + 1);
	cladatum = (class_datum_t *) datum;
	(void) hashtab_map(cladatum->permissions.table, perm_destroy, 0);
	hashtab_destroy(cladatum->permissions.table);
	constraint = cladatum->constraints;
	while (constraint) {
		e = constraint->expr;
		while (e) {
			ebitmap_destroy(&e->names);
			etmp = e;
			e = e->next;
			SS_FREE(etmp, sizeof (constraint_expr_t));
		}
		ctemp = constraint;
		constraint = constraint->next;
		SS_FREE(ctemp, sizeof (constraint_node_t));
	}
	if (cladatum->comkey)
		SS_FREE(cladatum->comkey, strlen(cladatum->comkey) + 1);
	SS_FREE(datum, sizeof (class_datum_t));
	return (0);
}

static int
role_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	role_datum_t *role;

	_NOTE(ARGUNUSED(p));

	if (key)
		SS_FREE(key, strlen(key) + 1);
	role = (role_datum_t *) datum;
	ebitmap_destroy(&role->dominates);
	ebitmap_destroy(&role->types);
	SS_FREE(datum, sizeof (role_datum_t));
	return (0);
}

static int
type_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	_NOTE(ARGUNUSED(p));

	if (key)
		SS_FREE(key, strlen(key) + 1);
	SS_FREE(datum, sizeof (type_datum_t));
	return (0);
}

static int
user_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	user_datum_t *usrdatum;

	_NOTE(ARGUNUSED(p));

	if (key)
		SS_FREE(key, strlen(key) + 1);
	usrdatum = (user_datum_t *) datum;
	ebitmap_destroy(&usrdatum->roles);
	mls_user_destroy(usrdatum);
	SS_FREE(datum, sizeof (user_datum_t));
	return (0);
}

static int (*destroy_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum,
    void *datap) =
{
	common_destroy,
	class_destroy,
	role_destroy,
	type_destroy,
	user_destroy
	mls_destroy_f
};

/*
 * Free any memory allocated by a policy database structure.
 */
void
policydb_destroy(policydb_t *p)
{
	ocontext_t *c, *ctmp;
	genfs_t *g, *gtmp;
	int i;

	for (i = 0; i < SYM_NUM; i++) {
		(void) hashtab_map(p->symtab[i].table, destroy_f[i], 0);
		hashtab_destroy(p->symtab[i].table);
	}

	for (i = 0; i < SYM_NUM; i++) {
		if (p->sym_val_to_name[i])
			SS_FREE(p->sym_val_to_name[i],
				p->symtab[i].nprim * sizeof (char *));
	}

	if (p->class_val_to_struct)
		SS_FREE(p->class_val_to_struct,
			p->p_classes.nprim * sizeof (class_datum_t *));
	if (p->role_val_to_struct)
		SS_FREE(p->role_val_to_struct,
			p->p_roles.nprim * sizeof (role_datum_t *));
	if (p->user_val_to_struct)
		SS_FREE(p->user_val_to_struct,
			p->p_users.nprim * sizeof (user_datum_t *));

	avtab_destroy(&p->te_avtab);

	for (i = 0; i < OCON_NUM; i++) {
		c = p->ocontexts[i];
		while (c) {
			ctmp = c;
			c = c->next;
			context_destroy(&ctmp->context[0]);
			context_destroy(&ctmp->context[1]);
			if ((i == OCON_ISID || i == OCON_FS ||
			    i == OCON_NETIF || i == OCON_FSUSE) &&
			    ctmp->u.name)
				SS_FREE(ctmp->u.name, strlen(ctmp->u.name) + 1);
			SS_FREE(ctmp, sizeof (ocontext_t));
		}
	}

	g = p->genfs;
	while (g) {
		SS_FREE(g->fstype, strlen(g->fstype) + 1);
		c = g->head;
		while (c) {
			ctmp = c;
			c = c->next;
			context_destroy(&ctmp->context[0]);
			SS_FREE(ctmp->u.name, strlen(ctmp->u.name) + 1);
			SS_FREE(ctmp, sizeof (ocontext_t));
		}
		gtmp = g;
		g = g->next;
		SS_FREE(gtmp, sizeof (genfs_t));
	}
}


/*
 * Load the initial SIDs specified in a policy database
 * structure into a SID table.
 */
int
policydb_load_isids(policydb_t *p, sidtab_t *s)
{
	ocontext_t *head, *c;

	if (sidtab_init(s)) {
		(void) printf("security:  out of memory on SID table init\n");
		return (-1);
	}

	head = p->ocontexts[OCON_ISID];
	for (c = head; c; c = c->next) {
		if (!c->context[0].user) {
			(void) printf("security:  SID %s was never defined.\n",
			    c->u.name);
			return (-1);
		}
		if (sidtab_insert(s, c->sid[0], &c->context[0])) {
			(void) printf("security:  unable to load initial "
			    "SID %s.\n",
			    c->u.name);
			return (-1);
		}
	}

	return (0);
}

/*
 * Return TRUE if the fields in the security context
 * structure `c' are valid.  Return FALSE otherwise.
 */
int
policydb_context_isvalid(policydb_t *p, context_struct_t *c)
{
	role_datum_t *role;
	user_datum_t *usrdatum;


	/*
	 * Role must be authorized for the type.
	 */
	if (!c->role || c->role > p->p_roles.nprim)
		return (FALSE);

	if (c->role != OBJECT_R_VAL) {
		role = p->role_val_to_struct[c->role - 1];
		if (!ebitmap_get_bit(&role->types,
		    c->type - 1))
			/* role may not be associated with type */
			return (FALSE);

		/*
		 * User must be authorized for the role.
		 */
		if (!c->user || c->user > p->p_users.nprim)
			return (FALSE);
		usrdatum = p->user_val_to_struct[c->user - 1];
		if (!usrdatum)
			return (FALSE);

		if (!ebitmap_get_bit(&usrdatum->roles, c->role - 1))
			/* user may not be associated with role */
			return (FALSE);
	}

	if (mls_context_isvalid(p, c) != TRUE)
		return (FALSE);

	return (TRUE);
}

/*
 * Read and validate a security context structure
 * from a policydb binary representation file.
 */
static int
context_read_and_validate(context_struct_t *c, policydb_t *p, void *fp)
{
	uint32_t buf[3];
	size_t items;

	items = next_entry(buf, sizeof (uint32_t), 3, fp);
	if (items != 3) {
		(void) printf("security: context truncated\n");
		return (-1);
	}
	c->user = SS_LE32_TO_CPU(buf[0]);
	c->role = SS_LE32_TO_CPU(buf[1]);
	c->type = SS_LE32_TO_CPU(buf[2]);
	if (mls_read_range(c, fp)) {
		(void) printf("security: error reading MLS range of context\n");
		return (-1);
	}

	if (!policydb_context_isvalid(p, c)) {
		(void) printf("security:  invalid security context\n");
		context_destroy(c);
		return (-1);
	}
	return (0);
}

/*
 * The following *_read functions are used to
 * read the symbol data from a policy database
 * binary representation file.
 */
static int
perm_read(policydb_t *p, hashtab_t h, void *fp)
{
	char		*key = 0;
	perm_datum_t	*perdatum;
	uint32_t	buf[2], len;
	int		items, items2;

	_NOTE(ARGUNUSED(p));

	perdatum = SS_ALLOC_SLEEP(sizeof (perm_datum_t));
	if (!perdatum)
		return (-1);
	(void) memset(perdatum, 0, sizeof (perm_datum_t));

	items = 2;
	items2 = next_entry(buf, sizeof (uint32_t), items, fp);
	if (items != items2)
		goto bad;

	len = SS_LE32_TO_CPU(buf[0]);
	perdatum->value = SS_LE32_TO_CPU(buf[1]);
	if (mls_read_perm(perdatum, fp))
		goto bad;

	key = SS_ALLOC_SLEEP(len + 1);
	if (!key)
		goto bad;
	items = next_entry(key, 1, len, fp);
	if (items != len)
		goto bad;
	key[len] = 0;

	if (hashtab_insert(h, key, perdatum))
		goto bad;

	return (0);

bad:
	(void) perm_destroy(key, perdatum, NULL);
	return (-1);
}

static int
common_read(policydb_t *p, hashtab_t h, void *fp)
{
	char *key = 0;
	common_datum_t *comdatum;
	uint32_t buf[4], len, nel;
	int items, i;

	comdatum = SS_ALLOC_SLEEP(sizeof (common_datum_t));
	if (!comdatum)
		return (-1);
	(void) memset(comdatum, 0, sizeof (common_datum_t));

	items = next_entry(buf, sizeof (uint32_t), 4, fp);
	if (items != 4)
		goto bad;

	len = SS_LE32_TO_CPU(buf[0]);
	comdatum->value = SS_LE32_TO_CPU(buf[1]);

	if (symtab_init(&comdatum->permissions, PERM_SYMTAB_SIZE))
		goto bad;
	comdatum->permissions.nprim = SS_LE32_TO_CPU(buf[2]);
	nel = SS_LE32_TO_CPU(buf[3]);

	key = SS_ALLOC_SLEEP(len + 1);
	if (!key)
		goto bad;
	items = next_entry(key, 1, len, fp);
	if (items != len)
		goto bad;
	key[len] = 0;

	for (i = 0; i < nel; i++) {
		if (perm_read(p, comdatum->permissions.table, fp))
			goto bad;
	}

	if (hashtab_insert(h, key, comdatum))
		goto bad;

	return (0);

bad:
	(void) common_destroy(key, comdatum, NULL);
	return (-1);
}

static int
class_read(policydb_t *p, hashtab_t h, void *fp)
{
	char *key = 0;
	class_datum_t *cladatum;
	constraint_node_t *c, *lc;
	constraint_expr_t *e, *le;
	uint32_t buf[6], len, len2, ncons, nexpr, nel;
	int items, i, j, depth;

	cladatum = (class_datum_t *) SS_ALLOC_SLEEP(sizeof (class_datum_t));
	if (!cladatum)
		return (-1);
	(void) memset(cladatum, 0, sizeof (class_datum_t));

	items = next_entry(buf, sizeof (uint32_t), 6, fp);
	if (items != 6)
		goto bad;

	len = SS_LE32_TO_CPU(buf[0]);
	len2 = SS_LE32_TO_CPU(buf[1]);
	cladatum->value = SS_LE32_TO_CPU(buf[2]);

	if (symtab_init(&cladatum->permissions, PERM_SYMTAB_SIZE))
		goto bad;
	cladatum->permissions.nprim = SS_LE32_TO_CPU(buf[3]);
	nel = SS_LE32_TO_CPU(buf[4]);

	ncons = SS_LE32_TO_CPU(buf[5]);

	key = SS_ALLOC_SLEEP(len + 1);
	if (!key)
		goto bad;
	items = next_entry(key, 1, len, fp);
	if (items != len)
		goto bad;
	key[len] = 0;

	if (len2) {
		cladatum->comkey = SS_ALLOC_SLEEP(len2 + 1);
		if (!cladatum->comkey)
			goto bad;
		items = next_entry(cladatum->comkey, 1, len2, fp);
		if (items != len2)
			goto bad;
		cladatum->comkey[len2] = 0;

		cladatum->comdatum = hashtab_search(p->p_commons.table,
						    cladatum->comkey);
		if (!cladatum->comdatum) {
			(void) printf("security:  unknown common %s\n",
			    cladatum->comkey);
			goto bad;
		}
	}
	for (i = 0; i < nel; i++) {
		if (perm_read(p, cladatum->permissions.table, fp))
			goto bad;
	}

	lc = NULL;
	for (i = 0; i < ncons; i++) {
		c = SS_ALLOC_SLEEP(sizeof (constraint_node_t));
		if (!c)
			goto bad;
		(void) memset(c, 0, sizeof (constraint_node_t));
		items = next_entry(buf, sizeof (uint32_t), 2, fp);
		if (items != 2)
			goto bad;
		c->permissions = SS_LE32_TO_CPU(buf[0]);
		nexpr = SS_LE32_TO_CPU(buf[1]);
		le = NULL;
		depth = -1;
		for (j = 0; j < nexpr; j++) {
			e = SS_ALLOC_SLEEP(sizeof (constraint_expr_t));
			if (!e)
				goto bad;
			(void) memset(e, 0, sizeof (constraint_expr_t));
			items = next_entry(buf, sizeof (uint32_t), 3, fp);
			if (items != 3) {
				SS_FREE(e, sizeof (constraint_expr_t));
				goto bad;
			}
			e->expr_type = SS_LE32_TO_CPU(buf[0]);
			e->attr = SS_LE32_TO_CPU(buf[1]);
			e->op = SS_LE32_TO_CPU(buf[2]);

			switch (e->expr_type) {
			case CEXPR_NOT:
				if (depth < 0) {
					SS_FREE(e,
						sizeof (constraint_expr_t));
					goto bad;
				}
				break;
			case CEXPR_AND:
			case CEXPR_OR:
				if (depth < 1) {
					SS_FREE(e,
						sizeof (constraint_expr_t));
					goto bad;
				}
				depth--;
				break;
			case CEXPR_ATTR:
				if (depth == (CEXPR_MAXDEPTH-1)) {
					SS_FREE(e,
						sizeof (constraint_expr_t));
					goto bad;
				}
				depth++;
				break;
			case CEXPR_NAMES:
				if (depth == (CEXPR_MAXDEPTH-1)) {
					SS_FREE(e,
						sizeof (constraint_expr_t));
					goto bad;
				}
				depth++;
				if (!ebitmap_read(&e->names, fp)) {
					SS_FREE(e,
						sizeof (constraint_expr_t));
					goto bad;
				}
				break;
			default:
				SS_FREE(e, sizeof (constraint_expr_t));
				goto bad;
			}
			if (le) {
				le->next = e;
			} else {
				c->expr = e;
			}
			le = e;
		}
		if (depth != 0)
			goto bad;
		if (lc) {
			lc->next = c;
		} else {
			cladatum->constraints = c;
		}
		lc = c;
	}

	if (mls_read_class(cladatum, fp))
		goto bad;

	if (hashtab_insert(h, key, cladatum))
		goto bad;

	return (0);

bad:
	(void) class_destroy(key, cladatum, NULL);
	return (-1);
}

static int
role_read(policydb_t *p, hashtab_t h, void *fp)
{
	char *key = 0;
	role_datum_t *role;
	uint32_t buf[2], len;
	int items;

	_NOTE(ARGUNUSED(p));

	role = SS_ALLOC_SLEEP(sizeof (role_datum_t));
	if (!role)
		return (-1);
	(void) memset(role, 0, sizeof (role_datum_t));

	items = next_entry(buf, sizeof (uint32_t), 2, fp);
	if (items != 2)
		goto bad;

	len = SS_LE32_TO_CPU(buf[0]);
	role->value = SS_LE32_TO_CPU(buf[1]);

	key = SS_ALLOC_SLEEP(len + 1);
	if (!key)
		goto bad;
	items = next_entry(key, 1, len, fp);
	if (items != len)
		goto bad;
	key[len] = 0;

	if (!ebitmap_read(&role->dominates, fp))
		goto bad;

	if (!ebitmap_read(&role->types, fp))
		goto bad;

	if (strcmp(key, OBJECT_R) == 0) {
		if (role->value != OBJECT_R_VAL) {
			(void) printf("Role %s has wrong value %d\n",
			    OBJECT_R, role->value);
			(void) role_destroy(key, role, NULL);
			return (-1);
		}
		(void) role_destroy(key, role, NULL);
		return (0);
	}

	if (hashtab_insert(h, key, role))
		goto bad;

	return (0);

bad:
	(void) role_destroy(key, role, NULL);
	return (-1);
}

static int
type_read(policydb_t *p, hashtab_t h, void *fp)
{
	char *key = 0;
	type_datum_t *typdatum;
	uint32_t buf[3], len;
	int items;

	_NOTE(ARGUNUSED(p));

	typdatum = SS_ALLOC_SLEEP(sizeof (type_datum_t));
	if (!typdatum)
		return (-1);
	(void) memset(typdatum, 0, sizeof (type_datum_t));

	items = next_entry(buf, sizeof (uint32_t), 3, fp);
	if (items != 3)
		goto bad;

	len = SS_LE32_TO_CPU(buf[0]);
	typdatum->value = SS_LE32_TO_CPU(buf[1]);
	typdatum->primary = SS_LE32_TO_CPU(buf[2]);

	key = SS_ALLOC_SLEEP(len + 1);
	if (!key)
		goto bad;
	items = next_entry(key, 1, len, fp);
	if (items != len)
		goto bad;
	key[len] = 0;

	if (hashtab_insert(h, key, typdatum))
		goto bad;

	return (0);

bad:
	(void) type_destroy(key, typdatum, NULL);
	return (-1);
}

static int
user_read(policydb_t *p, hashtab_t h, void *fp)
{
	char *key = 0;
	user_datum_t *usrdatum;
	uint32_t buf[2], len;
	int items;

	_NOTE(ARGUNUSED(p));

	usrdatum = SS_ALLOC_SLEEP(sizeof (user_datum_t));
	if (!usrdatum)
		return (-1);
	(void) memset(usrdatum, 0, sizeof (user_datum_t));

	items = next_entry(buf, sizeof (uint32_t), 2, fp);
	if (items != 2)
		goto bad;

	len = SS_LE32_TO_CPU(buf[0]);
	usrdatum->value = SS_LE32_TO_CPU(buf[1]);

	key = SS_ALLOC_SLEEP(len + 1);
	if (!key)
		goto bad;
	items = next_entry(key, 1, len, fp);
	if (items != len)
		goto bad;
	key[len] = 0;

	if (!ebitmap_read(&usrdatum->roles, fp))
		goto bad;

	if (mls_read_user(usrdatum, fp))
		goto bad;

	if (hashtab_insert(h, key, usrdatum))
		goto bad;

	return (0);

bad:
	(void) user_destroy(key, usrdatum, NULL);
	return (-1);
}

static int (*read_f[SYM_NUM]) (policydb_t *p, hashtab_t h, void *fp) =
{
	common_read,
	class_read,
	role_read,
	type_read,
	user_read
	mls_read_f
};

#define	mls_config(x)	((x) & POLICYDB_CONFIG_MLS) ? "mls" : "no_mls"

/*
 * Read the configuration data from a policy database binary
 * representation file into a policy database structure.
 */
int
policydb_read(policydb_t *p, void *fp)
{
	struct role_allow *ra, *lra;
	struct role_trans *tr, *ltr;
	ocontext_t *l, *c, *newc;
	genfs_t *genfs_p, *genfs, *newgenfs;
	int i, j;
	uint32_t buf[4], len, len2, config, nprim, nel, nel2;
	size_t items;
	char *policydb_str;

	config = 0;
	mls_set_config(config);

	if (policydb_init(p))
		return (-1);

	/* Read the magic number and string length. */
	items = next_entry(buf, sizeof (uint32_t), 2, fp);
	if (items != 2)
		goto bad;
	for (i = 0; i < 2; i++)
		buf[i] = SS_LE32_TO_CPU(buf[i]);

	if (buf[0] != POLICYDB_MAGIC) {
		(void) printf("security:  policydb magic number 0x%x does "
			"not match expected magic number 0x%x\n",
			buf[0],
			POLICYDB_MAGIC);
		goto bad;
	}

	len = buf[1];
	if (len != strlen(POLICYDB_STRING)) {
		(void) printf("security:  policydb string length %u does "
			"not match expected length %lu\n",
			len,
			strlen(POLICYDB_STRING));
		goto bad;
	}
	policydb_str = SS_ALLOC_SLEEP(len + 1);
	if (!policydb_str) {
		(void) printf("security:  unable to allocate memory for "
			"policydb string of length %d\n",
			len);
		goto bad;
	}
	items = next_entry(policydb_str, 1, len, fp);
	if (items != len) {
		(void) printf("security:  truncated policydb string "
		    "identifier\n");
		goto bad;
	}
	policydb_str[len] = 0;
	if (strcmp(policydb_str, POLICYDB_STRING)) {
		(void) printf("security:  policydb string %s does not match "
			"my string %s\n",
			policydb_str,
			POLICYDB_STRING);
		SS_FREE(policydb_str, len + 1);
		goto bad;
	}
	/* Done with policydb_str. */
	SS_FREE(policydb_str, len + 1);
	policydb_str = NULL;

	/* Read the version, config, and table sizes. */
	items = next_entry(buf, sizeof (uint32_t), 4, fp);
	if (items != 4)
		goto bad;
	for (i = 0; i < 4; i++)
		buf[i] = SS_LE32_TO_CPU(buf[i]);

	if (buf[0] != POLICYDB_VERSION) {
		(void) printf("security:  policydb version %d does not "
			"match my version %d\n",
			buf[0],
			POLICYDB_VERSION);
		goto bad;
	}
	if (buf[1] != config) {
		(void) printf("security:  policydb configuration (%s) does "
			"not match my configuration (%s)\n",
			mls_config(buf[1]),
			mls_config(config));
		goto bad;
	}
	if (buf[2] != SYM_NUM || buf[3] != OCON_NUM) {
		(void) printf("security:  policydb table sizes (%d,%d) do not "
			"match mine (%d,%d)\n",
			buf[2],
			buf[3],
			SYM_NUM, OCON_NUM);
		goto bad;
	}

	if (mls_read_nlevels(p, fp))
		goto bad;

	for (i = 0; i < SYM_NUM; i++) {
		items = next_entry(buf, sizeof (uint32_t), 2, fp);
		if (items != 2)
			goto bad;
		nprim = SS_LE32_TO_CPU(buf[0]);
		nel = SS_LE32_TO_CPU(buf[1]);
		for (j = 0; j < nel; j++) {
			if (read_f[i] (p, p->symtab[i].table, fp))
				goto bad;
		}

		p->symtab[i].nprim = nprim;
	}

	if (avtab_read(&p->te_avtab, fp, config))
		goto bad;

	items = next_entry(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		goto bad;
	nel = SS_LE32_TO_CPU(buf[0]);
	ltr = NULL;
	for (i = 0; i < nel; i++) {
		tr = SS_ALLOC_SLEEP(sizeof (struct role_trans));
		if (!tr) {
			goto bad;
		}
		(void) memset(tr, 0, sizeof (struct role_trans));
		if (ltr) {
			ltr->next = tr;
		} else {
			p->role_tr = tr;
		}
		items = next_entry(buf, sizeof (uint32_t), 3, fp);
		if (items != 3)
			goto bad;
		tr->role = SS_LE32_TO_CPU(buf[0]);
		tr->type = SS_LE32_TO_CPU(buf[1]);
		tr->new_role = SS_LE32_TO_CPU(buf[2]);
		ltr = tr;
	}

	items = next_entry(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		goto bad;
	nel = SS_LE32_TO_CPU(buf[0]);
	lra = NULL;
	for (i = 0; i < nel; i++) {
		ra = SS_ALLOC_SLEEP(sizeof (struct role_allow));
		if (!ra) {
			goto bad;
		}
		(void) memset(ra, 0, sizeof (struct role_allow));
		if (lra) {
			lra->next = ra;
		} else {
			p->role_allow = ra;
		}
		items = next_entry(buf, sizeof (uint32_t), 2, fp);
		if (items != 2)
			goto bad;
		ra->role = SS_LE32_TO_CPU(buf[0]);
		ra->new_role = SS_LE32_TO_CPU(buf[1]);
		lra = ra;
	}

	if (policydb_index_classes(p))
		goto bad;

	if (policydb_index_others(p))
		goto bad;

	for (i = 0; i < OCON_NUM; i++) {
		items = next_entry(buf, sizeof (uint32_t), 1, fp);
		if (items != 1)
			goto bad;
		nel = SS_LE32_TO_CPU(buf[0]);
		l = NULL;
		for (j = 0; j < nel; j++) {
			c = SS_ALLOC_SLEEP(sizeof (ocontext_t));
			if (!c) {
				goto bad;
			}
			(void) memset(c, 0, sizeof (ocontext_t));
			if (l) {
				l->next = c;
			} else {
				p->ocontexts[i] = c;
			}
			l = c;
			switch (i) {
			case OCON_ISID:
				items = next_entry(buf, sizeof (uint32_t), 1,
				    fp);
				if (items != 1)
					goto bad;
				c->sid[0] = SS_LE32_TO_CPU(buf[0]);
				if (context_read_and_validate(&c->context[0],
				    p, fp))
					goto bad;
				break;
			case OCON_FS:
			case OCON_NETIF:
				items = next_entry(buf, sizeof (uint32_t), 1,
				    fp);
				if (items != 1)
					goto bad;
				len = SS_LE32_TO_CPU(buf[0]);
				c->u.name = SS_ALLOC_SLEEP(len + 1);
				if (!c->u.name) {
					goto bad;
				}
				items = next_entry(c->u.name, 1, len, fp);
				if (items != len)
					goto bad;
				c->u.name[len] = 0;
				if (context_read_and_validate(&c->context[0],
				    p, fp))
					goto bad;
				if (context_read_and_validate(&c->context[1],
				    p, fp))
					goto bad;
				break;
			case OCON_PORT:
				items = next_entry(buf, sizeof (uint32_t), 3,
				    fp);
				if (items != 3)
					goto bad;
				c->u.port.protocol = SS_LE32_TO_CPU(buf[0]);
				c->u.port.low_port = SS_LE32_TO_CPU(buf[1]);
				c->u.port.high_port = SS_LE32_TO_CPU(buf[2]);
				if (context_read_and_validate(&c->context[0],
				    p, fp))
					goto bad;
				break;
			case OCON_NODE:
				items = next_entry(buf, sizeof (uint32_t), 2,
				    fp);
				if (items != 2)
					goto bad;
				/* addr and mask stored in network order */
				c->u.node.addr = buf[0];
				c->u.node.mask = buf[1];
				if (context_read_and_validate(&c->context[0],
				    p, fp))
					goto bad;
				break;
			case OCON_FSUSE:
				items = next_entry(buf, sizeof (uint32_t), 2,
				    fp);
				if (items != 2)
					goto bad;
				c->v.behavior = SS_LE32_TO_CPU(buf[0]);
				len = SS_LE32_TO_CPU(buf[1]);
				c->u.name = SS_ALLOC_SLEEP(len + 1);
				if (!c->u.name) {
					goto bad;
				}
				items = next_entry(c->u.name, 1, len, fp);
				if (items != len)
					goto bad;
				c->u.name[len] = 0;
				if (context_read_and_validate(&c->context[0],
				    p, fp))
					goto bad;
				break;
			}
		}
	}

	items = next_entry(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		goto bad;
	nel = SS_LE32_TO_CPU(buf[0]);
	genfs_p = NULL;
	for (i = 0; i < nel; i++) {
		newgenfs = SS_ALLOC_SLEEP(sizeof (genfs_t));
		if (!newgenfs) {
			goto bad;
		}
		(void) memset(newgenfs, 0, sizeof (genfs_t));
		items = next_entry(buf, sizeof (uint32_t), 1, fp);
		if (items != 1)
			goto bad;
		len = SS_LE32_TO_CPU(buf[0]);
		newgenfs->fstype = SS_ALLOC_SLEEP(len + 1);
		if (!newgenfs->fstype) {
			goto bad;
		}
		items = next_entry(newgenfs->fstype, 1, len, fp);
		if (items != len)
			goto bad;
		newgenfs->fstype[len] = 0;
		for (genfs_p = NULL, genfs = p->genfs; genfs;
		    genfs_p = genfs, genfs = genfs->next) {
			if (strcmp(newgenfs->fstype, genfs->fstype) == 0) {
				(void) printf("security:  dup genfs "
				    "fstype %s\n",
				    newgenfs->fstype);
				goto bad;
			}
			if (strcmp(newgenfs->fstype, genfs->fstype) < 0)
				break;
		}
		newgenfs->next = genfs;
		if (genfs_p)
			genfs_p->next = newgenfs;
		else
			p->genfs = newgenfs;
		items = next_entry(buf, sizeof (uint32_t), 1, fp);
		if (items != 1)
			goto bad;
		nel2 = SS_LE32_TO_CPU(buf[0]);
		for (j = 0; j < nel2; j++) {
			newc = SS_ALLOC_SLEEP(sizeof (ocontext_t));
			if (!newc) {
				goto bad;
			}
			(void) memset(newc, 0, sizeof (ocontext_t));
			items = next_entry(buf, sizeof (uint32_t), 1, fp);
			if (items != 1)
				goto bad;
			len = SS_LE32_TO_CPU(buf[0]);
			newc->u.name = SS_ALLOC_SLEEP(len + 1);
			if (!newc->u.name) {
				goto bad;
			}
			items = next_entry(newc->u.name, 1, len, fp);
			if (items != len)
				goto bad;
			newc->u.name[len] = 0;
			items = next_entry(buf, sizeof (uint32_t), 1, fp);
			if (items != 1)
				goto bad;
			newc->v.sclass = SS_LE32_TO_CPU(buf[0]);
			if (context_read_and_validate(&newc->context[0], p, fp))
				goto bad;
			for (l = NULL, c = newgenfs->head; c; l = c,
			    c = c->next) {
				if (strcmp(newc->u.name, c->u.name) == 0 &&
				    (!c->v.sclass || !newc->v.sclass ||
				    newc->v.sclass == c->v.sclass)) {
					(void) printf("security:  dup genfs "
					    "entry (%s,%s)\n",
					    newgenfs->fstype, c->u.name);
					goto bad;
				}
				len = strlen(newc->u.name);
				len2 = strlen(c->u.name);
				if (len > len2)
					break;
			}
			newc->next = c;
			if (l)
				l->next = newc;
			else
				newgenfs->head = newc;
		}
	}

	if (mls_read_trusted(p, fp))
		goto bad;

	return (0);
bad:
	policydb_destroy(p);
	return (-1);
}
