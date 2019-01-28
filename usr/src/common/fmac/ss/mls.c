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
 * Implementation of the multi-level security (MLS) policy.
 */

#if defined(_KERNEL)
#include <sys/inttypes.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#else
#include <inttypes.h>
#include <stdio.h>
#include <strings.h>
#endif /* defined(_KERNEL) */

#include <sys/types.h>
#include <sys/note.h>
#include "ss_impl.h"
#include "mls.h"
#include "policydb.h"
#include "services.h"

/*
 * Remove any permissions from `allowed' that are
 * denied by the MLS policy.
 */
void
mls_compute_av(context_struct_t *scontext, context_struct_t *tcontext,
    class_datum_t *tclass, access_vector_t *allowed)
{
	unsigned int rel[2];
	int l;

	for (l = 0; l < 2; l++)
		rel[l] = mls_level_relation(scontext->range.level[l],
					    tcontext->range.level[l]);

	if (rel[1] != MLS_RELATION_EQ) {
		if (rel[1] != MLS_RELATION_DOM &&
		    !ebitmap_get_bit(&policydb.trustedreaders,
			scontext->type - 1) &&
		    !ebitmap_get_bit(&policydb.trustedobjects,
			tcontext->type - 1)) {
			/* read(s,t) = (s.high >= t.high) = False */
			*allowed = (*allowed) & ~(tclass->mlsperms.read);
		}
		if (rel[1] != MLS_RELATION_DOMBY &&
		    !ebitmap_get_bit(&policydb.trustedreaders,
			tcontext->type - 1) &&
		    !ebitmap_get_bit(&policydb.trustedobjects,
			scontext->type - 1)) {
			/* readby(s,t) = read(t,s) = False */
			*allowed = (*allowed) & ~(tclass->mlsperms.readby);
		}
	}
	if (((rel[0] != MLS_RELATION_DOMBY && rel[0] != MLS_RELATION_EQ) ||
	    ((!mls_level_eq(tcontext->range.level[0],
			    tcontext->range.level[1])) &&
	    (rel[1] != MLS_RELATION_DOM && rel[1] != MLS_RELATION_EQ))) &&
	    !ebitmap_get_bit(&policydb.trustedwriters, scontext->type - 1) &&
	    !ebitmap_get_bit(&policydb.trustedobjects, tcontext->type - 1)) {
		/*
		 * write(s,t) = ((s.low <= t.low = t.high) or (s.low
		 * <= t.low <= t.high <= s.high)) = False
		 */
		*allowed = (*allowed) & ~(tclass->mlsperms.write);
	}

	if (((rel[0] != MLS_RELATION_DOM && rel[0] != MLS_RELATION_EQ) ||
	    ((!mls_level_eq(scontext->range.level[0],
			    scontext->range.level[1])) &&
	    (rel[1] != MLS_RELATION_DOMBY && rel[1] != MLS_RELATION_EQ))) &&
	    !ebitmap_get_bit(&policydb.trustedwriters, tcontext->type - 1) &&
	    !ebitmap_get_bit(&policydb.trustedobjects, scontext->type - 1)) {
		/* writeby(s,t) = write(t,s) = False */
		*allowed = (*allowed) & ~(tclass->mlsperms.writeby);
	}
}

/*
 * Return the length in bytes for the MLS fields of the
 * security context string representation of `context'.
 */
int
mls_compute_context_len(context_struct_t *context)
{
	int i;
	int l;
	int len;

	len = 0;

	/* Scan through sensitivities */
	for (l = 0; l < 2; l++) {
		/* Add sensitivity size */
		len += strlen(
		    policydb.p_sens_val_to_name[context->range.level[l].sens
		    - 1]);

		/* Scan through categories */
		for (i = 1; i <= ebitmap_length(&context->range.level[l].cat);
		    i++) {

			/* Add category size */
			if (ebitmap_get_bit(&context->range.level[l].cat,
			    i - 1)) {

				/*
				 * This is either the first category or
				 * the next, so adjust for the separators
				 * ":" or ",".
				 */
				len++;

				len +=
				    strlen(policydb.p_cat_val_to_name[i - 1]);
			}
		}
		if (mls_level_relation(context->range.level[0],
		    context->range.level[1]) != MLS_RELATION_EQ) {
			/*
			 * If the first sensitivity was written and there
			 * is a range, then add the separator.
			 */
			if (l == 0) {
				/* Add range separator "-" size */
				len++;
			}
		} else {
			break;
		}
	}

	return (len);
}

/*
 * Write the security context string representation of
 * the MLS fields of `context' into the string `*scontext'.
 * Update `*scontext' to point to the end of the MLS fields.
 *
 * Format: sensitivity[:category,...][-sensitivity[:category,...]]
 */
void
mls_sid_to_context(context_struct_t *context, char *scontextp)
{
	int categories;
	int i;
	int l;

	/* Scan through sensitivities */
	for (l = 0; l < 2; l++) {
		/* Add sensitivity value */
		(void) strcpy(scontextp,
		    policydb.p_sens_val_to_name[context->range.level[l].sens
		    - 1]);
		scontextp += strlen(
		    policydb.p_sens_val_to_name[context->range.level[l].sens
		    - 1]);
		/* Scan through categories */
		for (i = 1, categories = 0;
		    i <= ebitmap_length(&context->range.level[l].cat); i++) {

			/* Add category value */
			if (ebitmap_get_bit(&context->range.level[l].cat,
			    i - 1)) {

				/* First category, add separator ":" */
				if (categories == 0) {
					*scontextp = ':';
					scontextp++;
				} else {
					/* Otherwise add add separator "," */
					*scontextp = ',';
					scontextp++;
				}

				(void) strcpy(scontextp,
				    policydb.p_cat_val_to_name[i - 1]);

				scontextp += strlen(
					policydb.p_cat_val_to_name[i - 1]);

				categories++;
			}
		}

		if (mls_level_relation(context->range.level[0],
		    context->range.level[1]) != MLS_RELATION_EQ) {
			/*
			 * If the first sensitivity was written and there
			 * is a range, then add the separator.
			 */
			if (l == 0) {
				/* Add range separator */
				*scontextp = '-';
				scontextp++;
			}
		} else {
			break;
		}
	}
}

/*
 * Return TRUE if the MLS fields in the security context
 * structure `c' are valid.  Return FALSE otherwise.
 */
int
mls_context_isvalid(policydb_t *p, context_struct_t *c)
{
	unsigned int		relation;
	level_datum_t		*levdatum;
	user_datum_t		*usrdatum;
	mls_range_list_t	*rnode;
	int			i;
	int			l;

	/*
	 * MLS range validity checks: high must dominate low, low level must
	 * be valid (category set <-> sensitivity check), and high level must
	 * be valid (category set <-> sensitivity check)
	 */
	relation = mls_level_relation(c->range.level[1], c->range.level[0]);
	if (!(relation & (MLS_RELATION_DOM | MLS_RELATION_EQ)))
		/* High does not dominate low. */
		return (FALSE);

	for (l = 0; l < 2; l++) {
		if (!c->range.level[l].sens || c->range.level[l].sens >
		    p->p_levels.nprim)
			return (FALSE);
		levdatum = (level_datum_t *) hashtab_search(p->p_levels.table,
		    p->p_sens_val_to_name[c->range.level[l].sens - 1]);
		if (!levdatum)
			return (FALSE);

		for (i = 1; i <= ebitmap_length(&c->range.level[l].cat); i++) {
			if (ebitmap_get_bit(&c->range.level[l].cat, i - 1)) {
				if (i > p->p_cats.nprim)
					return (FALSE);
				if (!ebitmap_get_bit(&levdatum->level->cat,
				    i - 1)) {
					/*
					 * Category may not be associated with
					 * sensitivity in low level.
					 */
					return (FALSE);
				}
			}
		}
	}

	if (c->role == OBJECT_R_VAL)
		return (TRUE);

	/*
	 * User must be authorized for the MLS range.
	 */
	if (!c->user || c->user > p->p_users.nprim)
		return (FALSE);
	usrdatum = p->user_val_to_struct[c->user - 1];
	for (rnode = usrdatum->ranges; rnode; rnode = rnode->next) {
		if (mls_range_contains(rnode->range, c->range))
			break;
	}
	if (!rnode)
		/* user may not be associated with range */
		return (FALSE);

	return (TRUE);
}

/*
 * Set the MLS fields in the security context structure
 * `context' based on the string representation in
 * the string `*scontext'.  Update `*scontext' to
 * point to the end of the string representation of
 * the MLS fields.
 *
 * This function modifies the string in place, inserting
 * NULL characters to terminate the MLS fields.
 */
int
mls_context_to_sid(char oldc, char **scontext, context_struct_t *context)
{

	char		delim;
	char		*scontextp, *p;
	level_datum_t	*levdatum;
	cat_datum_t	*catdatum;
	int		l;

	if (!oldc) {
		/*
		 * No MLS component to the security context.  Try
		 * to use a default 'unclassified' value.
		 */
		levdatum =
		    (level_datum_t *) hashtab_search(policydb.p_levels.table,
		    (hashtab_key_t) "unclassified");

		if (!levdatum)
			return (EINVAL);
		context->range.level[0].sens = levdatum->level->sens;
		context->range.level[1].sens = context->range.level[0].sens;
		return (0);
	}

	/* Extract low sensitivity. */
	scontextp = p = *scontext;
	while (*p && *p != ':' && *p != '-')
		p++;

	delim = *p;
	if (delim != 0)
		*p++ = 0;

	for (l = 0; l < 2; l++) {
		levdatum =
		    (level_datum_t *) hashtab_search(policydb.p_levels.table,
			(hashtab_key_t) scontextp);

		if (!levdatum)
			return (EINVAL);

		context->range.level[l].sens = levdatum->level->sens;

		if (delim == ':') {
			/* Extract low category set. */
			for (;;) {
				scontextp = p;
				while (*p && *p != ',' && *p != '-')
					p++;
				delim = *p;
				if (delim != 0)
					*p++ = 0;

				catdatum =
				    (cat_datum_t *) hashtab_search(
				    policydb.p_cats.table,
				    (hashtab_key_t) scontextp);

				if (!catdatum)
					return (EINVAL);

				if (!ebitmap_set_bit(
				    &context->range.level[l].cat,
				    catdatum->value - 1, TRUE))
					return (ENOMEM);
				if (delim != ',')
					break;
			}
		}
		if (delim == '-') {
			/* Extract high sensitivity. */
			scontextp = p;
			while (*p && *p != ':')
				p++;

			delim = *p;
			if (delim != 0)
				*p++ = 0;
		} else
			break;
	}

	if (l == 0) {
		context->range.level[1].sens = context->range.level[0].sens;
		if (!ebitmap_cpy(&context->range.level[1].cat,
		    &context->range.level[0].cat))
			return (ENOMEM);
	}
	*scontext = ++p;
	return (0);
}

/*
 * Copies the MLS range from `src' into `dst'.
 */
static inline int
mls_copy_context(context_struct_t *dst, context_struct_t *src)
{
	int l;

	/* Copy the MLS range from the source context */
	for (l = 0; l < 2; l++) {
		dst->range.level[l].sens = src->range.level[l].sens;
		if (!ebitmap_cpy(&dst->range.level[l].cat,
		    &src->range.level[l].cat))
			return (ENOMEM);
	}

	return (0);
}

/*
 * Convert the MLS fields in the security context
 * structure `c' from the values specified in the
 * policy `oldp' to the values specified in the policy `newp'.
 */
int
mls_convert_context(policydb_t *oldp, policydb_t *newp, context_struct_t *c)
{
	level_datum_t	*levdatum;
	cat_datum_t	*catdatum;
	ebitmap_t	bitmap;
	int		l;
	int		i;

	for (l = 0; l < 2; l++) {
		levdatum = (level_datum_t *) hashtab_search(
						    newp->p_levels.table,
		    oldp->p_sens_val_to_name[c->range.level[l].sens - 1]);

		if (!levdatum)
			return (EINVAL);
		c->range.level[l].sens = levdatum->level->sens;

		ebitmap_init(&bitmap);
		for (i = 1; i <= ebitmap_length(&c->range.level[l].cat); i++) {
			if (ebitmap_get_bit(&c->range.level[l].cat, i - 1)) {
				catdatum =
				    (cat_datum_t *) hashtab_search(
				    newp->p_cats.table,
				    oldp->p_cat_val_to_name[i - 1]);
				if (!catdatum)
					return (EINVAL);
				if (!ebitmap_set_bit(
				    &bitmap, catdatum->value - 1, TRUE))
					return (ENOMEM);
			}
		}
		ebitmap_destroy(&c->range.level[l].cat);
		c->range.level[l].cat = bitmap;
	}

	return (0);
}

int
mls_compute_sid(context_struct_t *scontext, context_struct_t *tcontext,
    security_class_t tclass, uint32_t specified, context_struct_t *newcontext)
{
	_NOTE(ARGUNUSED(tclass));

	switch (specified) {
	case AVTAB_TRANSITION:
	case AVTAB_CHANGE:
		/* Use the process MLS attributes. */
		return (mls_copy_context(newcontext, scontext));
	case AVTAB_MEMBER:
		/*
		 * Only polyinstantiate the MLS attributes if
		 * the type is being polyinstantiated
		 */
		if (newcontext->type != tcontext->type) {
			/* Use the process MLS attributes. */
			return (mls_copy_context(newcontext, scontext));
		} else {
			/* Use the related object MLS attributes. */
			return (mls_copy_context(newcontext, tcontext));
		}
	default:
		break;
	}
	return (EINVAL);
}

void
mls_user_destroy(user_datum_t *usrdatum)
{
	mls_range_list_t *rnode, *rtmp;

	rnode = usrdatum->ranges;

	while (rnode) {
		rtmp = rnode;
		rnode = rnode->next;
		ebitmap_destroy(&rtmp->range.level[0].cat);
		ebitmap_destroy(&rtmp->range.level[1].cat);
		SS_FREE(rtmp, sizeof (mls_range_list_t));
	}
}

int
mls_read_perm(perm_datum_t *perdatum, void *fp)
{
	uint32_t buf[1];
	int items;

	items = next_entry(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		return (-1);
	perdatum->base_perms = SS_LE32_TO_CPU(buf[0]);
	return (0);
}

/*
 * Read a MLS level structure from a policydb binary
 * representation file.
 */
mls_level_t
*mls_read_level(void *fp)
{
	mls_level_t *l;
	uint32_t sens;
	int items;

	l = SS_ALLOC_NOSLEEP(sizeof (mls_level_t));
	if (!l) {
		(void) printf("security: mls: out of memory\n");
		return (NULL);
	}
	(void) memset(l, 0, sizeof (mls_level_t));

	items = next_entry(&sens, sizeof (uint32_t), 1, fp);
	if (items != 1) {
		(void) printf("security: mls: truncated level\n");
		goto bad;
	}
	l->sens = cpu_to_le32(sens);

	if (!ebitmap_read(&l->cat, fp)) {
		(void) printf("security: mls:  error reading level "
		    "categories\n");
		goto bad;
	}
	return (l);

bad:
	SS_FREE(l, sizeof (mls_level_t));
	return (NULL);
}


/*
 * Read a MLS range structure from a policydb binary
 * representation file.
 */

static int
mls_read_range_helper(mls_range_t *r, void *fp)
{
	uint32_t buf[3];
	int items, items2;

	items = next_entry(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		return (-1);

	items2 = SS_LE32_TO_CPU(buf[0]);
	if (items2 > (sizeof (buf) / sizeof (uint32_t))) {
		(void) printf("security: mls:  range too large\n");
		return (-1);
	}
	items = next_entry(buf, sizeof (uint32_t), items2, fp);
	if (items != items2) {
		(void) printf("security: mls:  truncated range\n");
		return (-1);
	}
	r->level[0].sens = SS_LE32_TO_CPU(buf[0]);
	if (items > 1) {
		r->level[1].sens = SS_LE32_TO_CPU(buf[1]);
	} else {
		r->level[1].sens = r->level[0].sens;
	}

	if (!ebitmap_read(&r->level[0].cat, fp)) {
		(void) printf("security: mls:  error reading low categories\n");
		return (-1);
	}
	if (items > 1) {
		if (!ebitmap_read(&r->level[1].cat, fp)) {
			(void) printf("security: mls:  error reading high "
			    "categories\n");
			goto bad_high;
		}
	} else {
		if (!ebitmap_cpy(&r->level[1].cat, &r->level[0].cat)) {
			(void) printf("security: mls:  out of memory\n");
			goto bad_high;
		}
	}

	return (0);

bad_high:
	ebitmap_destroy(&r->level[0].cat);
	return (-1);
}

int
mls_read_range(context_struct_t *c, void *fp)
{
	return (mls_read_range_helper(&c->range, fp));
}


/*
 * Read a MLS perms structure from a policydb binary
 * representation file.
 */
int
mls_read_class(class_datum_t *cladatum, void *fp)
{
	mls_perms_t * p = &cladatum->mlsperms;
	uint32_t buf[4];
	int items;

	items = next_entry(buf, sizeof (uint32_t), 4, fp);
	if (items != 4) {
		(void) printf("security: mls:  truncated mls permissions\n");
		return (-1);
	}
	p->read = SS_LE32_TO_CPU(buf[0]);
	p->readby = SS_LE32_TO_CPU(buf[1]);
	p->write = SS_LE32_TO_CPU(buf[2]);
	p->writeby = SS_LE32_TO_CPU(buf[3]);
	return (0);
}

int
mls_read_user(user_datum_t *usrdatum, void *fp)
{
	mls_range_list_t	*r, *l;
	uint32_t		nel, i;
	uint32_t		buf[1];
	int			items;

	items = next_entry(buf, sizeof (uint32_t), 1, fp);
	if (items != 1)
		goto bad;
	nel = SS_LE32_TO_CPU(buf[0]);
	l = NULL;
	for (i = 0; i < nel; i++) {
		r = SS_ALLOC_NOSLEEP(sizeof (mls_range_list_t));
		if (!r)
			goto bad;
		(void) memset(r, 0, sizeof (mls_range_list_t));

		if (mls_read_range_helper(&r->range, fp))
			goto bad;

		if (l)
			l->next = r;
		else
			usrdatum->ranges = r;
		l = r;
	}
	return (0);
bad:
	return (-1);
}

int
mls_read_nlevels(policydb_t *p, void *fp)
{
	uint32_t buf[2];
	int items;

	items = next_entry(buf, sizeof (uint32_t), 1, fp);
	if (items != 1) {
		return (-1);
	}
	p->nlevels = SS_LE32_TO_CPU(buf[0]);
	return (0);
}

int
mls_read_trusted(policydb_t *p, void *fp)
{
	if (!ebitmap_read(&p->trustedreaders, fp))
		return (-1);
	if (!ebitmap_read(&p->trustedwriters, fp))
		return (-1);
	if (!ebitmap_read(&p->trustedobjects, fp))
		return (-1);
	return (0);
}

int
sens_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	level_datum_t *levdatum;


	levdatum = (level_datum_t *) datum;
	p = (policydb_t *) datap;

	if (!levdatum->isalias)
		p->p_sens_val_to_name[levdatum->level->sens - 1] = (char *) key;

	return (0);
}

int
cat_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	cat_datum_t *catdatum;


	catdatum = (cat_datum_t *) datum;
	p = (policydb_t *) datap;


	if (!catdatum->isalias)
		p->p_cat_val_to_name[catdatum->value - 1] = (char *) key;

	return (0);
}

int
sens_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	level_datum_t *levdatum;

	_NOTE(ARGUNUSED(p));

	if (key)
		SS_FREE(key, strlen(key) + 1);
	levdatum = (level_datum_t *) datum;
	if (!levdatum->isalias) {
		ebitmap_destroy(&levdatum->level->cat);
		SS_FREE(levdatum->level, sizeof (mls_level_t));
	}
	SS_FREE(datum, sizeof (level_datum_t));
	return (0);
}

int
cat_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	_NOTE(ARGUNUSED(p));

	if (key)
		SS_FREE(key, strlen(key) + 1);
	SS_FREE(datum, sizeof (cat_datum_t));
	return (0);
}

int
sens_read(policydb_t *p, hashtab_t h, void *fp)
{
	char		*key = 0;
	level_datum_t	*levdatum;
	uint32_t	buf[2], len;
	int		items;

	_NOTE(ARGUNUSED(p));

	levdatum = SS_ALLOC_NOSLEEP(sizeof (level_datum_t));
	if (!levdatum)
		return (-1);
	(void) memset(levdatum, 0, sizeof (level_datum_t));

	items = next_entry(buf, sizeof (uint32_t), 2, fp);
	if (items != 2)
		goto bad;

	len = SS_LE32_TO_CPU(buf[0]);
	levdatum->isalias = SS_LE32_TO_CPU(buf[1]);

	key = SS_ALLOC_NOSLEEP(len + 1);
	if (!key)
		goto bad;
	items = next_entry(key, 1, len, fp);
	if (items != len)
		goto bad;
	key[len] = 0;

	levdatum->level = mls_read_level(fp);
	if (!levdatum->level)
		goto bad;

	if (hashtab_insert(h, key, levdatum))
		goto bad;

	return (0);

bad:
	(void) sens_destroy(key, levdatum, NULL);
	return (-1);
}


int
cat_read(policydb_t *p, hashtab_t h, void *fp)
{
	char		*key = 0;
	cat_datum_t	*catdatum;
	uint32_t	buf[3], len;
	int		items;

	_NOTE(ARGUNUSED(p));

	catdatum = SS_ALLOC_NOSLEEP(sizeof (cat_datum_t));
	if (!catdatum)
		return (-1);
	(void) memset(catdatum, 0, sizeof (cat_datum_t));

	items = next_entry(buf, sizeof (uint32_t), 3, fp);
	if (items != 3)
		goto bad;

	len = SS_LE32_TO_CPU(buf[0]);
	catdatum->value = SS_LE32_TO_CPU(buf[1]);
	catdatum->isalias = SS_LE32_TO_CPU(buf[2]);

	key = SS_ALLOC_NOSLEEP(len + 1);
	if (!key)
		goto bad;
	items = next_entry(key, 1, len, fp);
	if (items != len)
		goto bad;
	key[len] = 0;

	if (hashtab_insert(h, key, catdatum))
		goto bad;

	return (0);

bad:
	(void) cat_destroy(key, catdatum, NULL);
	return (-1);
}
