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
 * A policy database (policydb) specifies the
 * configuration data for the security policy.
 */

#ifndef _POLICYDB_H
#define	_POLICYDB_H

#if defined(_KERNEL)
#include <sys/inttypes.h>
#include <sys/kobj.h>
#else
#include <inttypes.h>
#endif /* defined(_KERNEL) */

#include <sys/types.h>
#include "ss_impl.h"
#include "symtab.h"
#include "avtab.h"
#include "sidtab.h"
#include "context.h"
#include "constraint.h"

/*
 * A datum type is defined for each kind of symbol
 * in the configuration data:  individual permissions,
 * common prefixes for access vectors, classes,
 * users, roles, types, sensitivities, categories, etc.
 */

/* Permission attributes */
typedef struct perm_datum {
	uint32_t value;		/* permission bit + 1 */
#ifdef CONFIG_FLASK_MLS
#define	MLS_BASE_READ    1	/* MLS base permission `read' */
#define	MLS_BASE_WRITE   2	/* MLS base permission `write' */
#define	MLS_BASE_READBY  4	/* MLS base permission `readby' */
#define	MLS_BASE_WRITEBY 8	/* MLS base permission `writeby' */
	uint32_t base_perms;	/* MLS base permission mask */
#endif
} perm_datum_t;

/* Attributes of a common prefix for access vectors */
typedef struct common_datum {
	uint32_t value;		/* internal common value */
	symtab_t permissions;	/* common permissions */
} common_datum_t;

/* Class attributes */
typedef struct class_datum {
	uint32_t value;		/* class value */
	char *comkey;		/* common name */
	common_datum_t *comdatum;	/* common datum */
	symtab_t permissions;	/* class-specific permission symbol table */
	constraint_node_t *constraints;	/* constraints on class permissions */
#ifdef CONFIG_FLASK_MLS
	mls_perms_t mlsperms;	/* MLS base permission masks */
#endif
} class_datum_t;

/* Role attributes */
typedef struct role_datum {
	uint32_t value;		/* internal role value */
	ebitmap_t dominates;	/* set of roles dominated by this role */
	ebitmap_t types;	/* set of authorized types for role */
} role_datum_t;

typedef struct role_trans {
	uint32_t role;		/* current role */
	uint32_t type;		/* program executable type */
	uint32_t new_role;	/* new role */
	struct role_trans *next;
} role_trans_t;

typedef struct role_allow {
	uint32_t role;		/* current role */
	uint32_t new_role;	/* new role */
	struct role_allow *next;
} role_allow_t;

/* Type attributes */
typedef struct type_datum {
	uint32_t value;		/* internal type value */
	unsigned char primary;	/* primary name? */
#ifndef _KERNEL
	unsigned char isattr;   /* is this a type attribute? */
	ebitmap_t types;	/* types with this attribute */
#endif /* _KERNEL */
} type_datum_t;

/* User attributes */
typedef struct user_datum {
	uint32_t value;			/* internal user value */
	ebitmap_t roles;		/* set of authorized roles for user */
#ifdef CONFIG_FLASK_MLS
	mls_range_list_t *ranges;	/* list of authorized MLS ranges */
					/* for user */
#endif
} user_datum_t;


#ifdef CONFIG_FLASK_MLS
/* Sensitivity attributes */
typedef struct level_datum {
	mls_level_t *level;	/* sensitivity and associated categories */
	unsigned char isalias;  /* is this sensitivity an alias for another? */
} level_datum_t;

/* Category attributes */
typedef struct cat_datum {
	uint32_t value;		/* internal category bit + 1 */
	unsigned char isalias;  /* is this category an alias for another? */
} cat_datum_t;
#endif


/*
 * The configuration data includes security contexts for
 * initial SIDs, unlabeled file systems, TCP and UDP port numbers,
 * network interfaces, and nodes.  This structure stores the
 * relevant data for one such entry.  Entries of the same kind
 * (e.g. all initial SIDs) are linked together into a list.
 */
typedef struct ocontext {
	union {
		char *name;	/* name of initial SID, fs, netif, fstype, */
				/* path */
		struct {
			uint8_t protocol;
			uint16_t low_port;
			uint16_t high_port;
		} port;		/* TCP or UDP port information */
		struct {
			uint32_t addr;
			uint32_t mask;
		} node;		/* node information */
	} u;
	union {
		uint32_t sclass;  /* security class for genfs */
		uint32_t behavior;  /* labeling behavior for fs_use */
	} v;
	context_struct_t context[2];	/* security context(s) */
	security_id_t sid[2];	/* SID(s) */
	struct ocontext *next;
} ocontext_t;

typedef struct genfs {
	char *fstype;
	struct ocontext *head;
	struct genfs *next;
} genfs_t;

/* symbol table array indices */
#define	SYM_COMMONS	0
#define	SYM_CLASSES	1
#define	SYM_ROLES	2
#define	SYM_TYPES	3
#define	SYM_USERS	4
#ifdef CONFIG_FLASK_MLS
#define	SYM_LEVELS	5
#define	SYM_CATS	6
#define	SYM_NUM		7
#else
#define	SYM_NUM		5
#endif

/* object context array indices */
#define	OCON_ISID  0	/* initial SIDs */
#define	OCON_FS    1	/* unlabeled file systems */
#define	OCON_PORT  2	/* TCP and UDP port numbers */
#define	OCON_NETIF 3	/* network interfaces */
#define	OCON_NODE  4	/* nodes */
#define	OCON_FSUSE 5	/* fs_use */
#define	OCON_NUM   6

/* The policy database */
typedef struct policydb {
	/* symbol tables */
	symtab_t symtab[SYM_NUM];
#define	p_commons symtab[SYM_COMMONS]
#define	p_classes symtab[SYM_CLASSES]
#define	p_roles symtab[SYM_ROLES]
#define	p_types symtab[SYM_TYPES]
#define	p_users symtab[SYM_USERS]
#define	p_levels symtab[SYM_LEVELS]
#define	p_cats symtab[SYM_CATS]

	/* symbol names indexed by (value - 1) */
	char **sym_val_to_name[SYM_NUM];
#define	p_common_val_to_name sym_val_to_name[SYM_COMMONS]
#define	p_class_val_to_name sym_val_to_name[SYM_CLASSES]
#define	p_role_val_to_name sym_val_to_name[SYM_ROLES]
#define	p_type_val_to_name sym_val_to_name[SYM_TYPES]
#define	p_user_val_to_name sym_val_to_name[SYM_USERS]
#define	p_sens_val_to_name sym_val_to_name[SYM_LEVELS]
#define	p_cat_val_to_name sym_val_to_name[SYM_CATS]

	/* class, role, and user attributes indexed by (value - 1) */
	class_datum_t **class_val_to_struct;
	role_datum_t **role_val_to_struct;
	user_datum_t **user_val_to_struct;

	/* type enforcement access vectors and transitions */
	avtab_t te_avtab;

	/* role transitions */
	role_trans_t *role_tr;

	/* role allows */
	role_allow_t *role_allow;

	/*
	 * security contexts of initial SIDs, unlabeled file systems,
	 * TCP or UDP port numbers, network interfaces and nodes
	 */
	ocontext_t *ocontexts[OCON_NUM];

	/*
	 * security contexts for files in filesystems that cannot support
	 * a persistent label mapping or use another
	 * fixed labeling behavior.
	 */
	genfs_t *genfs;

#ifdef CONFIG_FLASK_MLS
	/* number of legitimate MLS levels */
	uint32_t nlevels;

	ebitmap_t trustedreaders;
	ebitmap_t trustedwriters;
	ebitmap_t trustedobjects;
#endif
} policydb_t;

extern int policydb_init(policydb_t * p);

extern int policydb_index_classes(policydb_t * p);

extern int policydb_index_others(policydb_t * p);

extern int constraint_expr_destroy(constraint_expr_t * expr);

extern void policydb_destroy(policydb_t * p);

extern int policydb_load_isids(policydb_t *p, sidtab_t *s);

extern int policydb_context_isvalid(policydb_t *p, context_struct_t *c);

extern int policydb_read(policydb_t * p, void * fp);

#define	PERM_SYMTAB_SIZE 32

#define	POLICYDB_VERSION 15
#define	POLICYDB_CONFIG_MLS    1

#define	OBJECT_R "object_r"
#define	OBJECT_R_VAL 1

#define	POLICYDB_MAGIC SEMAGIC
#define	POLICYDB_STRING "Flask"

struct policy_file {
	char *data;
	size_t len;
};

#if defined(_KERNEL)
static inline
ssize_t next_entry(void *buf, size_t size, size_t nitems,
    struct policy_file *fp)
{
	struct _buf *policy_handle = (struct _buf *)fp->data;
	unsigned long bytes = nitems * size;
	unchar *cptr = (unchar *)buf;
	int ch;

	while (bytes-- && (ch = kobj_getc(policy_handle)) != -1) {
		*cptr++ = (unchar)ch;
	}

	return ((cptr-(unchar *)buf) / size);
}
#else
static inline
ssize_t next_entry(void *buf, size_t size, size_t nitems,
    struct policy_file *fp)
{
	unsigned long bytes = nitems * size;

	if (bytes > fp->len)
		bytes = fp->len;

	memcpy(buf, fp->data, bytes);
	fp->data += bytes;
	fp->len -= bytes;
	return (bytes / size);
}
#endif /* defined(_KERNEL) */

#endif	/* _POLICYDB_H */
