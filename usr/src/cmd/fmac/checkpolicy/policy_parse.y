%{
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
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil> 
 */

#include <policydb.h>
#include <services.h>
#include "queue.h"
#include <sys/fmac/av_inherit.h>
#include <sys/fmac/security.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "checkpolicy.h"
#include <stdint.h>
#include <stdio.h>

policydb_t *policydbp;
queue_info_ptr_t id_queue = 0;
unsigned int pass;

extern unsigned long policydb_lineno;

extern char yytext[];
extern int yywarn(char *msg);
extern int yyerror(char *msg);

static char errormsg[255];

static int insert_separator(int push);
static int insert_id(char *id,int push);
static int define_class(void);
static int define_initial_sid(void);
static int define_common_perms(void);
static int define_av_perms(int inherits);
static int define_sens(void);
static int define_dominance(void);
static int define_category(void);
static int define_level(void);
static int define_common_base(void);
static int define_av_base(void);
static int define_attrib(void);
static int define_type(int alias);
static int define_compute_type(int which);
static int define_te_avtab(int which);
static int define_role_types(void);
static role_datum_t *merge_roles_dom(role_datum_t *r1,role_datum_t *r2);
static role_datum_t *define_role_dom(role_datum_t *r);
static int define_role_trans(void);
static int define_role_allow(void);
static int define_constraint(constraint_expr_t *expr);
static uintptr_t define_cexpr(uint32_t expr_type, uintptr_t arg1, uintptr_t arg2);
static int define_user(void);
static int parse_security_context(context_struct_t *c);
static int define_initial_sid_context(void);
static int define_fs_use(int behavior);
static int define_genfs_context(int has_type);
static int define_fs_context(int major, int minor);
static int define_port_context(int low, int high);
static int define_netif_context(void);
static int define_node_context(int addr, int mask);
%}

%union {
	unsigned int val;
	uintptr_t valptr;
	void *ptr;
}

%type <ptr> role_def roles 
%type <valptr> cexpr cexpr_prim op roleop
%type <val> ipv4_addr_def number 

%token PATH
%token CLONE
%token COMMON
%token CLASS
%token CONSTRAIN
%token INHERITS
%token SID
%token ROLE
%token ROLES
%token TYPE
%token TYPES
%token ALIAS
%token ATTRIBUTE
%token TYPE_TRANSITION
%token TYPE_MEMBER
%token TYPE_CHANGE
%token ROLE_TRANSITION
%token SENSITIVITY
%token DOMINANCE
%token DOM DOMBY INCOMP
%token CATEGORY
%token LEVEL
%token RANGES
%token USER
%token NEVERALLOW
%token ALLOW
%token AUDITALLOW
%token AUDITDENY
%token DONTAUDIT
%token SOURCE
%token TARGET
%token SAMEUSER
%token FSCON PORTCON NETIFCON NODECON 
%token FSUSEXATTR FSUSETASK FSUSETRANS
%token GENFSCON
%token U1 U2 R1 R2 T1 T2
%token NOT AND OR 
%token IDENTIFIER
%token USER_IDENTIFIER
%token NUMBER
%token IPV4ADDRESS
%token EQUALS
%token NOTEQUAL

%left OR
%left AND
%right NOT
%left EQUALS NOTEQUAL
%%
policy			: classes initial_sids access_vectors 
                          { if (pass == 1) { if (policydb_index_classes(policydbp)) return -1; } }
			  opt_mls te_rbac users opt_constraints 
			  { if (pass == 2) { if (policydb_index_others(policydbp)) return -1;} } 
			  initial_sid_contexts opt_fs_contexts opt_fs_uses opt_genfs_contexts net_contexts 
			;
classes			: class_def 
			| classes class_def
			;
class_def		: CLASS identifier
			{if (define_class()) return -1;}
			;
initial_sids 		: initial_sid_def 
			| initial_sids initial_sid_def
			;
initial_sid_def		: SID identifier
                        {if (define_initial_sid()) return -1;}
			;
access_vectors		: opt_common_perms av_perms
			;
opt_common_perms        : common_perms
                        |
                        ;
common_perms		: common_perms_def
			| common_perms common_perms_def
			;
common_perms_def	: COMMON identifier '{' identifier_list '}'
			{if (define_common_perms()) return -1;}
			;
av_perms		: av_perms_def
			| av_perms av_perms_def
			;
av_perms_def		: CLASS identifier '{' identifier_list '}'
			{if (define_av_perms(FALSE)) return -1;}
                        | CLASS identifier INHERITS identifier 
			{if (define_av_perms(TRUE)) return -1;}
                        | CLASS identifier INHERITS identifier '{' identifier_list '}'
			{if (define_av_perms(TRUE)) return -1;}
			;
opt_mls			: mls
                        | 
			;
mls			: sensitivities dominance opt_categories levels base_perms
			;
sensitivities	 	: sensitivity_def 
			| sensitivities sensitivity_def
			;
sensitivity_def		: SENSITIVITY identifier alias_def ';'
			{if (define_sens()) return -1;}
			| SENSITIVITY identifier ';'
			{if (define_sens()) return -1;}
	                ;
alias_def		: ALIAS names
			;
dominance		: DOMINANCE identifier 
			{if (define_dominance()) return -1;}
                        | DOMINANCE '{' identifier_list '}' 
			{if (define_dominance()) return -1;}
			;
opt_categories          : categories
                        |
                        ;
categories 		: category_def 
			| categories category_def
			;
category_def		: CATEGORY identifier alias_def ';'
			{if (define_category()) return -1;}
			| CATEGORY identifier ';'
			{if (define_category()) return -1;}
			;
levels	 		: level_def 
			| levels level_def
			;
level_def		: LEVEL identifier ':' id_comma_list ';'
			{if (define_level()) return -1;}
			| LEVEL identifier ';' 
			{if (define_level()) return -1;}
			;
base_perms		: opt_common_base av_base
			;
opt_common_base         : common_base
                        |
                        ;
common_base		: common_base_def
			| common_base common_base_def
			;
common_base_def	        : COMMON identifier '{' perm_base_list '}'
	                {if (define_common_base()) return -1;}
			;
av_base		        : av_base_def
			| av_base av_base_def
			;
av_base_def		: CLASS identifier '{' perm_base_list '}'
	                {if (define_av_base()) return -1;}
                        | CLASS identifier
	                {if (define_av_base()) return -1;}
			;
perm_base_list		: perm_base
			| perm_base_list perm_base
			;
perm_base		: identifier ':' identifier
			{if (insert_separator(0)) return -1;}
                        | identifier ':' '{' identifier_list '}'
			{if (insert_separator(0)) return -1;}
			;
te_rbac			: te_rbac_decl
			| te_rbac te_rbac_decl
			;
te_rbac_decl		: te_decl
			| rbac_decl
			| ';'
                        ;
rbac_decl		: role_type_def
                        | role_dominance
                        | role_trans_def
 			| role_allow_def
			;
te_decl			: attribute_def
                        | type_def
                        | transition_def
                        | te_avtab_def
			;
attribute_def           : ATTRIBUTE identifier ';'
                        { if (define_attrib()) return -1;}
                        ;
type_def		: TYPE identifier alias_def opt_attr_list ';'
                        {if (define_type(1)) return -1;}
	                | TYPE identifier opt_attr_list ';'
                        {if (define_type(0)) return -1;}
    			;
opt_attr_list           : ',' id_comma_list
			| 
			;
transition_def		: TYPE_TRANSITION names names ':' names identifier ';'
                        {if (define_compute_type(AVTAB_TRANSITION)) return -1;}
                        | TYPE_MEMBER names names ':' names identifier ';'
                        {if (define_compute_type(AVTAB_MEMBER)) return -1;}
                        | TYPE_CHANGE names names ':' names identifier ';'
                        {if (define_compute_type(AVTAB_CHANGE)) return -1;}
    			;
te_avtab_def		: allow_def
			| auditallow_def
			| auditdeny_def
			| dontaudit_def
			| neverallow_def
			;
allow_def		: ALLOW names names ':' names names  ';'
			{if (define_te_avtab(AVTAB_ALLOWED)) return -1; }
		        ;
auditallow_def		: AUDITALLOW names names ':' names names ';'
			{if (define_te_avtab(AVTAB_AUDITALLOW)) return -1; }
		        ;
auditdeny_def		: AUDITDENY names names ':' names names ';'
			{if (define_te_avtab(AVTAB_AUDITDENY)) return -1; }
		        ;
dontaudit_def		: DONTAUDIT names names ':' names names ';'
			{if (define_te_avtab(-AVTAB_AUDITDENY)) return -1; }
		        ;
neverallow_def		: NEVERALLOW names names ':' names names  ';'
			{if (define_te_avtab(-AVTAB_ALLOWED)) return -1; }
		        ;
role_type_def		: ROLE identifier TYPES names ';'
			{if (define_role_types()) return -1;}
                        ;
role_dominance		: DOMINANCE '{' roles '}'
			;
role_trans_def		: ROLE_TRANSITION names names identifier ';'
			{if (define_role_trans()) return -1; }
			;
role_allow_def		: ALLOW names names ';'
			{if (define_role_allow()) return -1; }
			;
roles			: role_def
			{ $$ = $1; }
			| roles role_def
			{ $$ = merge_roles_dom((role_datum_t*)$1, (role_datum_t*)$2); if ($$ == 0) return -1;}
			;
role_def		: ROLE identifier_push ';'
                        {$$ = define_role_dom(NULL); if ($$ == 0) return -1;}
			| ROLE identifier_push '{' roles '}'
                        {$$ = define_role_dom((role_datum_t*)$4); if ($$ == 0) return -1;}
			;
opt_constraints         : constraints
                        |
                        ;
constraints		: constraint_def
			| constraints constraint_def
			;
constraint_def		: CONSTRAIN names names cexpr ';'
			{ if (define_constraint((constraint_expr_t*)$4)) return -1; }
			;
cexpr			: '(' cexpr ')'
			{ $$ = $2; }
			| NOT cexpr
			{ $$ = define_cexpr(CEXPR_NOT, $2, 0);
			  if ($$ == 0) return -1; }
			| cexpr AND cexpr
			{ $$ = define_cexpr(CEXPR_AND, $1, $3);
			  if ($$ == 0) return -1; }
			| cexpr OR cexpr
			{ $$ = define_cexpr(CEXPR_OR, $1, $3);
			  if ($$ == 0) return -1; }
			| cexpr_prim
			{ $$ = $1; }
			;
cexpr_prim		: U1 op U2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_USER, $2);
			  if ($$ == 0) return -1; }
			| R1 roleop R2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| T1 op T2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_TYPE, $2);
			  if ($$ == 0) return -1; }
			| U1 op { if (insert_separator(1)) return -1; } user_names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_USER, $2);
			  if ($$ == 0) return -1; }
			| U2 op { if (insert_separator(1)) return -1; } user_names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_USER | CEXPR_TARGET), $2);
			  if ($$ == 0) return -1; }
			| R1 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| R2 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_TARGET), $2);
			  if ($$ == 0) return -1; }
			| T1 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_TYPE, $2);
			  if ($$ == 0) return -1; }
			| T2 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_TARGET), $2);
			  if ($$ == 0) return -1; }
			| SAMEUSER
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_USER, CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| SOURCE ROLE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_ROLE, CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| TARGET ROLE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_TARGET), CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| ROLE roleop
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| SOURCE TYPE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_TYPE, CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| TARGET TYPE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_TARGET), CEXPR_EQ);
			  if ($$ == 0) return -1; }
			;
op			: EQUALS
			{ $$ = CEXPR_EQ; }
			| NOTEQUAL
			{ $$ = CEXPR_NEQ; }
			;
roleop			: op 
			{ $$ = $1; }
			| DOM
			{ $$ = CEXPR_DOM; }
			| DOMBY
			{ $$ = CEXPR_DOMBY; }
			| INCOMP
			{ $$ = CEXPR_INCOMP; }
			;
users			: user_def
			| users user_def
			;
user_id			: identifier
			| user_identifier
			;
user_def		: USER user_id ROLES names opt_user_ranges ';'
	                {if (define_user()) return -1;}
			;
opt_user_ranges		: RANGES user_ranges 
			|
			;
user_ranges		: mls_range_def
			| '{' user_range_def_list '}' 
			;
user_range_def_list	: mls_range_def
			| user_range_def_list mls_range_def
			;
initial_sid_contexts	: initial_sid_context_def
			| initial_sid_contexts initial_sid_context_def
			;
initial_sid_context_def	: SID identifier security_context_def
			{if (define_initial_sid_context()) return -1;}
			;
opt_fs_contexts         : fs_contexts 
                        |
                        ;
fs_contexts		: fs_context_def
			| fs_contexts fs_context_def
			;
fs_context_def		: FSCON number number security_context_def security_context_def
			{if (define_fs_context($2,$3)) return -1;}
			;
net_contexts		: opt_port_contexts opt_netif_contexts opt_node_contexts 
			;
opt_port_contexts       : port_contexts
                        |
                        ;
port_contexts		: port_context_def
			| port_contexts port_context_def
			;
port_context_def	: PORTCON identifier number security_context_def
			{if (define_port_context($3,$3)) return -1;}
			| PORTCON identifier number '-' number security_context_def
			{if (define_port_context($3,$5)) return -1;}
			;
opt_netif_contexts      : netif_contexts 
                        |
                        ;
netif_contexts		: netif_context_def
			| netif_contexts netif_context_def
			;
netif_context_def	: NETIFCON identifier security_context_def security_context_def
			{if (define_netif_context()) return -1;} 
			;
opt_node_contexts       : node_contexts 
                        |
                        ;
node_contexts		: node_context_def
			| node_contexts node_context_def
			;
node_context_def	: NODECON ipv4_addr_def ipv4_addr_def security_context_def
			{if (define_node_context($2,$3)) return -1;}
			;
fs_uses                 : fs_use_def
                        | fs_uses fs_use_def
                        ;
opt_fs_uses		: fs_uses
			|
			;
fs_use_def              : FSUSEXATTR identifier security_context_def ';' 
                        {if (define_fs_use(SECURITY_FS_USE_XATTR)) return -1;}
                        | FSUSETASK identifier security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_TASK)) return -1;}
                        | FSUSETRANS identifier security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_TRANS)) return -1;}
                        ;
opt_genfs_contexts      : genfs_contexts
                        | 
                        ;
genfs_contexts	        : genfs_context_def
			| genfs_contexts genfs_context_def
			;
genfs_context_def	: GENFSCON identifier path '-' identifier security_context_def
			{if (define_genfs_context(1)) return -1;}
			| GENFSCON identifier path '-' '-' {insert_id("-", 0);} security_context_def
			{if (define_genfs_context(1)) return -1;}
                        | GENFSCON identifier path security_context_def
			{if (define_genfs_context(0)) return -1;}
			;
ipv4_addr_def		: IPV4ADDRESS
			{ 
			  in_addr_t addr;
			  if (inet_pton(AF_INET, yytext, &addr) != 1) {
				yyerror("invalid IPv4 address");
				return -1;
			  }
			  $$ = addr;	/* network order */
			}
    			;
security_context_def	: user_id ':' identifier ':' identifier opt_mls_range_def
	                ;
opt_mls_range_def	: ':' mls_range_def
			|	
			;
mls_range_def		: mls_level_def '-' mls_level_def
			{if (insert_separator(0)) return -1;}
	                | mls_level_def
			{if (insert_separator(0)) return -1;}
	                ;
mls_level_def		: identifier ':' id_comma_list
			{if (insert_separator(0)) return -1;}
	                | identifier 
			{if (insert_separator(0)) return -1;}
	                ;
id_comma_list           : identifier
			| id_comma_list ',' identifier
			;
tilde			: '~'
			;
asterisk		: '*'
			;
names           	: identifier
			{ if (insert_separator(0)) return -1; }
			| nested_id_set
			{ if (insert_separator(0)) return -1; }
			| asterisk
                        { if (insert_id("*", 0)) return -1; 
			  if (insert_separator(0)) return -1; }
			| tilde identifier
                        { if (insert_id("~", 0)) return -1;
			  if (insert_separator(0)) return -1; }
			| tilde nested_id_set
	 		{ if (insert_id("~", 0)) return -1; 
			  if (insert_separator(0)) return -1; }
			;
tilde_push              : tilde
                        { if (insert_id("~", 1)) return -1; }
			;
asterisk_push           : asterisk
                        { if (insert_id("*", 1)) return -1; }
			;
names_push		: identifier_push
			| '{' identifier_list_push '}'
			| asterisk_push
			| tilde_push identifier_push
			| tilde_push '{' identifier_list_push '}'
			;
identifier_list_push	: identifier_push
			| identifier_list_push identifier_push
			;
identifier_push		: IDENTIFIER
			{ if (insert_id(yytext, 1)) return -1; }
			;
identifier_list		: identifier
			| identifier_list identifier
			;
nested_id_set           : '{' nested_id_list '}'
                        ;
nested_id_list          : nested_id_element | nested_id_list nested_id_element
                        ;
nested_id_element       : identifier | nested_id_set
                        ;
identifier		: IDENTIFIER
			{ if (insert_id(yytext,0)) return -1; }
			;
user_identifier		: USER_IDENTIFIER
			{ if (insert_id(yytext,0)) return -1; }
			;
user_identifier_push	: USER_IDENTIFIER
			{ if (insert_id(yytext, 1)) return -1; }
			;
user_identifier_list_push : user_identifier_push
			| identifier_list_push user_identifier_push
			| user_identifier_list_push identifier_push
			| user_identifier_list_push user_identifier_push
			;
user_names_push		: names_push
			| user_identifier_push
			| '{' user_identifier_list_push '}'
			| tilde_push user_identifier_push
			| tilde_push '{' user_identifier_list_push '}'
			;
path     		: PATH
			{ if (insert_id(yytext,0)) return -1; }
			;
number			: NUMBER 
			{ $$ = strtoul(yytext,NULL,0); }
			;
%%
static int insert_separator(int push)
{
	int error;

	if (push)
		error = queue_push(id_queue, 0);
	else
		error = queue_insert(id_queue, 0);

	if (error) {
		yyerror("queue overflow");
		return -1;
	}
	return 0;
}

static int insert_id(char *id, int push)
{
	char *newid = 0;
	int error;

	newid = (char *) malloc(strlen(id) + 1);
	if (!newid) {
		yyerror("out of memory");
		return -1;
	}
	strcpy(newid, id);
	if (push)
		error = queue_push(id_queue, (queue_element_t) newid);
	else
		error = queue_insert(id_queue, (queue_element_t) newid);

	if (error) {
		yyerror("queue overflow");
		free(newid);
		return -1;
	}
	return 0;
}


static int define_class(void)
{
	char *id = 0;
	class_datum_t *datum = 0;
	int ret;


	if (pass == 2) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no class name for class definition?");
		return -1;
	}
	datum = (class_datum_t *) malloc(sizeof(class_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(datum, 0, sizeof(class_datum_t));
	datum->value = ++policydbp->p_classes.nprim;

	ret = hashtab_insert(policydbp->p_classes.table,
			     (hashtab_key_t) id, (hashtab_datum_t) datum);

	if (ret == HASHTAB_PRESENT) {
		--policydbp->p_classes.nprim;
		yyerror("duplicate class definition");
		goto bad;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		goto bad;
	}
	return 0;

      bad:
	if (id)
		free(id);
	if (datum)
		free(datum);
	return -1;
}

static int define_initial_sid(void)
{
	char *id = 0;
	ocontext_t *newc = 0, *c, *head;


	if (pass == 2) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no sid name for SID definition?");
		return -1;
	}
	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		goto bad;
	}
	memset(newc, 0, sizeof(ocontext_t));
	newc->u.name = id;
	context_init(&newc->context[0]);
	head = policydbp->ocontexts[OCON_ISID];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg, "duplicate initial SID %s", id);
			yyerror(errormsg);
			goto bad;
		}
	}

	if (head) {
		newc->sid[0] = head->sid[0] + 1;
	} else {
		newc->sid[0] = 1;
	}
	newc->next = head;
	policydbp->ocontexts[OCON_ISID] = newc;

	return 0;

      bad:
	if (id)
		free(id);
	if (newc)
		free(newc);
	return -1;
}

static int define_common_perms(void)
{
	char *id = 0, *perm = 0;
	common_datum_t *comdatum = 0;
	perm_datum_t *perdatum = 0;
	int ret;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no common name for common perm definition?");
		return -1;
	}
	comdatum = (common_datum_t *) malloc(sizeof(common_datum_t));
	if (!comdatum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(comdatum, 0, sizeof(common_datum_t));
	comdatum->value = ++policydbp->p_commons.nprim;
	ret = hashtab_insert(policydbp->p_commons.table,
			 (hashtab_key_t) id, (hashtab_datum_t) comdatum);

	if (ret == HASHTAB_PRESENT) {
		yyerror("duplicate common definition");
		goto bad;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		goto bad;
	}
	if (symtab_init(&comdatum->permissions, PERM_SYMTAB_SIZE)) {
		yyerror("out of memory");
		goto bad;
	}
	while ((perm = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) malloc(sizeof(perm_datum_t));
		if (!perdatum) {
			yyerror("out of memory");
			goto bad_perm;
		}
		memset(perdatum, 0, sizeof(perm_datum_t));
		perdatum->value = ++comdatum->permissions.nprim;

#ifdef CONFIG_FLASK_MLS
		/*
		 * By default, we set all four base permissions on this
		 * permission. This means that if base_permissions is not
		 * explicitly defined for this permission, then this
		 * permission will only be granted in the equivalent case.
		 */
		perdatum->base_perms = MLS_BASE_READ | MLS_BASE_WRITE |
		    MLS_BASE_READBY | MLS_BASE_WRITEBY;
#endif

		if (perdatum->value > (sizeof(access_vector_t) * 8)) {
			yyerror("too many permissions to fit in an access vector");
			goto bad_perm;
		}
		ret = hashtab_insert(comdatum->permissions.table,
				     (hashtab_key_t) perm,
				     (hashtab_datum_t) perdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg, "duplicate permission %s in common %s",
				perm, id);
			yyerror(errormsg);
			goto bad_perm;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			goto bad_perm;
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (comdatum)
		free(comdatum);
	return -1;

      bad_perm:
	if (perm)
		free(perm);
	if (perdatum)
		free(perdatum);
	return -1;
}


static int define_av_perms(int inherits)
{
	char *id;
	class_datum_t *cladatum;
	common_datum_t *comdatum;
	perm_datum_t *perdatum = 0, *perdatum2 = 0;
	int ret;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no tclass name for av perm definition?");
		return -1;
	}
	cladatum = (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						    (hashtab_key_t) id);
	if (!cladatum) {
		sprintf(errormsg, "class %s is not defined", id);
		yyerror(errormsg);
		goto bad;
	}
	free(id);

	if (cladatum->comdatum || cladatum->permissions.nprim) {
		yyerror("duplicate access vector definition");
		return -1;
	}
	if (symtab_init(&cladatum->permissions, PERM_SYMTAB_SIZE)) {
		yyerror("out of memory");
		return -1;
	}
	if (inherits) {
		id = (char *) queue_remove(id_queue);
		if (!id) {
			yyerror("no inherits name for access vector definition?");
			return -1;
		}
		comdatum = (common_datum_t *) hashtab_search(policydbp->p_commons.table,
						     (hashtab_key_t) id);

		if (!comdatum) {
			sprintf(errormsg, "common %s is not defined", id);
			yyerror(errormsg);
			goto bad;
		}
		cladatum->comkey = id;
		cladatum->comdatum = comdatum;

		/*
		 * Class-specific permissions start with values 
		 * after the last common permission.
		 */
		cladatum->permissions.nprim += comdatum->permissions.nprim;
	}
	while ((id = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) malloc(sizeof(perm_datum_t));
		if (!perdatum) {
			yyerror("out of memory");
			goto bad;
		}
		memset(perdatum, 0, sizeof(perm_datum_t));
		perdatum->value = ++cladatum->permissions.nprim;

#ifdef CONFIG_FLASK_MLS
		/*
		 * By default, we set all four base permissions on this
		 * permission. This means that if base_permissions is not
		 * explicitly defined for this permission, then this
		 * permission will only be granted in the equivalent case.
		 */
		perdatum->base_perms = MLS_BASE_READ | MLS_BASE_WRITE |
		    MLS_BASE_READBY | MLS_BASE_WRITEBY;
		/* actual value set in define_av_base */
#endif

		if (perdatum->value > (sizeof(access_vector_t) * 8)) {
			yyerror("too many permissions to fit in an access vector");
			goto bad;
		}
		if (inherits) {
			/*
			 * Class-specific permissions and 
			 * common permissions exist in the same
			 * name space.
			 */
			perdatum2 = (perm_datum_t *) hashtab_search(cladatum->comdatum->permissions.table,
						     (hashtab_key_t) id);
			if (perdatum2) {
				sprintf(errormsg, "permission %s conflicts with an inherited permission", id);
				yyerror(errormsg);
				goto bad;
			}
		}
		ret = hashtab_insert(cladatum->permissions.table,
				     (hashtab_key_t) id,
				     (hashtab_datum_t) perdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg, "duplicate permission %s", id);
			yyerror(errormsg);
			goto bad;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			goto bad;
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (perdatum)
		free(perdatum);
	return -1;
}


static int define_sens(void)
{
#ifdef CONFIG_FLASK_MLS
	char *id;
	mls_level_t *level = 0;
	level_datum_t *datum = 0, *aliasdatum = 0;
	int ret;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no sensitivity name for sensitivity definition?");
		return -1;
	}
	level = (mls_level_t *) malloc(sizeof(mls_level_t));
	if (!level) {
		yyerror("out of memory");
		goto bad;
	}
	memset(level, 0, sizeof(mls_level_t));
	level->sens = 0;	/* actual value set in define_dominance */
	++policydbp->p_levels.nprim;
	ebitmap_init(&level->cat);	/* actual value set in define_level */

	datum = (level_datum_t *) malloc(sizeof(level_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(datum, 0, sizeof(level_datum_t));
	datum->isalias = FALSE;
	datum->level = level;

	ret = hashtab_insert(policydbp->p_levels.table,
			     (hashtab_key_t) id, (hashtab_datum_t) datum);

	if (ret == HASHTAB_PRESENT) {
		--policydbp->p_levels.nprim;
		sprintf(errormsg, "duplicate definition for sensitivity %s", id);
		yyerror(errormsg);
		goto bad;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		goto bad;
	}

	while ((id = queue_remove(id_queue))) {
		aliasdatum = (level_datum_t *) malloc(sizeof(level_datum_t));
		if (!aliasdatum) {
			yyerror("out of memory");
			goto bad_alias;
		}
		memset(aliasdatum, 0, sizeof(level_datum_t));
		aliasdatum->isalias = TRUE;
		aliasdatum->level = level;

		ret = hashtab_insert(policydbp->p_levels.table,
		       (hashtab_key_t) id, (hashtab_datum_t) aliasdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg, "duplicate definition for level %s", id);
			yyerror(errormsg);
			goto bad_alias;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			goto bad_alias;
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (level)
		free(level);
	if (datum)
		free(datum);
	return -1;

      bad_alias:
	if (id)
		free(id);
	if (aliasdatum)
		free(aliasdatum);
	return -1;
#else
	yyerror("sensitivity definition in non-MLS configuration");
	return -1;
#endif
}

static int define_dominance(void)
{
#ifdef CONFIG_FLASK_MLS
	level_datum_t *datum;
	int order;
	char *id;

	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	order = 0;
	while ((id = (char *) queue_remove(id_queue))) {
		datum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						     (hashtab_key_t) id);
		if (!datum) {
			sprintf(errormsg, "unknown sensitivity %s used in dominance definition", id);
			yyerror(errormsg);
			free(id);
			continue;
		}
		if (datum->level->sens != 0) {
			sprintf(errormsg, "sensitivity %s occurs multiply in dominance definition", id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		datum->level->sens = ++order;

		/* no need to keep sensitivity name */
		free(id);
	}

	if (order != policydbp->p_levels.nprim) {
		yyerror("all sensitivities must be specified in dominance definition");
		return -1;
	}
	return 0;
#else
	yyerror("dominance definition in non-MLS configuration");
	return -1;
#endif
}

static int define_category(void)
{
#ifdef CONFIG_FLASK_MLS
	char *id;
	cat_datum_t *datum = 0, *aliasdatum = 0;
	int ret;

	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no category name for category definition?");
		return -1;
	}
	datum = (cat_datum_t *) malloc(sizeof(cat_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(datum, 0, sizeof(cat_datum_t));
	datum->isalias = FALSE;
	datum->value = ++policydbp->p_cats.nprim;

	ret = hashtab_insert(policydbp->p_cats.table,
			     (hashtab_key_t) id, (hashtab_datum_t) datum);

	if (ret == HASHTAB_PRESENT) {
		--policydbp->p_cats.nprim;
		sprintf(errormsg, "duplicate definition for category %s", id);
		yyerror(errormsg);
		goto bad;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		goto bad;
	}

	while ((id = queue_remove(id_queue))) {
		aliasdatum = (cat_datum_t *) malloc(sizeof(cat_datum_t));
		if (!aliasdatum) {
			yyerror("out of memory");
			goto bad_alias;
		}
		memset(aliasdatum, 0, sizeof(cat_datum_t));
		aliasdatum->isalias = TRUE;
		aliasdatum->value = datum->value;

		ret = hashtab_insert(policydbp->p_cats.table,
		       (hashtab_key_t) id, (hashtab_datum_t) aliasdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg, "duplicate definition for category %s", id);
			yyerror(errormsg);
			goto bad_alias;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			goto bad_alias;
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (datum)
		free(datum);
	return -1;

      bad_alias:
	if (id)
		free(id);
	if (aliasdatum)
		free(aliasdatum);
	return -1;
#else
	yyerror("category definition in non-MLS configuration");
	return -1;
#endif
}


static int define_level(void)
{
#ifdef CONFIG_FLASK_MLS
	int n;
	char *id, *levid;
	level_datum_t *levdatum;
	cat_datum_t *catdatum;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no level name for level definition?");
		return -1;
	}
	levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						    (hashtab_key_t) id);
	if (!levdatum) {
		sprintf(errormsg, "unknown sensitivity %s used in level definition", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	if (ebitmap_length(&levdatum->level->cat)) {
		sprintf(errormsg, "sensitivity %s used in multiple level definitions", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	levid = id;
	n = 1;
	while ((id = queue_remove(id_queue))) {
		catdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
						     (hashtab_key_t) id);
		if (!catdatum) {
			sprintf(errormsg, "unknown category %s used in level definition", id);
			yyerror(errormsg);
			free(id);
			continue;
		}
		if (!ebitmap_set_bit(&levdatum->level->cat, catdatum->value - 1, TRUE)) {
			yyerror("out of memory");
			free(id);
			free(levid);
			return -1;
		}
		/* no need to keep category name */
		free(id);

		n = n * 2;
	}

	free(levid);

	policydbp->nlevels += n;

	return 0;
#else
	yyerror("level definition in non-MLS configuration");
	return -1;
#endif
}


static int define_common_base(void)
{
#ifdef CONFIG_FLASK_MLS
	char *id, *perm, *base;
	common_datum_t *comdatum;
	perm_datum_t *perdatum;


	if (pass == 2) {
		id = queue_remove(id_queue); free(id);
		while ((id = queue_remove(id_queue))) {
			free(id);
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
		}
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no common name for common base definition?");
		return -1;
	}
	comdatum = (common_datum_t *) hashtab_search(policydbp->p_commons.table,
						     (hashtab_key_t) id);
	if (!comdatum) {
		sprintf(errormsg, "common %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	while ((perm = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) hashtab_search(comdatum->permissions.table,
						   (hashtab_key_t) perm);
		if (!perdatum) {
			sprintf(errormsg, "permission %s is not defined for common %s", perm, id);
			yyerror(errormsg);
			free(id);
			free(perm);
			return -1;
		}

		/*
		 * An explicit definition of base_permissions for this
		 * permission.  Reset the value to zero.
		 */
		perdatum->base_perms = 0;

		while ((base = queue_remove(id_queue))) {
			if (!strcmp(base, "read"))
				perdatum->base_perms |= MLS_BASE_READ;
			else if (!strcmp(base, "write"))
				perdatum->base_perms |= MLS_BASE_WRITE;
			else if (!strcmp(base, "readby"))
				perdatum->base_perms |= MLS_BASE_READBY;
			else if (!strcmp(base, "writeby"))
				perdatum->base_perms |= MLS_BASE_WRITEBY;
			else if (strcmp(base, "none")) {
				sprintf(errormsg, "base permission %s is not defined", base);
				yyerror(errormsg);
				free(base);
				return -1;
			}
			free(base);
		}

		free(perm);
	}

	free(id);

	return 0;
#else
	yyerror("MLS base permission definition in non-MLS configuration");
	return -1;
#endif
}


#ifdef CONFIG_FLASK_MLS
static int common_base_set(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	perm_datum_t *perdatum;
	class_datum_t *cladatum;

	perdatum = (perm_datum_t *) datum;
	cladatum = (class_datum_t *) p;

	if (perdatum->base_perms & MLS_BASE_READ)
		cladatum->mlsperms.read |= (1 << (perdatum->value - 1));

	if (perdatum->base_perms & MLS_BASE_WRITE)
		cladatum->mlsperms.write |= (1 << (perdatum->value - 1));

	if (perdatum->base_perms & MLS_BASE_READBY)
		cladatum->mlsperms.readby |= (1 << (perdatum->value - 1));

	if (perdatum->base_perms & MLS_BASE_WRITEBY)
		cladatum->mlsperms.writeby |= (1 << (perdatum->value - 1));

	return 0;
}
#endif

static int define_av_base(void)
{
#ifdef CONFIG_FLASK_MLS
	char *id, *base;
	class_datum_t *cladatum;
	perm_datum_t *perdatum;

	if (pass == 2) {
		id = queue_remove(id_queue); free(id);
		while ((id = queue_remove(id_queue))) {
			free(id);
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
		}
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no tclass name for av base definition?");
		return -1;
	}
	cladatum = (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						    (hashtab_key_t) id);
	if (!cladatum) {
		sprintf(errormsg, "class %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	free(id);

	/*
	 * Determine which common permissions should be included in each MLS
	 * vector for this access vector definition.
	 */
	if (cladatum->comdatum)
		hashtab_map(cladatum->comdatum->permissions.table, common_base_set, cladatum);

	while ((id = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) hashtab_search(cladatum->permissions.table,
						     (hashtab_key_t) id);
		if (!perdatum) {
			sprintf(errormsg, "permission %s is not defined", id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		/*
		 * An explicit definition of base_permissions for this
		 * permission.  Reset the value to zero.
		 */
		perdatum->base_perms = 0;

		while ((base = queue_remove(id_queue))) {
			if (!strcmp(base, "read")) {
				perdatum->base_perms |= MLS_BASE_READ;
				cladatum->mlsperms.read |= (1 << (perdatum->value - 1));
			} else if (!strcmp(base, "write")) {
				perdatum->base_perms |= MLS_BASE_WRITE;
				cladatum->mlsperms.write |= (1 << (perdatum->value - 1));
			} else if (!strcmp(base, "readby")) {
				perdatum->base_perms |= MLS_BASE_READBY;
				cladatum->mlsperms.readby |= (1 << (perdatum->value - 1));
			} else if (!strcmp(base, "writeby")) {
				perdatum->base_perms |= MLS_BASE_WRITEBY;
				cladatum->mlsperms.writeby |= (1 << (perdatum->value - 1));
			} else if (strcmp(base, "none")) {
				sprintf(errormsg, "base permission %s is not defined", base);
				yyerror(errormsg);
				free(base);
				continue;
			}
			free(base);
		}

		free(id);
	}

	return 0;
#else
	yyerror("MLS base permission definition in non-MLS configuration");
	return -1;
#endif
}

static int define_attrib(void)
{
	char *id;
	type_datum_t *attr;
	int ret;


	if (pass == 2) {
		free(queue_remove(id_queue));
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		return -1;
	}

	attr = hashtab_search(policydbp->p_types.table, id);
	if (attr) {
		sprintf(errormsg, "duplicate declaration for attribute %s\n",
			id);
		yyerror(errormsg);
		return -1;
	}

	attr = (type_datum_t *) malloc(sizeof(type_datum_t));
	if (!attr) {
		yyerror("out of memory");
		return -1;
	}
	memset(attr, 0, sizeof(type_datum_t));
	attr->isattr = TRUE;
	ret = hashtab_insert(policydbp->p_types.table,
			     id, (hashtab_datum_t) attr);
	if (ret) {
		yyerror("hash table overflow");
		return -1;
	}

	return 0;
}


static int define_type(int alias)
{
	char *id;
	type_datum_t *datum, *aliasdatum, *attr;
	int ret, newattr = 0;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		if (alias) {
			while ((id = queue_remove(id_queue))) 
				free(id);
		}
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for type definition?");
		return -1;
	}

	datum = (type_datum_t *) malloc(sizeof(type_datum_t));
	if (!datum) {
		yyerror("out of memory");
		free(id);
		return -1;
	}
	memset(datum, 0, sizeof(type_datum_t));
	datum->primary = TRUE;
	datum->value = ++policydbp->p_types.nprim;

	ret = hashtab_insert(policydbp->p_types.table,
			     (hashtab_key_t) id, (hashtab_datum_t) datum);

	if (ret == HASHTAB_PRESENT) {
		--policydbp->p_types.nprim;
		free(datum);
		sprintf(errormsg, "name conflict for type %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		free(datum);
		free(id);
		return -1;
	}

	if (alias) { 
		while ((id = queue_remove(id_queue))) {
			aliasdatum = (type_datum_t *) malloc(sizeof(type_datum_t));
			if (!aliasdatum) {
				yyerror("out of memory");
				return -1;
			}
			memset(aliasdatum, 0, sizeof(type_datum_t));
			aliasdatum->value = datum->value;

			ret = hashtab_insert(policydbp->p_types.table,
					     (hashtab_key_t) id, (hashtab_datum_t) aliasdatum);

			if (ret == HASHTAB_PRESENT) {
				sprintf(errormsg, "name conflict for type alias %s", id);
				yyerror(errormsg);
				free(aliasdatum);
				free(id);
				return -1;
			}
			if (ret == HASHTAB_OVERFLOW) {
				yyerror("hash table overflow");
				free(aliasdatum);
				free(id);
				return -1;
			}
		}
	}

	while ((id = queue_remove(id_queue))) {
#ifdef CONFIG_FLASK_MLS
		if (!strcmp(id, "mlstrustedreader")) {
			if (!ebitmap_set_bit(&policydbp->trustedreaders, datum->value - 1, TRUE)) {
				yyerror("out of memory");
				free(id);
				return -1;
			}
		} else if (!strcmp(id, "mlstrustedwriter")) {
			if (!ebitmap_set_bit(&policydbp->trustedwriters, datum->value - 1, TRUE)) {
				yyerror("out of memory");
				free(id);
				return -1;
			}
		} else if (!strcmp(id, "mlstrustedobject")) {
			if (!ebitmap_set_bit(&policydbp->trustedobjects, datum->value - 1, TRUE)) {
				yyerror("out of memory");
				free(id);
				return -1;
			}
		}
#endif
		attr = hashtab_search(policydbp->p_types.table, id);
		if (!attr) {
			sprintf(errormsg, "attribute %s is not declared", id);
#if 1
			/* treat it as a fatal error */
			yyerror(errormsg);
			return -1;
#else
			/* Warn but automatically define the attribute.
			   Useful for quickly finding all those attributes you
			   forgot to declare. */
			yywarn(errormsg);
			attr = (type_datum_t *) malloc(sizeof(type_datum_t));
			if (!attr) {
				yyerror("out of memory");
				return -1;
			}
			memset(attr, 0, sizeof(type_datum_t));
			attr->isattr = TRUE;
			ret = hashtab_insert(policydbp->p_types.table,
					     id, (hashtab_datum_t) attr);
			if (ret) {
				yyerror("hash table overflow");
				return -1;
			}
			newattr = 1;
#endif
		} else {
			newattr = 0;
		}

		if (!attr->isattr) {
			sprintf(errormsg, "%s is a type, not an attribute", id);
			yyerror(errormsg);
			return -1;
		}

		if (!newattr)
			free(id);

		ebitmap_set_bit(&attr->types, datum->value - 1, TRUE);
	}

	return 0;
}

struct val_to_name {
	unsigned int val;
	char *name;
};

static int type_val_to_name_helper(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	type_datum_t *typdatum;
	struct val_to_name *v = p;

	typdatum = (type_datum_t *) datum;

	if (v->val == typdatum->value) {
		v->name = key;
		return 1;
	}

	return 0;
}

static char *type_val_to_name(unsigned int val) 
{
	struct val_to_name v;
	int rc;

	v.val = val;
	rc = hashtab_map(policydbp->p_types.table, 
			 type_val_to_name_helper, &v);
	if (rc)
		return v.name;
	return NULL;
}


static int set_types(ebitmap_t *set,
		     char *id)
{
	type_datum_t *t;
	int i;

	if (strcmp(id, "*") == 0) {
		/* set all types */
		for (i = 0; i < policydbp->p_types.nprim; i++) 
			ebitmap_set_bit(set, i, TRUE);
		free(id);
		return 0;
	}

	if (strcmp(id, "~") == 0) {
		/* complement the set */
		for (i = 0; i < policydbp->p_types.nprim; i++) {
			if (ebitmap_get_bit(set, i))
				ebitmap_set_bit(set, i, FALSE);
			else 
				ebitmap_set_bit(set, i, TRUE);
		}
		free(id);
		return 0;
	}

	t = hashtab_search(policydbp->p_types.table, id);
	if (!t) {
		sprintf(errormsg, "unknown type %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}

	if (t->isattr) {
		/* set all types with this attribute */
		for (i = ebitmap_startbit(&t->types); i < ebitmap_length(&t->types); i++) {
			if (!ebitmap_get_bit(&t->types, i)) 
				continue;		
			ebitmap_set_bit(set, i, TRUE);
		}
	} else {
		/* set one type */
		ebitmap_set_bit(set, t->value - 1, TRUE);
	}

	free(id);
	return 0;
}


static int define_compute_type(int which)
{
	char *id;
	avtab_key_t avkey;
	avtab_datum_t avdatum, *avdatump;
	type_datum_t *datum;
	class_datum_t *cladatum;
	ebitmap_t stypes, ttypes, tclasses;
	uint32_t newtype = 0;
	int ret, i, j, k;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	ebitmap_init(&stypes);
	ebitmap_init(&ttypes);
	ebitmap_init(&tclasses);

	while ((id = queue_remove(id_queue))) {
		if (set_types(&stypes, id))
			return -1;
	}

	while ((id = queue_remove(id_queue))) {
		if (set_types(&ttypes, id))
			return -1;
	}

	while ((id = queue_remove(id_queue))) {
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			sprintf(errormsg, "unknown class %s", id);
			yyerror(errormsg);
			goto bad;
		}
		ebitmap_set_bit(&tclasses, cladatum->value - 1, TRUE);
		free(id);
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no newtype?");
		goto bad;
	}
	datum = (type_datum_t *) hashtab_search(policydbp->p_types.table,
						(hashtab_key_t) id);
	if (!datum || datum->isattr) {
		sprintf(errormsg, "unknown type %s", id);
		yyerror(errormsg);
		goto bad;
	}

	for (i = ebitmap_startbit(&stypes); i < ebitmap_length(&stypes); i++) {
		if (!ebitmap_get_bit(&stypes, i)) 
			continue;
		for (j = ebitmap_startbit(&ttypes); j < ebitmap_length(&ttypes); j++) {
			if (!ebitmap_get_bit(&ttypes, j)) 
				continue;
			for (k = ebitmap_startbit(&tclasses); k < ebitmap_length(&tclasses); k++) {
				if (!ebitmap_get_bit(&tclasses, k)) 
					continue;
				avkey.source_type = i + 1;
				avkey.target_type = j + 1;
				avkey.target_class = k + 1;
				avdatump = avtab_search(&policydbp->te_avtab, &avkey, AVTAB_TYPE);
				if (avdatump) {
					switch (which) {
					case AVTAB_TRANSITION:
						newtype = avtab_transition(avdatump);
						break;
					case AVTAB_MEMBER:
						newtype = avtab_member(avdatump);
						break;
					case AVTAB_CHANGE:
						newtype = avtab_change(avdatump);
						break;
					}
					if ( (avdatump->specified & which) &&
					     (newtype != datum->value) ) {
						sprintf(errormsg, "conflicting rule for (%s, %s:%s):  default was %s, is now %s", type_val_to_name(i+1), type_val_to_name(j+1), policydbp->p_class_val_to_name[k],
							type_val_to_name(newtype),
							type_val_to_name(datum->value));
						yywarn(errormsg);
					}
					avdatump->specified |= which;
					switch (which) {
					case AVTAB_TRANSITION:
						avtab_transition(avdatump) = datum->value;
						break;
					case AVTAB_MEMBER:
						avtab_member(avdatump) = datum->value;
						break;
					case AVTAB_CHANGE:
						avtab_change(avdatump) = datum->value;
						break;
					}
				} else {
					memset(&avdatum, 0, sizeof avdatum);
					avdatum.specified |= which;
					switch (which) {
					case AVTAB_TRANSITION:
					        avtab_transition(&avdatum) = datum->value;
						break;
					case AVTAB_MEMBER:
						avtab_member(&avdatum) = datum->value;
						break;
					case AVTAB_CHANGE:
						avtab_change(&avdatum) = datum->value;
						break;
					}
					ret = avtab_insert(&policydbp->te_avtab, &avkey, &avdatum);
					if (ret) {
						yyerror("hash table overflow");
						goto bad;
					}
				}
			}
		}
	}

	return 0;

      bad:
	return -1;
}


static int perm_name(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	struct val_to_name *v = data;
	perm_datum_t *perdatum;

	perdatum = (perm_datum_t *) datum;

	if (v->val == perdatum->value) {
		v->name = key;
		return 1;
	}

	return 0;
}


char *av_to_string(uint32_t tclass, access_vector_t av)
{
	struct val_to_name v;
	static char avbuf[1024];
	class_datum_t *cladatum;
	char *perm = NULL, *p;
	int i, rc;

	cladatum = policydbp->class_val_to_struct[tclass-1];
	p = avbuf;
	for (i = 0; i < cladatum->permissions.nprim; i++) {
		if (av & (1 << i)) {
			v.val = i+1;
			rc = hashtab_map(cladatum->permissions.table,
					 perm_name, &v);
			if (!rc && cladatum->comdatum) {
				rc = hashtab_map(
					cladatum->comdatum->permissions.table,
					perm_name, &v);
			}
			if (rc)
				perm = v.name;
			if (perm) {
				sprintf(p, " %s", perm);
				p += strlen(p);
			}
		}
	}

	return avbuf;
}


static int te_avtab_helper(int which, int stype, int ttype, 
			   ebitmap_t *tclasses, access_vector_t *avp)

{
	avtab_key_t avkey;
	avtab_datum_t avdatum, *avdatump;
	int ret, k;

	if (which == -AVTAB_ALLOWED) {
		yyerror("neverallow should not reach this function.");
		return -1;
	}

	for (k = ebitmap_startbit(tclasses); k < ebitmap_length(tclasses); k++) {
		if (!ebitmap_get_bit(tclasses, k)) 
			continue;
		if (!avp[k])
			continue;
		avkey.source_type = stype + 1;
		avkey.target_type = ttype + 1;
		avkey.target_class = k + 1;
		avdatump = avtab_search(&policydbp->te_avtab, &avkey, AVTAB_AV);
		if (!avdatump) {
			memset(&avdatum, 0, sizeof avdatum);
			avdatum.specified = (which > 0) ? which : -which;
			ret = avtab_insert(&policydbp->te_avtab, &avkey, &avdatum);
			if (ret) {
				yyerror("hash table overflow");
				return -1;
			}
			avdatump = avtab_search(&policydbp->te_avtab, &avkey, AVTAB_AV);
			if (!avdatump) {
				yyerror("inserted entry vanished!");
				return -1;
			}
		}

		avdatump->specified |= ((which > 0) ? which : -which);

		switch (which) {
		case AVTAB_ALLOWED:
			avtab_allowed(avdatump) |= avp[k];
			break;
		case AVTAB_AUDITALLOW:
			avtab_auditallow(avdatump) |= avp[k];
			break;
		case AVTAB_AUDITDENY:
			avtab_auditdeny(avdatump) |= avp[k];
			break;
		case -AVTAB_AUDITDENY:
			if (avtab_auditdeny(avdatump))
				avtab_auditdeny(avdatump) &= ~avp[k];
			else
				avtab_auditdeny(avdatump) = ~avp[k];
			break;
		}
	}

	return 0;
}


static int define_te_avtab(int which)
{
	char *id;
	class_datum_t *cladatum;
	perm_datum_t *perdatum;
	ebitmap_t stypes, ttypes, tclasses;
	access_vector_t *avp;
	int i, j, hiclass, self = 0;
	te_assert_t *newassert;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	ebitmap_init(&stypes);
	ebitmap_init(&ttypes);
	ebitmap_init(&tclasses);

	while ((id = queue_remove(id_queue))) {
		if (set_types(&stypes, id))
			return -1;
	}

	while ((id = queue_remove(id_queue))) {
		if (strcmp(id, "self") == 0) {
			self = 1;
			continue;
		}
		if (set_types(&ttypes, id))
			return -1;
	}

	hiclass = 0;
	while ((id = queue_remove(id_queue))) {
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			sprintf(errormsg, "unknown class %s used in rule", id);
			yyerror(errormsg);
			goto bad;
		}
		ebitmap_set_bit(&tclasses, cladatum->value - 1, TRUE);	
		if (cladatum->value > hiclass)
			hiclass = cladatum->value;
		free(id);
	}

	avp = malloc(hiclass * sizeof(access_vector_t));
	if (!avp) {
		yyerror("out of memory");
		return -1;
	}
	for (i = 0; i < hiclass; i++)
		avp[i] = 0;

	while ((id = queue_remove(id_queue))) {
		int found = 0;
		
		for (i = ebitmap_startbit(&tclasses); i < ebitmap_length(&tclasses); i++) {
			if (!ebitmap_get_bit(&tclasses, i)) 
				continue;
			cladatum = policydbp->class_val_to_struct[i];

			if (strcmp(id, "*") == 0) {
				/* set all permissions in the class */
				avp[i] = ~0;
				found = 1;
				continue;
			}

			if (strcmp(id, "~") == 0) {
				/* complement the set */
				if (which == -AVTAB_AUDITDENY) 
					yywarn("dontaudit rule with a ~?");
				avp[i] = ~avp[i];
				found = 1;
				continue;
			}

			perdatum = hashtab_search(cladatum->permissions.table,
						  id);
			if (!perdatum) {
				if (cladatum->comdatum) {
					perdatum = hashtab_search(cladatum->comdatum->permissions.table,
								  id);
				}
			}

			if (!perdatum) {
				/*  Permission undefined for this class; skip. */
				continue;
			}

			found = 1;
			avp[i] |= (1 << (perdatum->value - 1));
		}

		if (!found) {
			sprintf(errormsg, "permission %s not defined", id);
			yyerror(errormsg);
		}
		
		free(id);
	}

	if (which == -AVTAB_ALLOWED) {
		newassert = malloc(sizeof(te_assert_t));
		if (!newassert) {
			yyerror("out of memory");
			return -1;
		}
		memset(newassert, 0, sizeof(te_assert_t));
		newassert->stypes = stypes;
		newassert->ttypes = ttypes;
		newassert->tclasses = tclasses;
		newassert->self = self;
		newassert->avp = avp;
		newassert->line = policydb_lineno;
		newassert->next = te_assertions;
		te_assertions = newassert;
		return 0;
	}

	for (i = ebitmap_startbit(&stypes); i < ebitmap_length(&stypes); i++) {
		if (!ebitmap_get_bit(&stypes, i)) 
			continue;
		if (self) {
			if (te_avtab_helper(which, i, i, &tclasses, avp))
				return -1;
		}
		for (j = ebitmap_startbit(&ttypes); j < ebitmap_length(&ttypes); j++) {
			if (!ebitmap_get_bit(&ttypes, j)) 
				continue;
			if (te_avtab_helper(which, i, j, &tclasses, avp))
				return -1;
		}
	}

	ebitmap_destroy(&stypes);
	ebitmap_destroy(&ttypes);
	ebitmap_destroy(&tclasses);
	free(avp);

	return 0;
 bad:
	return -1;
}


static int role_val_to_name_helper(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	struct val_to_name *v = p;
	role_datum_t *roldatum;

	roldatum = (role_datum_t *) datum;

	if (v->val == roldatum->value) {
		v->name = key;
		return 1;
	}

	return 0;
}


static char *role_val_to_name(unsigned int val) 
{
	struct val_to_name v;
	int rc;

	v.val = val;
	rc = hashtab_map(policydbp->p_roles.table, 
			 role_val_to_name_helper, &v);
	if (rc)
		return v.name;
	return NULL;
}

static int define_role_types(void)
{
	role_datum_t *role;
	char *role_id, *id;
	int ret;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	role_id = queue_remove(id_queue);

	role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
					       role_id);
	if (!role) {
		role = (role_datum_t *) malloc(sizeof(role_datum_t));
		if (!role) {
			yyerror("out of memory");
			free(role_id);
			return -1;
		}
		memset(role, 0, sizeof(role_datum_t));
		role->value = ++policydbp->p_roles.nprim;
		ebitmap_set_bit(&role->dominates, role->value-1, TRUE);
		ret = hashtab_insert(policydbp->p_roles.table,
				     (hashtab_key_t) role_id, (hashtab_datum_t) role);

		if (ret) {
			yyerror("hash table overflow");
			free(role);
			free(role_id);
			return -1;
		}
	} else
		free(role_id);

	while ((id = queue_remove(id_queue))) {
		if (set_types(&role->types, id))
			return -1;
	}

	return 0;
}


static role_datum_t *
 merge_roles_dom(role_datum_t * r1, role_datum_t * r2)
{
	role_datum_t *new;

	if (pass == 1) {
		return (role_datum_t *)1; /* any non-NULL value */
	}

	new = malloc(sizeof(role_datum_t));
	if (!new) {
		yyerror("out of memory");
		return NULL;
	}
	memset(new, 0, sizeof(role_datum_t));
	new->value = 0;		/* temporary role */
	if (!ebitmap_or(&new->dominates, &r1->dominates, &r2->dominates)) {
		yyerror("out of memory");
		return NULL;
	}
	if (!ebitmap_or(&new->types, &r1->types, &r2->types)) {
		yyerror("out of memory");
		return NULL;
	}
	if (!r1->value) {
		/* free intermediate result */
		ebitmap_destroy(&r1->types);
		ebitmap_destroy(&r1->dominates);
		free(r1);
	}
	if (!r2->value) {
		/* free intermediate result */
		yyerror("right hand role is temporary?");
		ebitmap_destroy(&r2->types);
		ebitmap_destroy(&r2->dominates);
		free(r2);
	}
	return new;
}


static role_datum_t *
 define_role_dom(role_datum_t * r)
{
	role_datum_t *role;
	char *role_id;
	int i, ret;

	if (pass == 1) {
		role_id = queue_remove(id_queue);
		free(role_id);
		return (role_datum_t *)1; /* any non-NULL value */
	}

	role_id = queue_remove(id_queue);
	role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
					       role_id);
	if (!role) {
		role = (role_datum_t *) malloc(sizeof(role_datum_t));
		if (!role) {
			yyerror("out of memory");
			free(role_id);
			return NULL;
		}
		memset(role, 0, sizeof(role_datum_t));
		role->value = ++policydbp->p_roles.nprim;
		ebitmap_set_bit(&role->dominates, role->value-1, TRUE);
		ret = hashtab_insert(policydbp->p_roles.table,
				     (hashtab_key_t) role_id, (hashtab_datum_t) role);

		if (ret) {
			yyerror("hash table overflow");
			free(role);
			free(role_id);
			return NULL;
		}
	}
	if (r) {
		for (i = ebitmap_startbit(&r->dominates); i < ebitmap_length(&r->dominates); i++) {
			if (ebitmap_get_bit(&r->dominates, i))
				ebitmap_set_bit(&role->dominates, i, TRUE);
		}
		for (i = ebitmap_startbit(&r->types); i < ebitmap_length(&r->types); i++)	{
			if (ebitmap_get_bit(&r->types, i))
				ebitmap_set_bit(&role->types, i, TRUE);
		}
		if (!r->value) {
			/* free intermediate result */
			ebitmap_destroy(&r->types);
			ebitmap_destroy(&r->dominates);
			free(r);
		}
	}
	return role;
}


static int set_roles(ebitmap_t *set,
		     char *id)
{
	role_datum_t *r;
	int i;

	if (strcmp(id, "*") == 0) {
		/* set all roles */
		for (i = 0; i < policydbp->p_roles.nprim; i++) 
			ebitmap_set_bit(set, i, TRUE);
		free(id);
		return 0;
	}

	if (strcmp(id, "~") == 0) {
		/* complement the set */
		for (i = 0; i < policydbp->p_roles.nprim; i++) {
			if (ebitmap_get_bit(set, i))
				ebitmap_set_bit(set, i, FALSE);
			else 
				ebitmap_set_bit(set, i, TRUE);
		}
		free(id);
		return 0;
	}

	r = hashtab_search(policydbp->p_roles.table, id);
	if (!r) {
		sprintf(errormsg, "unknown role %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}

	/* set one role */
	ebitmap_set_bit(set, r->value - 1, TRUE);
	free(id);
	return 0;
}


static int define_role_trans(void)
{
	char *id;
	role_datum_t *role;
	ebitmap_t roles, types;
	struct role_trans *tr = 0;
	int i, j;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	yywarn("Role transition rules are DEPRECATED, use domain transitions.");

	ebitmap_init(&roles);
	ebitmap_init(&types);

	while ((id = queue_remove(id_queue))) {
		if (set_roles(&roles, id))
			return -1;
	}

	while ((id = queue_remove(id_queue))) {
		if (set_types(&types, id))
			return -1;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no new role in transition definition?");
		goto bad;
	}
	role = hashtab_search(policydbp->p_roles.table, id);
	if (!role) {
		sprintf(errormsg, "unknown role %s used in transition definition", id);
		yyerror(errormsg);
		goto bad;
	}

	for (i = ebitmap_startbit(&roles); i < ebitmap_length(&roles); i++) {
		if (!ebitmap_get_bit(&roles, i)) 
			continue;
		for (j = ebitmap_startbit(&types); j < ebitmap_length(&types); j++) {
			if (!ebitmap_get_bit(&types, j)) 
				continue;

			for (tr = policydbp->role_tr; tr; tr = tr->next) {
				if (tr->role == (i+1) && tr->type == (j+1)) {
					sprintf(errormsg, "duplicate role transition defined for (%s,%s)", 
						role_val_to_name(i+1), type_val_to_name(j+1));
					yyerror(errormsg);
					goto bad;
				}
			}

			tr = malloc(sizeof(struct role_trans));
			if (!tr) {
				yyerror("out of memory");
				return -1;
			}
			memset(tr, 0, sizeof(struct role_trans));
			tr->role = i+1;
			tr->type = j+1;
			tr->new_role = role->value;
			tr->next = policydbp->role_tr;
			policydbp->role_tr = tr;
		}
	}

	return 0;

 bad:
	return -1;
}


static int define_role_allow(void)
{
	char *id;
	ebitmap_t roles, new_roles;
	struct role_allow *ra = 0;
	int i, j;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	ebitmap_init(&roles);
	ebitmap_init(&new_roles);

	while ((id = queue_remove(id_queue))) {
		if (set_roles(&roles, id))
			return -1;
	}


	while ((id = queue_remove(id_queue))) {
		if (set_roles(&new_roles, id))
			return -1;
	}

	for (i = ebitmap_startbit(&roles); i < ebitmap_length(&roles); i++) {
		if (!ebitmap_get_bit(&roles, i)) 
			continue;
		for (j = ebitmap_startbit(&new_roles); j < ebitmap_length(&new_roles); j++) {
			if (!ebitmap_get_bit(&new_roles, j)) 
				continue;

			for (ra = policydbp->role_allow; ra; ra = ra->next) {
				if (ra->role == (i+1) && ra->new_role == (j+1))
					break;
			}

			if (ra) 
				continue;

			ra = malloc(sizeof(struct role_allow));
			if (!ra) {
				yyerror("out of memory");
				return -1;
			}
			memset(ra, 0, sizeof(struct role_allow));
			ra->role = i+1;
			ra->new_role = j+1;
			ra->next = policydbp->role_allow;
			policydbp->role_allow = ra;
		}
	}

	return 0;
}


static int define_constraint(constraint_expr_t * expr)
{
	struct constraint_node *node;
	char *id;
	class_datum_t *cladatum;
	perm_datum_t *perdatum;
	ebitmap_t classmap;
	constraint_expr_t *e;
	int i, depth;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	depth = -1;
	for (e = expr; e; e = e->next) {
		switch (e->expr_type) {
		case CEXPR_NOT:
			if (depth < 0) {
				yyerror("illegal constraint expression");
				return -1;
			}
			break;
		case CEXPR_AND:
		case CEXPR_OR:
			if (depth < 1) {
				yyerror("illegal constraint expression");
				return -1;
			}
			depth--;
			break;
		case CEXPR_ATTR:
		case CEXPR_NAMES:
			if (depth == (CEXPR_MAXDEPTH-1)) {
				yyerror("constraint expression is too deep");
				return -1;
			}
			depth++;
			break;
		default:
			yyerror("illegal constraint expression");
			return -1;
		}
	}
	if (depth != 0) {
		yyerror("illegal constraint expression");
		return -1;
	}

	ebitmap_init(&classmap);
	while ((id = queue_remove(id_queue))) {
		cladatum = (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						     (hashtab_key_t) id);
		if (!cladatum) {
			sprintf(errormsg, "class %s is not defined", id);
			ebitmap_destroy(&classmap);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		if (!ebitmap_set_bit(&classmap, cladatum->value - 1, TRUE)) {
			yyerror("out of memory");
			ebitmap_destroy(&classmap);
			free(id);
			return -1;
		}
		node = malloc(sizeof(struct constraint_node));
		if (!node) {
			yyerror("out of memory");
			return -1;
		}
		memset(node, 0, sizeof(constraint_node_t));
		node->expr = expr;
		node->permissions = 0;

		node->next = cladatum->constraints;
		cladatum->constraints = node;

		free(id);
	}

	while ((id = queue_remove(id_queue))) {
		for (i = ebitmap_startbit(&classmap); i < ebitmap_length(&classmap); i++) {
			if (ebitmap_get_bit(&classmap, i)) {
				cladatum = policydbp->class_val_to_struct[i];
				node = cladatum->constraints;

				perdatum = (perm_datum_t *) hashtab_search(cladatum->permissions.table,
						     (hashtab_key_t) id);
				if (!perdatum) {
					if (cladatum->comdatum) {
						perdatum = (perm_datum_t *) hashtab_search(cladatum->comdatum->permissions.table,
						     (hashtab_key_t) id);
					}
					if (!perdatum) {
						sprintf(errormsg, "permission %s is not defined", id);
						yyerror(errormsg);
						free(id);
						ebitmap_destroy(&classmap);
						return -1;
					}
				}
				node->permissions |= (1 << (perdatum->value - 1));
			}
		}
		free(id);
	}

	ebitmap_destroy(&classmap);

	return 0;
}


static uintptr_t define_cexpr(uint32_t expr_type, uintptr_t arg1, uintptr_t arg2)
{
	struct constraint_expr *expr, *e1 = NULL, *e2;
	user_datum_t *user;
	role_datum_t *role;
	char *id;
	uint32_t val;

	if (pass == 1) {
		if (expr_type == CEXPR_NAMES) {
			while ((id = queue_remove(id_queue))) 
				free(id);
		}
		return 1; /* any non-NULL value */
	}

	expr = malloc(sizeof(struct constraint_expr));
	if (!expr) {
		yyerror("out of memory");
		return 0;
	}
	memset(expr, 0, sizeof(constraint_expr_t));
	expr->expr_type = expr_type;

	switch (expr_type) {
	case CEXPR_NOT:
		e1 = NULL;
		e2 = (struct constraint_expr *) arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			free(expr);
			return 0;
		}
		e1->next = expr;
		return arg1;
	case CEXPR_AND:
	case CEXPR_OR:
		e1 = NULL;
		e2 = (struct constraint_expr *) arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			free(expr);
			return 0;
		}
		e1->next = (struct constraint_expr *) arg2;

		e1 = NULL;
		e2 = (struct constraint_expr *) arg2;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			free(expr);
			return 0;
		}
		e1->next = expr;
		return arg1;
	case CEXPR_ATTR:
		expr->attr = arg1;
		expr->op = arg2;
		return (uintptr_t)expr;
	case CEXPR_NAMES:
		expr->attr = arg1;
		expr->op = arg2;
		while ((id = (char *) queue_remove(id_queue))) {
			if (expr->attr & CEXPR_USER) {
				user = (user_datum_t *) hashtab_search(policydbp->p_users.table,
								       (hashtab_key_t) id);
				if (!user) {
					sprintf(errormsg, "unknown user %s", id);
					yyerror(errormsg);
					free(expr);
					return 0;
				}
				val = user->value;
			} else if (expr->attr & CEXPR_ROLE) {
				role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
								       (hashtab_key_t) id);
				if (!role) {
					sprintf(errormsg, "unknown role %s", id);
					yyerror(errormsg);
					free(expr);
					return 0;
				}
				val = role->value;
			} else if (expr->attr & CEXPR_TYPE) {
				if (set_types(&expr->names, id)) {
					free(expr);
					return 0;
				}
				continue;
			} else {
				yyerror("invalid constraint expression");
				free(expr);
				return 0;
			}
			if (!ebitmap_set_bit(&expr->names, val - 1, TRUE)) {
				yyerror("out of memory");
				ebitmap_destroy(&expr->names);
				free(expr);
				return 0;
			}
			free(id);
		}
		return (uintptr_t)expr;
	default:
		yyerror("invalid constraint expression");
		free(expr);
		return 0;
	}

	yyerror("invalid constraint expression");
	free(expr);
	return 0;
}


static int set_user_roles(ebitmap_t *set,
			  char *id)
{
	role_datum_t *r;
	int i;

	if (strcmp(id, "*") == 0) {
		/* set all roles */
		for (i = 0; i < policydbp->p_roles.nprim; i++) 
			ebitmap_set_bit(set, i, TRUE);
		free(id);
		return 0;
	}

	if (strcmp(id, "~") == 0) {
		/* complement the set */
		for (i = 0; i < policydbp->p_roles.nprim; i++) {
			if (ebitmap_get_bit(set, i))
				ebitmap_set_bit(set, i, FALSE);
			else 
				ebitmap_set_bit(set, i, TRUE);
		}
		free(id);
		return 0;
	}

	r = hashtab_search(policydbp->p_roles.table, id);
	if (!r) {
		sprintf(errormsg, "unknown role %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}

	/* set the role and every role it dominates */
	for (i = ebitmap_startbit(&r->dominates); i < ebitmap_length(&r->dominates); i++) {
		if (ebitmap_get_bit(&r->dominates, i))
			ebitmap_set_bit(set, i, TRUE);
	}
	free(id);
	return 0;
}


static int define_user(void)
{
	char *id;
	user_datum_t *usrdatum;
	int ret;
#ifdef CONFIG_FLASK_MLS
	mls_range_list_t *rnode;
	level_datum_t *levdatum;
	cat_datum_t *catdatum;
	int relation, l;
	char *levid;
#endif

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
#ifdef CONFIG_FLASK_MLS
		while ((id = queue_remove(id_queue))) { 
			free(id);
			for (l = 0; l < 2; l++) {
				while ((id = queue_remove(id_queue))) { 
					free(id);
				}
			}
		}
#endif
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no user name for user definition?");
		return -1;
	}
	usrdatum = (user_datum_t *) hashtab_search(policydbp->p_users.table,
						   (hashtab_key_t) id);
	if (!usrdatum) {
		usrdatum = (user_datum_t *) malloc(sizeof(user_datum_t));
		if (!usrdatum) {
			yyerror("out of memory");
			free(id);
			return -1;
		}
		memset(usrdatum, 0, sizeof(user_datum_t));
		usrdatum->value = ++policydbp->p_users.nprim;
		ebitmap_init(&usrdatum->roles);
		ret = hashtab_insert(policydbp->p_users.table,
				     (hashtab_key_t) id, (hashtab_datum_t) usrdatum);
		if (ret) {
			yyerror("hash table overflow");
			free(usrdatum);
			free(id);
			return -1;
		}
	} else
		free(id);

	while ((id = queue_remove(id_queue))) {
		if (set_user_roles(&usrdatum->roles, id))
			continue;
	}

#ifdef CONFIG_FLASK_MLS
	id = queue_remove(id_queue);
	if (!id) {
		rnode = (mls_range_list_t *) malloc(sizeof(mls_range_list_t));
		if (!rnode) {
			yyerror("out of memory");
			free(id);
			return -1;
		}
		memset(rnode, 0, sizeof(mls_range_list_t));
		levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
							    (hashtab_key_t) "unclassified");
		if (!levdatum) {
			yyerror("no range for user");
			return -1;
		}
		rnode->range.level[0].sens = levdatum->level->sens;
		rnode->range.level[1].sens = levdatum->level->sens;
		rnode->next = usrdatum->ranges;
		usrdatum->ranges = rnode;
		goto skip_mls;
	} 
	do {
		rnode = (mls_range_list_t *) malloc(sizeof(mls_range_list_t));
		if (!rnode) {
			yyerror("out of memory");
			free(id);
			return -1;
		}
		memset(rnode, 0, sizeof(mls_range_list_t));

		for (l = 0; l < 2; l++) {
			levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						     (hashtab_key_t) id);
			if (!levdatum) {
				sprintf(errormsg, "unknown sensitivity %s used in user range definition", id);
				yyerror(errormsg);
				free(rnode);
				free(id);
				continue;
			}
			rnode->range.level[l].sens = levdatum->level->sens;
			ebitmap_init(&rnode->range.level[l].cat);

			levid = id;

			while ((id = queue_remove(id_queue))) {
				catdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
						     (hashtab_key_t) id);
				if (!catdatum) {
					sprintf(errormsg, "unknown category %s used in user range definition", id);
					yyerror(errormsg);
					free(id);
					continue;
				}
				if (!(ebitmap_get_bit(&levdatum->level->cat, catdatum->value - 1))) {
					sprintf(errormsg, "category %s cannot be associated with level %s", id, levid);
					yyerror(errormsg);
					free(id);
					continue;
				}
				if (!ebitmap_set_bit(&rnode->range.level[l].cat, catdatum->value - 1, TRUE)) {
					yyerror("out of memory");
					free(id);
					free(levid);
					ebitmap_destroy(&rnode->range.level[l].cat);
					free(rnode);
					return -1;
				}

				/*
				 * no need to keep category name
				 */
				free(id);
			}

			/*
			 * no need to keep sensitivity name
			 */
			free(levid);

			id = queue_remove(id_queue);
			if (!id)
				break;
		}

		if (l == 0) {
			rnode->range.level[1].sens = rnode->range.level[0].sens;
			if (!ebitmap_cpy(&rnode->range.level[1].cat, &rnode->range.level[0].cat)) {
				yyerror("out of memory");
				free(id);
				ebitmap_destroy(&rnode->range.level[0].cat);
				free(rnode);
				return -1;
			}
		}
		relation = mls_level_relation(rnode->range.level[1], rnode->range.level[0]);
		if (!(relation & (MLS_RELATION_DOM | MLS_RELATION_EQ))) {
			/* high does not dominate low */
			yyerror("high does not dominate low");
			ebitmap_destroy(&rnode->range.level[0].cat);
			ebitmap_destroy(&rnode->range.level[1].cat);
			free(rnode);
			return -1;
		}
		rnode->next = usrdatum->ranges;
		usrdatum->ranges = rnode;
	} while ((id = queue_remove(id_queue)));
skip_mls:
#endif

	return 0;
}


static int parse_security_context(context_struct_t * c)
{
	char *id;
	role_datum_t *role;
	type_datum_t *typdatum;
	user_datum_t *usrdatum;
#ifdef CONFIG_FLASK_MLS
	char *levid;
	level_datum_t *levdatum;
	cat_datum_t *catdatum;
	int l;
#endif

	if (pass == 1) {
		id = queue_remove(id_queue); free(id); /* user  */
		id = queue_remove(id_queue); free(id); /* role  */
		id = queue_remove(id_queue); free(id); /* type  */
#ifdef CONFIG_FLASK_MLS
		id = queue_remove(id_queue); free(id); 
		for (l = 0; l < 2; l++) {
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
		}
#endif 
		return 0;
	}

	context_init(c);

	/* extract the user */
	id = queue_remove(id_queue);
	if (!id) {
		yyerror("no effective user?");
		goto bad;
	}
	usrdatum = (user_datum_t *) hashtab_search(policydbp->p_users.table,
						   (hashtab_key_t) id);
	if (!usrdatum) {
		sprintf(errormsg, "user %s is not defined", id);
		yyerror(errormsg);
		free(id);
		goto bad;
	}
	c->user = usrdatum->value;

	/* no need to keep the user name */
	free(id);

	/* extract the role */
	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no role name for sid context definition?");
		return -1;
	}
	role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
					       (hashtab_key_t) id);
	if (!role) {
		sprintf(errormsg, "role %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	c->role = role->value;

	/* no need to keep the role name */
	free(id);


	/* extract the type */
	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for sid context definition?");
		return -1;
	}
	typdatum = (type_datum_t *) hashtab_search(policydbp->p_types.table,
						   (hashtab_key_t) id);
	if (!typdatum || typdatum->isattr) {
		sprintf(errormsg, "type %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	c->type = typdatum->value;

	/* no need to keep the type name */
	free(id);

#ifdef CONFIG_FLASK_MLS
	/* extract the low sensitivity */
	id = (char *) queue_head(id_queue);
	if (!id || strcmp(id, "system_u") == 0 /* hack */) {
		/* No MLS component to the security context.  Try
		   to use a default 'unclassified' value. */
		levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
							    (hashtab_key_t) "unclassified");
		if (!levdatum) {
			yyerror("no sensitivity name for sid context definition?");
			return -1;
		}
		c->range.level[0].sens = levdatum->level->sens;
		c->range.level[1].sens = levdatum->level->sens;
		goto skip_mls;
	}

	id = (char *) queue_remove(id_queue);
	for (l = 0; l < 2; l++) {
		levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						     (hashtab_key_t) id);
		if (!levdatum) {
			sprintf(errormsg, "Sensitivity %s is not defined", id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		c->range.level[l].sens = levdatum->level->sens;

		/* extract low category set */
		levid = id;
		while ((id = queue_remove(id_queue))) {
			catdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
						     (hashtab_key_t) id);
			if (!catdatum) {
				sprintf(errormsg, "unknown category %s used in initial sid context", id);
				yyerror(errormsg);
				free(levid);
				free(id);
				goto bad;
			}
			if (!ebitmap_set_bit(&c->range.level[l].cat,
					     catdatum->value - 1, TRUE)) {
				yyerror("out of memory");
				free(levid);
				free(id);
				goto bad;
			}
			/* no need to keep category name */
			free(id);
		}

		/* no need to keep the sensitivity name */
		free(levid);

		/* extract high sensitivity */
		id = (char *) queue_remove(id_queue);
		if (!id)
			break;
	}

	if (l == 0) {
		c->range.level[1].sens = c->range.level[0].sens;
		if (!ebitmap_cpy(&c->range.level[1].cat, &c->range.level[0].cat)) {

			yyerror("out of memory");
			goto bad;
		}
	}
skip_mls:
#endif

	if (!policydb_context_isvalid(policydbp, c)) {
		yyerror("invalid security context");
		goto bad;
	}
	return 0;

      bad:
	context_destroy(c);

	return -1;
}


static int define_initial_sid_context(void)
{
	char *id;
	ocontext_t *c, *head;

	if (pass == 1) {
		id = (char *) queue_remove(id_queue); free(id);
		parse_security_context(NULL);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no sid name for SID context definition?");
		return -1;
	}
	head = policydbp->ocontexts[OCON_ISID];
	for (c = head; c; c = c->next) {
		if (!strcmp(id, c->u.name))
			break;
	}

	if (!c) {
		sprintf(errormsg, "SID %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	if (c->context[0].user) {
		sprintf(errormsg, "The context for SID %s is multiply defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	/* no need to keep the sid name */
	free(id);

	if (parse_security_context(&c->context[0]))
		return -1;

	return 0;
}

static int define_fs_context(int major, int minor)
{
	ocontext_t *newc, *c, *head;

	if (pass == 1) {
		parse_security_context(NULL);
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *) malloc(6);
	if (!newc->u.name) {
		yyerror("out of memory");
		free(newc);
		return -1;
	}
	sprintf(newc->u.name, "%02x:%02x", major, minor);

	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[1])) {
		context_destroy(&newc->context[0]);
		free(newc->u.name);
		free(newc);
		return -1;
	}
	head = policydbp->ocontexts[OCON_FS];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg, "duplicate entry for file system %s", newc->u.name);
			yyerror(errormsg);
			context_destroy(&newc->context[0]);
			context_destroy(&newc->context[1]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_FS] = newc;

	return 0;
}

static int define_port_context(int low, int high)
{
	ocontext_t *newc;
	char *id;

	if (pass == 1) {
		id = (char *) queue_remove(id_queue); free(id);
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	id = (char *) queue_remove(id_queue);
	if (!id) {
		free(newc);
		return -1;
	}
	if ((strcmp(id, "tcp") == 0) || (strcmp(id, "TCP") == 0)) {
		newc->u.port.protocol = IPPROTO_TCP;
	} else if ((strcmp(id, "udp") == 0) || (strcmp(id, "UDP") == 0)) {
		newc->u.port.protocol = IPPROTO_UDP;
	} else {
		sprintf(errormsg, "unrecognized protocol %s", id);
		yyerror(errormsg);
		free(newc);
		return -1;
	}

	newc->u.port.low_port = low;
	newc->u.port.high_port = high;

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}
	newc->next = policydbp->ocontexts[OCON_PORT];
	policydbp->ocontexts[OCON_PORT] = newc;
	return 0;
}

static int define_netif_context(void)
{
	ocontext_t *newc, *c, *head;

	if (pass == 1) {
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *) queue_remove(id_queue);
	if (!newc->u.name) {
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[1])) {
		context_destroy(&newc->context[0]);
		free(newc->u.name);
		free(newc);
		return -1;
	}
	head = policydbp->ocontexts[OCON_NETIF];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg, "duplicate entry for network interface %s", newc->u.name);
			yyerror(errormsg);
			context_destroy(&newc->context[0]);
			context_destroy(&newc->context[1]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_NETIF] = newc;
	return 0;
}

static int define_node_context(int addr, int mask)
{
	ocontext_t *newc, *c, *l, *head;

	if (pass == 1) {
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.node.addr = addr;
	newc->u.node.mask = mask;

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}
	/* Place this at the end of the list, to retain
	   the matching order specified in the configuration. */
	head = policydbp->ocontexts[OCON_NODE];
	for (l = NULL, c = head; c; l = c, c = c->next);

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_NODE] = newc;

	return 0;
}

static int define_fs_use(int behavior)
{
	ocontext_t *newc, *c, *head;

	if (pass == 1) {
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *) queue_remove(id_queue);
	if (!newc->u.name) {
		free(newc);
		return -1;
	}
	newc->v.behavior = behavior;
	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}

	head = policydbp->ocontexts[OCON_FSUSE];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg, "duplicate fs_use entry for filesystem type %s", newc->u.name);
			yyerror(errormsg);
			context_destroy(&newc->context[0]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_FSUSE] = newc;
	return 0;
}

static int define_genfs_context_helper(char *fstype, int has_type)
{
	struct genfs *genfs_p, *genfs, *newgenfs;
	ocontext_t *newc, *c, *head, *p;
	char *type = NULL;
	int len, len2;

	if (pass == 1) {
		free(fstype);
		free(queue_remove(id_queue));
		if (has_type)
			free(queue_remove(id_queue));
		parse_security_context(NULL);
		return 0;
	}

	for (genfs_p = NULL, genfs = policydbp->genfs; 
	     genfs; genfs_p = genfs, genfs = genfs->next) {
		if (strcmp(fstype, genfs->fstype) <= 0)
			break;
	}

	if (!genfs || strcmp(fstype, genfs->fstype)) {
		newgenfs = malloc(sizeof(struct genfs));
		if (!newgenfs) {
			yyerror("out of memory");
			return -1;
		}
		memset(newgenfs, 0, sizeof(struct genfs));
		newgenfs->fstype = fstype;
		newgenfs->next = genfs;
		if (genfs_p) 
			genfs_p->next = newgenfs;
		else
			policydbp->genfs = newgenfs;
		genfs = newgenfs;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *) queue_remove(id_queue);
	if (!newc->u.name) 
		goto fail;
	if (has_type) {
		type = (char *) queue_remove(id_queue);
		if (!type) 
			goto fail;
		if (type[1] != 0) {
			sprintf(errormsg, "invalid type %s", type);
			yyerror(errormsg);
			goto fail;
		}
		switch (type[0]) {
		case 'b':
			newc->v.sclass = SECCLASS_BLK_FILE;
			break;
		case 'c':
			newc->v.sclass = SECCLASS_CHR_FILE;
			break;
		case 'd':
			newc->v.sclass = SECCLASS_DIR;
			break;
		case 'p':
			newc->v.sclass = SECCLASS_FIFO_FILE;
			break;
		case 'l':
			newc->v.sclass = SECCLASS_LNK_FILE;
			break;
		case 's':
			newc->v.sclass = SECCLASS_SOCK_FILE;
			break;
		case '-':
			newc->v.sclass = SECCLASS_FILE;
			break;
		default:
			sprintf(errormsg, "invalid type %s", type);
			yyerror(errormsg);
			goto fail;
		}
	}
	if (parse_security_context(&newc->context[0])) 
		goto fail;

	head = genfs->head;

	for (p = NULL, c = head; c; p = c, c = c->next) {
		if (!strcmp(newc->u.name, c->u.name) && 
		    (!newc->v.sclass || !c->v.sclass || newc->v.sclass == c->v.sclass)) {
			sprintf(errormsg, "duplicate entry for genfs entry (%s, %s)", fstype, newc->u.name);
			yyerror(errormsg);
			goto fail;
		}
		len = strlen(newc->u.name);
		len2 = strlen(c->u.name);
		if (len > len2)
			break;
	}

	newc->next = c;
	if (p) 
		p->next = newc;
	else
		genfs->head = newc;
	return 0;
fail:
	if (type)
		free(type);
	context_destroy(&newc->context[0]);
	if (fstype)
		free(fstype);
	if (newc->u.name)
		free(newc->u.name);
	free(newc);
	return -1;
}

static int define_genfs_context(int has_type)
{
	return define_genfs_context_helper(queue_remove(id_queue), has_type);
}

/* FLASK */


