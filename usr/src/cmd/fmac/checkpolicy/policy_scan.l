%array

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

#include <strings.h>
#include "policy_parse.h"

static char linebuf[2][255];
static unsigned int lno = 0;

unsigned long policydb_lineno = 1;

unsigned int policydb_errors = 0;

int yywarn(char *msg);
%}
%e 5000
%p 12500
%a 10000
%n 2500
letter		[A-Za-z]
digit		[0-9]
octet		({digit}{1,3})
ipv4address	{octet}((\.{octet}){3})
%%
\n.*				{ strncpy(linebuf[lno], yytext+1, 255);
                                  linebuf[lno][254] = 0;
                                  lno = 1 - lno; 
                                  policydb_lineno++;
                                  yyless(1); }
CLONE |
clone				{ return(CLONE); }
COMMON |
common				{ return(COMMON); }
CLASS |
class				{ return(CLASS); }
CONSTRAIN |
constrain			{ return(CONSTRAIN); }
INHERITS |
inherits			{ return(INHERITS); }
SID |
sid				{ return(SID); }
ROLE |
role				{ return(ROLE); }
ROLES |
roles				{ return(ROLES); }
TYPES |
types				{ return(TYPES); }
TYPE |
type				{ return(TYPE); }
ALIAS |
alias				{ return(ALIAS); }
ATTRIBUTE |
attribute			{ return(ATTRIBUTE); }
TYPE_TRANSITION |
type_transition			{ return(TYPE_TRANSITION); }
TYPE_MEMBER |
type_member			{ return(TYPE_MEMBER); }
TYPE_CHANGE |
type_change			{ return(TYPE_CHANGE); }
ROLE_TRANSITION |
role_transition			{ return(ROLE_TRANSITION); }
SENSITIVITY |
sensitivity		{ return(SENSITIVITY); }
DOMINANCE |
dominance			{ return(DOMINANCE); }
CATEGORY |
category			{ return(CATEGORY); }
LEVEL |
level				{ return(LEVEL); }
RANGES |
ranges				{ return(RANGES); }
USER |
user				{ return(USER); }
NEVERALLOW |
neverallow		        { return(NEVERALLOW); }
ALLOW |
allow			        { return(ALLOW); }
AUDITALLOW |
auditallow		        { return(AUDITALLOW); }
AUDITDENY |
auditdeny		        { return(AUDITDENY); }
DONTAUDIT |
dontaudit                       { return(DONTAUDIT); }
SOURCE |
source			        { return(SOURCE); }
TARGET |
target			        { return(TARGET); }
SAMEUSER |
sameuser			{ return(SAMEUSER);}
OR |
or     			        { return(OR);}
AND |
and				{ return(AND);}
NOT |
not				{ return(NOT);}
eq |
EQ				{ return(EQUALS);}
dom |
DOM				{ return(DOM);}
domby |
DOMBY				{ return(DOMBY);}
INCOMP |
incomp				{ return(INCOMP);}
fscon |
FSCON                           { return(FSCON);}
portcon |
PORTCON                        { return(PORTCON);}
netifcon |                     
NETIFCON                       { return(NETIFCON);}
nodecon |                     
NODECON                       { return(NODECON);}
fs_use_xattr |
FS_USE_XATTR                     {return(FSUSEXATTR);}
fs_use_task |
FS_USE_TASK                     {return(FSUSETASK);}
fs_use_trans |
FS_USE_TRANS                    {return(FSUSETRANS);}
genfscon |
GENFSCON                        { return(GENFSCON);}
r1 |
R1				{ return(R1); }
r2 |
R2				{ return(R2); }
u1 |
U1				{ return(U1); }
u2 |
U2				{ return(U2); }
t1 |
T1				{ return(T1); }
t2 |
T2				{ return(T2); }
"/"({letter}|{digit}|_|"."|"-"|"/")*	{ return(PATH); }
{letter}({letter}|{digit}|_)*	{ return(IDENTIFIER); }
{letter}({letter}|{digit}|_|"."|"-")*	{ return(USER_IDENTIFIER); }
{digit}{digit}*                 { return(NUMBER); }
{ipv4address}			{ return(IPV4ADDRESS); }
#[^\n]*                         { /* delete comments */ }
[ \t\f]+			{ /* delete whitespace */ }
"==" 				{ return(EQUALS); }
"!="				{ return (NOTEQUAL); }
"&&"				{ return (AND); }
"||"				{ return (OR); }
"!"				{ return (NOT); }
"," |
":" |
";" |
"(" | 
")" |
"{" | 
"}" |
"[" |
"-" |
"." |
"]" |
"~" |
"*"				{ return(yytext[0]); } 
.                               { yywarn("unrecognized character");}
%%
int yyerror(char *msg)
{
	fprintf(stderr, "ERROR '%s' at token '%s' on line %ld:\n%s\n%s\n",
			msg,
			yytext,
			policydb_lineno,
			linebuf[0], linebuf[1]);
	policydb_errors++;
	return -1;
}

int yywarn(char *msg)
{
	fprintf(stderr, "WARNING '%s' at token '%s' on line %ld:\n%s\n%s\n",
			msg,
			yytext,
			policydb_lineno,
			linebuf[0], linebuf[1]);
	return 0;
}


