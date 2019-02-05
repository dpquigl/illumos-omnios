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

/*
 * This source code originated from
 * http://www.nsa.gov/selinux/archives/libselinux-2.0.65.tgz
 * with the following LICENSE file in the top-level of the tar archive:
 *
 * This library (libselinux) is public domain software, i.e. not copyrighted.
 *
 * Warranty Exclusion
 * ------------------
 * You agree that this software is a
 * non-commercially developed program that may contain "bugs" (as that
 * term is used in the industry) and that it may not function as intended.
 * The software is licensed "as is". NSA makes no, and hereby expressly
 * disclaims all, warranties, express, implied, statutory, or otherwise
 * with respect to the software, including noninfringement and the implied
 * warranties of merchantability and fitness for a particular purpose.
 *
 * Limitation of Liability
 * -----------------------
 * In no event will NSA be liable for any damages, including loss of data,
 * lost profits, cost of cover, or other special, incidental,
 * consequential, direct or indirect damages arising from the software or
 * the use thereof, however caused and on any theory of liability. This
 * limitation will apply even if NSA has been advised of the possibility
 * of such damage. You acknowledge that this is a reasonable allocation of
 * risk.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include "fmac_private.h"

#define	FMACDIR "/etc/security/fmac"
#define	FMACCONFIG FMACDIR "config"
#define	FMACDEFAULT "targeted"
#define	FMACTYPETAG "FMACTYPE="
#define	FMACTAG "FMAC="
#define	SETLOCALDEFS "SETLOCALDEFS="
#define	REQUIRESEUSERS "REQUIRESEUSERS="

/* Indices for file paths arrays. */
#define	BINPOLICY		0
#define	CONTEXTS_DIR		1
#define	FILE_CONTEXTS		2
#define	HOMEDIR_CONTEXTS	3
#define	DEFAULT_CONTEXTS	4
#define	USER_CONTEXTS		5
#define	FAILSAFE_CONTEXT	6
#define	DEFAULT_TYPE		7
#define	BOOLEANS		8
#define	MEDIA_CONTEXTS		9
#define	REMOVABLE_CONTEXT	10
#define	CUSTOMIZABLE_TYPES	11
#define	USERS_DIR		12
#define	DEFAULT_USER		13
#define	TRANSLATIONS		14
#define	NETFILTER_CONTEXTS	15
#define	FILE_CONTEXTS_HOMEDIR	16
#define	FILE_CONTEXTS_LOCAL	17
#define	SECURETTY_TYPES		18
#define	X_CONTEXTS		19
#define	NEL			20

#define	FMAC_PATH(s)	FMACDIR s

/* New layout is relative to FMACDIR/policytype. */
static char *file_paths[NEL] = {
	FMAC_PATH("/ss_policy"),
	FMAC_PATH("/contexts"),
	FMAC_PATH("/contexts/files/file_contexts"),
	FMAC_PATH("/contexts/files/homedir_template"),
	FMAC_PATH("/contexts/default_contexts"),
	FMAC_PATH("/contexts/users/"),
	FMAC_PATH("/contexts/failsafe_context"),
	FMAC_PATH("/contexts/default_type"),
	FMAC_PATH("/booleans"),
	FMAC_PATH("/contexts/files/media"),
	FMAC_PATH("/contexts/removable_context"),
	FMAC_PATH("/contexts/customizable_types"),
	FMAC_PATH("/users/"),
	FMAC_PATH("/default_user"),
	FMAC_PATH("/setrans.conf"),
	FMAC_PATH("/contexts/netfilter_contexts"),
	FMAC_PATH("/contexts/files/file_contexts.homedirs"),
	FMAC_PATH("/contexts/files/file_contexts.local"),
	FMAC_PATH("/contexts/securetty_types"),
	FMAC_PATH("/contexts/x_contexts")
};

static char *fmac_policyroot = FMACDIR;
static char *fmac_rootpath = FMACDIR;

static const char *
get_path(int idx)
{
	return (file_paths[idx]);
}

const char *
fmac_default_type_path()
{
	return (get_path(DEFAULT_TYPE));
}


const char *
fmac_policy_root()
{
	return (fmac_policyroot);
}

const char *
fmac_path()
{
	return (fmac_rootpath);
}

const char *
fmac_default_context_path()
{
	return (get_path(DEFAULT_CONTEXTS));
}

const char *
fmac_securetty_types_path()
{
	return (get_path(SECURETTY_TYPES));
}

const char *
fmac_failsafe_context_path()
{
	return (get_path(FAILSAFE_CONTEXT));
}

const char *
fmac_removable_context_path()
{
	return (get_path(REMOVABLE_CONTEXT));
}

const char *
fmac_binary_policy_path()
{
	return (get_path(BINPOLICY));
}

const char *
fmac_file_context_path()
{
	return (get_path(FILE_CONTEXTS));
}

const char *
fmac_homedir_context_path()
{
	return (get_path(HOMEDIR_CONTEXTS));
}

const char *
fmac_media_context_path()
{
	return (get_path(MEDIA_CONTEXTS));
}

const char *
fmac_customizable_types_path()
{
	return (get_path(CUSTOMIZABLE_TYPES));
}

const char *
fmac_contexts_path()
{
	return (get_path(CONTEXTS_DIR));
}

const char *
fmac_user_contexts_path()
{
	return (get_path(USER_CONTEXTS));
}

const char *
fmac_booleans_path()
{
	return (get_path(BOOLEANS));
}

const char *
fmac_users_path()
{
	return (get_path(USERS_DIR));
}

const char *
fmac_default_user_path()
{
	return (get_path(DEFAULT_USER));
}

const char *
fmac_translations_path()
{
	return (get_path(TRANSLATIONS));
}

const char *
fmac_netfilter_context_path()
{
	return (get_path(NETFILTER_CONTEXTS));
}

const char *
fmac_file_context_homedir_path()
{
	return (get_path(FILE_CONTEXTS_HOMEDIR));
}

const char *
fmac_file_context_local_path()
{
	return (get_path(FILE_CONTEXTS_LOCAL));
}

const char *
fmac_x_context_path()
{
	return (get_path(X_CONTEXTS));
}
