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

#ifndef _FMAC_PRIVATE_H
#define	_FMAC_PRIVATE_H

/*
 * Block comment that describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

const char *fmac_default_type_path();
const char *fmac_policy_root();
const char *fmac_path();
const char *fmac_default_context_path();
const char *fmac_securetty_types_path();
const char *fmac_failsafe_context_path();
const char *fmac_removable_context_path();
const char *fmac_binary_policy_path();
const char *fmac_file_context_path();
const char *fmac_homedir_context_path();
const char *fmac_media_context_path();
const char *fmac_customizable_types_path();
const char *fmac_contexts_path();
const char *fmac_user_contexts_path();
const char *fmac_booleans_path();
const char *fmac_users_path();
const char *fmac_default_user_path();
const char *fmac_default_translations_path();
const char *fmac_netfilter_context_path();
const char *fmac_file_context_homedir_path();
const char *fmac_file_context_local_path();
const char *fmac_x_context_path();

#ifdef __cplusplus
}
#endif

#endif /* _FMAC_PRIVATE_H */
