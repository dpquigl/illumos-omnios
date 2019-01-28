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

#ifndef _FMAC_H
#define	_FMAC_H

/*
 * Flexible Mandatory Access Control (FMAC)
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/fmac/fmac.h>
#include <sys/fmac/flask_types.h>

int security_load_policy(char *path);

int security_compute_av(security_context_t scontext,
    security_context_t tcontext, security_class_t tclass,
    access_vector_t request, struct av_decision *avd);
int security_compute_user(security_context_t scontext, const char *username,
    security_context_t **context);
int security_check_context(security_context_t context);
int security_getenforce(void);
int security_setenforce(int mode);
int is_fmac_enabled(void);
int getcon(security_context_t *context);
int getpidcon(pid_t pid, security_context_t *context);
int getexeccon(security_context_t *context);
int setexeccon(security_context_t context);
int getprevcon(security_context_t *context);
void freecon(security_context_t context);
void freeconary(security_context_t *context);
int getfilecon(const char *path, char **secctxp);
int setfilecon(const char *path, char *secctx);
int getfmacuserbyname(const char *name, char **fmacuser, char **level);
int get_default_type(const char *role, char **type);
int get_default_context(const char *user, security_context_t fromcon,
    security_context_t *newcon);
int get_default_context_with_level(const char *user, const char *level,
    security_context_t fromcon, security_context_t *newcon);
int get_default_context_with_role(const char *user, const char *role,
    security_context_t fromcon, security_context_t *newcon);
int get_default_context_with_rolelevel(const char *user, const char *role,
    const char *level, security_context_t fromcon, security_context_t *newcon);
int get_ordered_context_list(const char *user, security_context_t fromcon,
    security_context_t **list);
int get_ordered_context_list_with_level(const char *user, const char *level,
    security_context_t fromcon, security_context_t **list);
#ifdef __cplusplus
}
#endif

#endif /* _FMAC_H */