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
 * Global definitions that are included at the beginning
 * of every file using the -include directive.
 *
 * These definitions are used to permit the same
 * source code to be used to build both the security
 * server component of the kernel and the checkpolicy
 * program.
 */

#ifndef _SS_IMPL_H
#define	_SS_IMPL_H

#if defined(_KERNEL)
#include <sys/inttypes.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#else
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <sys/byteorder.h>

/*
 * Comment out the line below if you want to build
 * the security server without MLS.
 */
#define	CONFIG_FLASK_MLS

#define	SS_CPU_TO_LE32(x)	cpu_to_le32(x)
#define	SS_LE32_TO_CPU(x)	le32_to_cpu(x)
#define	SS_CPU_TO_LE64(x)	cpu_to_le64(x)
#define	SS_LE64_TO_CPU(x)	le64_to_cpu(x)

static uint32_t
cpu_to_le32(uint32_t x)
{
	return (LE_32(x));
}
#pragma inline(cpu_to_le32)

static uint32_t
le32_to_cpu(uint32_t x)
{
	return (LE_32(x));
}
#pragma inline(le32_to_cpu)

static uint64_t
le64_to_cpu(uint64_t x)
{
	return (LE_64(x));
}
#pragma inline(le64_to_cpu)

static uint64_t
cpu_to_le64(uint64_t x)
{
	return (LE_64(x));
}
#pragma inline(cpu_to_le64)

#if defined(_KERNEL)
#define	SS_ALLOC_SLEEP(s)	kmem_alloc((s), KM_SLEEP)
#define	SS_ALLOC_NOSLEEP(s)	kmem_alloc((s), KM_NOSLEEP)
#define	SS_FREE(p, s)		kmem_free((p), (s))
#else
#define	SS_ALLOC_SLEEP(s)	malloc((s))
#define	SS_ALLOC_NOSLEEP(s)	malloc((s))
#define	SS_FREE(p, s)		free((p))
#endif

#endif /* _SS_IMPL_H */
