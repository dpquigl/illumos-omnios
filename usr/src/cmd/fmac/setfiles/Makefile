#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Original files contributed to OpenSolaris.org under license by the
# United States Government (NSA) to Sun Microsystems, Inc.
#

# Installation directories.

PROG = setfiles

include ../../Makefile.cmd

CPPFLAGS += -D_FILE_OFFSET_BITS=64

C99MODE = -xc99=%all
C99LMODE = -Xc99=%all

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTSBINPROG)

clean:

lint:	lint_PROG

#relabel: install
#	setfilecon system_u:object_r:setfiles_exec_t $(SBINDIR)/setfiles

include ../../Makefile.targ
