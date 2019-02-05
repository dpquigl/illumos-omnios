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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

FMACPROG= sysadm_u user_u

include ../../../../Makefile.cmd

FMACCONTEXTSUSERSD= $(ROOTETC)/security/fmac/contexts/users
FMACCONTEXTSUSERSPROG=	$(FMACPROG:%=$(FMACCONTEXTSUSERSD)/%)
FILEMODE= 0644
OWNER= root
GROUP= sys

.KEEP_STATE:

all: $(FMACPROG)

install: all $(FMACCONTEXTSUSERSD) $(FMACCONTEXTSUSERSPROG)

$(FMACCONTEXTSUSERSD)/% : %
	$(INS.file)

$(FMACCONTEXTSUSERSD):
	$(INS.dir)

FRC:

clean clobber lint:

include ../../../../Makefile.targ
