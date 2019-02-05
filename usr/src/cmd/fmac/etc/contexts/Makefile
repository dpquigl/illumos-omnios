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

FMACPROG= default_type default_contexts failsafe_context
SUBDIRS= users

include ../../../Makefile.cmd

all:=			TARGET= all
install:=		TARGET= install

FMACCONTEXTSD=		$(ROOTETC)/security/fmac/contexts
FMACCONTEXTSPROG=	$(FMACPROG:%=$(FMACCONTEXTSD)/%)

FILEMODE= 0644
OWNER= root
GROUP= sys

.KEEP_STATE:

all: $(FMACPROG)

install:	all $(FMACCONTEXTSD) $(FMACCONTEXTSPROG) $(SUBDIRS)

$(FMACCONTEXTSD)/% : %
	$(INS.file)

$(FMACCONTEXTSD):
	$(INS.dir)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

clean clobber lint:

include ../../../Makefile.targ
