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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Original files contributed to OpenSolaris.org under license by the
# United States Government (NSA) to Sun Microsystems, Inc.
#

#
# Makefile for building the checkpolicy program
#

MYPROG =		checkpolicy
PROG =			$(MYPROG)

include ../../Makefile.cmd

LOCAL_OBJS =		queue.o		\
			write.o		\
			policy_parse.o	\
			policy_scan.o	\
			checkpolicy.o

COMMON_OBJS =

COMMON_SS_OBJS =	ebitmap.o	\
			hashtab.o	\
			symtab.o	\
			sidtab.o	\
			avtab.o		\
			policydb.o	\
			services.o

CHECK_FOR_MLS =		if $(EGREP) -s '^\#define.CONFIG_FLASK_MLS'	\
				$(SRC)/common/fmac/ss/ss_impl.h ; then	\
				echo "mls.o" ;				\
			else						\
				echo "" ;				\
			fi ;

MLS_OBJ =		$(CHECK_FOR_MLS:sh)

COMMON_SS_OBJS +=	$(MLS_OBJ)

OBJS =			$(LOCAL_OBJS)	\
			$(COMMON_OBJS)	\
			$(COMMON_SS_OBJS)

LOCAL_SRCS =		$(LOCAL_OBJS:%.o=%.c)

COMMON_SRCS =		$(COMMON_OBJS:%.o=$(SRC)/common/fmac/%.c)

COMMON_SS_SRCS =	$(COMMON_SS_OBJS:%.o=$(SRC)/common/fmac/ss/%.c)

SRCS =			$(LOCAL_SRCS)	\
			$(COMMON_SRCS)	\
			$(COMMON_SS_SRCS)

LNTS =			$(OBJS:.o=.po)

INCS += -I.
INCS += -I../../../common/fmac/ss

CPPFLAGS += $(INCS)

LFLAGS += -t
YFLAGS += -d

C99MODE = -xc99=%all

CLOBBERFILES += policy_scan.c policy_parse.c policy_parse.h

PDFILES = 	$(PROG)_all.po
LDLIBS +=	-ll -lnsl

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(PROFILE): $(POFILES)
	$(CAT) $(PROFILES) > $(POFILE)

policy_scan.c: policy_scan.l policy_parse.h
	$(LEX) $(LFLAGS) policy_scan.l > $@

policy_parse.h policy_parse.c: policy_parse.y
	$(YACC) $(YFLAGS) policy_parse.y
	@$(MV) y.tab.h policy_parse.h
	@$(MV) y.tab.c policy_parse.c

install: all $(ROOTSBINPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

%.o: %.c
	$(COMPILE.c) $<

%.o: $(SRC)/common/fmac/%.c
	$(COMPILE.c) $<

%.o: $(SRC)/common/fmac/ss/%.c
	$(COMPILE.c) $<

%.ln: $(SRCS)
	$(LINT.c) $(LINTFLAGS) $(SRCS) $(@:.ln=.c)

%.ln: $(SRC)/common/fmac/%.c
	$(LINT.c) $(LINTFLAGS) -c $<

%.ln: $(SRC)/common/fmac/ss/%.c
	$(LINT.c) $(LINTFLAGS) -c $<

relabel: install
	setfilecon system_u:object_r:checkpolicy_exec_t $(BINDIR)/checkpolicy

include ../../Makefile.targ
