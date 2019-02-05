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
# Makefile for the security policy.
#
# Targets:
# 
# policy - compile the policy configuration.
# install - compile and install the policy configuration.
# load    - compile, install, and load the policy configuration.
# relabel - relabel the file system based on file_contexts.
#
# The default target is 'policy'.
#

include ../../Makefile.cmd

M4FLAGS = -B81920

COMMONBASE = $(SRC)/common

PRIVS_AWK = $(SRC)/uts/common/os/privs.awk
PRIVS_DEF = $(SRC)/uts/common/os/priv_defs

# Detect if MLS is enabled
CHECK_FOR_MLS =		if $(EGREP) -s '^\#define.CONFIG_FLASK_MLS'	\
				$(SRC)/common/fmac/ss/ss_impl.h ; then	\
				echo "yes" ;				\
			else						\
				echo "" ;				\
			fi ;

CHECKPOLICY = ../checkpolicy/checkpolicy

SETFILES = ../setfiles/setfiles

MLS_FLAG =		$(CHECK_FOR_MLS:sh)

ADMIN_DOMAINS =		domains/admin/sysadm.te

PROGRAM_DOMAINS =	domains/program/crontab.te		\
			domains/program/fsadm.te		\
			domains/program/gnome-pty-helper.te	\
			domains/program/ifconfig.te		\
			domains/program/logrotate.te		\
			domains/program/lpr.te			\
			domains/program/mail.te			\
			domains/program/modutil.te		\
			domains/program/mozilla.te		\
			domains/program/newrole.te		\
			domains/program/passwd.te		\
			domains/program/su.te			\
			domains/program/utempter.te		\
			domains/program/xserver.te

SYSTEM_DOMAINS =	domains/system/apmd.te			\
			domains/system/atd.te			\
			domains/system/cardmgr.te		\
			domains/system/crond.te			\
			domains/system/ftpd.te			\
			domains/system/getty.te			\
			domains/system/gpm.te			\
			domains/system/inetd.te			\
			domains/system/init.te			\
			domains/system/initrc.te		\
			domains/system/kernel.te		\
			domains/system/klogd.te			\
			domains/system/kmod.te			\
			domains/system/login.te			\
			domains/system/lpd.te			\
			domains/system/portmap.te		\
			domains/system/rlogind.te		\
			domains/system/rpcd.te			\
			domains/system/rshd.te			\
			domains/system/sendmail.te		\
			domains/system/sshd.te			\
			domains/system/syslogd.te		\
			domains/system/tcpd.te			\
			domains/system/xfs.te			\
			domains/system/ypbind.te

USER_DOMAINS =		domains/user/user.te

ALL_DOMAINS =		$(ADMIN_DOMAINS)			\
			$(PROGRAM_DOMAINS)			\
			$(SYSTEM_DOMAINS)			\
			$(USER_DOMAINS)

TYPES =			types/device.te				\
			types/devpts.te				\
			types/file.te				\
			types/network.te			\
			types/nfs.te				\
			types/procfs.te				\
			types/security.te

ALL_TE = macros.te attrib.te $(TYPES) domains/every.te $(SYSTEM_DOMAINS) $(PROGRAM_DOMAINS) $(USER_DOMAINS) $(ADMIN_DOMAINS) assert.te

FLASK_FILES =		$(COMMONBASE)/fmac/policy/flask/security_classes    \
			security_classes.priv \
			$(COMMONBASE)/fmac/policy/flask/initial_sids	    \
			$(COMMONBASE)/fmac/policy/flask/access_vectors	    \
			access_vectors.priv

USERS_FILE =		users$(MLS_SUFFIX)

CONTEXT_FILES =		initial_sid_contexts$(MLS_SUFFIX)		\
			fs_use$(MLS_SUFFIX)				\
			net_contexts$(MLS_SUFFIX)

MLS_FILE =		$(MLS_FLAG:yes=mls)

MLS_SUFFIX =		$(MLS_FLAG:yes=.mls)

POLICYFILES += $(FLASK_FILES)

POLICYFILES += $(MLS_FILE)

POLICYFILES += $(ALL_TE) rbac

POLICYFILES += $(USERS_FILE)

POLICYFILES += constraints 

POLICYFILES += $(CONTEXT_FILES)

.KEEP_STATE:

all: ss_policy

ss_policy:  policy.conf
	$(CHECKPOLICY) -o $@ policy.conf
	$(CHECKPOLICY) -b $@

policy.conf: $(POLICYFILES)
	$(M4) $(M4FLAGS) -s $^ > policy.conf

access_vectors.priv: $(PRIVS_AWK) $(PRIVS_DEF)
	$(NAWK) -f $(PRIVS_AWK) < $(PRIVS_DEF) fmacfile=$@

security_classes.priv:  access_vectors.priv
	grep '^class' $^ > $@

fs_contexts.mls: fs_contexts
	$(SED) 's/_t/_t:u/g' $^ > $@

fs_use.mls: fs_use
	$(SED) 's/_t/_t:u/g' $^ > $@

net_contexts.mls: net_contexts
	$(SED) 's/_t/_t:u/g' $^ > $@

initial_sid_contexts.mls: initial_sid_contexts
	$(SED) 's/_t/_t:u/g' $^ > $@

users.mls: users
	$(SED) 's/;/ ranges u;/' $^ > $@

install: ss_policy file_contexts
	install -s -m 744 -d $(ROOT)/etc/security/fmac
	install -s -m 644 -f $(ROOT)/etc/security/fmac ss_policy
	install -s -m 644 -f $(ROOT)/etc/security/fmac file_contexts 

load: install
	load_policy $(ROOT)/etc/security/fmac/ss_policy

relabel:  file_contexts
	$(SETFILES) -v file_contexts `mount -p | awk '/zfs/{print $$3}'`
	$(TOUCH) relabel

clean:
	$(RM) -f ss_policy policy.conf

include ../../Makefile.targ
