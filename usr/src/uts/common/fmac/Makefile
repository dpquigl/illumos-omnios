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

UTSBASE = ../../..

include $(UTSBASE)/../Makefile.master

.KEEP_STATE:

COMMONBASE = $(SRC)/common

PRIVS_AWK = $(SRC)/uts/common/os/privs.awk
PRIVS_DEF = $(SRC)/uts/common/os/priv_defs

FMAC_MKFLASK_AWK = mkflask.awk
FMAC_MKACCESSVECTOR_AWK = mkaccess_vector.awk

DERIVED_FLASK_DEFS =						\
	$(COMMONBASE)/fmac/policy/flask/security_classes	\
	security_classes.priv					\
	$(COMMONBASE)/fmac/policy/flask/initial_sids

DERIVED_FLASK_FILES =						\
	class_to_string.h					\
	flask.h							\
	initial_sid_to_string.h

DERIVED_ACCESSVECTOR_DEFS =					\
	$(COMMONBASE)/fmac/policy/flask/access_vectors		\
	access_vectors.priv

DERIVED_ACCESSVECTOR_FILES =					\
	av_inherit.h						\
	common_perm_to_string.h					\
	av_perm_to_string.h					\
	av_permissions.h

DERIVED_FILES =							\
	$(DERIVED_FLASK_FILES)					\
	$(DERIVED_ACCESSVECTOR_FILES)

all install lint clean.lint:	$(DERIVED_FILES)

clean clobber:
	$(RM) $(DERIVED_FILES)

$(DERIVED_FLASK_FILES): $(FMAC_MKFLASK_AWK) $(DERIVED_FLASK_DEFS)
	$(NAWK) -f $(FMAC_MKFLASK_AWK) $(DERIVED_FLASK_DEFS)

$(DERIVED_ACCESSVECTOR_FILES): $(FMAC_MKACCESSVECTOR_AWK) $(DERIVED_ACCESSVECTOR_DEFS)
	$(NAWK) -f $(FMAC_MKACCESSVECTOR_AWK) $(DERIVED_ACCESSVECTOR_DEFS)

access_vectors.priv: $(PRIVS_AWK) $(PRIVS_DEF)
	$(NAWK) -f $(PRIVS_AWK) < $(PRIVS_DEF) fmacfile=$@

security_classes.priv:  access_vectors.priv
	grep '^class' $^ > $@

