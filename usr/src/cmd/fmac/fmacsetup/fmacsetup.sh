#!/usr/bin/sh
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
# Use full pathnames so that we can run from the environment
# BFU leaves us in.
#
GETFILECON="/usr/bin/getfilecon"
SETFILES="/sbin/setfiles"
FILE_CONTEXTS="/etc/security/fmac/file_contexts"
LOADPOLICY="/sbin/loadpolicy"
SS_POLICY="/etc/security/fmac/ss_policy"

#
# Test if mount point is on a ZFS file system
#
is_zfs() {
	mtype=`mount -p | nawk '$3=='\""$1"\"' && $4=="zfs" {print $4}'`
	[ "${mtype}" = "zfs" ] && return 0
	return 1;
}

#
# Only set /export/home context if its on a ZFS file system and is
# not already labeled. This prevents the relabeling of existing home
# directories.
#
label_home() {
	if is_zfs /export/home ; then
		HCONTEXT=`${GETFILECON} /export/home | \
			nawk '{print $2}' ` 2>&1 >/dev/null
		if [ "${HCONTEXT}" != "system_u:object_r:user_home_t" ]; then
			echo "Labeling files in /export/home"
			${SETFILES} ${FILE_CONTEXTS} /export/home
		else
			echo "/export/home already labeled"
		fi
		return 0
	else
		echo "/export/home is not a ZFS file system"
		return 1
	fi
}

#
# Label root if it's on a ZFS file system.
#
label_root() {
	if is_zfs / ; then
		echo "Labeling files in /"
		${SETFILES} ${FILE_CONTEXTS} /
		return 0
	else
		echo "/ is not a ZFS file system"
		return 1
	fi
}

#
# Unmount libraries so that the underlying object can be labeled
#
unmount_libs () {
	for lib in `mount | egrep '^*\.so.*' | nawk '{ print $1 }'`; do
		umount ${lib}
	done
	return 0;
}

#
# Load the current and/or updated policy
#
reload_policy() {

	if ${LOADPOLICY} ${SS_POLICY}; then
		echo "Policy reloaded"
		return 0
	else
		echo "Policy load failed"
		return 1
	fi
}

#
# Perform post-BFU labeling and boot setup
#
# Normal sequence is:
#  bfu
#  acr
#  /sbin/fmacsetup
#  reboot
#
/usr/sbin/zfs mount -a		# Make sure all ZFS file systems are mounted
unmount_libs			# Unmount platform specific libraries
reload_policy			# Load the new BFU'd policy before labeling
label_root			# Relabel /export/home if necessary
label_home			# Relabel /export/home if necessary
echo "System labeling complete, please reboot now"
