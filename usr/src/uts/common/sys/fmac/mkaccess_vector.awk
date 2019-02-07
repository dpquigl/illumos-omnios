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

function generate_preamble(s, f) {

	while (getline headerdefs < "generated_defs")
		print headerdefs > f;
	close("generated_defs");

	printf("\n") > f;

	print("/* THIS FILE WAS GENERATED; DO NOT EDIT */\n") > f;
	printf("#ifndef %s\n", s) > f;
	printf("#define %s\n", s) > f;

	printf("\n") > f;

	printf("#ifdef __cplusplus\n") > f;
	printf("extern \"C\" {\n") > f;
	printf("#endif\n") > f;

	printf("\n") > f;
}

function generate_postamble(s, f) {

	printf("#ifdef __cplusplus\n") > f;
	printf("}\n") > f;
	printf("#endif\n\n") > f;

	printf("#endif /* %s */\n", s) > f;

}

BEGIN	{
	outfile = "av_permissions.h"
	inheritfile = "av_inherit.h"
	cpermfile = "common_perm_to_string.h"
	avpermfile = "av_perm_to_string.h"
	nextstate = "COMMON_OR_AV";

	# Start of av_permissions.h
	generate_preamble("_SYS_FMAC_AV_PERMISSIONS_H", outfile);

	# Start of av_inherit.h
	generate_preamble("_SYS_FMAC_AV_INHERIT_H", inheritfile);

	# Start of common_perm_to_string.h
	generate_preamble("_SYS_FMAC_COMMON_PERM_TO_STRING_H", cpermfile);

	# Start of av_perm_to_string.h
	generate_preamble("_SYS_FMAC_AV_PERM_TO_STRING_H", avpermfile);

	printf("#include <sys/fmac/flask.h>\n") > inheritfile;
	printf("#include <sys/fmac/common_perm_to_string.h>\n") > inheritfile;

	printf("typedef struct\n") > inheritfile;
	printf("{\n") > inheritfile;
	printf("    security_class_t tclass;\n") > inheritfile;
	printf("    char **common_pts;\n") > inheritfile; 
	printf("    access_vector_t common_base;\n") > inheritfile; 
	printf("} av_inherit_t;\n\n") > inheritfile;
	printf("static av_inherit_t av_inherit[] = {\n") > inheritfile;
	
	printf("typedef struct\n") > avpermfile;
	printf("{\n") > avpermfile;
	printf("    security_class_t tclass;\n") > avpermfile;
	printf("    access_vector_t value;\n") > avpermfile; 
	printf("    char *name;\n") > avpermfile; 
	printf("} av_perm_to_string_t;\n\n") > avpermfile;
	printf("static av_perm_to_string_t av_perm_to_string[] = {\n") > avpermfile;
}
/^[ \t]*#/	{ 
	next;
}
$1 == "common"	{ 
	if (nextstate != "COMMON_OR_AV") {
		printf("Parse error:  Unexpected COMMON definition on line %d\n", NR);
		next;	
	}

	if ($2 in common_defined) {
		printf("Duplicate COMMON definition for %s on line %d.\n", $2, NR);
		next;
	}	
	common_defined[$2] = 1;

	tclass = $2;
	common_name = $2; 
	permission = 1;

	printf("static char *common_%s_perm_to_string[] =\n{\n", $2) > cpermfile;

	nextstate = "COMMON-OPENBRACKET";
	next;
}
$1 == "class"	{
	if (nextstate != "COMMON_OR_AV" &&
	    nextstate != "CLASS_OR_CLASS-OPENBRACKET") {
		printf("Parse error:  Unexpected class definition on line %d\n", NR);
			next;	
	}

	tclass = $2;

	if (tclass in av_defined) {
		printf("Duplicate access vector definition for %s on line %d\n", tclass, NR);
		next;
	} 
	av_defined[tclass] = 1;

	inherits = "";
	permission = 1;

	nextstate = "INHERITS_OR_CLASS-OPENBRACKET";
	next;
}
$1 == "inherits" {			
	if (nextstate != "INHERITS_OR_CLASS-OPENBRACKET") {
		printf("Parse error:  Unexpected INHERITS definition on line %d\n", NR);
		next;	
	}

	if (!($2 in common_defined)) {
		printf("COMMON %s is not defined (line %d).\n", $2, NR);
		next;
	}

	inherits = $2;
	permission = common_base[$2];

	for (combined in common_perms) {
		split(combined,separate, SUBSEP);
		if (separate[1] == inherits) {
			printf("#define %s__%s", toupper(tclass), toupper(separate[2])) > outfile; 
			spaces = 40 - (length(separate[2]) + length(tclass));
			if (spaces < 1)
			      spaces = 1;
			for (i = 0; i < spaces; i++) 
				printf(" ") > outfile; 
			printf("0x%08xUL\n", common_perms[combined]) > outfile; 
		}
	}
	printf("\n") > outfile;
	
	printf("   { SECCLASS_%s, common_%s_perm_to_string, 0x%08xUL },\n", toupper(tclass), inherits, permission) > inheritfile; 

	nextstate = "CLASS_OR_CLASS-OPENBRACKET";
	next;
}
$1 == "{"	{ 
	if (nextstate != "INHERITS_OR_CLASS-OPENBRACKET" &&
	    nextstate != "CLASS_OR_CLASS-OPENBRACKET" &&
	    nextstate != "COMMON-OPENBRACKET") {
		printf("Parse error:  Unexpected { on line %d\n", NR);
		next;
	}

	if (nextstate == "INHERITS_OR_CLASS-OPENBRACKET")
		nextstate = "CLASS-CLOSEBRACKET";

	if (nextstate == "CLASS_OR_CLASS-OPENBRACKET")
		nextstate = "CLASS-CLOSEBRACKET";

	if (nextstate == "COMMON-OPENBRACKET")
		nextstate = "COMMON-CLOSEBRACKET";
}
/[a-z][a-z_]*/	{
	if (nextstate != "COMMON-CLOSEBRACKET" &&
	    nextstate != "CLASS-CLOSEBRACKET") {
		printf("Parse error:  Unexpected symbol %s on line %d\n", $1, NR);		
		next;
	}

	if (nextstate == "COMMON-CLOSEBRACKET") {
		if ((common_name,$1) in common_perms) {
			printf("Duplicate permission %s for common %s on line %d.\n", $1, common_name, NR);
			next;
		}

		common_perms[common_name,$1] = permission;

		printf("#define COMMON_%s__%s", toupper(common_name), toupper($1)) > outfile; 

		printf("    \"%s\",\n", $1) > cpermfile;
	} else {
		if ((tclass,$1) in av_perms) {
			printf("Duplicate permission %s for %s on line %d.\n", $1, tclass, NR);
			next;
		}

		av_perms[tclass,$1] = permission;
		
		if (inherits != "") {
			if ((inherits,$1) in common_perms) {
				printf("Permission %s in %s on line %d conflicts with common permission.\n", $1, tclass, inherits, NR);
				next;
			}
		}

		printf("#define %s__%s", toupper(tclass), toupper($1)) > outfile; 

		printf("   { SECCLASS_%s, %s__%s, \"%s\" },\n", toupper(tclass), toupper(tclass), toupper($1), $1) > avpermfile; 
	}

	spaces = 40 - (length($1) + length(tclass));

	if (spaces < 1)
	      spaces = 1;

	for (i = 0; i < spaces; i++) 
		printf(" ") > outfile; 
	printf("0x%08xUL\n", permission) > outfile; 
	permission = permission * 2;
}
$1 == "}"	{
	if (nextstate != "CLASS-CLOSEBRACKET" && 
	    nextstate != "COMMON-CLOSEBRACKET") {
		printf("Parse error:  Unexpected } on line %d\n", NR);
		next;
	}

	if (nextstate == "COMMON-CLOSEBRACKET") {
		common_base[common_name] = permission;
		printf("};\n\n") > cpermfile; 
	}

	printf("\n") > outfile;

	nextstate = "COMMON_OR_AV";
}
END	{
	if (nextstate != "COMMON_OR_AV" && nextstate != "CLASS_OR_CLASS-OPENBRACKET")
		printf("Parse error:  Unexpected end of file\n");

	# End of av_permissions.h
	generate_postamble("_SYS_FMAC_AV_PERMISSIONS_H", outfile);

	# End of common_perm_to_string.h
	generate_postamble("_SYS_FMAC_COMMON_PERM_TO_STRING_H", cpermfile);

	printf("};\n\n") > inheritfile;
	printf("#define AV_INHERIT_SIZE (sizeof (av_inherit)/sizeof (av_inherit_t))\n\n") > inheritfile;

	# End of av_inherit.h
	generate_postamble("_SYS_FMAC_AV_INHERIT_H", inheritfile);

	printf("};\n\n") > avpermfile;
	printf("#define AV_PERM_TO_STRING_SIZE (sizeof (av_perm_to_string)/sizeof (av_perm_to_string_t))\n\n") > avpermfile;
	# End of av_perm_to_string.h
	generate_postamble("_SYS_FMAC_AV_PERM_TO_STRING_H", avpermfile);
}

