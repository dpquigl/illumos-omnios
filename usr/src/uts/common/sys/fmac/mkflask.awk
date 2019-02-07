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
	outfile = "flask.h"
	debugfile = "class_to_string.h"
	debugfile2 = "initial_sid_to_string.h"
	nextstate = "CLASS";

	# Start of flask.h 
	generate_preamble("_SYS_FMAC_FLASK_H", outfile);
	printf("\n/*\n * Security object class definitions\n */\n") > outfile;

	# Start of class_to_string.h
	generate_preamble("_SYS_FMAC_CLASS_TO_STRING_H", debugfile);
	printf("/*\n * Security object class definitions\n */\n") > debugfile;
	printf("static char *class_to_string[] =\n{\n") > debugfile;
	printf("    \"null\",\n") > debugfile;

	# Start of initial_sid_to_string.h
	generate_preamble("_SYS_FMAC_INITIAL_SID_TO_STRING_H", debugfile2);
	printf("static char *initial_sid_to_string[] =\n{\n") > debugfile2;
	printf("    \"null\",\n") > debugfile2;
}
/^[ \t]*#/	{ 
	next;
}
$1 == "class"	{ 
	if (nextstate != "CLASS") {
		printf("Parse error:  Unexpected class definition on line %d\n", NR);
		next;	
	}

	if ($2 in class_found) {
		printf("Duplicate class definition for %s on line %d.\n", $2, NR);
		next;
	}	
	class_found[$2] = 1;

	class_value++;

	printf("#define SECCLASS_%s", toupper($2)) > outfile;

	for (i = 0; i < 40 - length($2); i++) 
		printf(" ") > outfile; 

	printf("%d\n", class_value) > outfile; 

	printf("    \"%s\",\n", $2) > debugfile;
}
$1 == "sid"	{
	if (nextstate == "CLASS") {
		nextstate = "SID";
		printf("};\n\n") > debugfile;
		printf("\n/*\n * Security identifier indices for initial entities\n */\n") > outfile;			    
	}

	if ($2 in sid_found) {
		printf("Duplicate SID definition for %s on line %d.\n", $2, NR);
		next;
	}	
	sid_found[$2] = 1;
	sid_value++;

	printf("#define SECINITSID_%s", toupper($2)) > outfile;

	for (i = 0; i < 37 - length($2); i++) 
		printf(" ") > outfile; 

	printf("%d\n", sid_value) > outfile; 
		printf("    \"%s\",\n", $2) > debugfile2;
}
END	{
	if (nextstate != "SID")
		printf("Parse error:  Unexpected end of file\n");

	printf("\n#define SECINITSID_NUM") > outfile;

	for (i = 0; i < 34; i++) 
		printf(" ") > outfile; 

	printf("%d\n\n", sid_value) > outfile; 

	# End of flask.h
	generate_postamble("_SYS_FMAC_FLASK_H", outfile);

	# End of class_to_string.h
	generate_postamble("_SYS_FMAC_CLASS_TO_STRING_H", debugfile);

	printf("};\n\n") > debugfile2;

	# End of initial_sid_to_string.h
	generate_postamble("_SYS_FMAC_INITIAL_SID_TO_STRING_H", debugfile2);
}

