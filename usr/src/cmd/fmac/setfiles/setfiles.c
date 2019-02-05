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
 * Author:  Stephen Smalley <sds@epoch.ncsc.mil>
 */

/*
 * setfiles
 *
 * PURPOSE:
 * This program reads a set of file security context specifications
 * based on pathname regular expressions and labels files
 * accordingly, traversing a set of file systems specified by
 * the user.  The program does not cross file system boundaries.
 *
 * USAGE:
 * setfiles [-dnpqsvW] spec_file pathname...
 *
 * -d   Show what specification matched each file.
 * -n	Do not change any file labels.
 * -q   Be quiet (suppress non-error output).
 * -v	Show changes in file labels.
 * -W   Warn about entries that have no matching file.
 *
 * spec_file	The specification file.
 * pathname...	The file systems to label (omit if using -s).
 *
 * EXAMPLE USAGE:
 * ./setfiles -v file_contexts `mount | awk '/ext3/{print $3}'`
 *
 * SPECIFICATION FILE:
 * Each specification has the form:
 *       regexp [ -type ] ( context | <<none>> )
 *
 * By default, the regexp is an anchored match on both ends (i.e. a
 * caret (^) is prepended and a dollar sign ($) is appended automatically).
 * This default may be overridden by using .* at the beginning and/or
 * end of the regular expression.
 *
 * The optional type field specifies the file type as shown in the mode
 * field by ls, e.g. use -d to match only directories or -- to match only
 * regular files.
 *
 * The value of <<none> may be used to indicate that matching files
 * should not be relabeled.
 *
 * The last matching specification is used.
 *
 * If there are multiple hard links to a file that match
 * different specifications and those specifications indicate
 * different security contexts, then a warning is displayed
 * but the file is still labeled based on the last matching
 * specification other than <<none>>.
 */

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/vfs.h>
#include <ftw.h>
#include <limits.h>
#include <fmac/fmac.h>

static int add_assoc = 1;

/*
 * Command-line options.
 */
static int debug = 0;
static int change = 1;
static int quiet = 0;
#define	QPRINTF(args...) do { if (!quiet) printf(args); } while (0)
static int verbose = 0;
static int warn_no_match = 0;

/*
 * Program name and error message buffer.
 */
static char *progname;
static char errbuf[255 + 1];

/*
 * A file security context specification.
 */
typedef struct spec {
	char	*regex_str;	/* regular expession string for diagnostic */
				/* messages */
	char	*type_str;	/* type string for diagnostic messages */
	char	*context;	/* context string */
	regex_t	regex;		/* compiled regular expression */
	mode_t	mode;		/* mode format value */
	int	matches;	/* number of matching pathnames */
	int	hasMetaChars;	/* indicates whether the RE has */
				/* any meta characters. */
				/* 0 = no meta chars */
				/* 1 = has one or more meta chars */
} spec_t;

/*
 * The array of specifications, initially in the
 * same order as in the specification file.
 * Sorting occurs based on hasMetaChars
 */
static spec_t *spec;
static int nspec;

/*
 * An association between an inode and a
 * specification.
 */
typedef struct file_spec {
	ino_t ino;		/* inode number */
	int specind;		/* index of specification in spec */
	char *file;		/* full pathname for diagnostic messages */
				/* about conflicts */
	struct file_spec *next;	/* next association in hash bucket chain */
} file_spec_t;

/*
 * The hash table of associations, hashed by inode number.
 * Chaining is used for collisions, with elements ordered
 * by inode number in each bucket.  Each hash bucket has a dummy
 * header.
 */
#define	HASH_BITS 16
#define	HASH_BUCKETS (1 << HASH_BITS)
#define	HASH_MASK (HASH_BUCKETS-1)
static file_spec_t fl_head[HASH_BUCKETS];

/*
 * Try to add an association between an inode and
 * a specification.  If there is already an association
 * for the inode and it conflicts with this specification,
 * then use the specification that occurs later in the
 * specification array.
 */
static file_spec_t *
file_spec_add(ino_t ino, int specind, const char *file)
{
	file_spec_t *prevfl, *fl;
	int h, no_conflict, ret;
	struct stat sb;

	h = (ino + (ino >> HASH_BITS)) & HASH_MASK;
	for (prevfl = &fl_head[h], fl = fl_head[h].next; fl;
		prevfl = fl, fl = fl->next) {
		if (ino == fl->ino) {
			ret = lstat(fl->file, &sb);
			if (ret < 0 || sb.st_ino != ino) {
				fl->specind = specind;
				free(fl->file);
				fl->file = malloc(strlen(file) + 1);
				if (!fl->file) {
					fprintf(stderr,
					    "%s:  insufficient memory for "
					    "file label entry for %s\n",
					    progname, file);
					return (NULL);
				}
				strcpy(fl->file, file);
				return (fl);
			}

			no_conflict = (strcmp(spec[fl->specind].context,
			    spec[specind].context) == 0);
			if (no_conflict)
				return (fl);

			fprintf(stderr, "%s:  conflicting specifications "
			    "for %s and %s, using %s.\n",
			    progname, file, fl->file,
			    ((specind > fl->specind) ? spec[specind].context :
			    spec[fl->specind].context));
			fl->specind =
			    (specind > fl->specind) ? specind : fl->specind;
			free(fl->file);
			fl->file = malloc(strlen(file) + 1);
			if (!fl->file) {
				fprintf(stderr,
				    "%s:  insufficient memory for file "
				    "label entry for %s\n",
				    progname, file);
				return (NULL);
			}
			strcpy(fl->file, file);
			return (fl);
		}

		if (ino > fl->ino)
			break;
	}

	fl = malloc(sizeof (file_spec_t));
	if (!fl) {
		fprintf(stderr,
		    "%s:  insufficient memory for file label entry for %s\n",
		    progname, file);
		return (NULL);
	}
	fl->ino = ino;
	fl->specind = specind;
	fl->file = malloc(strlen(file) + 1);
	if (!fl->file) {
		fprintf(stderr,
		    "%s:  insufficient memory for file label entry for %s\n",
		    progname, file);
		return (NULL);
	}
	strcpy(fl->file, file);
	fl->next = prevfl->next;
	prevfl->next = fl;
	return (fl);
}

/*
 * Evaluate the association hash table distribution.
 */
static void
file_spec_eval(void)
{
	file_spec_t *fl;
	int h, used, nel, len, longest;

	used = 0;
	longest = 0;
	nel = 0;
	for (h = 0; h < HASH_BUCKETS; h++) {
		len = 0;
		for (fl = fl_head[h].next; fl; fl = fl->next) {
			len++;
		}
		if (len)
			used++;
		if (len > longest)
			longest = len;
		nel += len;
	}

	QPRINTF("%s:  hash table stats: %d elements, %d/%d buckets used, "
	    "longest chain length %d\n",
	    progname, nel, used, HASH_BUCKETS, longest);
}


/*
 * Destroy the association hash table.
 */
static void
file_spec_destroy(void)
{
	file_spec_t *fl, *tmp;
	int h;

	for (h = 0; h < HASH_BUCKETS; h++) {
		fl = fl_head[h].next;
		while (fl) {
			tmp = fl;
			fl = fl->next;
			free(tmp->file);
			free(tmp);
		}
		fl_head[h].next = NULL;
	}
}


int
match(const char *name, struct stat *sb)
{
	int i, ret;

	ret = lstat(name, sb);
	if (ret) {
		fprintf(stderr, "%s:  unable to stat file %s\n", progname,
			name);
		return (-1);
	}

	/*
	 * Check for matching specifications in reverse order, so that
	 * the last matching specification is used.
	 */
	for (i = nspec - 1; i >= 0; i--) {
		ret = regexec(&spec[i].regex, name, 0, NULL, 0);
		if (ret == 0 && (!spec[i].mode ||
		    (sb->st_mode & S_IFMT) == spec[i].mode))
			break;
		if (ret) {
			if (ret == REG_NOMATCH)
				continue;
			regerror(ret, &spec[i].regex, errbuf, sizeof (errbuf));
			fprintf(stderr,
			    "%s:  unable to match %s against %s:  %s\n",
			    progname, name, spec[i].regex_str, errbuf);
			return (-1);
		}
	}

	if (i < 0)
		/* No matching specification. */
		return (-1);

	spec[i].matches++;

	return (i);
}

/*
 * Check for duplicate specifications. If a duplicate specification is found
 * and the context is the same, give a warning to the user. If a duplicate
 * specification is found and the context is different, give a warning
 * to the user (This could be changed to error). Return of non-zero is
 * an error.
 */
int
nodups_specs()
{
	int ii, jj;
	struct spec *curr_spec;

	for (ii = 0; ii < nspec; ii++) {
		curr_spec = &spec[ii];
		for (jj = ii + 1; jj < nspec; jj++) {
			/* Check if same RE string */
			if ((strcmp(spec[jj].regex_str,
			    curr_spec->regex_str) == 0) &&
			    (!spec[jj].mode || !curr_spec->mode ||
			    spec[jj].mode == curr_spec->mode)) {
				/* Same RE string found */
				if (strcmp(spec[jj].context,
				    curr_spec->context)) {
					/*
					 * If different contexts, give
					 * warning
					 */
					fprintf(stderr,
					    "ERROR: Multiple different "
					    "specifications for %s  "
					    "(%s and %s).\n",
					    curr_spec->regex_str,
					    spec[jj].context,
					    curr_spec->context);
				} else {
					/* If same contexts give warning */
					fprintf(stderr,
					    "WARNING: Multiple same "
					    "specifications for %s.\n",
					    curr_spec->regex_str);
				}
			}
		}
	}
	return (0);
}


/*
 * Determine if the regular expression specification has any meta characters.
 */
void
spec_hasMetaChars(struct spec *spec)
{
	char *c;
	int len;
	char *end;

	c = spec->regex_str;
	len = strlen(spec->regex_str);
	end = c + len;

	spec->hasMetaChars = 0;

	/*
	 * Look at each character in the RE specification string for a
	 * meta character. Return when any meta character reached.
	 */
	while (c != end) {
		switch (*c) {
			case '.':
			case '^':
			case '$':
			case '?':
			case '*':
			case '+':
			case '|':
			case '[':
			case '(':
			case '{':
				spec->hasMetaChars = 1;
				return;
			case '\\':		// skip the next character
				c++;
				break;
			default:
				break;

		}
		c++;
	}
}

#define	SZ 255

/*
 * Apply the last matching specification to a file.
 * This function is called by nftw on each file during
 * the directory traversal.
 */
static int
apply_spec(const char *file, const struct stat *sb, int flag, struct FTW *s)
{
	const char	*my_file;
	file_spec_t	*fl;
	struct stat	my_sb;
	int		i;
	int		ret;
	char		*context;

	/* Skip the extra slash at the beginning, if present. */
	if (file[0] == '/' && file[1] == '/')
		my_file = &file[1];
	else
		my_file = file;

	if (flag == FTW_DNR) {
		fprintf(stderr, "%s:  unable to read directory %s\n",
			progname, my_file);
		return (0);
	}

	/*
	 * At present only regular files and directories can be labeled.
	 * XXX This needs to be fixed in the kernel.
	 */
	if (flag == FTW_SL ||
	    (!S_ISDIR(sb->st_mode) && !S_ISREG(sb->st_mode)))
		return (0);

	i = match(my_file, &my_sb);
	if (i < 0)
		/* No matching specification. */
		return (0);

	/*
	 * Try to add an association between this inode and
	 * this specification.  If there is already an association
	 * for this inode and it conflicts with this specification,
	 * then use the last matching specification.
	 */
	if (add_assoc) {
		fl = file_spec_add(my_sb.st_ino, i, my_file);
		if (!fl)
			/* Insufficient memory to proceed. */
			return (1);

		if (fl->specind != i)
			/*
			 * There was already an association and it
			 * took precedence.
			 */
			return (0);
	}

	if (debug) {
		if (spec[i].type_str) {
			printf("%s:  %s matched by (%s,%s,%s)\n",
			    progname, my_file, spec[i].regex_str,
			    spec[i].type_str, spec[i].context);
		} else {
			printf("%s:  %s matched by (%s,%s)\n",
			    progname, my_file, spec[i].regex_str,
			    spec[i].context);
		}
	}

	/* Get the current context of the file. */
	ret = getfilecon(my_file, &context);
	if (ret < 0) {
		if (errno == ENODATA) {
			context = malloc(10);
			strcpy(context, "<<none>>");
		} else {
			fprintf(stderr, "%s:  unable to obtain attribute for "
			    "file %s:  %s\n",
			    progname, my_file, strerror(errno));
			return (-1);
		}
	}

	/*
	 * Do not relabel the file if the matching specification is
	 * <<none>> or the file is already labeled according to the
	 * specification.
	 */
	if ((strcmp(spec[i].context, "<<none>>") == 0) ||
	    (strcmp(context, spec[i].context) == 0)) {
		freecon(context);
		return (0);
	}

	if (verbose) {
		printf("%s:  relabeling %s from %s to %s\n", progname, my_file,
		    context, spec[i].context);
	}

	freecon(context);

	/*
	 * Do not relabel the file if -n was used.
	 */
	if (!change)
		return (0);

	/*
	 * Relabel the file to the specified context.
	 */
	ret = setfilecon(my_file, spec[i].context);
	if (ret) {
		perror(my_file);
		fprintf(stderr, "%s:  unable to relabel %s to %s\n",
			progname, my_file, spec[i].context);
		return (1);
	}

	return (0);
}


int
main(int argc, char **argv)
{
	FILE *fp;
	char buf[255 + 1], *buf_p;
	char regex[256], type[256], context[256];
	char *anchored_regex;
	int opt, items, len, lineno, pass, nerr, regerr, i, j;
	spec_t *spec_copy;

	/* Process any options. */
	while ((opt = getopt(argc, argv, "dnpqvxW")) > 0) {
		switch (opt) {
		case 'd':
			debug = 1;
			break;
		case 'n':
			change = 0;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'x':
			/* now the default */
			break;
		case 'W':
			warn_no_match = 1;
			break;
		case '?':
			fprintf(stderr,
			    "usage:  %s [-dnpqsvW] spec_file pathname...\n",
			    argv[0]);
			exit(1);
		}
	}

	if (optind > (argc - 2)) {
		fprintf(stderr,
			"usage:  %s [-dnpqvW] spec_file pathname...\n",
			argv[0]);
		exit(1);
	}

	/* Open the specification file. */
	if ((fp = fopen(argv[optind], "r")) == NULL) {
		perror(argv[optind]);
		exit(1);
	}
	optind++;

	/*
	 * Perform two passes over the specification file.
	 * The first pass counts the number of specifications and
	 * performs simple validation of the input.  At the end
	 * of the first pass, the spec array is allocated.
	 * The second pass performs detailed validation of the input
	 * and fills in the spec array.
	 */
	for (pass = 0; pass < 2; pass++) {
		lineno = 0;
		nspec = 0;
		nerr = 0;
		while (fgets(buf, sizeof (buf), fp)) {
			lineno++;
			len = strlen(buf);
			if (buf[len - 1] != '\n') {
				fprintf(stderr,
				    "%s:  no newline on line number %d "
				    "(only read %s)\n",
				    argv[0], lineno, buf);
				nerr++;
				continue;
			}
			buf[len - 1] = 0;
			buf_p = buf;
			while (isspace(*buf_p))
				buf_p++;
			/* Skip comment lines and empty lines. */
			if (*buf_p == '#' || *buf_p == 0)
				continue;
			items = sscanf(buf, "%255s %255s %255s",
					regex,
					type,
					context);
			if (items < 2) {
				fprintf(stderr,
				    "%s:  line number %d is missing fields "
				    "(only read %s)\n",
				    argv[0], lineno, buf);
				nerr++;
				continue;
			} else if (items == 2) {
				/* The type field is optional. */
				strncpy(context, type, sizeof (context));
				type[0] = 0;
			}

			if (pass == 1) {
				/*
				 * On the second pass, compile and store
				 * the specification in spec.
				 */
				spec[nspec].regex_str = strdup(regex);

				/* Anchor the regular expression. */
				len = strlen(regex);
				anchored_regex = malloc(len + 3);
				if (!anchored_regex) {
					fprintf(stderr,
					    "%s:  insufficient memory for "
					    "anchored regexp on line %d\n",
					    argv[0], lineno);
					exit(1);
				}
				sprintf(anchored_regex, "^%s$", regex);

				/* Compile the regular expression. */
				regerr = regcomp(&spec[nspec].regex,
				    anchored_regex, REG_EXTENDED | REG_NOSUB);
				if (regerr < 0) {
					regerror(regerr, &spec[nspec].regex,
					    errbuf, sizeof (errbuf));
					fprintf(stderr,
					    "%s:  unable to compile regular "
					    "expression %s on line number "
					    "%d:  %s\n",
						argv[0], regex, lineno, errbuf);
					nerr++;
				}
				free(anchored_regex);

				/* Convert the type string to a mode format */
				if (type[0] != 0)
					spec[nspec].type_str = strdup(type);
				else
					spec[nspec].type_str = NULL;
				spec[nspec].mode = 0;
				if (strlen(type) == 0)
					goto skip_type;
				len = strlen(type);
				if (type[0] != '-' || len != 2) {
					fprintf(stderr,
					    "%s:  invalid type specifier %s "
					    "on line number %d\n",
					    argv[0], type, lineno);
					nerr++;
					goto skip_type;
				}
				switch (type[1]) {
				case 'b':
					spec[nspec].mode = S_IFBLK;
					break;
				case 'c':
					spec[nspec].mode = S_IFCHR;
					break;
				case 'd':
					spec[nspec].mode = S_IFDIR;
					break;
				case 'p':
					spec[nspec].mode = S_IFIFO;
					break;
				case 'l':
					spec[nspec].mode = S_IFLNK;
					break;
				case 's':
					spec[nspec].mode = S_IFSOCK;
					break;
				case '-':
					spec[nspec].mode = S_IFREG;
					break;
				default:
					fprintf(stderr,
					    "%s:  invalid type specifier %s "
					    "on line number %d\n",
						argv[0], type, lineno);
					nerr++;
				}

skip_type:

				spec[nspec].context = strdup(context);

				if (strcmp(context, "<<none>>")) {
					if (security_check_context(context) <
					    0) {
						fprintf(stderr,
						    "%s:  invalid context %s "
						    "on line number %d\n",
						    argv[0], context, lineno);
						nerr++;
					}
				}

				/*
				 * Determine if specification has
				 * any meta characters in the RE
				 */
				spec_hasMetaChars(&spec[nspec]);
			}

			nspec++;
		}

		if (nerr)
			exit(1);

		if (pass == 0) {
			QPRINTF("%s:  read %d specifications\n", argv[0],
			    nspec);
			if (nspec == 0)
				exit(0);
			if ((spec = malloc(sizeof (spec_t) * nspec)) ==
			    NULL) {
				fprintf(stderr,
				    "%s:  insufficient memory for "
				    "specifications\n",
				    argv[0]);
				exit(1);
			}
			memset(spec, 0, sizeof (spec_t) * nspec);
			rewind(fp);
		}
	}
	fclose(fp);

	/* Move exact pathname specifications to the end. */
	spec_copy = malloc(sizeof (spec_t) * nspec);
	if (!spec_copy) {
		fprintf(stderr,
			"%s:  insufficient memory for specifications\n",
			argv[0]);
		exit(1);
	}
	j = 0;
	for (i = 0; i < nspec; i++) {
		if (spec[i].hasMetaChars)
			memcpy(&spec_copy[j++], &spec[i], sizeof (spec_t));
	}
	for (i = 0; i < nspec; i++) {
		if (!spec[i].hasMetaChars)
			memcpy(&spec_copy[j++], &spec[i], sizeof (spec_t));
	}
	free(spec);
	spec = spec_copy;

	/* Verify no exact duplicates */
	if (nodups_specs() != 0) {
		exit(1);
	}

	/*
	 * Apply the specifications to the file systems.
	 */
	progname = argv[0];
	for (; optind < argc; optind++) {

		QPRINTF("%s:  labeling files under %s\n", argv[0],
			argv[optind]);

		/* Walk the file tree, calling apply_spec on each file. */
		if (nftw(argv[optind], apply_spec, 1024,
		    FTW_PHYS | FTW_MOUNT)) {
			fprintf(stderr,
				"%s:  error while labeling files under %s\n",
				argv[0], argv[optind]);
			exit(1);
		}

		/*
		 * Evaluate the association hash table distribution for the
		 * directory tree just traversed.
		 */
		file_spec_eval();

		/*
		 * Reset the association hash table for the next
		 * directory tree.
		 */
		file_spec_destroy();
	}

	if (warn_no_match) {
		for (i = 0; i < nspec; i++) {
			if (spec[i].matches == 0) {
				if (spec[i].type_str) {
					printf("%s:  Warning!  No matches for "
					    "(%s, %s, %s)\n",
					    argv[0], spec[i].regex_str,
					    spec[i].type_str, spec[i].context);
				} else {
					printf("%s:  Warning!  No matches for "
					    "(%s, %s)\n",
					    argv[0], spec[i].regex_str,
					    spec[i].context);
				}
			}
		}
	}

	QPRINTF("%s:  Done.\n", argv[0]);

	exit(0);
}
