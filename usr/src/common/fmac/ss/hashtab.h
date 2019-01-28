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
 * Original files contributed to OpenSolaris.org under license by the
 * United States Government (NSA) to Sun Microsystems, Inc.
 */

/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/*
 * A hash table (hashtab) maintains associations between
 * key values and datum values.  The type of the key values
 * and the type of the datum values is arbitrary.  The
 * functions for hash computation and key comparison are
 * provided by the creator of the table.
 */

#ifndef _HASHTAB_H
#define	_HASHTAB_H

#if defined(_KERNEL)
#include <sys/inttypes.h>
#else
#include <inttypes.h>
#endif /* defined(_KERNEL) */

typedef char *hashtab_key_t;	/* generic key type */
typedef void *hashtab_datum_t;	/* generic datum type */

typedef struct hashtab_node *hashtab_ptr_t;

typedef struct hashtab_node {
	hashtab_key_t	key;
	hashtab_datum_t	datum;
	hashtab_ptr_t	next;
} hashtab_node_t;

typedef struct hashtab_val {
	hashtab_ptr_t *htable;	/* hash table */
	unsigned int size;	/* number of slots in hash table */
	uint32_t nel;		/* number of elements in hash table */
	unsigned int (*hash_value) (
		struct hashtab_val *h,
		hashtab_key_t key); /* hash function */
	int (*keycmp) (
		struct hashtab_val *h,
		hashtab_key_t key1,
		hashtab_key_t key2); /* key comparison function */
} hashtab_val_t;


typedef hashtab_val_t *hashtab_t;

/* Define status codes for hash table functions */
#define	HASHTAB_SUCCESS		0
#define	HASHTAB_OVERFLOW	ENOMEM
#define	HASHTAB_PRESENT		EEXIST
#define	HASHTAB_MISSING		ENOENT

/*
 * Creates a new hash table with the specified characteristics.
 *
 * Returns NULL if insufficent space is available or
 * the new hash table otherwise.
 */
hashtab_t hashtab_create(unsigned int (*hash_value) (hashtab_t h,
    hashtab_key_t key), int (*keycmp) (hashtab_t h, hashtab_key_t key1,
    hashtab_key_t key2), unsigned int size);

/*
 * Inserts the specified (key, datum) pair into the specified hash table.
 *
 * Returns HASHTAB_OVERFLOW if insufficient space is available or
 * HASHTAB_PRESENT  if there is already an entry with the same key or
 * HASHTAB_SUCCESS otherwise.
 */
int hashtab_insert(hashtab_t h, hashtab_key_t k, hashtab_datum_t d);

/*
 * Removes the entry with the specified key from the hash table.
 * Applies the specified destroy function to (key,datum,args) for
 * the entry.
 *
 * Returns HASHTAB_MISSING if no entry has the specified key or
 * HASHTAB_SUCCESS otherwise.
 */
int hashtab_remove(
	hashtab_t h,
	hashtab_key_t k,
	void (*destroy) (hashtab_key_t k,
		hashtab_datum_t d,
		void *args),
	void *args);

/*
 * Insert or replace the specified (key, datum) pair in the specified
 * hash table.  If an entry for the specified key already exists,
 * then the specified destroy function is applied to (key,datum,args)
 * for the entry prior to replacing the entry's contents.
 *
 * Returns HASHTAB_OVERFLOW if insufficient space is available or
 * HASHTAB_SUCCESS otherwise.
 */
int hashtab_replace(hashtab_t h, hashtab_key_t k, hashtab_datum_t d,
    void (*destroy) (hashtab_key_t k, hashtab_datum_t d, void *args),
    void *args);

/*
 * Searches for the entry with the specified key in the hash table.
 *
 * Returns NULL if no entry has the specified key or
 * the datum of the entry otherwise.
 */
hashtab_datum_t hashtab_search(hashtab_t h, hashtab_key_t k);

/*
 * Destroys the specified hash table.
 */
void hashtab_destroy(hashtab_t h);

/*
 * Applies the specified apply function to (key,datum,args)
 * for each entry in the specified hash table.
 *
 * The order in which the function is applied to the entries
 * is dependent upon the internal structure of the hash table.
 *
 * If apply returns a non-zero status, then hashtab_map will cease
 * iterating through the hash table and will propagate the error
 * return to its caller.
 */
int hashtab_map(hashtab_t h, int (*apply) (hashtab_key_t k, hashtab_datum_t d,
    void *args), void *args);

/*
 * Same as hashtab_map, except that if apply returns a non-zero status,
 * then the (key,datum) pair will be removed from the hashtab and the
 * destroy function will be applied to (key,datum,args).
 */
void hashtab_map_remove_on_error(hashtab_t h, int (*apply) (hashtab_key_t k,
    hashtab_datum_t d, void *args), void (*destroy) (hashtab_key_t k,
    hashtab_datum_t d, void *args), void *args);

void hashtab_hash_eval(hashtab_t h, char *tag);


#endif /* _HASHTAB_H */
