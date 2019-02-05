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
 * A double-ended queue is a singly linked list of
 * elements of arbitrary type that may be accessed
 * at either end.
 */

#ifndef _QUEUE_H
#define	_QUEUE_H

typedef void *queue_element_t;

typedef struct queue_node *queue_node_ptr_t;

typedef struct queue_node {
	queue_element_t element;
	queue_node_ptr_t next;
} queue_node_t;

typedef struct queue_info {
	queue_node_ptr_t head;
	queue_node_ptr_t tail;
} queue_info_t;

typedef queue_info_t *queue_info_ptr_t;

queue_info_ptr_t queue_create(void);
int queue_insert(queue_info_ptr_t, queue_element_t);
int queue_push(queue_info_ptr_t, queue_element_t);
queue_element_t queue_remove(queue_info_ptr_t);
queue_element_t queue_head(queue_info_ptr_t);
void queue_destroy(queue_info_ptr_t);

/*
 * Applies the specified function f to each element in the
 * specified queue.
 *
 * In addition to passing the element to f, queue_map
 * passes the specified void* pointer to f on each invocation.
 *
 * If f returns a non-zero status, then queue_map will cease
 * iterating through the hash table and will propagate the error
 * return to its caller.
 */
int queue_map(queue_info_ptr_t, int (*f) (queue_element_t, void *), void *);

/*
 * Same as queue_map, except that if f returns a non-zero status,
 * then the element will be removed from the queue and the g
 * function will be applied to the element.
 */
void queue_map_remove_on_error(
	queue_info_ptr_t,
	int (*f) (queue_element_t, void *),
	void (*g) (queue_element_t, void *),
	void *);

#endif /* _QUEUE_H */
