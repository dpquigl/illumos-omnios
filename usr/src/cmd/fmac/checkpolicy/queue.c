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
 * Implementation of the double-ended queue type.
 */

#include <stdlib.h>
#include <queue.h>

queue_info_ptr_t
queue_create(void)
{
	queue_info_ptr_t q;

	q = (queue_info_ptr_t) malloc(sizeof (struct queue_info));
	if (q == NULL)
		return (NULL);

	q->head = q->tail = NULL;

	return (q);
}

int
queue_insert(queue_info_ptr_t q, queue_element_t e)
{
	queue_node_ptr_t newnode;


	if (!q)
		return (-1);

	newnode = (queue_node_ptr_t) malloc(sizeof (struct queue_node));
	if (newnode == NULL)
		return (-1);

	newnode->element = e;
	newnode->next = NULL;

	if (q->head == NULL) {
		q->head = q->tail = newnode;
	} else {
		q->tail->next = newnode;
		q->tail = newnode;
	}

	return (0);
}

int
queue_push(queue_info_ptr_t q, queue_element_t e)
{
	queue_node_ptr_t newnode;


	if (!q)
		return (-1);

	newnode = (queue_node_ptr_t) malloc(sizeof (struct queue_node));
	if (newnode == NULL)
		return (-1);

	newnode->element = e;
	newnode->next = NULL;

	if (q->head == NULL) {
		q->head = q->tail = newnode;
	} else {
		newnode->next = q->head;
		q->head = newnode;
	}

	return (0);
}

queue_element_t
queue_remove(queue_info_ptr_t q)
{
	queue_node_ptr_t node;
	queue_element_t e;


	if (!q)
		return (NULL);

	if (q->head == NULL)
		return (NULL);

	node = q->head;
	q->head = q->head->next;
	if (q->head == NULL)
		q->tail = NULL;

	e = node->element;
	free(node);

	return (e);
}

queue_element_t
queue_head(queue_info_ptr_t q)
{
	if (!q)
		return (NULL);

	if (q->head == NULL)
		return (NULL);

	return (q->head->element);
}

void
queue_destroy(queue_info_ptr_t q)
{
	queue_node_ptr_t p, temp;


	if (!q)
		return;

	p = q->head;
	while (p != NULL) {
		temp = p;
		p = p->next;
		free(temp);
	}

	free(q);
}

int
queue_map(queue_info_ptr_t q, int (*f) (queue_element_t, void *), void *vp)
{
	queue_node_ptr_t p;
	int ret;


	if (!q)
		return (0);

	p = q->head;
	while (p != NULL) {
		ret = f(p->element, vp);
		if (ret)
			return (ret);
		p = p->next;
	}
	return (0);
}


void
queue_map_remove_on_error(queue_info_ptr_t q,
    int (*f) (queue_element_t, void *), void (*g) (queue_element_t, void *),
    void *vp)
{
	queue_node_ptr_t p, last, temp;
	int ret;


	if (!q)
		return;

	last = NULL;
	p = q->head;
	while (p != NULL) {
		ret = f(p->element, vp);
		if (ret) {
			if (last) {
				last->next = p->next;
				if (last->next == NULL)
					q->tail = last;
			} else {
				q->head = p->next;
				if (q->head == NULL)
					q->tail = NULL;
			}

			temp = p;
			p = p->next;
			g(temp->element, vp);
			free(temp);
		} else {
			last = p;
			p = p->next;
		}
	}
}
