/*
 * Dimitriu Dragos-Cosmin 331CA
 */
#include "my_heap.h"
#include <stdlib.h>

static int compare_gt(my_heap_entry *, my_heap_entry *);

/*
 * initialization of the heap and memory allocation
 */
void heap_init(my_heap *h)
{
	h->size = 4;
	h->count = 0;
	h->data = calloc(h->size, sizeof(my_heap_entry *));

	if (h->data == NULL)
		exit(1);
}

/*
 * delete the heap and free the memory
 */
void heap_destroy(my_heap *h)
{
	unsigned int i;

	h->size = 0;

	for (i = 0 ; i < h->size; i++) {
		if (h->data[i] != NULL) {
			free(h->data[i]);
			h->data[i] = NULL;
		}
	}

	h->count = 0;

	if (h->data != NULL) {
		free(h->data);
		h->data = NULL;
	}
}

/*
 * insert an element to the heap
 */
void heap_insert(my_heap *h, my_heap_entry *he)
{
	unsigned int idx, parrent;
	my_heap_entry *aux;

	if (h->size == h->count) {
		h->size *= 2;
		h->data = realloc(h->data, h->size * sizeof(my_heap_entry *));

		if (h->data == NULL)
			exit(1);

		for (idx = h->count; idx < h->size ; idx++)
			h->data[idx] = NULL;
	}

	idx = h->count;
	parrent = (idx - 1) / 2;

	if (h->data[idx] == NULL)
		h->data[idx] = malloc(sizeof(my_heap_entry));

		if (h->data[idx] == NULL)
			exit(1);

	h->data[idx]->id = he->id;
	h->data[idx]->priority = he->priority;
	h->data[idx]->order = he->order;


	/* push up */
	while (idx != 0 && compare_gt(h->data[idx], h->data[parrent]) > 0) {
		aux = h->data[parrent];
		h->data[parrent] = h->data[idx];
		h->data[idx] = aux;

		idx = parrent;
		parrent = (idx - 1) / 2;
	}

	++h->count;
}

/*
 * delete the idx-th element from the heap
 */
static void heap_erase(my_heap *h, unsigned int idx)
{
	my_heap_entry *aux;
	unsigned int left, right;

	--h->count;
	h->data[idx]->id = h->data[h->count]->id;
	h->data[idx]->priority = h->data[h->count]->priority;
	h->data[idx]->order = h->data[h->count]->order;

	/* push down */
	while (1) {

		left = idx * 2 + 1;
		right = idx * 2 + 2;

		if (left < h->count &&
			(compare_gt(h->data[left], h->data[idx]) > 0) &&
			(right >= h->count ||
			(right < h->count &&
			(compare_gt(h->data[left], h->data[right]) > 0)))) {

			aux = h->data[left];
			h->data[left] = h->data[idx];
			h->data[idx] = aux;
			idx = left;
		} else if (right < h->count &&
			(compare_gt(h->data[right], h->data[idx]) > 0)) {

			aux = h->data[right];
			h->data[right] = h->data[idx];
			h->data[idx] = aux;
			idx = right;
		} else
			break;
	}

}

/*
 * delete the element with the given id from the heap
 * if it doesn't exist, the function doesn't do anything
 */
void heap_remove(my_heap *h, unsigned int id)
{
	unsigned int i;

	for (i = 0 ; i < h->count ; i++) {
		if (h->data[i]->id == id) {
			heap_erase(h, i);
			return;
		}
	}
}

/*
 * delete the max from the heap and return it's value
 */
my_heap_entry *heap_pop(my_heap *h)
{
	my_heap_entry *to_ret;

	if (h->count == 0)
		return NULL;

	to_ret = h->data[0];
	heap_erase(h, 0);

	return to_ret;
}

/*
 * return max from the heap, or NULL if heap is empty
 */
my_heap_entry *heap_top(my_heap *h)
{
	if (h->count == 0)
		return NULL;
	else
		return h->data[0];
}

/*
 * compares two elements. similar to '>' comparison
 */
static int compare_gt(my_heap_entry *left, my_heap_entry *right)
{
	if (left->priority > right->priority)
		return 1;
	else if (left->priority < right->priority)
		return -1;
	else if (left->order < right->order)
		return 1;
	else if (left->order > right->order)
		return -1;

	return 0;
}
