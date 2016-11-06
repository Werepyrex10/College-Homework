/*
 * Dimitriu Dragos-Cosmin 331CA
 */
#ifndef __MY_HEAP__
#define __MY_HEAP__

typedef struct {
	unsigned int id;
	unsigned int order;
	unsigned priority;
} my_heap_entry;

typedef struct {
	my_heap_entry **data;
	unsigned int size;
	unsigned int count;
} my_heap;

void heap_init(my_heap *);
void heap_destroy(my_heap *);
void heap_insert(my_heap *, my_heap_entry *);
void heap_remove(my_heap *, unsigned int);
my_heap_entry *heap_pop(my_heap *);
my_heap_entry *heap_top(my_heap *);

#endif
