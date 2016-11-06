/*
* Dimitriu Dragos-Cosmin 331CA
*/

#ifndef __HELPERS__
#define __HELPERS__

#include "common.h"
#include "vmsim.h"

enum page_state {
	STATE_IN_RAM,
	STATE_IN_SWAP,
	STATE_NOT_ALLOC
};

struct frame;

/* handle pages (virtual pages) */
struct page_table_entry {
	enum page_state state;
	enum page_state prev_state;
	w_boolean_t dirty;
	w_prot_t protection;
	w_ptr_t start;
	struct frame *frame;	/* NULL in case page is not mapped */
};

/* handle frames (physical pages) */
struct frame {
	/* "backlink" to page_table_entry; NULL in case of free frame */
	struct page_table_entry *pte;
};

/* Memory information */
struct mem {
	struct frame *fr;
	w_size_t num_frames;
	int num_ram;

	struct page_table_entry *pg;
	w_size_t num_pages;

	w_handle_t ram_handle;
	w_handle_t swap_handle;

	/* number of alocated pages */
	w_ptr_t start;
};

/* Memory list */
struct node {
	struct node *next;
	struct mem *data;
};


#endif
