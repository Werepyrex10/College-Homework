/*
* Dimitriu Dragos-Cosmin 331CA
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "helpers.h"
#include "vmsim.h"

#include "debug.h"
#include "util.h"

static void signal_handler(int, siginfo_t *, void*);
static w_handle_t create_temp_handle(w_size_t num, char);
static void page_init(struct page_table_entry *, w_ptr_t, int);
static struct mem *find_node(w_ptr_t);
static void swap_out(struct mem *);
static w_size_t get_page_no(struct mem *, struct page_table_entry *);
static void init_mem_entry(struct node *mem_entry, w_size_t, w_size_t);

/* All the mappings throughout the program */
static struct node *memory;

/* Set my exception handler */
w_boolean_t vmsim_init(void)
{
	return w_set_exception_handler(signal_handler);
}

/* Set the empty exception handler */
w_boolean_t vmsim_cleanup(void)
{
	return w_set_exception_handler(empty_exception_handler);
}

/* Aloc virtual memory in the vm_map_t structure */
w_boolean_t vm_alloc(w_size_t num_pages, w_size_t num_frames,
				      vm_map_t *map)
{
	struct node *mem_entry = malloc(sizeof(struct node));

	if (num_pages < num_frames)
		return FALSE;

	init_mem_entry(mem_entry, num_frames, num_pages);

	map->ram_handle = mem_entry->data->ram_handle;
	map->swap_handle = mem_entry->data->swap_handle;
	map->start = mem_entry->data->start;

	/* adding the entry to the list of mappings */
	if (memory == NULL)
		memory = mem_entry;
	else {
		struct node *aux = memory;

		while (aux->next != NULL)
			aux = aux->next;

		aux->next = mem_entry;
	}

	return TRUE;
}

/* Releasing the virtual memory and the structures used to
* administrate the area
*/
w_boolean_t vm_free(w_ptr_t start)
{
	int rc;
	struct node *aux = memory, *p = NULL;

	if (start == NULL || memory == NULL)
		return FALSE;

	/* Looking for the entry in the memory map */
	while (aux->data->start != start && aux->next != NULL) {
		p = aux;
		aux = aux->next;
	}

	if (aux->data->start == start) {
		rc = munmap(start, w_get_page_size() * aux->data->num_pages);
		DIE(rc < 0, "MUNMAP");
	} else
		return FALSE;

	w_close_file(aux->data->ram_handle);
	w_close_file(aux->data->swap_handle);

	free(aux->data->fr);
	free(aux->data->pg);
	free(aux->data);

	/* Eliminating the node from the memory maps */
	if (aux == memory) {
		memory = memory->next;
		free(aux);
	} else {
		p->next = aux->next;
		free(aux);
	}

	return TRUE;
}

/* Initialize memory mapping with given initial parameters */
static void init_mem_entry(struct node *mem_entry, w_size_t num_frames,
							w_size_t num_pages)
{
	int i;

	mem_entry->data = malloc(sizeof(struct mem));
	mem_entry->data->num_pages = num_pages;
	mem_entry->data->num_frames = num_frames;
	mem_entry->data->num_ram = 0;

	/* Files for the virtual mapping (RAM and SWAP) */
	mem_entry->data->ram_handle = create_temp_handle(num_frames, RAM);
	DIE(mem_entry->data->ram_handle == -1, "CREATE_HANDLE RAM");

	mem_entry->data->swap_handle = create_temp_handle(num_pages, SWAP);
	DIE(mem_entry->data->swap_handle == -1, "CREATE_HANDLE_SWAP");

	/* Virtual memory */
	mem_entry->data->start = mmap(
		NULL,
		w_get_page_size() * num_pages,
		PROT_NONE,
		MAP_SHARED | MAP_ANONYMOUS,
		-1,
		0
	);
	DIE(mem_entry->data->start == MAP_FAILED, "MMAP ALLOC");

	/* Data for the structures which retain mapping information */
	mem_entry->data->fr = malloc(num_frames * sizeof(struct frame));
	DIE(mem_entry->data->fr == NULL, "MALLOC FRAME");

	mem_entry->data->pg = malloc(num_pages *
		sizeof(struct page_table_entry));
	DIE(mem_entry->data->pg == NULL, "MALLOC PAGE");

	for (i = 0 ; i < num_pages ; i++)
		page_init(&mem_entry->data->pg[i], mem_entry->data->start, i);

	for (i = 0 ; i < num_frames ; i++)
		mem_entry->data->fr[i].pte = NULL;

	mem_entry->next = NULL;
}

/* Creating temporary files for the file mapping
* These files are deleted once the program has ended
*/
static w_handle_t create_temp_handle(w_size_t num, char type)
{
	char name[12];
	int rc;
	w_handle_t fd;

	if (type == RAM)
		strcpy(name, "RAM_XXXXXX");
	else if (type == SWAP)
		strcpy(name, "SWAP_XXXXXX");

	fd = mkstemp(name);
	DIE(fd == INVALID_HANDLE, "MKSTEMP");

	/* The files will exists as long as they're not closed */
	rc = unlink(name);
	DIE(rc == -1, "UNLINK");

	/* Reserving size for the files */
	rc = ftruncate(fd, w_get_page_size() * num);
	DIE(rc < 0, "FTRUNCATE");

	return fd;

}

static void page_init(struct page_table_entry *page, w_ptr_t start, int i)
{
		page->state = STATE_NOT_ALLOC;
		page->prev_state = STATE_NOT_ALLOC;
		page->dirty = FALSE;
		page->protection = PROTECTION_NONE;
		page->start = (start + i * w_get_page_size());
		page->frame = NULL;
}

/* My SIGSEGV handler */
static void signal_handler(int signum, siginfo_t *info, void *context)
{
	struct mem *mem_entry;
	struct page_table_entry *pte;
	int rc;
	w_ptr_t rcp;
	w_ptr_t page_addr;
	w_size_t page_size = w_get_page_size();
	w_size_t page_num;

	if (signum != SIGSEGV)
		return;

	/* Extract the aligned address */
	page_addr = info->si_addr - ((w_size_t)info->si_addr % page_size);

	/* Find the node which contains the page address */
	mem_entry = find_node(page_addr);

	/* Get the number of the page */
	page_num = (w_size_t)(page_addr - mem_entry->start) / page_size;
	pte = &(mem_entry->pg[page_num]);

	/* First access to a page */
	if (mem_entry->num_ram < mem_entry->num_frames &&
		pte->protection == PROTECTION_NONE) {
		rc = munmap(page_addr, page_size);
		DIE(rc < 0, "MUNMMAP PROT NONE");

		rcp = mmap(
			page_addr,
			page_size,
			PROT_READ,
			MAP_SHARED | MAP_FIXED,
			mem_entry->ram_handle,
			mem_entry->num_ram * page_size);
		DIE(rcp == MAP_FAILED, "MMAP PROT NONE");

		pte->state = STATE_IN_RAM;
		pte->protection = PROTECTION_READ;
		pte->dirty = FALSE;

		pte->frame = &mem_entry->fr[mem_entry->num_ram];
		mem_entry->fr[mem_entry->num_ram].pte = pte;
		mem_entry->num_ram++;

		return;
	} else if (pte->state == STATE_IN_RAM) {
		/* A read protected area was accessed for write */
		rc = w_protect_mapping(page_addr, 1, PROTECTION_WRITE);
		memset(page_addr, 0, page_size);
		w_sync_mapping(page_addr, 1);
		DIE(rc == FALSE, "W_PROTECT_MAPPING");

		pte->protection = PROTECTION_WRITE;
		pte->dirty = TRUE;

		return;
	} else if (mem_entry->num_ram == mem_entry->num_frames) {
		/* Ram is full and we need to swap out a page */
		swap_out(mem_entry);
		rc = munmap(page_addr, page_size);
		DIE(rc < 0, "MUNMAP SWAP");

		rcp = mmap(
			page_addr,
			page_size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED,
			mem_entry->ram_handle,
			0
			);
		DIE(rcp == MAP_FAILED, "MMAP SWAP");

		/* The page we need is in swap has been dealt with in the past
		* and is in the swap memory right now
		*/
		if (pte->state == STATE_IN_SWAP) {
			rc = w_set_file_pointer(mem_entry->swap_handle,
				page_num * page_size);
			DIE(rc < 0, "W_SET_FILE_POINTER SWAP");

			rc = w_read_file(mem_entry->swap_handle,
							 pte->start,
							 page_size);

			DIE(rc == FALSE, "W_READ_FILE SWAP");
		} else {
			memset(page_addr, 0, page_size);
			w_sync_mapping(pte->start, 1);
		}

		rc = w_protect_mapping(page_addr, 1, PROTECTION_READ);
		DIE(rc < 0, "W_PROTECT_MAPPING SWAP");

		pte->prev_state = pte->state;
		pte->state = STATE_IN_RAM;
		pte->protection = PROTECTION_READ;
		pte->dirty = FALSE;

		pte->frame = &mem_entry->fr[0];
		mem_entry->fr[0].pte = pte;

		return;
	}

	DIE(1, "UNKNOWN");
}

/* Looking through memory to find node which administers
* this memory zone
*/
static struct mem *find_node(w_ptr_t page_addr)
{
	struct node *nod = memory;
	w_ptr_t low, high;
	w_size_t page_size = w_get_page_size();

	low = nod->data->start;
	high = nod->data->start + nod->data->num_pages * page_size;

	/* looking for the entry which contains my page_addr */
	while (nod != NULL && !(page_addr >= low && page_addr < high)) {
		nod = nod->next;
		low = nod->data->start;
		high = nod->data->start + nod->data->num_pages * page_size;
	}
	DIE(nod == NULL, "SEGFAULT node not found");

	return nod->data;
}

/* Swap out the page_num page from the mem_entry entry, residing in RAM
* at the moment
*/
static void swap_out(struct mem *mem_entry)
{
	struct page_table_entry *to_swap = mem_entry->fr[0].pte;
	w_size_t page_size = w_get_page_size();
	int rc;
	w_ptr_t rcp;
	w_size_t swap_no = get_page_no(mem_entry, to_swap);

	/* If the page is dirty or if it was only accessed for write
	*then write it to the file
	*/
	if (to_swap->dirty == TRUE || to_swap->prev_state == STATE_NOT_ALLOC) {
		rc = w_set_file_pointer(mem_entry->swap_handle,
			swap_no * page_size);
		DIE(rc == FALSE, "W_SET_FILE_POINTER SWAP OUT");

		rc = w_write_file(mem_entry->swap_handle,
						  to_swap->start,
						  page_size);
		DIE(rc == FALSE, "W_WRITE_FILE SWAP OUT");

		to_swap->prev_state = to_swap->state;
		to_swap->dirty = FALSE;
		to_swap->frame = NULL;
	}
	rc = munmap(to_swap->start, page_size);
	DIE(rc < 0, "MUNMAP SWAP OUT");

	rcp = mmap(to_swap->start,
				page_size,
				PROT_NONE,
				MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS,
				-1,
				0);
	DIE(rcp == MAP_FAILED, "MMAP SWAP OUT");

	to_swap->protection = PROTECTION_NONE;
	to_swap->prev_state = to_swap->state;
	to_swap->state = STATE_IN_SWAP;
}

/* Get the index of page from the mem_entry */
static w_size_t get_page_no(struct mem *mem_entry,
	struct page_table_entry *page)
{
	w_size_t no = 0;

	while (&mem_entry->pg[no] != page)
		++no;

	return no;
}
