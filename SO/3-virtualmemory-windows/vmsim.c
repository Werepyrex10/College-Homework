/*
* Dimitriu Dragos-Cosmin 331CA
*/
#define DLL_EXPORTS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "helpers.h"
#include "vmsim.h"

#include "debug.h"
#include "util.h"

static LONG signal_handler(PEXCEPTION_POINTERS);
static w_handle_t create_temp_handle(w_size_t num, TCHAR *, TCHAR *);
static void page_init(struct page_table_entry *, w_ptr_t, int);
static struct mem *find_node(w_ptr_t);
static void swap_out(struct mem *);
static w_size_t get_page_no(struct mem *, struct page_table_entry *);
static w_size_t get_frame_no(struct mem *, struct frame *);
static void init_mem_entry(struct node *mem_entry, w_size_t, w_size_t);

/* All the mappings throughout the program */
static struct node *memory;
static w_handle_t segfault_handle;

/* Set my exception handler */
w_boolean_t vmsim_init(void)
{
	segfault_handle = w_add_exception_handler(signal_handler);
	return segfault_handle != NULL;
}

/* Set the empty exception handler */
w_boolean_t vmsim_cleanup(void)
{
	return w_remove_exception_handler(segfault_handle);
}

/* Aloc virtual memory in the vm_map_t structure */
w_boolean_t vm_alloc(w_size_t num_pages, w_size_t num_frames,
				      vm_map_t *map)
{
	struct node *mem_entry = (struct node *)malloc(sizeof(struct node));

	if (num_pages < num_frames)
		return FALSE;

	init_mem_entry(mem_entry, num_frames, num_pages);

	map->ram_handle = mem_entry->data->ram_file;
	map->swap_handle = mem_entry->data->swap_file;
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
	w_boolean_t rcb;
	unsigned int i;
	struct node *aux = memory, *p = NULL;

	if (start == NULL || memory == NULL)
		return FALSE;

	/* Looking for the entry in the memory map */
	while (aux->data->start != start && aux->next != NULL) {
		p = aux;
		aux = aux->next;
	}

	/* Free memory for each independent page */
	if (aux->data->start == start) {
		for (i = 0 ; i < aux->data->num_pages ; i++) {
			if (aux->data->pg[i].state == STATE_NOT_ALLOC ||
				aux->data->pg[i].state == STATE_IN_SWAP) {
				rc = VirtualFree(
					aux->data->pg[i].start,
					0,
					MEM_RELEASE
					);
				DIE(rc < 0, "VIRTUALFREE FREE");
			} else {
				rcb = UnmapViewOfFile(aux->data->pg[i].start);
				DIE(rcb == FALSE, "UNMAPVIEWOFFILE FREE");
			}
		}
	} else
		return FALSE;

	w_close_file(aux->data->ram_handle);

	w_close_file(aux->data->ram_file);
	w_close_file(aux->data->swap_file);

	rc = DeleteFile(aux->data->ram_name);
	DIE(rc == 0, "DELETEFILE RAM");

	rc = DeleteFile(aux->data->swap_name);
	DIE(rc == 0, "DELETEFILE SWAP");

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
	int rc;
	w_size_t i;

	mem_entry->data = (struct mem *)malloc(sizeof(struct mem));
	mem_entry->data->num_pages = num_pages;
	mem_entry->data->num_frames = num_frames;
	mem_entry->data->num_ram = 0;

	/* Files for the virtual mapping (RAM and SWAP) */
	mem_entry->data->ram_file = create_temp_handle(num_frames,
		mem_entry->data->ram_name, "RAM");
	DIE(
		mem_entry->data->ram_file == INVALID_HANDLE_VALUE,
		"CREATETEMPHANDLE RAM"
		);

	mem_entry->data->swap_file = create_temp_handle(num_pages,
		mem_entry->data->swap_name, "SWAP");
	DIE(
		mem_entry->data->swap_file == INVALID_HANDLE_VALUE,
		"CREATETEMPHANDLE SWAP"
		);

	/* Virtual memory */
	mem_entry->data->ram_handle = CreateFileMapping(
		mem_entry->data->ram_file,
		NULL,
		PAGE_READWRITE,
		0,
		num_frames * w_get_page_size(),
		NULL);
	DIE(mem_entry->data->ram_handle == NULL, "CREATEFILEMAPPING RAM");

	/* Getting a start address to work with */
	mem_entry->data->start = VirtualAlloc(
		NULL,
		w_get_page_size() * num_pages,
		MEM_RESERVE,
		PAGE_NOACCESS
	);
	DIE(mem_entry->data->start == NULL, "VIRTUAL ALLOC");

	rc = VirtualFree(mem_entry->data->start, 0, MEM_RELEASE);
	DIE(rc == 0, "VIRTUALFREE");

	/* Data for the structures which retain mapping information */
	mem_entry->data->fr = (struct frame *)malloc(num_frames *
		sizeof(struct frame));
	DIE(mem_entry->data->fr == NULL, "MALLOC FRAME");

	mem_entry->data->pg = (struct page_table_entry *)malloc(num_pages *
		sizeof(struct page_table_entry));
	DIE(mem_entry->data->pg == NULL, "MALLOC PAGE");

	/* Alocate a virtual space for each page to manage it easier */
	for (i = 0 ; i < num_pages ; i++)
		page_init(&mem_entry->data->pg[i], mem_entry->data->start, i);

	for (i = 0 ; i < num_frames ; i++)
		mem_entry->data->fr[i].pte = NULL;

	mem_entry->next = NULL;
}

/* Creating temporary files for the file mapping
* These files are deleted once the program has ended
*/
static w_handle_t create_temp_handle(w_size_t num,
	TCHAR *filename, TCHAR *pref)
{
	int rc;
	w_handle_t h;

	rc = GetTempFileName(".", pref, 0, filename);
	DIE(rc == 0, "MKSTEMP");

	/* Reserving size for the files */
	h = w_open_file(filename, MODE_FULL_OPEN);
	DIE(h == INVALID_HANDLE_VALUE, "W_OPEN_FILE");

	rc = w_set_file_pointer(h, w_get_page_size() * num);
	DIE(rc == FALSE, "W_SET_FILE_POINTER END");

	rc = SetEndOfFile(h);
	DIE(rc == 0, "SETENDOFFILE");

	rc = w_set_file_pointer(h, 0);
	DIE(rc == FALSE, "W_SET_FILE_POINTER START");

	return h;
}

static void page_init(struct page_table_entry *page, w_ptr_t start, int i)
{
		page->state = STATE_NOT_ALLOC;
		page->prev_state = STATE_NOT_ALLOC;
		page->dirty = FALSE;
		page->protection = PROTECTION_NONE;
		page->start = VirtualAlloc(
			(w_ptr_t)((w_size_t)start + i * w_get_page_size()),
			w_get_page_size(),
			MEM_RESERVE,
			PAGE_NOACCESS
		);
		DIE(page->start == NULL, "VIRTUALALLOC PAGES");
		page->frame = NULL;
}

/* My SIGSEGV handler */
static LONG signal_handler(PEXCEPTION_POINTERS info)
{
	struct mem *mem_entry;
	struct page_table_entry *pte;
	int rc;
	w_ptr_t rcp;
	w_boolean_t rcb;
	w_ptr_t page_addr;
	w_size_t page_size = w_get_page_size();
	w_size_t page_num;

	if (info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
		return EXCEPTION_CONTINUE_EXECUTION;

	/* Extract the aligned address */
	page_addr = (w_ptr_t)(
		(w_size_t)info->ExceptionRecord->ExceptionInformation[1] -
		((w_size_t)info->ExceptionRecord->ExceptionInformation[1] %
		page_size));

	/* Find the node which contains the page address */
	mem_entry = find_node(page_addr);

	/* Get the number of the page */
	page_num = (
		(w_size_t)page_addr - (w_size_t)mem_entry->start) /
		page_size;
	pte = &(mem_entry->pg[page_num]);

	/* First access to a page */
	if (mem_entry->num_ram < mem_entry->num_frames &&
		pte->protection == PROTECTION_NONE) {
		rcb = VirtualFree(page_addr, 0, MEM_RELEASE);
		DIE(rcb == FALSE, "VIRTUALFREE");

		rcp = MapViewOfFileEx(
			mem_entry->ram_handle,
			FILE_MAP_READ,
			0,
			mem_entry->num_ram * page_size,
			page_size,
			page_addr
			);
		DIE(rcp == NULL, "MAPVIEWOFFILEEX PROT_NONE");

		rc = w_protect_mapping(page_addr, 1, PROTECTION_READ);
		DIE(rc < 0, "W_PROTECT_MAPPING READ");


		pte->state = STATE_IN_RAM;
		pte->protection = PROTECTION_READ;
		pte->dirty = FALSE;

		pte->frame = &mem_entry->fr[mem_entry->num_ram];
		mem_entry->fr[mem_entry->num_ram].pte = pte;
		mem_entry->num_ram++;

		return EXCEPTION_CONTINUE_EXECUTION;
	} else if (pte->state == STATE_IN_RAM) {
		/* A read protected area was accessed for write */
		rcb = UnmapViewOfFile(page_addr);
		DIE(rcb == FALSE, "UNMAPVIEWOFFILE PROT_READ");

		rcp = MapViewOfFileEx(
			mem_entry->ram_handle,
			FILE_MAP_WRITE,
			0,
			get_frame_no(mem_entry, pte->frame) * page_size,
			page_size,
			page_addr
			);
		DIE(rcp == NULL, "MAPVIEWOFFILEEX PROT_READ");

		rc = w_protect_mapping(page_addr, 1, PROTECTION_WRITE);
		DIE(rc < FALSE, "W_PROTECT_MAPPING PROT_READ");

		memset(page_addr, 0, page_size);
		w_sync_mapping(page_addr, 1);

		pte->protection = PROTECTION_WRITE;
		pte->dirty = TRUE;

		return EXCEPTION_CONTINUE_EXECUTION;
	} else if (mem_entry->num_ram == mem_entry->num_frames) {
		/* Ram is full and we need to swap out a page */
		swap_out(mem_entry);
		rc = VirtualFree(page_addr, 0, MEM_RELEASE);
		DIE(rc < 0, "UNMAPVIEWOFFILE SWAP");

		rcp = MapViewOfFileEx(
			mem_entry->ram_handle,
			FILE_MAP_WRITE,
			0,
			0 * page_size,
			page_size,
			page_addr
			);
		DIE(rcp == NULL, "MAPVIEWOFFILEEX SWAP WRITE");

		/* The page we need has been dealt with in the past
		* and is in the swap memory right now
		*/
		if (pte->state == STATE_IN_SWAP) {
			rc = w_set_file_pointer(mem_entry->swap_file,
				page_num * page_size);
			DIE(rc < 0, "W_SET_FILE_POINTER SWAP");

			rc = w_read_file(mem_entry->swap_file,
							 pte->start,
							 page_size);

			DIE(rc == FALSE, "W_READ_FILE SWAP");
		} else {
			memset(page_addr, 0, page_size);
			w_sync_mapping(pte->start, 1);
		}

		rcb = UnmapViewOfFile(page_addr);
		DIE(rcb == FALSE, "UNMAPVIEWOFFILE SWAP");

		rcp = MapViewOfFileEx(
			mem_entry->ram_handle,
			FILE_MAP_READ,
			0,
			0 * page_size,
			page_size,
			page_addr
			);
		DIE(rcp == NULL, "MAPVIEWOFFILEEX SWAP READ");

		rc = w_protect_mapping(page_addr, 1, PROTECTION_READ);
		DIE(rc < 0, "W_PROTECT_MAPPING SWAP");

		pte->prev_state = pte->state;
		pte->state = STATE_IN_RAM;
		pte->protection = PROTECTION_READ;
		pte->dirty = FALSE;

		pte->frame = &mem_entry->fr[0];
		mem_entry->fr[0].pte = pte;

		return EXCEPTION_CONTINUE_EXECUTION;
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
	high = (w_ptr_t)(
		(w_size_t)nod->data->start + nod->data->num_pages *
		page_size);

	while (nod != NULL && !(page_addr >= low && page_addr < high)) {
		nod = nod->next;
		low = nod->data->start;
		high = (w_ptr_t)(
			(w_size_t)nod->data->start + nod->data->num_pages *
			page_size);
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
		rc = w_set_file_pointer(mem_entry->swap_file,
			swap_no * page_size);
		DIE(rc == FALSE, "W_SET_FILE_POINTER SWAP OUT");

		rc = w_write_file(mem_entry->swap_file,
						  to_swap->start,
						  page_size);
		DIE(rc == FALSE, "W_WRITE_FILE SWAP OUT");

		to_swap->prev_state = to_swap->state;
		to_swap->dirty = FALSE;
		to_swap->frame = NULL;
	}
	rc = UnmapViewOfFile(to_swap->start);
	DIE(rc < 0, "UNMAPVIEWOFFILE SWAP OUT");

		rcp = VirtualAlloc(
			to_swap->start,
			page_size,
			MEM_RESERVE,
			PAGE_NOACCESS
			);
	DIE(rcp == NULL, "MAPVIEWOFFILE SWAP OUT");

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

static w_size_t get_frame_no(struct mem *mem_entry,
	struct frame *frame)
{
	w_size_t no = 0;

	while (&mem_entry->fr[no] != frame)
		++no;

	return no;
}
