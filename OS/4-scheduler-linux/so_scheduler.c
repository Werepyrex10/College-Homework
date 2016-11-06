/*
 * Dimitriu Dragos-Cosmin 331CA
 */
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>

#include "so_scheduler.h"
#include "my_heap.h"

#define NOWAIT -1

#define FINISH 0
#define NOFINISH 1

/*
 * thread state information
 */
typedef struct {
	tid_t tid;
	int wait;
	unsigned priority;
	unsigned order;
	so_handler *handler;
	sem_t *sem;
} thread_state;

static unsigned int count;
static unsigned int s_quantum;
static unsigned int s_max_io;

static thread_state *threads;
static unsigned int size;

static unsigned current_quantum;
static unsigned int current_thread;
static my_heap *heap;
static unsigned int order;

static void *start_thread(void *);
static void scheduler(char finish);
static void change_context(unsigned, char);

/*
 * creates and initializes scheduler
 * + time quantum for each thread
 * + number of IO devices supported
 * returns: 0 on success or negative on error
 */
int so_init(unsigned quantum, unsigned max_io)
{
	/* check if values are valid */
	if (quantum == 0 || max_io > SO_MAX_NUM_EVENTS)
		return -1;

	/* check for multiple so_init calls */
	if (s_quantum != 0)
		return -1;

	size = 4;

	s_quantum = quantum;
	s_max_io = max_io;
	count = 0;
	threads = calloc(size, sizeof(thread_state));

	if (threads == NULL)
		return -1;

	order = 0;
	heap = malloc(sizeof(my_heap));
	if (heap == NULL)
		return -1;

	heap_init(heap);

	return 0;
}

/*
 * creates a new so_task_t and runs it according to the scheduler
 * + handler function
 * + priority
 * returns: tid of the new task if successful or INVALID_TID
 */
tid_t so_fork(so_handler *handler, unsigned priority)
{
	sem_t *s;
	int rc;
	my_heap_entry he;

	if (handler == NULL || priority > SO_MAX_PRIO)
		return INVALID_TID;

	s = calloc(1, sizeof(sem_t));
	if (s == NULL)
		return INVALID_TID;

	rc = sem_init(s, 0, 0);
	if (rc == -1)
		return INVALID_TID;

	if (count == size) {
		size *= 2;
		threads = realloc(threads, size * sizeof(thread_state));
		if (threads == NULL)
			return INVALID_TID;
	}

	threads[count].order = order;
	threads[count].wait = NOWAIT;
	threads[count].priority = priority;
	threads[count].handler = handler;
	threads[count].sem = s;

	he.id = count;
	he.priority = priority;
	he.order = order;
	heap_insert(heap, &he);

	rc = pthread_create(&threads[count].tid, NULL,
		start_thread, (void *)(long)count);
	if (rc != 0)
		return INVALID_TID;
	count++;
	order++;

	/* check if it's the first thread created */
	if (count == 1) {
		current_thread = 0;
		current_quantum = s_quantum;
		heap_pop(heap);
		rc = sem_post(threads[0].sem);

		if (rc == -1)
			return INVALID_TID;

	} else {
		--current_quantum;
		scheduler(NOFINISH);
	}

	return threads[count - 1].tid;
}

/*
 * waits for an IO device
 * + device index
 * returns: -1 if the device does not exist or 0 on success
 */
int so_wait(unsigned dev_idx)
{
	if (dev_idx >= s_max_io)
		return -1;

	threads[current_thread].wait = dev_idx;

	scheduler(NOFINISH);

	return 0;
}

/*
 * signals an IO device
 * + device index
 * return the number of tasks woke or -1 on error
 */
int so_signal(unsigned dev_idx)
{
	unsigned int i;
	unsigned int counter = 0;
	my_heap_entry he;

	if (dev_idx >= s_max_io)
		return -1;

	for (i = 0 ; i < count ; i++) {
		if (threads[i].wait == dev_idx) {
			threads[i].wait = NOWAIT;
			he.id = i;
			he.priority = threads[i].priority;
			he.order = threads[i].order;
			heap_insert(heap, &he);
			++counter;
		}
	}

	--current_quantum;

	scheduler(NOFINISH);

	return counter;
}

/*
 * does whatever operation
 */
void so_exec(void)
{
	--current_quantum;
	scheduler(NOFINISH);
}

/*
 * destroys a scheduler
 */
void so_end(void)
{
	unsigned int i;
	int rc;

	for (i = 0 ; i < count ; i++) {
		rc = pthread_join(threads[i].tid, NULL);

		if (rc != 0)
			exit(1);

		rc = sem_destroy(threads[i].sem);

		if (rc == -1)
			exit(1);
	}

	if (threads != NULL) {
		free(threads);
		threads = NULL;
	}

	s_quantum = s_max_io = 0;

	if (heap != NULL) {
		heap_destroy(heap);
		free(heap);
		heap = NULL;
	}
}

/*
 * starting function for a new thread
 */
static void *start_thread(void *arg)
{
	unsigned id = (unsigned)(long)arg;
	int rc;

	rc = sem_wait(threads[id].sem);

	if (rc == -1)
		exit(1);

	threads[id].handler(threads[id].priority);
	current_quantum = 0;
	scheduler(FINISH);

	return NULL;
}

/*
 * scheduling logic using a max-heap
 */
static void scheduler(char finish)
{
	my_heap_entry *entry = heap_top(heap);
	unsigned int id;
	my_heap_entry he;

	/* check if top element is valid or if the current quantum
	 * needs to be reset
	 */
	if (entry == NULL ||
		(threads[current_thread].priority > entry->priority &&
		finish == NOFINISH && threads[current_thread].wait == NOWAIT)) {
		if (current_quantum == 0)
			current_quantum = s_quantum;
		return;
	}

	/* check if priority of the top thread is worthy of running */
	id = entry->id;
	if (threads[id].priority > threads[current_thread].priority) {
		/* current thread has a lower priority and is preempted */
		heap_pop(heap);
		if (finish == NOFINISH &&
			threads[current_thread].wait == NOWAIT) {
			/* current thread needs to be inserted in the heap
			* for future selection
			*/
			he.id = current_thread;
			he.priority = threads[current_thread].priority;
			he.order = order;
			threads[current_thread].order = order;
			heap_insert(heap, &he);
			++order;
		}
		change_context(id, finish);
		return;
	} else if (current_quantum == 0 ||
		threads[current_thread].wait != NOWAIT) {
		/* current thread has expired or is in waiting state */
		heap_pop(heap);

		if (finish == NOFINISH &&
			threads[current_thread].wait == NOWAIT) {
			/* current thread needs to be inserted in the heap
			* for future selection
			*/
			he.id = current_thread;
			he.priority = threads[current_thread].priority;
			he.order = order;
			threads[current_thread].order = order;
			heap_insert(heap, &he);
			++order;
		}

		change_context(id, finish);
		return;
		}
}

/*
 * change the context to the tid thread and
 * wait on the semaphore if finish is not set
 */
static void change_context(unsigned tid, char finish)
{
	unsigned int old;
	int rc;

	old = current_thread;
	current_thread = tid;
	current_quantum = s_quantum;

	sem_post(threads[current_thread].sem);

	if (finish == NOFINISH) {
		rc = sem_wait(threads[old].sem);

		if (rc == -1)
			exit(1);
	}
}
