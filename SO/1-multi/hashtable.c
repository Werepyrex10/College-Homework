#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "hashtable.h"
#include "hash.h"

/*Function which initializes a Hashtable*/
void init(struct Hashtable *h)
{
	int i = 0;

	h->buckets = calloc(h->size, sizeof(struct Bucket));
	DIE(h->buckets == NULL, "Malloc error");

	for (i = 0 ; i < h->size ; i++) {
		h->buckets[i].value = NULL;
		h->buckets[i].next = NULL;
		h->buckets[i].prev = NULL;
	}
}

/*Function which adds a new word to a list of buckets*/
void add_to_bucket(char *word, int key, struct Bucket *bucket)
{
	if (bucket->value == NULL) {
		bucket->value = malloc((strlen(word) + 1)*sizeof(char));
		strcpy(bucket->value, word);
		bucket->key = key;
		return;
	}
	while (bucket->next != NULL) {
		if (strcmp(bucket->value, word) == 0)
			return;
		bucket = bucket->next;
	}

	if (strcmp(bucket->value, word) == 0)
		return;

	bucket->next = calloc(1, sizeof(struct Bucket));
	DIE(bucket->next == NULL, "Malloc error");

	bucket->next->prev = bucket;
	bucket->next->next = NULL;
	bucket->next->value = NULL;

	bucket = bucket->next;

	bucket->value = malloc((strlen(word) + 1)*sizeof(char));
	strcpy(bucket->value, word);
	bucket->key = key;
}

/*Function which removes a word from a list of buckets*/
void remove_from_bucket(char *word, struct Bucket *bucket)
{
	while (bucket != NULL && bucket->value != NULL) {
		if (strcmp(bucket->value, word) == 0) {
			while (bucket->next != NULL) {

				free(bucket->value);

				bucket->value = malloc(
					(strlen(bucket->next->value)
					+ 1) * sizeof(char));
				strcpy(bucket->value, bucket->next->value);

				bucket = bucket->next;
			}

			free(bucket->value);
			bucket->value = NULL;

			if (bucket->prev != NULL) {
				bucket->prev->next = NULL;
				free(bucket);
				bucket = NULL;
			}

			return;
		}

		bucket = bucket->next;
	}

}

/*Function which adds a word to a Hashtable*/
void add_to_hash(char *word, struct Hashtable *h)
{
	int hashval = hash(word, h->size);

	if (h->buckets == NULL)
		init(h);

	add_to_bucket(word, hashval, &h->buckets[hashval]);
}

/*Function which removes a word from a Hashtable*/
void remove_from_hash(char *word, struct Hashtable *h)
{
	int hashval = hash(word, h->size);

	if (h->buckets == NULL)
		return;

	remove_from_bucket(word, &h->buckets[hashval]);
}

/*Function which returns 1 if it found 'word' in a
*bucket list or 0 otherwise
*/
int find_in_bucket(char *word, struct Bucket *bucket)
{
	while (bucket != NULL && bucket->value != NULL) {
		if (strcmp(word, bucket->value) == 0)
			return 1;

		bucket = bucket->next;
	}

	return 0;
}

/*Function which looks for a word in a Hashtable and prints to
*file or to stdout if file is null
*/
void find_in_hash(char *word, struct Hashtable *h, char *file)
{
	int hashval = hash(word, h->size);
	int rc;
	FILE *f;

	if (file == NULL)
		f = stdout;
	else
		f = fopen(file, "a");

	if (h->buckets == NULL) {
		fprintf(f, "False\n");

		if (file != NULL) {
			rc = fclose(f);
			DIE(rc == -1, "Fclose error");
		}

		return;
	}

	if (find_in_bucket(word, &h->buckets[hashval]) == 1) {
		fprintf(f, "True\n");

		if (file != NULL) {
			rc = fclose(f);
			DIE(rc == -1, "Fclose error");
		}

		return;
	}

	fprintf(f, "False\n");

	if (file != NULL) {
		rc = fclose(f);
		DIE(rc == -1, "Fclose error");
	}
}

/*Function which prints all the values from a list of buckets
*to file or to stdout if file is null
*/
void print_bucket(struct Bucket *bucket, char *file)
{
	FILE *f;
	int rc;

	if (bucket->value == NULL)
		return;

	if (file == NULL)
		f = stdout;
	else
		f = fopen(file, "a");

	if (bucket->value != NULL)
		fprintf(f, "%s", bucket->value);

	bucket = bucket->next;

	while (bucket != NULL && bucket->value != NULL) {
		fprintf(f, " %s", bucket->value);

		bucket = bucket->next;
	}
	fprintf(f, "\n");

	if (file != NULL) {
		rc = fclose(f);
		DIE(rc == -1, "Fclose error");
	}
}

/*Function which prints a bucket from a Hashmap to file
*or to stdout if file is null
*/
void print_hash_bucket(struct Hashtable *h, int index, char *file)
{
	print_bucket(&h->buckets[index], file);
}

/*Function which prints an entire Hashmap to a file
*or to stdout is file is null
*/
void print(struct Hashtable *h, char *file)
{
	int i = 0, rc;
	FILE *f;

	if (h->buckets == NULL) {
		if (file == NULL)
			fprintf(stdout, "\n");
		else {
			f = fopen(file, "a");

			fprintf(f, "\n");

			rc = fclose(f);
			DIE(rc == -1, "Fclose error");

			return;
		}
	} else {
		for (; i < h->size ; i++)
			print_bucket(&h->buckets[i], file);
	}
}

/*Function which adds all the words from a bucket list to a Hashtable*/
void add_all_from_bucket(struct Hashtable *h, struct Bucket *bucket)
{
	struct Bucket *b;

	while (bucket != NULL && bucket->value != NULL) {
		add_to_hash(bucket->value, h);

		b = bucket->next;

		bucket = b;
	}
}

/*Function which adds all words from src to dst, both Hashtables*/
void add_all_from_hash(struct Hashtable *dst, struct Hashtable *src)
{
	int i = 0;

	for (; i < src->size ; i++)
		add_all_from_bucket(dst, &src->buckets[i]);
}

/*Function which doubles/halves the size of the
*hashtable given as parameter
*/
void resize(struct Hashtable **h, char *type)
{
	struct Hashtable *new = calloc(1, sizeof(struct Hashtable));

	DIE(new == NULL, "Malloc error");

	new->size = 0;

	if (strcmp(type, "double") == 0)
		new->size = (*h)->size * 2;
	else if (strcmp(type, "halve") == 0)
		new->size = (*h)->size / 2;

	DIE(new->size == 0, "Error resize type");

	init(new);

	add_all_from_hash(new, (*h));

	clear(*h);
	free((*h)->buckets);
	free(*h);

	*h = new;
}

/*Function which clears all the values from a bucket
*and frees memory
*/
void clear_bucket(struct Bucket *bucket)
{
	struct Bucket *b;

	if (bucket == NULL)
		return;

	free(bucket->value);
	bucket->value = NULL;

	bucket = bucket->next;

	while (bucket != NULL) {
		free(bucket->value);

		bucket->value = NULL;

		b = bucket->next;

		free(bucket);

		bucket = b;
	}
}

/*Method which clears all the values from a Hashtable
*and frees memory
*/
void clear(struct Hashtable *h)
{
	int i = 0;

	if (h->buckets != NULL) {
		for (; i < h->size ; i++)
			clear_bucket(&h->buckets[i]);

		free(h->buckets);
		h->buckets = NULL;
	}
}
