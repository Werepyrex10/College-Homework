#ifndef __HASHTABLE__
#define __HASHTABLE__

#include "utils.h"

struct Bucket {
	int key;
	char *value;
	struct Bucket *prev;
	struct Bucket *next;
};

struct Hashtable {
	struct Bucket *buckets;
	int size;
};

void init(struct Hashtable *h);
void add_to_bucket(char *word, int key, struct Bucket *bucket);
void remove_from_bucket(char *word, struct Bucket *bucket);
void add_to_hash(char *word, struct Hashtable *h);
void remove_from_hash(char *word, struct Hashtable *h);
void find_in_hash(char *word, struct Hashtable *h, char *file);
int find_in_bucket(char *word, struct Bucket *bucket);
void print_bucket(struct Bucket *bucket, char *file);
void print_hash_bucket(struct Hashtable *h, int index, char *file);
void print(struct Hashtable *h, char *file);
void resize(struct Hashtable **h, char *type);
void add_all_from_hash(struct Hashtable *dst, struct Hashtable *src);
void add_all_from_bucket(struct Hashtable *h, struct Bucket *bucket);
void clear(struct Hashtable *h);
void destroy(struct Hashtable *h);

#endif
