CC = gcc

build: main.o hash.o hashtable.o utils.h
	$(CC) $^ -o tema1

main.o: main.c

hash.o: hash.c

hashtable.o: hashtable.c

.PHONY: clean

clean:
	rm -f *.o tema1
