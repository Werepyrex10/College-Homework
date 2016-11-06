CC = gcc
CFLAGS = -Wall

TARGET = libscheduler.so
OBJ = so_scheduler.o my_heap.o

build: $(OBJ)
	$(CC) $(CFLAGS) -shared -fPIC $^ -o $(TARGET)

so_scheduler.o: so_scheduler.c so_scheduler.h
	$(CC) $(CFLAGS) -fPIC -c so_scheduler.c

my_heap.o: my_heap.c my_heap.h
	$(CC) $(CFLAGS) -fPIC -c my_heap.c

clean:
	rm -rf $(OBJ) $(TARGET)
