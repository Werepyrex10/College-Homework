CC = gcc
CFLAGS = -Wall

HEADERS = vmsim.h common.h debug.h util.h helpers.h
TARGET = libvmsim.so
OBJ = common_lin.o vmsim.o

build: $(OBJ) $(HEADERS)
	$(CC) $(CFLAGS) -shared -fPIC $^ -o $(TARGET)

common_lin.o:
	$(CC) $(CFLAGS) -fPIC -c common_lin.c

vmsim.o:
	$(CC) $(CFLAGS) -fPIC -c vmsim.c

clean:
	rm -rf $(OBJ) $(TARGET)
