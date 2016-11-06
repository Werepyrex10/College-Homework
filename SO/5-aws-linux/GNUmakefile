CC = gcc
CFLAGS = -Wall -g
CLIB = -laio

TARGET = aws
OBJ = aws.o http_parser.o sock_util.o

build: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(CLIB)

aws.o: aws.c aws.h
	$(CC) $(CFLAGS) -c aws.c

http_parser.o: http_parser.c http_parser.h
	$(CC) $(CFLAGS) -c http_parser.c

sock_util.o: sock_util.c sock_util.h
	$(CC) $(CFLAGS) -c sock_util.c

clean:
	rm -rf $(OBJ) $(TARGET)
