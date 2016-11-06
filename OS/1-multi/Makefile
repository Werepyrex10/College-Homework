CC = cl

build: hash.obj hashtable.obj main.obj
	$(CC) /Fetema1.exe $**

main.obj: main.c
	$(CC) /Fo$@ /c $**

hash.obj: hash.c
	$(CC) /Fo$@ /c $**

hashtable.obj: hashtable.c
	$(CC) /Fo$@ /c $**

.PHONY: clean

clean:
	del  *.o tema1
