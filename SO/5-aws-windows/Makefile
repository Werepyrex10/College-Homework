CC=cl
OBJ=aws.obj sock_util.obj
TARGET=aws.exe
CLIB=ws2_32.lib wsock32.lib

build: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) $(CLIB) /Fe$(TARGET)
	
clean:
	del $(OBJ) $(TARGET)