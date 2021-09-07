CC=gcc

TARGET=pe_signers
OBJECTS=pe_signers.o

CFLAGS=-ggdb3 -O0

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS) -lcrypto

clean:
	rm -f *.o pe_signers
