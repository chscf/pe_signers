all: pe_signers.c
	gcc -o pe_signers pe_signers.c -lcrypto

clean:
	rm *.o

clobber:
	rm *.o
	rm pe_signers

