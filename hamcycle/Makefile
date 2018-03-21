CC = gcc
CFLAGS = -O2 -g -std=c99 -lssl -lcrypto -fsanitize=address

all: prover verifier

prover: prover.c zklib.h
	$(CC) $(CFLAGS) prover.c -o prover

verifier: verifier.c zklib.h
	$(CC) $(CFLAGS) verifier.c -o verifier

clean:
	rm -f prover verifier