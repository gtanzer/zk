CC = gcc
CFLAGS = -O2 -std=c99 -lssl -lcrypto -fsanitize=address

all: prover verifier

prover: prover.c
	$(CC) $(CFLAGS) prover.c -o prover

verifier: verifier.c
	$(CC) $(CFLAGS) verifier.c -o verifier

clean:
	rm -f prover verifier