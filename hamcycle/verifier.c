// Garrett Tanzer
// zk hamiltonian cycle verifier

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#define UDS_NAME "hamcycle"
#define NROUNDS_DEFAULT 64


uint8_t verify(int64_t fd, uint64_t n) {
    uint64_t len = strlen("hi");
	
	int64_t err = write(fd, (void *) &len, sizeof(size_t));
	if(err < 0) {
		close(fd);
		perror("header write() failed\n");
		_exit(1);
	}
	
	err = write(fd, "hi", len);
	if(err < 0) {
		close(fd);
		perror("body write() failed\n");
		_exit(1);
	}
    
    return 1;
}


uint8_t amplify_verify(int64_t fd, uint64_t nrounds, uint64_t n) {
    uint8_t accept = 1;
    for(uint64_t i = 0; i < nrounds; i++) {
        accept &= verify(fd, n);
    }
    return accept;
}


int main(int argc, char **argv) {

    // ------ command line arguments -------------------------------------------
    
    uint64_t nrounds;
    if(argc < 2) {
        nrounds = NROUNDS_DEFAULT;
    }
    else {
        nrounds = strtol(argv[1], NULL, 10);
    }

    // ------ read graph from stdin --------------------------------------------
    
    char input[1UL << 6];
    char *ret = fgets(input, sizeof(input), stdin);
    if(ret == NULL) {
        perror("fgets() failed\n");
        _exit(1);
    }
    uint64_t n = strtol(input, NULL, 10);
    uint8_t (*graph)[n] = (uint8_t (*)[n]) calloc(n * n, 1);
    
    char *iptr = malloc(2*n+1);
    for(uint64_t i = 0; i < n; i++) {
        ret = fgets(iptr, 2*n+1, stdin);
        if(ret == NULL) {
            perror("fgets() failed\n");
            _exit(1);
        }
        for(uint64_t j = 0; j < n; j++) {
            graph[i][j] = iptr[2*j] - 48;
        }
    }
    free(iptr);

    // ------ connect to prover's UDS ------------------------------------------

    int64_t fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(fd < 0) {
		perror("socket() failed\n");
		_exit(1);
	}
	
	struct sockaddr_un server;
	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, UDS_NAME, 100);
	
	int64_t err = connect(fd, (struct sockaddr *) &server, sizeof(struct sockaddr_un));
	if(err < 0) {
		close(fd);
		perror("connect() failed\n");
		_exit(1);
	}
    
    // ------ send graph to prover ---------------------------------------------
    
    
    
    // ------ enter proof protocol ---------------------------------------------

    uint8_t accept = amplify_verify(fd, nrounds, n);
    printf("%u\n", accept);
    
    close(fd);

    return 0;
}
