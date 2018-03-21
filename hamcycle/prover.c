// Garrett Tanzer
// zk hamiltonian cycle prover

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
#define QUEUE 1
#define NROUNDS_DEFAULT 64


void prove(int64_t fd, uint64_t n) {

}


void amplify_prove(int64_t fd, uint64_t nrounds, uint64_t n) {
    for(uint64_t i = 0; i < nrounds; i++) {
        prove(fd, n);
    }
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

    // ------ open UDS for verifier --------------------------------------------

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(fd < 0) {
        perror("socket() failed");
        _exit(1);
    }
    
    struct sockaddr_un server;
    server.sun_family = AF_UNIX;
    unlink(UDS_NAME);
    strncpy(server.sun_path, UDS_NAME, 100);
    
    int err = bind(fd, (struct sockaddr *) &server, sizeof(struct sockaddr_un));
    if(err < 0) {
        perror("bind() failed\n");
        _exit(1);
    }
    
    err = listen(fd, QUEUE);
    if(err < 0) {
        perror("listen() failed");
        _exit(1);
    }
    
    int conn = accept(fd, NULL, NULL);
    if(conn < 0) {
        perror("accept() failed");
        _exit(1);
    }
    
    // ------ receive graph from verifier --------------------------------------
    
    uint64_t n = 0;
    
    // ------ read cycle from stdin --------------------------------------------
    
    // ------ enter proof protocol ---------------------------------------------
    
    amplify_prove(fd, nrounds, n);

    return 0;
}
