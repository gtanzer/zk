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

uint8_t flip_coin(void) {
    return 0;
}


uint8_t decommit_graph(uint64_t n, uint8_t (*commitment)[n][32], uint8_t (*salts)[n][32], uint64_t *permutation) {

    uint8_t cur[32];

    for(uint64_t i = 0; i < n; i++) {
        for(uint64_t j = 0; j < n; j++) {
            uint64_t p = permutation[i];
            uint64_t q = permutation[j];
        
            if(salts[p][q][31] != graph[i][j]) {
                printf("invalid salt\n");
                return 0;
            }
            
            (void) SHA256(&salts[p][q][0], 32, &cur);
            for(uint64_t k = 0; k < 32; k++) {
                if(cur[k] != commitment[p][q][k]) {
                    printf("salt produces incorrect hash\n");
                    return 0;
                }
            }
        }
    }
    
    return 1;
}


uint8_t verify(int64_t conn, uint64_t n, uint8_t (*graph)[n], uint64_t *cycle, uint8_t (*commitment)[n][32], uint8_t (*salts)[n][32], uint64_t *permutation, uint8_t *visited) {

    uint64_t sz = n * n * 32;

    int64_t nread = read(conn, commitment, sz);
    if(nread < sz) {
        perror("commitment read() failed");
        _exit(1);
    }
    
    uint8_t b = flip_coin();
    int64_t err = write(conn, &b, sizeof(uint8_t));
    if(err < 0) {
        perror("b write() failed");
        _exit(1);
    }
    
    switch(b) {
        
        case 0: {   // decommit the entire permuted adjacency matrix
        
            nread = read(conn, permutation, n);
            if(nread < n) {
                perror("permutation read() failed");
                _exit(1);
            }
            
            memset(visited, 0, n);
            for(uint64_t i = 0; i < n; i++) {
                if(visited[permutation[i]] == 0) {
                    visited[permutation[i]] = 1;
                }
                else {
                    printf("invalid permutation\n");
                    _exit(1);
                }
            }
            
            nread = read(conn, salts, sz);
            if(nread < sz) {
                perror("salts read() failed");
                _exit(1);
            }
            
            return decommit_graph(n, commitment, salts, permutation);
            
            break;
            
        }
        
        case 1: {   // decommit only the hamiltonian cycle
        
            nread = read(conn, cycle, n+1);
            if(nread < n+1) {
                perror("cycle read() failed");
                _exit(1);
            }
            
            nread = read(conn, salts[0], n);
            if(nread < n) {
                perror("cycle salts read() failed");
                _exit(1);
            }
        
            break;
            
        }
        
        default: {
            printf("b = %u\n", b);
            _exit(1);
        }
        
    }
    
    return 1;
}


uint8_t amplify_verify(int64_t conn, uint64_t nrounds, uint64_t n, uint8_t (*graph)[n]) {
    
    uint64_t sz = n * n * 32;
    uint64_t *cycle = calloc(n+1, sizeof(uint64_t));
    uint8_t (*commitment)[n][32] = (uint8_t (*)[n][32]) malloc(sz);
    uint8_t (*salts)[n][32] = (uint8_t (*)[n][32]) malloc(sz);
    uint64_t *permutation = (uint64_t *) malloc(n);
    uint8_t *visited = (uint8_t *) malloc(n);

    uint8_t accept = 1;
    for(uint64_t i = 0; i < nrounds; i++) {
        accept &= verify(conn, n, graph, cycle, commitment, salts, permutation, visited);
    }
    
    free(cycle);
    free(commitment);
    free(salts);
    free(permutation);
    
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
        perror("fgets() failed");
        _exit(1);
    }
    uint64_t n = strtol(input, NULL, 10);
    uint8_t (*graph)[n] = (uint8_t (*)[n]) calloc(n * n, 1);
    
    uint64_t sz = 2*n + 1;
    char *iptr = malloc(sz);
    for(uint64_t i = 0; i < n; i++) {
        ret = fgets(iptr, sz, stdin);
        if(ret == NULL) {
            perror("fgets() failed");
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
		perror("socket() failed");
		_exit(1);
	}
	
	struct sockaddr_un server;
	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, UDS_NAME, 100);
	
	int64_t err = connect(fd, (struct sockaddr *) &server, sizeof(struct sockaddr_un));
	if(err < 0) {
		perror("connect() failed");
		_exit(1);
	}
    
    // ------ send graph to prover ---------------------------------------------
    
    err = write(fd, &n, sizeof(uint64_t));
	if(err < 0) {
		perror("n write() failed");
		_exit(1);
	}
    
    err = write(fd, graph, n * n);
	if(err < 0) {
		perror("graph write() failed");
		_exit(1);
	}
    
    // ------ enter proof protocol ---------------------------------------------

    uint8_t accept = amplify_verify(fd, nrounds, n, graph);
    printf("%u\n", accept);
    
    free(graph);

    return 0;
}
