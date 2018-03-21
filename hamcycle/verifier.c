// Garrett Tanzer
// zk hamiltonian cycle verifier

#include "zklib.h"


uint8_t decommit_graph(uint64_t n, uint8_t (*graph)[n], uint8_t (*commitment)[n][32], uint8_t (*salts)[n][32], uint64_t *permutation) {

    uint8_t cur[32];

    for(uint64_t i = 0; i < n; i++) {
        for(uint64_t j = 0; j < n; j++) {
            uint64_t p = permutation[i];
            uint64_t q = permutation[j];
        
            if(salts[p][q][31] != graph[i][j]) {
                verbose_printf("invalid salt\n");
                return 0;
            }
            
            (void) SHA256(&salts[p][q][0], 32, cur);
            for(uint64_t k = 0; k < 32; k++) {
                if(cur[k] != commitment[p][q][k]) {
                    verbose_printf("salt produces incorrect hash\n");
                    return 0;
                }
            }
        }
    }
    
    return 1;
}


uint8_t decommit_cycle(uint64_t n, uint8_t (*commitment)[n][32], uint8_t (*salts)[32], uint64_t *cycle) {

    uint8_t cur[32];

    for(uint64_t i = 0; i < n; i++) {
        uint64_t p = cycle[i];
        uint64_t q = cycle[i+1];
    
        if(salts[i][31] != 1) {
            verbose_printf("invalid salt\n");
            return 0;
        }
    
        (void) SHA256(salts[i], 32, cur);
        for(uint64_t k = 0; k < 32; k++) {
            if(cur[k] != commitment[p][q][k]) {
                verbose_printf("salt produces incorrect hash\n");
                return 0;
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
    verbose_printf("commitment:\n");
    for(uint64_t i = 0; i < n; i++) {
        for(uint64_t j = 0; j < n; j++) {
            for(uint64_t k = 0; k < 32; k++) {
                verbose_printf("%x", commitment[i][j][k]);
            }
            verbose_printf("\n");
        }
        verbose_printf("\n");
    }
    
    uint8_t b = random_flip(0);
    int64_t err = write(conn, &b, sizeof(uint8_t));
    if(err < 0) {
        perror("b write() failed");
        _exit(1);
    }
    verbose_printf("b = %u\n\n", b);
    
    switch(b) {
        
        case 0: {   // decommit the entire permuted adjacency matrix
        
            verbose_printf("decommitting adjacency matrix\n\n");
        
            nread = read(conn, permutation, n * sizeof(uint64_t));
            if(nread < n) {
                perror("permutation read() failed");
                _exit(1);
            }
            verbose_printf("permutation:\n");
            
            memset(visited, 0, n);
            for(uint64_t i = 0; i < n; i++) {
                verbose_printf("%llu: %llu\n", i, permutation[i]);
                if(permutation[i] < n && visited[permutation[i]] == 0) {
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
            verbose_printf("salts:\n");
            for(uint64_t i = 0; i < n; i++) {
                for(uint64_t j = 0; j < n; j++) {
                    for(uint64_t k = 0; k < 32; k++) {
                        verbose_printf("%x", salts[i][j][k]);
                    }
                    verbose_printf("\n");
                }
                verbose_printf("\n");
            }
            
            return decommit_graph(n, graph, commitment, salts, permutation);
            
        }
        
        case 1: {   // decommit only the hamiltonian cycle
        
            verbose_printf("decommitting hamiltonian cycle\n\n");
        
            nread = read(conn, cycle, (n+1) * sizeof(uint64_t));
            if(nread < n+1) {
                perror("cycle read() failed");
                _exit(1);
            }
            verbose_printf("cycle:\n");
            
            memset(visited, 0, n);
            for(uint64_t i = 0; i < n; i++) {
                verbose_printf("%llu -> ", cycle[i]);
                if(cycle[i] < n && visited[cycle[i]] == 0) {
                    visited[cycle[i]] = 1;
                }
                else {
                    printf("invalid cycle\n");
                    _exit(1);
                }
            }
            verbose_printf("%llu\n\n", cycle[0]);
            if(cycle[n] >= n || cycle[0] != cycle[n]) {
                printf("incomplete cycle\n");
            }
            
            nread = read(conn, salts[0], n * 32);
            if(nread < n) {
                perror("cycle salts read() failed");
                _exit(1);
            }
            verbose_printf("salts:\n");
            for(uint64_t j = 0; j < n; j++) {
                for(uint64_t k = 0; k < 32; k++) {
                    verbose_printf("%x", salts[0][j][k]);
                }
                verbose_printf("\n");
            }
            
            return decommit_cycle(n, commitment, salts[0], cycle);
            
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
    uint64_t *permutation = (uint64_t *) calloc(n, sizeof(uint64_t));
    uint8_t *visited = (uint8_t *) malloc(n);

    (void) random_flip(nrounds);

    uint8_t accept = 1;
    for(uint64_t i = 0; i < nrounds; i++) {
        verbose_printf("------ verifying round %llu ------\n\n", i);
        accept &= verify(conn, n, graph, cycle, commitment, salts, permutation, visited);
        verbose_printf("\n");
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
