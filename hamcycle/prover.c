// Garrett Tanzer
// zk hamiltonian cycle prover

#include "zklib.h"


// commit(n, graph, commitment, salts, permutation)
//  randomly permute `graph`, choose random `salts`, and commit with SHA256

//  `n`             number of vertices
//  `graph`         n x n adjacency matrix
//  `commitment`    n x n matrix to be filled with 256-bit commitment hashes
//  `salts`         n x n matrix to be filled with the preimage of `commitment`
//  `permutation`   n item array to be filled with a vertex permutation

void commit(uint64_t n, uint8_t (*graph)[n], uint8_t (*commitment)[n][32], uint8_t (*salts)[n][32], uint64_t *permutation) {
    
    // randomly select a vertex permutation
    permute(n, permutation);
    
    for(uint64_t i = 0; i < n; i++) {
        for(uint64_t j = 0; j < n; j++) {
            uint64_t p = permutation[i];
            uint64_t q = permutation[j];
            
            // pick a random salt + {0, 1} for each edge
            random_fill(32, &salts[p][q][0]);
            salts[p][q][31] = graph[i][j];
            
            // commit that salt
            (void) SHA256(&salts[p][q][0], 32, &commitment[p][q][0]);
        }
    }
}


// prove(conn, n, graph, cycle, commitment, salts, permutation)
//  perform a single round of the zk hamiltonian cycle protocol as the prover

//  `conn`          socket file descriptor
//  `n`             number of vertices
//  `graph`         n x n adjacency matrix
//  `cycle`         n+1 item array with the secret hamiltonian cycle
//  `commitment`    n x n matrix to store 256-bit commitment hashes
//  `salts`         n x n matrix to store the inversion of `commitments`
//  `permutation`   n item array to store a random vertex permutation

void prove(int64_t conn, uint64_t n, uint8_t (*graph)[n], uint64_t *cycle, uint8_t (*commitment)[n][32], uint8_t (*salts)[n][32], uint64_t *permutation) {
    
    // generate a commitment
    commit(n, graph, commitment, salts, permutation);

    // send `commitment` to the verifier
    int64_t err = write(conn, commitment, n * n * 32);
    if(err < 0) {
        perror("commitment write() failed");
        _exit(1);
    }
    
    // read `b` from the verifier
    uint8_t b;
    int64_t nread = read(conn, &b, sizeof(uint8_t));
    if(nread < 1) {
        perror("b read() failed");
        _exit(1);
    }
    
    switch(b) {
    
        case 0: {   // decommit the entire permuted adjacency matrix
        
            // send the vertex `permutation` to the verifier
            err = write(conn, permutation, n * sizeof(uint64_t));
            if(err < 0) {
                perror("permutation write() failed");
                _exit(1);
            }
        
            // send the original `salts` to the verifier
            err = write(conn, salts, n * n * 32);
            if(err < 0) {
                perror("salts write() failed");
                _exit(1);
            }
            break;
        }
        
        case 1: {   // decommit only the hamiltonian cycle
            
            uint64_t *pcycle = (uint64_t *) commitment[0];
            uint8_t (*psalts)[32] = commitment[1];
            
            // permute the hamiltonian cycle
            for(uint64_t i = 0; i < n+1; i++) {
                pcycle[i] = permutation[cycle[i]];
            }
            
            // pick out the corresponding salts to the cycle
            for(uint64_t i = 0; i < n; i++) {
                uint64_t p = pcycle[i];
                uint64_t q = pcycle[i+1];
                
                for(uint64_t k = 0; k < 32; k++) {
                    psalts[i][k] = salts[p][q][k];
                }
            }
            
            // send the permuted cycle to the verifier
            err = write(conn, pcycle, (n+1) * sizeof(uint64_t));
            if(err < 0) {
                perror("salts write() failed");
                _exit(1);
            }
            
            // send the corresponding salts to the verifier
            err = write(conn, psalts, n * 32);
            if(err < 0) {
                perror("salts write() failed");
                _exit(1);
            }
        
            break;
            
        }
        
        default: {
            printf("b = %u\n", b);
            _exit(1);
        }
        
    }
}


// amplify_prove(conn, nrounds, n, graph, cycle)
//  perform the repeated zk hamiltonian cycle protocol as the prover

//  `conn`      socket file descriptor
//  `nrounds`   number of rounds (soundness is 2^{-nrounds})
//  `n`         number of vertices
//  `graph`     n x n adjacency matrix
//  `cycle`     n+1 item array with the secret hamiltonian cycle

void amplify_prove(int64_t conn, uint64_t nrounds, uint64_t n, uint8_t (*graph)[n], uint64_t *cycle) {
    
    uint64_t sz = n * n * 32;
    uint8_t (*commitment)[n][32] = (uint8_t (*)[n][32]) malloc(sz);
    uint8_t (*salts)[n][32] = (uint8_t (*)[n][32]) malloc(sz);
    uint64_t *permutation = (uint64_t *) calloc(n, sizeof(uint64_t));
    
    // declare /dev/urandom cache size
    random_init(n * n * 32);
    
    // repeat protocol to improve soundness
    for(uint64_t i = 0; i < nrounds; i++) {
        prove(conn, n, graph, cycle, commitment, salts, permutation);
    }
    
    free(commitment);
    free(salts);
    free(permutation);
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

    int64_t fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(fd < 0) {
        perror("socket() failed");
        _exit(1);
    }
    
    struct sockaddr_un server;
    server.sun_family = AF_UNIX;
    unlink(UDS_NAME);
    strncpy(server.sun_path, UDS_NAME, 100);
    
    int64_t err = bind(fd, (struct sockaddr *) &server, sizeof(struct sockaddr_un));
    if(err < 0) {
        perror("bind() failed");
        _exit(1);
    }
    
    err = listen(fd, QUEUE);
    if(err < 0) {
        perror("listen() failed");
        _exit(1);
    }
    
    int64_t conn = accept(fd, NULL, NULL);
    if(conn < 0) {
        perror("accept() failed");
        _exit(1);
    }
    
    // ------ receive graph from verifier --------------------------------------
    
    // get n from the verifier
    uint64_t n = 0;
    uint64_t nread = read(conn, &n, sizeof(uint64_t));
    if(nread < sizeof(uint64_t)) {
        perror("n read() failed");
        _exit(1);
    }
    
    uint8_t (*graph)[n] = (uint8_t (*)[n]) calloc(n * n, 1);
    
    // get adjacency matrix from the verifier
    nread = read(conn, graph, n * n);
    if(nread < n * n) {
        perror("graph read() failed");
        _exit(1);
    }
    
    // check adjacency matrix validity
    for(uint64_t i = 0; i < n; i++) {
        for(uint64_t j = 0; j < n; j++) {
            if(graph[i][j] != 0 && graph[i][j] != 1) {
                printf("graph[%llu][%llu] = %u\n", i, j, graph[i][j]);
                _exit(1);
            }
        }
    }
    
    // ------ read cycle from stdin --------------------------------------------
    
    // read n for the cycle, and confirm it matches the verifier's n
    char input[1UL << 6];
    char *ret = fgets(input, sizeof(input), stdin);
    if(ret == NULL) {
        perror("fgets() failed");
        _exit(1);
    }
    uint64_t m = strtol(input, NULL, 10);
    if(n != m || n == 0) {
        printf("n: %llu but m: %llu\n", n, m);
        _exit(1);
    }
    
    uint64_t *cycle = calloc(n+1, sizeof(uint64_t));
    
    uint64_t logn = sizeof(n) * 8 - __builtin_clzl(n);  // find max input length
    uint64_t sz = n * (logn/3 + 1) + 1;
    char *iptr = malloc(sz);
    char *optr = iptr;
    
    // read the secret hamiltonian cycle
    ret = fgets(iptr, sz, stdin);
    if(ret == NULL) {
        perror("fgets() failed");
        _exit(1);
    }
    for(uint64_t i = 0; i < n+1; i++) {
        cycle[i] = strtol(iptr, &iptr, 10);
    }
    free(optr);
    
    // check cycle validity
    for(uint64_t i = 0; i < n; i++) {
        if(graph[cycle[i]][cycle[i+1]] != 1) {
            printf("invalid cycle: (%llu, %llu) not an edge\n", cycle[i], cycle[i+1]);
            _exit(1);
        }
    }
    
    // ------ enter proof protocol ---------------------------------------------
    
    amplify_prove(conn, nrounds, n, graph, cycle);
    
    free(graph);
    free(cycle);

    return 0;
}
