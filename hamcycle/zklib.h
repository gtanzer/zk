// Garrett Tanzer
// zk library functions

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
#define QUEUE 1

#define VERBOSE 0
#if VERBOSE
    #define verbose_printf printf
#else
    #define verbose_printf(fmt, ...) (0)
#endif


#define RBUFSZ 4096

static int64_t fd = -1;
static uint64_t n = 0;
static uint64_t bufsz = 0;
static uint8_t *buf = NULL;


static void buffer_refill(void) {
    int64_t nread = read(fd, buf, bufsz);
    if(nread < bufsz) {
        perror("urandom read() failed");
        _exit(1);
    }
    n = 0;
}


void random_init(uint64_t sz) {
    bufsz = sz;
    
    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        perror("urandom open() failed");
        _exit(1);
    }
    
    buf = malloc(bufsz);
    buffer_refill();
}


uint8_t random_flip(void) {
    if(fd < 0) {
        printf("forgot to random_init()\n");
        _exit(1);
    }
    
    if(n == bufsz) {
        buffer_refill();
    }
    return buf[n++] % 2;
}


uint8_t random64(void) {
    if(fd < 0) {
        printf("forgot to random_init()\n");
        _exit(1);
    }
    
    if(bufsz < 8) {
        printf("bufsz must be at least 8 to random64()\n");
        _exit(1);
    }
    
    if(n+8 > bufsz) {
        buffer_refill();
    }
    
    n += 8;
    return *((uint64_t *) &buf[n - 8]);
}


void random_fill(uint64_t len, uint8_t *dst) {
    if(fd < 0) {
        printf("forgot to random_init()\n");
        _exit(1);
    }
    
    for(uint64_t i = 0; i < len; i++) {
        if(n == bufsz) {
            buffer_refill();
        }
        dst[i] = buf[n++];
    }
}


// Fisher-Yates shuffle
// produces a `permutation` of [0...n-1]
void permute(uint64_t n, uint64_t *permutation) {
    if(fd < 0) {
        printf("forgot to random_init()\n");
        _exit(1);
    }

    for(uint64_t i = 0; i < n; i++) {
        permutation[i] = i;
    }
    
    for(uint64_t i = n-1; i > 0; i--) {
        uint64_t j = n;
        while(j > i) {
            j = random64();
    
            uint64_t logn = sizeof(n) * 8 - __builtin_clzl(n);
            uint64_t mod = 1UL << logn;
            
            j = j % mod;
        }
    
        uint64_t temp = permutation[j];
        permutation[j] = permutation[i];
        permutation[i] = temp;
    }
}
