# zk
zero knowledge protocols

## hamiltonian cycle

implementation of the protocol described [here](http://www.intensecrypto.org/public/lec_14_zero_knowledge.pdf)

requires:
* unix domain sockets (no Windows)
* `<openssl/sha.h>`

### usage:

`prover [nrounds] < cycle.txt`

`verifier [nrounds] < graph.txt`

### input format:
(see /tests/ for examples)

`cycle.txt`:

* on the first line, `n` (number of vertices)
* on the second line, the `n+1`-long sequence of vertices in the cycle (space-separated)

```
n
i j k...i
```

where `i`, `j`, `k`... are in `[n]`

`graph.txt`:

* on the first line, `n` (number of vertices)
* on the next `n` lines, the adjacency matrix of the graph (each entry space-separated)

```
n
b_{0,0} b_{0,1} b_{0,2}...b_{0,n-1}
b_{1,0} b_{1,1} b_{1,2}...b_{1,n-1}
.
.
.
b_{n-1,0} b_{n-1,1} b_{n-1,2}...b_{n-1,n-1}
```

where each `b_{i,j}` in `{0,1}` represents the presence or absence of an edge connecting `i` to `j`
