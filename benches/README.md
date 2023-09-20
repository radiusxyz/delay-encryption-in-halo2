## Bench(draft)

To run all benches, run

````bash
cargo bench
````

To run a specific bench, run

```bash
cargo bench --bench $name
````

For example, to run a bench `pose_enc` defined in "benches" folder

```bash
cargo bench --bench posei_enc
```

When the "data" folder contains same name of data to be created or there is no folder, benching the function fails.

Note that, the parameter size depends on the $k$ which has to set bigger than or equal to the minimum degree requirement for creating polynomial. In general, the $k$ is set by subtracting 1 from the number of rows in the table to represent the circuit.



## Result 

- Spec (MacBook pro 16 - 2021)
    - CPU: Apple M1 Pro
    - Memory: 16GB
    - Storage: SSD 1T
$\quad$
- Notation
    - $k$: degree of the poly.
    - $| g |$: bit-size of the base in $g^T$
    - $| T |$: bit-size of the exponent in $g^T$
    - $| msg |$: # of field elements to express an message
    - $|\pi |$: proof size
    - $| pk |$: prover key size
    - $| vk |$: verifier key size


### performance of PVDE circuit

| $k$ | advice |  fixed | $\|g \|$ | $\| msg \|$ | proving time | verifying time | $\|\pi \|$ | $\|pk\|$ | $\|vk\|$ |
| :-: | :----: | :----: | :------: | :---------: | :----------: | :------------: | :--------: | :------: | :------: |
|  15 |  20912 |  20912 | 2048-bit |           1 |     2.0394 s |      3.6456 ms |       286K |     138M |     9.3K |
|  15 |  20916 |  20916 | 2048-bit |           2 |     2.0321 s |      3.5573 ms |       286K |     138M |     9.3K |
|  15 |  26058 |  26058 | 2048-bit |          31 |     3.7977 s |      3.9912 ms |       286K |     138M |     9.3K |

### performance of delay encryption circuit

| $k$ | advice |  fixed | $\|g \|$ | $\|T\|$ | $\| msg \|$ | proving time | verifying time | $\|\pi \|$ | $\|pk\|$ | $\|vk\|$ |
| :-: | :----: | :----: | :------: | :-----: | :---------: | :----------: | :------------: | :--------: | :------: | :------: |
|  15 |  26461 |  26461 | 2048-bit |   2-bit |           2 |     2.2692 s |      3.8226 ms |       286K |     138M |     9.3K |
|  16 |  34473 |  34473 | 2048-bit |   3-bit |           2 |     3.7977 s |      3.9912 ms |       281K |     276M |      17K |
|  16 |  58417 |  58417 | 2048-bit |   6-bit |           2 |     4.1609 s |      3.8044 ms |       281K |     276M |      17K |
|  17 | 122267 | 122267 | 2048-bit |   7-bit |           2 |     6.8335 s |      3.6529 ms |       281K |     552M |      33K |
|  17 | 130248 | 130248 | 2048-bit |  15-bit |           2 |     7.4216 s |      3.4140 ms |       281K |     552M |      33K |
|  18 | 138229 | 138229 | 2048-bit |  16-bit |           2 |     12.524 s |      3.6422 ms |       281K |     1.1G |      65K |
|  18 | 257948 | 257948 | 2048-bit |  31-bit |           2 |     13.397 s |      3.4005 ms |       281K |     1.1G |      65K |
|  19 | 265929 | 265929 | 2048-bit |  32-bit |           2 |     23.841 s |      3.4429 ms |       281K |     2.2G |     129K |


### performance of modulo power circuit

| $k$ | advice |  fixed | $\|g \|$ | $\|T\|$ | proving time | verifying time | $\|\pi \|$ | $\|pk\|$ | $\|vk\|$ |
| :-: | :----: | :----: | :------: | :-----: | :----------: | :------------: | :--------: | :------: | :------: |
|  15 |  17822 |  17822 | 2048-bit |   2-bit |     1.9365 s |      3.6873 ms |       286K |     138M |     9.3K |
|  15 |  25803 |  25803 | 2048-bit |   3-bit |     2.0866 s |      3.8051 ms |       286K |     138M |     9.3K |
|  16 |  33784 |  33784 | 2048-bit |   4-bit |     3.4051 s |      3.4529 ms |       281K |     276M |      17K |
|  16 |  41766 |  41766 | 2048-bit |   5-bit |     3.5665 s |      3.5643 ms |       281K |     276M |      17K |
|  16 |  49747 |  49747 | 2048-bit |   6-bit |     3.5869 s |      3.4665 ms |       281K |     276M |      17K |
|  16 |  57728 |  57728 | 2048-bit |   7-bit |     3.7930 s |      3.5109 ms |       281K |     276M |      17K |
|  17 |  65709 |  65709 | 2048-bit |   8-bit |     6.2824 s |      3.4320 ms |       281K |     276M |      17K |
|  17 | 121578 | 121578 | 2048-bit |  15-bit |     7.0485 s |      3.4704 ms |       281K |     552M |      33K |
|  17 | 129559 | 129559 | 2048-bit |  16-bit |     7.1383 s |      3.6634 ms |       281K |     552M |      33K |
|  18 | 137541 | 137541 | 2048-bit |  17-bit |     11.897 s |      3.4222 ms |       281K |     1.1G |      65K |
|  18 | 249278 | 249278 | 2048-bit |  31-bit |     13.601 s |      3.5342 ms |       281K |     1.1G |      65K |
|  18 | 257259 | 257259 | 2048-bit |  32-bit |     13.724 s |      3.4590 ms |       281K |     1.1G |      65K |
|  19 | 265241 | 265241 | 2048-bit |  33-bit |     23.828 s |      3.4100 ms |       281K |     2.2G |     129K |


### performance of poseidon encryption circuit

| $k$ | advice |  fixed | $\|msg \|$ | proving time | verifying time | $\|\pi \|$ | $\|pk\|$ | $\|vk\|$ |
| :-: | :----: | :----: | :------: | :----------: | :------------: | :--------: | :------: | :------: |
|  11 |   1446 |   1446 |        1 |    138.62 ms |      2.9728 ms |       229K |     4.1M |     968B |
|  11 |   1450 |   1450 |        2 |    139.67 ms |      2.9779 ms |       229K |     4.1M |     968B |
|  11 |   1454 |   1454 |        3 |    141.39 ms |      2.9961 ms |       229K |     4.1M |     968B |
|  11 |   1458 |   1458 |        4 |    148.36 ms |      3.2246 ms |       229K |     4.1M |     968B |
|  12 |   2180 |   2180 |        5 |    222.49 ms |      3.0021 ms |       201K |     8.3M |     968B |
|  12 |   2184 |   2184 |        6 |    227.93 ms |      3.1882 ms |       201K |     8.3M |     968B |
|  12 |   3660 |   6592 |       16 |    234.34 ms |      2.9804 ms |       201K |     8.3M |     968B |
|  13 |   4394 |   4394 |       17 |    361.94 ms |      3.2370 ms |       201K |      17M |     968B |
|  13 |   4394 |   4394 |       20 |    365.13 ms |      3.0567 ms |       201K |      17M |     968B |
|  13 |   5116 |   5116 |       21 |    378.33 ms |      3.2038 ms |       201K |      17M |     968B |
|  13 |   6592 |   6592 |       31 |    391.79 ms |      3.1000 ms |       201K |      17M |     968B |

