### Test

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

If the "data" folder contains same name of data to be created, benching the function failed.