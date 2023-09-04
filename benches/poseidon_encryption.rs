use ff::Field;
use halo2::halo2curves::bn256::{Fr, G1Affine};
use halo2_delay_enc::encryption::poseidon_enc::PoseidonCipher;
use halo2_proofs::{
    circuit::Value,
    plonk::*,
    poly::{commitment::Params, VerificationStrategy},
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::{ProverIPA, VerifierIPA},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};

use halo2_delay_enc::encryption::poseidon_enc::{PoseidonEncKey, MESSAGE_CAPACITY};
use halo2_delay_enc::{
    encryption::chip::PoseidonEncCircuit,
    poseidon::{
        chip::{FULL_ROUND, PARTIAL_ROUND},
        *,
    },
};
use std::{
    fs::File,
    io::{BufReader, Read, Write},
    path::Path,
};
// bench-mark tool
use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

const K: u32 = 11;

fn bench_poseidon<const T: usize, const RATE: usize>(name: &str, c: &mut Criterion) {
    // define prover and verifier names
    let mut prover_name = "Measure prover time in ".to_string();
    let mut verifier_name = "Measure verifier time in ".to_string();
    prover_name += name;
    verifier_name += name;

    // set params for protocol
    let params_path = Path::new("./benches/data/params_pose_enc");
    if File::open(params_path).is_err() {
        let params: ParamsIPA<G1Affine> = ParamsIPA::new(K);
        let mut buf = Vec::new();

        params.write(&mut buf).expect("Failed to write params");
        let mut file = File::create(params_path).expect("Failed to create params");

        file.write_all(&buf[..])
            .expect("Failed to write params to file");
    }
    let params_fs = File::open(params_path).expect("Failed to load params");
    let params: ParamsIPA<G1Affine> =
        ParamsIPA::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    // set encyption key
    let key = PoseidonEncKey::<Fr> {
        key0: Fr::random(OsRng),
        key1: Fr::random(OsRng),
    };

    // set inputs for the encryption circuit
    let spec = Spec::<Fr, T, RATE>::new(8, 57);
    let inputs = (0..(MESSAGE_CAPACITY))
        .map(|_| Fr::ZERO)
        .collect::<Vec<Fr>>();

    // ref_cipher: expected result as the encryption
    let mut ref_pos_enc =
        PoseidonCipher::<Fr, FULL_ROUND, PARTIAL_ROUND, T, RATE>::new([key.key0, key.key1]);

    let ref_cipher = ref_pos_enc.encrypt(&inputs, &Fr::ONE);

    // wooju - TODO: knowing how to set the params for empty circuit

    let empty_circuit = PoseidonEncCircuit::<Fr, T, RATE> {
        spec: spec.clone(),
        num_input: MESSAGE_CAPACITY,
        message: Value::known(inputs.clone()),
        key: [key.key0, key.key1],
        expected: ref_cipher.to_vec(),
    };

    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk failed");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk failed");

    let circuit = PoseidonEncCircuit::<Fr, T, RATE> {
        spec: spec,
        num_input: MESSAGE_CAPACITY,
        message: Value::known(inputs),
        key: [key.key0, key.key1],
        expected: ref_cipher.to_vec(),
    };

    // Benchmark the proof generation and store the proof
    let proof_path = Path::new("./benches/data/proof_pose_enc");
    if File::open(proof_path).is_err() {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        c.bench_function(&prover_name, |b| {
            b.iter(|| {
                create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
                    &params,
                    &pk,
                    &[circuit.clone()],
                    &[&[&[]]],
                    &mut OsRng,
                    &mut transcript,
                )
                .expect("proof generation failed")
            })
        });
        let proof: Vec<u8> = transcript.finalize();
        let mut file = File::create(proof_path).expect("Failed to create proof");
        file.write_all(&proof[..]).expect("Failed to write proof");
    }

    let mut proof_fs = File::open(proof_path).expect("Failed to load proof");
    let mut proof = Vec::<u8>::new();
    proof_fs
        .read_to_end(&mut proof)
        .expect("Couldn't read proof");

    // Benchmark the verification
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = AccumulatorStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            let strategy = verify_proof::<IPACommitmentScheme<_>, VerifierIPA<_>, _, _, _>(
                &params,
                pk.get_vk(),
                strategy,
                &[&[&[]]],
                &mut transcript,
            )
            .unwrap();
            assert!(strategy.finalize());
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_poseidon::<5, 4>("poseidon encryption", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
