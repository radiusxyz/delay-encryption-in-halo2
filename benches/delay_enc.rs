use ff::Field;
use halo2_delay_enc::DelayEncryptCircuit;
use halo2_delay_enc::{
    encryption::poseidon_enc::{PoseidonEncKey, MESSAGE_CAPACITY},
    Spec,
};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::{
    SerdeFormat,
    plonk::*,
    poly::{commitment::Params, VerificationStrategy},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use num_bigint::{BigUint, RandomBits};
use rand::thread_rng;
use std::{
    fs::File,
    io::{BufReader, Read, Write},
    path::Path,
};
// bench-mark tool
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::OsRng, Rng};

fn bench_delay<const T: usize, const RATE: usize, const K: u32>(name: &str, c: &mut Criterion) {
    // define prover and verifier names
    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;
    // set params for protocol
    let params_path = "./benches/data/params_delay_enc_".to_owned() + &K.to_string();
    let params_path = Path::new(&params_path);
    if File::open(params_path).is_err() {
        // let params: ParamsIPA<G1Affine> = ParamsIPA::new(K);
        let params = ParamsKZG::<Bn256>::setup(K, OsRng);
        let mut buf = Vec::new();
        params.write(&mut buf).expect("Failed to write params");
        let mut file = File::create(params_path).expect("Failed to create params");
        file.write_all(&buf[..])
            .expect("Failed to write params to file");
    }
    let params_fs = File::open(params_path).expect("Failed to load params");
    // let params: ParamsIPA<G1Affine> =
    //     ParamsIPA::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");
    let params =
        ParamsKZG::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    // let mut rng = OsRng;
    let mut rng = thread_rng();
    let bits_len = DelayEncryptCircuit::<Fr, T, RATE>::BITS_LEN as u64;
    let mut n = BigUint::default();
    while n.bits() != bits_len {
        n = rng.sample(RandomBits::new(bits_len));
    }
    let e = rng.sample::<BigUint, _>(RandomBits::new(
        DelayEncryptCircuit::<Fr, T, RATE>::EXP_LIMB_BITS as u64,
    )) % &n;
    let x = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
    // let key: PoseidonEncKey<Fr> = PoseidonEncKey::init();

    let spec = Spec::<Fr, T, RATE>::new(8, 57);
    let inputs = (0..(MESSAGE_CAPACITY))
        .map(|_| Fr::ZERO)
        .collect::<Vec<Fr>>();

    let circuit = DelayEncryptCircuit::<Fr, T, RATE> {
        n: n,
        e: e,
        x: x,
        spec: spec.clone(),
        num_input: MESSAGE_CAPACITY,
        message: inputs,
    };

    // write verifying key
    let vk_path = "./benches/data/vk_delay_enc".to_owned() + &K.to_string();
    if File::open(&vk_path).is_err() {
        let vk = keygen_vk(&params, &circuit.clone()).expect("keygen_vk failed");
        let mut buf = Vec::new();
        let _ = vk.write(&mut buf, SerdeFormat::RawBytes);
        let mut file = File::create(&vk_path).expect("Failed to create vk");
        file.write_all(&buf[..])
            .expect("Failed to write vk to file");
    }
    let vk_fs = File::open(vk_path).expect("Failed to load vk");
    let vk = VerifyingKey::<G1Affine>::read::<BufReader<File>, DelayEncryptCircuit<Fr, T, RATE>>(
        &mut BufReader::new(vk_fs),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read vk");

    // write proving key
    let pk_path = "./benches/data/pk_delay_enc_".to_owned() + &K.to_string();
    if File::open(&pk_path).is_err() {
        let pk = keygen_pk(&params, vk, &circuit.clone()).expect("keygen_pk failed");
        let mut buf = Vec::new();
        let _ = pk.write(&mut buf, SerdeFormat::RawBytes);
        let mut file = File::create(&pk_path).expect("Failed to create pk");
        file.write_all(&buf[..])
            .expect("Failed to write pk to file");
    }
    let pk_fs = File::open(pk_path).expect("Failed to load pk");
    let pk = ProvingKey::<G1Affine>::read::<BufReader<File>, DelayEncryptCircuit<Fr, T, RATE>>(
        &mut BufReader::new(pk_fs),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read pk");
    // Benchmark the proof generation and store the proof
    let proof_path = "./benches/data/proof_delay_enc_".to_owned() + &K.to_string();
    let proof_path = Path::new(&proof_path);
    if File::open(proof_path).is_err() {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        c.bench_function(&prover_name, |b| {
            b.iter(|| {
                create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
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
        .expect("Fail to read proof");

    // Benchmark the verification
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy: AccumulatorStrategy<'_, Bn256> = AccumulatorStrategy::new(&params);
            let mut transcript: Blake2bRead<&[u8], G1Affine, Challenge255<_>> =
                Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);



            let accept = {
                let mut transcript: Blake2bRead<&[u8], _, Challenge255<_>> =
                    TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
                VerificationStrategy::<_, VerifierGWC<_>>::finalize(
                    verify_proof::<_, VerifierGWC<_>, _, _, _>(
                        params.verifier_params(),
                        pk.get_vk(),
                        AccumulatorStrategy::new(params.verifier_params()),
                        &[&[&[]]],
                        &mut transcript,
                    )
                    .unwrap(),
                )
            };
            assert!(accept);
        });
    });
}

// fn criterion_benchmark(c: &mut Criterion) {
//     bench_delay::<5, 4, 17>("delay encryption", c);
// }

// criterion_group!(benches, criterion_benchmark);
// criterion_main!(benches);

fn main() {
    let mut criterion = Criterion::default()
        .sample_size(10) // # of sample, >= 10
        .nresamples(10); // # of iteration

    let benches: Vec<Box<dyn Fn(&mut Criterion)>> =
        vec![Box::new(|c| bench_delay::<5, 4, 17>("delay encryption", c))];

    for bench in benches {
        bench(&mut criterion);
    }
}
