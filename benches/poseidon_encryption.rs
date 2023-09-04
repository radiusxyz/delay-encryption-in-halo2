use ff::Field;
use halo2::halo2curves::bn256::Fr;
use halo2::halo2curves::bn256::G1Affine;
use halo2_delay_enc::encryption::poseidon_enc::PoseidonCipher;
use halo2_proofs::{
    circuit::Value,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::ProverIPA,
            strategy::SingleStrategy,
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};

use halo2_delay_enc::encryption::poseidon_enc::{PoseidonEncKey, MESSAGE_CAPACITY};
use halo2_delay_enc::{
    encryption::chip::PoseidonEncCircuit,
    poseidon::{
        chip::{FULL_ROUND, PARTIAL_ROUND},
        *,
    },
};

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

const K: u32 = 11;

fn bench_poseidon<const T: usize, const RATE: usize>(name: &str, c: &mut Criterion) {
    let params: ParamsIPA<G1Affine> = ParamsIPA::new(K);

    let key = PoseidonEncKey::<Fr> {
        key0: Fr::random(OsRng),
        key1: Fr::random(OsRng),
    };

    let spec = Spec::<Fr, T, RATE>::new(8, 57);
    let inputs = (0..(MESSAGE_CAPACITY))
        .map(|_| Fr::ZERO)
        .collect::<Vec<Fr>>();

    let mut ref_pos_enc =
        PoseidonCipher::<Fr, FULL_ROUND, PARTIAL_ROUND, T, RATE>::new([key.key0, key.key1]);

    let ref_cipher = ref_pos_enc.encrypt(&inputs, &Fr::ONE);

    // wooju - knowing how to set the params for empty circuit

    let empty_circuit = PoseidonEncCircuit::<Fr, T, RATE> {
        spec: spec.clone(),
        num_input: MESSAGE_CAPACITY,
        message: Value::known(inputs.clone()),
        key: [key.key0, key.key1],
        expected: ref_cipher.to_vec(),
    };

    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let prover_name = name.to_string() + "-prover";
    let verifier_name = name.to_string() + "-verifier";

    let mut rng = OsRng;

    let circuit = PoseidonEncCircuit::<Fr, T, RATE> {
        spec: spec,
        num_input: MESSAGE_CAPACITY,
        message: Value::known(inputs),
        key: [key.key0, key.key1],
        expected: ref_cipher.to_vec(),
    };

    c.bench_function(&prover_name, |b| {
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        b.iter(|| {
            create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuit.clone()],
                &[&[&[]]],
                &mut rng,
                &mut transcript,
            )
            .expect("proof generation should not fail")
        })
    });

    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&[]]],
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(
                verify_proof(&params, pk.get_vk(), strategy, &[&[&[]]], &mut transcript).is_ok()
            );
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_poseidon::<5, 4>("WIDTH = 5, RATE = 4", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
