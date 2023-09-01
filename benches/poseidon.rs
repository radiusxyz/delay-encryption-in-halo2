use ff::{Field, FromUniformBytes, PrimeField};
use halo2::halo2curves::bn256::G1Affine;
use halo2::halo2curves::bn256::Fr;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance,
    },
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
// use halo2curves::{pasta::{pallas, vesta, EqAffine, Fp}, bn256::Fr};
// use halo2curves::{pasta::{pallas, vesta, EqAffine, Fp},bn256::Fr};

// use halo2_gadgets::poseidon::{
//     primitives::{self as poseidon, generate_constants, ConstantLength, Mds, Spec},
//     Hash, Pow5Chip, Pow5Config,
// };

use halo2wrong::RegionCtx;
use maingate::{
    AssignedValue, MainGate, MainGateConfig, MainGateInstructions, Term,
};
use halo2_delay_enc::{poseidon::{
    chip::{FULL_ROUND, PARTIAL_ROUND},
    *,
}, encryption::chip::PoseidonEncChip};
use halo2_delay_enc::encryption::poseidon_enc::{
    PoseidonCipher, PoseidonEncKey, CIPHER_SIZE, MESSAGE_CAPACITY,
};

use std::convert::TryInto;
use std::marker::PhantomData;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

#[derive(Clone)]
struct PoseidonEncCircuit<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    // Poseidon
    pub spec: Spec<F, T, RATE>,
    pub num_input: usize,      
    pub message: Value<Vec<F>>, 
    pub key: [F; 2],          
    pub expected: Vec<F>,      
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for PoseidonEncCircuit<F, T, RATE>
{
    type Config = MainGateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);

        main_gate_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let main_gate = MainGate::<F>::new(config.clone());

        layouter.assign_region(
            || "poseidon cipher",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let mut expected_result = vec![];

                // assign expected result
                for result in &self.expected {
                    let result = main_gate.assign_value(ctx, Value::known(result.clone()))?;
                    expected_result.push(result);
                }

                // == Encryption ciruit ==//

                // new assigns initial_state into cells.
                let mut pos_enc_chip =
                    PoseidonEncChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new(
                        ctx, &self.spec, &config, self.key,
                    )?;

                // check the assigned initial state
                // println!("\nzk_state: {:?}", pos_enc_chip.state.0);

                // permute before state message addtion
                pos_enc_chip.pose_chip.permutation(ctx, vec![])?;

                // check the permuted state
                // println!("zk_state2: {:?}\n", pos_enc_chip.state.0);

                // set the message to be an input to the encryption
                for e in self.message.as_ref().transpose_vec(self.num_input) {
                    let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
                    pos_enc_chip.pose_chip.set_inputs(&[e.clone()]);
                }

                // add the input to the currentn state and output encrypted result
                let cipher_text = pos_enc_chip.absorb_and_relese(ctx)?;

                // println!("cipher: {:?}", cipher_text);
                // println!("expected cipher: {:?}\n", expected_result);
                // println!("cipher len: {:?}", cipher_text.len());

                // constrain with encryption result
                // println!("check out equality..");
                // for i in 0..cipher_text.len() {
                //     main_gate.assert_equal(ctx, &cipher_text[i], &expected_result[i])?;
                // }
                Ok(())
            },
        )?;
        Ok(())
    }
}

const K: u32 = 11;

fn bench_poseidon<
F,
const T: usize,
const RATE: usize,
>(
    name: &str,
    c: &mut Criterion,
) {

    let params: ParamsIPA<G1Affine> = ParamsIPA::new(K);

    let _spec = Spec::<Fr, T, RATE>::new(8, 57);
    let inputs = (0..(MESSAGE_CAPACITY)).map(|_| Fr::ZERO).collect::<Vec<Fr>>();

    let _key = PoseidonEncKey::<Fr> {
        key0: Fr::random(OsRng),
        key1: Fr::random(OsRng),
    };

    // wooju - how to set the params for empty circuit?

    let empty_circuit = PoseidonEncCircuit::<Fr, T, RATE> {
        spec: _spec.clone(), 
        num_input: MESSAGE_CAPACITY,
        message: Value::known(inputs.clone()),
        key: [_key.key0, _key.key1],   
        expected: vec![],  
    };

    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let prover_name = name.to_string() + "-prover";
    let verifier_name = name.to_string() + "-verifier";

    let mut rng = OsRng;
    let message: [Fr; MESSAGE_CAPACITY] = (0..MESSAGE_CAPACITY)
        .map(|_| Fr::random(rng))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let output = 
    PoseidonCipher::<Fr, FULL_ROUND, PARTIAL_ROUND, T, RATE>::new([Fr::ZERO, Fr::ZERO]).encrypt(&message, &Fr::ONE);

    let circuit = PoseidonEncCircuit::<Fr, T, RATE> {
        spec: _spec,
        num_input: MESSAGE_CAPACITY,
        message: Value::known(inputs),
        key: [Fr::ZERO, Fr::ZERO],
        expected: output.to_vec(),
    };

    // let a = circuit.clone();
    c.bench_function(&prover_name, |b| {
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        b.iter(|| {
            create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuit.clone()],
                &[&[&output]],
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
        &[&[&output]],
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(
                &params,
                pk.get_vk(),
                strategy,
                &[&[&output]],
                &mut transcript
            )
            .is_ok());
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_poseidon::<Fr, 5, 4>("WIDTH = 5, RATE = 4", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);