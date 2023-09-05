use ff::{FromUniformBytes, PrimeField};
use halo2::halo2curves::bn256::{Fr, G1Affine};
use halo2_delay_enc::big_integer::big_pow_mod;
use halo2_delay_enc::*;
use halo2_proofs::{
    circuit::SimpleFloorPlanner,
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

use halo2wrong::RegionCtx;
use maingate::{decompose_big, MainGate, RangeChip, RangeInstructions};
use num_bigint::{BigUint, RandomBits};
use std::{
    fs::File,
    io::{BufReader, Read, Write},
    marker::PhantomData,
    path::Path,
};
// bench-mark tool
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::OsRng, Rng};

#[derive(Clone)]
struct RSACircuit<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> {
    // Mod power
    n: BigUint,
    e: BigUint,
    x: BigUint,
    _f: PhantomData<F>,
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    RSACircuit<F, T, RATE>
{
    const BITS_LEN: usize = 2048;
    const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH; // 64
    const EXP_LIMB_BITS: usize = 5;
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for RSACircuit<F, T, RATE>
{
    type Config = RSAConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);
        let (composition_bit_lens, overflow_bit_lens) =
            RSAChip::<F>::compute_range_lens(Self::BITS_LEN / Self::LIMB_WIDTH);

        let range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        let bigint_config = BigIntConfig::new(range_config, main_gate_config.clone());
        let rsa_config = RSAConfig::new(bigint_config);

        rsa_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), halo2wrong::halo2::plonk::Error> {
        // === RSA based Time-lock === //
        let rsa_chip = RSAChip::new(config.clone(), Self::BITS_LEN, Self::EXP_LIMB_BITS);
        let bigint_chip = rsa_chip.bigint_chip();
        let limb_width = Self::LIMB_WIDTH;
        let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;

        layouter.assign_region(
            || "rsa modpow with 2048 bits",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let e_limbs = decompose_big::<F>// (e, number_of_limbs, bit_len)
                    (self.e.clone(), 1, Self::EXP_LIMB_BITS); // EXP_LIMB_BITS 5
                let e_unassigned = UnassignedInteger::from(e_limbs);
                let e_var = RSAPubE::Var(e_unassigned);

                let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, limb_width);
                let n_unassigned = UnassignedInteger::from(n_limbs);

                let public_key_var = RSAPublicKey::new(n_unassigned.clone(), e_var);
                let public_key_var = rsa_chip.assign_public_key(ctx, public_key_var)?;

                let x_limbs = decompose_big::<F>(self.x.clone(), num_limbs, limb_width);
                let x_unssigned = UnassignedInteger::from(x_limbs);
                // Assigns a variable AssignedInteger whose RangeType is Fresh.
                // Returns a new AssignedInteger. The bit length of each limb is less than self.limb_width, and the number of its limbs is self.num_limbs.
                let x_assigned = bigint_chip.assign_integer(ctx, x_unssigned)?;
                // Given a base x, a RSA public key (e,n), performs the modular power x^e mod n.
                let powed_var = rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_var)?;

                let valid_powed_var_biguint = big_pow_mod(&self.x, &self.e, &self.n);

                let valid_powed_var_biguint =
                    bigint_chip.assign_constant_fresh(ctx, valid_powed_var_biguint)?;
                bigint_chip.assert_equal_fresh(ctx, &powed_var, &valid_powed_var_biguint)?;

                Ok(())
            },
        )?;
        Ok(())
    }
}

fn bench_poseidon<const T: usize, const RATE: usize, const K: u32>(name: &str, c: &mut Criterion) {
    // define prover and verifier names
    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;

    // set params for protocol
    let params_path = "./benches/data/params_pose_enc_".to_owned() + &K.to_string();
    let params_path = Path::new(&params_path);
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

    let mut rng = OsRng;
    let bits_len = RSACircuit::<Fr, T, RATE>::BITS_LEN as u64;
    let mut n = BigUint::default();
    while n.bits() != bits_len {
        n = rng.sample(RandomBits::new(bits_len));
    }
    let e = rng.sample::<BigUint, _>(RandomBits::new(
        RSACircuit::<Fr, T, RATE>::EXP_LIMB_BITS as u64,
    )) % &n;
    let x = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;

    let circuit = RSACircuit::<Fr, T, RATE> {
        n: n,
        e: e,
        x: x,
        _f: PhantomData,
    };

    let vk = keygen_vk(&params, &circuit.clone()).expect("keygen_vk failed");
    let pk = keygen_pk(&params, vk, &circuit.clone()).expect("keygen_pk failed");

    // Benchmark the proof generation and store the proof
    let proof_path = "./benches/data/proof_pose_enc_".to_owned() + &K.to_string();
    let proof_path = Path::new(&proof_path);
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
    bench_poseidon::<5, 4, 17>("modulo power", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
