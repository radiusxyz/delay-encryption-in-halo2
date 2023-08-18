pub mod big_integer;
use std::marker::PhantomData;

pub use big_integer::*;

pub mod rsa;
use hash::hasher::HasherChip;
use rand_core::OsRng;
pub use rsa::*;

pub mod hash;
pub use hash::*;

pub mod poseidon;
pub use poseidon::*;

pub mod encryption;

use ff::{PrimeField, FromUniformBytes};
use num_bigint::{BigUint, RandomBits};

use halo2wrong::{halo2::{ 
    plonk::{Circuit, ConstraintSystem},
    circuit::{SimpleFloorPlanner, Layouter},
}, RegionCtx, curves::{CurveAffine, bn256::{self, G1Affine}}};

use halo2wrong::halo2::plonk::Error;

use halo2::{circuit::{layouter, Region}, plonk::Challenge};
use maingate::{MainGate, RangeChip, decompose_big, RangeInstructions, MainGateConfig, RangeConfig, MainGateInstructions, mock_prover_verify};

use ecc::{EccConfig, integer::rns::Rns, BaseFieldEccChip};
use ecc::halo2::circuit::Value;

use ::poseidon::{Spec, Poseidon};


// Poseidon Constants
const NUMBER_OF_LIMBS: usize = 4;
const BIT_LEN_LIMB: usize = 68;

#[derive(Clone)]
struct DelayEncCircuitConfig {
    // RSA
    rsa_config: RSAConfig,

    // Poseidon Hash
    main_gate_config: MainGateConfig,
}

struct DelayEncryptCircuit<F: PrimeField , const T: usize, const RATE: usize> {
    // RSA
    n : BigUint,
    e : BigUint,
    x : BigUint,        // base integer
    _f: PhantomData<F>,

    // Poseidon
    spec: Spec<F, T, RATE>, // zeroknight : struct poseidon::Spec 
    n_hash: usize,
    inputs: Value<Vec<F>>,
    expected: Value<F>,

}

impl<F: PrimeField, const T: usize, const RATE: usize> DelayEncryptCircuit<F, T, RATE> {
    const BITS_LEN: usize = 2048;
    const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH; // 64
    const EXP_LIMB_BITS: usize = 5;
    const DEFAULT_E: u128 = 65537;

    fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
        RSAChip::new(config, Self::BITS_LEN, Self::EXP_LIMB_BITS)
    }
}

impl<F: PrimeField, const T: usize, const RATE: usize> Circuit<F> 
    for DelayEncryptCircuit<F, T, RATE> {

    type Config = DelayEncCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);
        let (composition_bit_lens, overflow_bit_lens) = 
            RSAChip::<F>::compute_range_lens(
                Self::BITS_LEN / Self::LIMB_WIDTH,
            );
        
        let range_config = RangeChip::<F>::configure( // meta, main_gate_config, composition_bit_lens, overflow_bit_lens)
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        let bigint_config = BigIntConfig::new(range_config, main_gate_config.clone());
        let rsa_config = RSAConfig::new(bigint_config);

        // Poseidon Hash
        //let main_gate_config = MainGate::<F>::configure(meta);

        DelayEncCircuitConfig {
            rsa_config,
            main_gate_config,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>) -> Result<(), halo2wrong::halo2::plonk::Error> {
        
        // === RSA based Time-lock === //
        let rsa_chip = self.rsa_chip(config.rsa_config.clone());
        let bigint_chip = rsa_chip.bigint_chip();
        let limb_width = Self::LIMB_WIDTH;
        let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;

        layouter.assign_region( //name, assignment)
            || "rsa modpow with 2048 bits",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let e_limbs = decompose_big::<F>// (e, number_of_limbs, bit_len)
                    (self.e.clone(), 1, Self::EXP_LIMB_BITS);   // EXP_LIMB_BITS 5
                let e_unassigned = UnassignedInteger::from(e_limbs);
                let e_var = RSAPubE::Var(e_unassigned);
                let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));

                let n_limbs = decompose_big::<F>(self.n.clone(), 
                                num_limbs, limb_width);
                let n_unassigned = UnassignedInteger::from(n_limbs);
                
                let public_key_var = RSAPublicKey::new(n_unassigned.clone(), e_var);
                let public_key_var = rsa_chip.assign_public_key(ctx, public_key_var)?;
                let public_key_fix = RSAPublicKey::new(n_unassigned, e_fix);
                let public_key_fix = rsa_chip.assign_public_key(ctx, public_key_fix)?;

                let x_limbs = decompose_big::<F>(self.x.clone(), 
                                    num_limbs, limb_width);
                let x_unssigned = UnassignedInteger::from(x_limbs);
                // Assigns a variable AssignedInteger whose RangeType is Fresh.
                //Returns a new AssignedInteger. The bit length of each limb is less than self.limb_width, and the number of its limbs is self.num_limbs.
                let x_assigned = bigint_chip.assign_integer(ctx, x_unssigned)?;
                // Given a base x, a RSA public key (e,n), performs the modular power x^e mod n.
                let powed_var = rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                let powed_fix = rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;

                let valid_powed_var = big_pow_mod(&self.x, &self.e, &self.n);
                let valid_powed_fix = big_pow_mod(&self.x, &BigUint::from(Self::DEFAULT_E), &self.n);

                let valid_powed_var = bigint_chip.assign_constant_fresh(ctx, valid_powed_var)?;
                let valid_powed_fix = bigint_chip.assign_constant_fresh(ctx, valid_powed_fix)?;
                bigint_chip.assert_equal_fresh(ctx, &powed_var, &valid_powed_var)?;
                bigint_chip.assert_equal_fresh(ctx, &powed_fix, &valid_powed_fix)?;

                Ok(())
            },
        )?;
        let range_chip = bigint_chip.range_chip();
        range_chip.load_table(&mut layouter)?;

        let mut main_gate = MainGate::<F>::new(config.main_gate_config.clone());
        layouter.assign_region(
        || "poseidon region", 
        |region| {
            let offset = 0;
            let ctx = &mut RegionCtx::new(region, offset);
            let mut hasher_chip = HasherChip::<F, NUMBER_OF_LIMBS, BIT_LEN_LIMB, T, RATE>::new(ctx, &self.spec, &config.main_gate_config )?;

            // inputs
            for e in self.inputs.as_ref().transpose_vec(self.n_hash) {
                let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
                println!("intpus_cell : {:?}", e.value());
                hasher_chip.update(&[e.clone()]);
            }
            // constrain squeezing new challenge
            let challenge = hasher_chip.hash(ctx)?;

            //println!("[in circuit] inputs: {:?}",self.inputs);
            //println!("[in circuit] challenge: {:?}", challenge.value());

            let expected = main_gate.assign_value(ctx, self.expected)?;

            //println!("[in circuit] expected: {:?}", expected.value());

            main_gate.assert_equal(ctx, &challenge, &expected)?;
            Ok(())
        })?;

        // Poseidon Encryption

        
        Ok(())
    }
}

#[test]
fn test_modpow_2048_circuit() {

    use rand::{thread_rng, Rng};
    use halo2wrong::halo2::dev::MockProver;

    // FromUniformBytes : Trait for constructing a PrimeField element from a fixed-length uniform byte array.
    fn run<F: FromUniformBytes<64> + Ord, const T: usize, const RATE: usize>() {
        let mut rng = thread_rng();
        let bits_len = DelayEncryptCircuit::<F, T, RATE>::BITS_LEN as u64;
        let mut n = BigUint::default();
        while n.bits() != bits_len {
            n = rng.sample(RandomBits::new(bits_len));
        }
        let e = rng.sample::<BigUint, _>(RandomBits::new(DelayEncryptCircuit::<F, T, RATE>::EXP_LIMB_BITS as u64)) % &n;
        let x = rng.sample::<BigUint,_>(RandomBits::new(bits_len)) % &n;

        //params for Poseidon
        let mut ref_hasher = Poseidon::<F, T, RATE>::new(8, 57);
        // Given number of round parameters constructs new Posedion instance calculating unoptimized round constants with reference Grain then calculates optimized constants and sparse matrices
        let spec = Spec::<F, T, RATE>::new(8, 57);
        let inputs = (0..(3*T)).map(|_| F::random(OsRng)).collect::<Vec<F>>();
        ref_hasher.update(&inputs[..]);
        let expected = ref_hasher.squeeze();
        //println!("inputs: {:?}",inputs);
        //println!("expected: {:?}", expected);

        let circuit = DelayEncryptCircuit::<F, T, RATE> {
            n,
            e,
            x,
            _f: PhantomData,
            // poseidon
            spec: spec.clone(), // zeroknight : struct poseidon::Spec 
            n_hash: 3*T,
            inputs: Value::known(inputs),
            expected: Value::known(expected),
        };

        let public_inputs = vec![vec![]];
        mock_prover_verify(&circuit, public_inputs);
        /*
        let k = 30; //17
        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e)
        };
        assert_eq!(prover.verify().is_err(), false);
        */
    }

    //run with different curves
    use halo2wrong::curves::bn256::Fr as BnFq;
    use halo2wrong::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
    run::<BnFq, 3, 2>();
    //run::<PastaFp, 5, 4>();
    //run::<PastaFq, 5, 4>();

}