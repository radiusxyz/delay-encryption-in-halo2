pub mod big_integer;
use std::marker::PhantomData;

pub use big_integer::*;

pub mod rsa;
use crate::encryption::poseidon_enc::PoseidonCipher;
pub use crate::rsa::*;
use encryption::{
    poseidon_enc::{
        PoseidonCipherKey, PoseidonCipherTest, CIPHER_SIZE, MESSAGE_CAPACITY, FULL_ROUND, PARTIAL_ROUND,
    },
    chip::*
};
use hash::hasher::HasherChip;
use rand_core::OsRng;

pub mod hash;
pub use hash::*;

pub mod poseidon;
pub use crate::poseidon::*;
pub mod encryption;

use ff::{FromUniformBytes, PrimeField};
use num_bigint::{BigUint, RandomBits};

use halo2wrong::{
    curves::{
        bn256::{self, G1Affine},
        CurveAffine,
    },
    halo2::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem},
    },
    RegionCtx,
};

use halo2wrong::halo2::plonk::Error;

use halo2::{
    circuit::{layouter, Region},
    plonk::Challenge,
};
use maingate::{
    decompose_big, mock_prover_verify, MainGate, MainGateConfig, MainGateInstructions, RangeChip,
    RangeConfig, RangeInstructions,
};

use ecc::halo2::circuit::Value;
use ecc::{integer::rns::Rns, BaseFieldEccChip, EccConfig};

// Poseidon Constants
const NUMBER_OF_LIMBS: usize = 4;
const BIT_LEN_LIMB: usize = 68;

#[derive(Clone)]
struct DelayEncCircuitConfig {
    // RSA
    rsa_config: RSAConfig,

    // Poseidon Hash
    poseidon_config: PoseidonCipherConfig,
}

#[derive(Debug, Clone)]
struct DelayEncChip<F: PrimeField+ ff::FromUniformBytes<64>, const T: usize, const RATE: usize> {
    rsa_chip: RSAChip<F>,
    enc_chip: PoseidonEncChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>,
}

impl<F: PrimeField+ ff::FromUniformBytes<64>, const T: usize, const RATE: usize> DelayEncChip<F, T, RATE> {

    pub fn new(rsa_chip: RSAChip<F>, enc_chip: PoseidonEncChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>) -> Self {
        Self {
            rsa_chip,
            enc_chip,
        }
    }
}

struct DelayEncryptCircuit<
F: PrimeField + FromUniformBytes<64>,
const T: usize,
const RATE: usize,
> { 
    // Mod power
    n: BigUint,
    e: BigUint,
    x: BigUint,
    // Poseidon
    spec: Spec<F, T, RATE>, // Spec for Poseidon Encryption
    num_input: usize,       // zeroknight - ??
    message: Value<Vec<F>>, // message to be encrypted
    key: PoseidonCipherKey<F>,
    expected: Vec<F>,       // expected cipher text
}
// struct DelayEncryptCircuit<F: PrimeField, const T: usize, const RATE: usize> {
//     // RSA
//     n: BigUint,
//     e: BigUint,
//     x: BigUint, // base integer
//     _f: PhantomData<F>,

//     // Poseidon
//     spec: Spec<F, T, RATE>, // zeroknight : struct poseidon::Spec
//     n_hash: usize,
//     inputs: Value<Vec<F>>,
//     expected: Value<F>,
// }

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> DelayEncryptCircuit<F, T, RATE> {
    const BITS_LEN: usize = 2048;
    const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH; // 64
    const EXP_LIMB_BITS: usize = 5;
    const DEFAULT_E: u128 = 65537;

    fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
        RSAChip::new(config, Self::BITS_LEN, Self::EXP_LIMB_BITS)
    }
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for DelayEncryptCircuit<F, T, RATE>
{
    type Config = DelayEncCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);
        let (composition_bit_lens, overflow_bit_lens) =
            RSAChip::<F>::compute_range_lens(Self::BITS_LEN / Self::LIMB_WIDTH);

        let range_config = RangeChip::<F>::configure(
            // meta, main_gate_config, composition_bit_lens, overflow_bit_lens)
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        let bigint_config = BigIntConfig::new(range_config, main_gate_config.clone());
        let rsa_config = RSAConfig::new(bigint_config);
        let poseidon_config = PoseidonCipherConfig { main_gate_config };

        // Poseidon Hash
        //let main_gate_config = MainGate::<F>::configure(meta);

        DelayEncCircuitConfig {
            rsa_config,
            poseidon_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), halo2wrong::halo2::plonk::Error> {
        // poseidoncipherchip = new();
        // enc_key = pcc.calucation_key();
        // pcc.encrypt_message (enc_key);

        // === RSA based Time-lock === //
        let rsa_chip = self.rsa_chip(config.rsa_config.clone());
        let bigint_chip = rsa_chip.bigint_chip();
        let limb_width = Self::LIMB_WIDTH;
        let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;

        layouter.assign_region(
            //name, assignment)
            || "rsa modpow with 2048 bits",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let e_limbs = decompose_big::<F>// (e, number_of_limbs, bit_len)
                    (self.e.clone(), 1, Self::EXP_LIMB_BITS); // EXP_LIMB_BITS 5
                let e_unassigned = UnassignedInteger::from(e_limbs);
                let e_var = RSAPubE::Var(e_unassigned);
                let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));

                let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, limb_width);
                let n_unassigned = UnassignedInteger::from(n_limbs);

                let public_key_var = RSAPublicKey::new(n_unassigned.clone(), e_var);
                let public_key_var = rsa_chip.assign_public_key(ctx, public_key_var)?;
                let public_key_fix = RSAPublicKey::new(n_unassigned, e_fix);
                let public_key_fix = rsa_chip.assign_public_key(ctx, public_key_fix)?;

                let x_limbs = decompose_big::<F>(self.x.clone(), num_limbs, limb_width);
                let x_unssigned = UnassignedInteger::from(x_limbs);
                // Assigns a variable AssignedInteger whose RangeType is Fresh.
                //Returns a new AssignedInteger. The bit length of each limb is less than self.limb_width, and the number of its limbs is self.num_limbs.
                let x_assigned = bigint_chip.assign_integer(ctx, x_unssigned)?;
                // Given a base x, a RSA public key (e,n), performs the modular power x^e mod n.
                let powed_var = rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                let powed_fix = rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;

                let valid_powed_var = big_pow_mod(&self.x, &self.e, &self.n);
                let valid_powed_fix =
                    big_pow_mod(&self.x, &BigUint::from(Self::DEFAULT_E), &self.n);

                let valid_powed_var = bigint_chip.assign_constant_fresh(ctx, valid_powed_var)?;
                let valid_powed_fix = bigint_chip.assign_constant_fresh(ctx, valid_powed_fix)?;
                bigint_chip.assert_equal_fresh(ctx, &powed_var, &valid_powed_var)?;
                bigint_chip.assert_equal_fresh(ctx, &powed_fix, &valid_powed_fix)?;

                Ok(())
            },
        )?;
        let range_chip = bigint_chip.range_chip();
        range_chip.load_table(&mut layouter)?;

        
        let main_gate = rsa_chip.main_gate();
        // let mut main_gate = config.poseidon_config.main_gate_config.clone(); //main_gate()
        layouter.assign_region(
            || "poseidon region",
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

                let mut pos_enc_chip = PoseidonEncChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new(
                    ctx,
                    &self.spec,
                    &config.poseidon_config.main_gate_config,
                    &self.key.key0,
                    &self.key.key1
                )?;

                // check the assigned initial state
                println!("\nzk_state: {:?}", pos_enc_chip.state.0);

                // permute before state message addtion
                pos_enc_chip.permutation(ctx, vec![])?;

                // check the permuted state
                println!("zk_state2: {:?}\n", pos_enc_chip.state.0);

                // set the message to be an input to the encryption
                for e in self.message.as_ref().transpose_vec(self.num_input) {
                    let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
                    pos_enc_chip.set_inputs(&[e.clone()]);
                }

                // add the input to the currentn state and output encrypted result
                let cipher_text = pos_enc_chip.absorb_and_relese(ctx)?;

                println!("cipher: {:?}", cipher_text);
                println!("expected cipher: {:?}\n", expected_result);
                println!("cipher len: {:?}", cipher_text.len());

                // constrain with encryption result
                println!("check out equality..");
                let _ = main_gate.assert_equal(ctx, &cipher_text[0], &expected_result[0])?;
                let _ = main_gate.assert_equal(ctx, &cipher_text[1], &expected_result[1])?;
                let _ = main_gate.assert_equal(ctx, &cipher_text[2], &expected_result[2])?;
                Ok(())
            },
        )?;

        // Poseidon Encryption

        Ok(())
    }
}

#[test]
fn test_modpow_2048_circuit() {
    use halo2wrong::halo2::dev::MockProver;
    use rand::{thread_rng, Rng};
    use encryption::chip::PoseidonCipherCircuit;

    // FromUniformBytes : Trait for constructing a PrimeField element from a fixed-length uniform byte array.
    fn run<F: FromUniformBytes<64> + Ord, const T: usize, const RATE: usize>() {
        let mut rng = thread_rng();
        let bits_len = DelayEncryptCircuit::<F, T, RATE>::BITS_LEN as u64;
        let mut n = BigUint::default();
        while n.bits() != bits_len {
            n = rng.sample(RandomBits::new(bits_len));
        }
        let e = rng.sample::<BigUint, _>(RandomBits::new(
            DelayEncryptCircuit::<F, T, RATE>::EXP_LIMB_BITS as u64,
        )) % &n;
        let x = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;

        //params for Poseidon
        let mut ref_pos_enc = PoseidonCipher::<F, FULL_ROUND, PARTIAL_ROUND, T, RATE>::new();

        let spec = Spec::<F, T, RATE>::new(8, 57);
        let inputs = (0..(MESSAGE_CAPACITY))
            .map(|_| F::ZERO)
            .collect::<Vec<F>>();

        //== Poseidon Encryption ==//

        let ref_cipher = ref_pos_enc.encrypt(&inputs, &F::ONE);


        let key = PoseidonCipherKey::<F> {
            key0: F::random(OsRng),
            key1: F::random(OsRng),
        };
        //== Circuit ==//
        
        let circuit = PoseidonCipherCircuit::<F, T, RATE> {
            spec: spec.clone(),
            num_input: MESSAGE_CAPACITY,
            message: Value::known(inputs),
            key: key.clone(),
            expected: ref_cipher.to_vec(),
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
    run::<BnFq, 5, 4>();
    //run::<PastaFp, 5, 4>();
    //run::<PastaFq, 5, 4>();
}

// //======================= Poseidon Encryption ==================//
// #[derive(Clone)]
// struct PECircuitConfig {
//     main_gate_config: MainGateConfig,
// }

// struct PECircuit<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> {
//     spec: Spec<F, T, RATE>,
//     n_hash: usize,
//     inputs: Value<Vec<F>>,
//     key: PoseidonCipherKey<F>,
//     expected: Value<F>,
//     encrypted: Value<Vec<F>>,
// }

// impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
//     PECircuit<F, T, RATE>
// {
//     const EXP_LIMB_BITS: usize = 5;
// }

// impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
//     for PECircuit<F, T, RATE>
// {
//     type Config = PECircuitConfig;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn without_witnesses(&self) -> Self {
//         todo!()
//     }

//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//         let main_gate_config = MainGate::<F>::configure(meta);
//         PECircuitConfig { main_gate_config }
//     }

//     fn synthesize(
//         &self,
//         config: Self::Config,
//         mut layouter: impl Layouter<F>,
//     ) -> Result<(), Error> {
//         let mut main_gate = MainGate::<F>::new(config.main_gate_config.clone());

//         layouter.assign_region(
//             || "poseidon region",
//             |region| {
//                 let offset = 0;
//                 let ctx = &mut RegionCtx::new(region, offset);
//                 let mut hasher_chip = HasherChip::<F, NUMBER_OF_LIMBS, BIT_LEN_LIMB, T, RATE>::new(
//                     ctx,
//                     &self.spec,
//                     &config.main_gate_config,
//                 )?;

//                 println!("hasher_chip state : {:?}", hasher_chip.state.0.to_vec());

//                 // inputs
//                 for e in self.inputs.as_ref().transpose_vec(self.n_hash) {
//                     let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
//                     // println!("intpus_cell : {:?}", e.value());
//                     hasher_chip.update(&[e.clone()]);
//                 }
//                 // constrain squeezing new challenge
//                 let challenge = hasher_chip.hash(ctx)?;

//                 //println!("[in circuit] inputs: {:?}",self.inputs);
//                 //println!("[in circuit] challenge: {:?}", challenge.value());

//                 let expected = main_gate.assign_value(ctx, self.expected)?;

//                 //println!("[in circuit] expected: {:?}", expected.value());

//                 println!("challenge: {:?}", challenge);
//                 println!("expected: {:?}", expected);
//                 main_gate.assert_equal(ctx, &challenge, &expected)?;
//                 Ok(())
//             },
//         )?;

//         // Poseidon Encryption
//         layouter.assign_region(
//             || "poseidon encryption",
//             |region| {
//                 let offset = 0;
//                 let ctx = &mut RegionCtx::new(region, offset);

//                 let mut cipher = PoseidonCipherTest::<F, T, RATE> {
//                     cipherKey: self.key.clone(),
//                     cipherByteSize: CIPHER_SIZE * (F::NUM_BITS as usize) / (8 as usize),
//                     cipher: [F::ZERO; CIPHER_SIZE],
//                 };
//                 // inputs: Value<Vec<F>>,
//                 self.inputs.clone().map(|e| {
//                     // == Native - Poseidon Encryption ==//
//                     cipher.encrypt(&e[..], &F::ONE);
//                 });
//                 let mut native_cipher = vec![];
//                 for e in cipher.cipher.clone() {
//                     let e = main_gate.assign_value(ctx, Value::known(e.clone()))?;
//                     native_cipher.push(e);
//                 }

//                 // == ciruit ==//
//                 let initial_state = cipher.initial_state(F::ONE);

//                 // assign initial_state into cells.
//                 let mut hasher_chip = HasherChip::<F, NUMBER_OF_LIMBS, BIT_LEN_LIMB, T, RATE>::new(
//                     ctx,
//                     &self.spec,
//                     &config.main_gate_config,
//                 )?;
//                 //let mut input_intial = vec![];

//                 println!("zk_hasher state: {:?}", hasher_chip.state.0);

//                 // transpose_vec
//                 let temp = Value::known(initial_state.to_vec().clone());
//                 for e in temp.transpose_vec(5) {
//                     let e = main_gate.assign_value(ctx, e.map(|v| v))?;
//                     hasher_chip.update(&[e.clone()]);
//                 }
//                 /*
//                 for e in initial_state {
//                     let e = main_gate.assign_value(ctx, Value::known(e))?;
//                     hasher_chip.update(&[e.clone()]);
//                     //input_intial.push(e);
//                 }
//                 */
//                 // !!!!!! = zeroknight - permutation doesn't work..
//                 // !!!!!!
//                 // hasher_chip.permutation(ctx, input_intial.clone())?;
//                 hasher_chip.hash(ctx)?;
//                 let states = hasher_chip.state.0.to_vec();
//                 println!("zk_hasher state2: {:?}", states);

//                 // assign message (inputs) into cells
//                 let mut message_state = vec![];
//                 for e in self.inputs.as_ref().transpose_vec(self.n_hash) {
//                     let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
//                     message_state.push(e);
//                 }

//                 let mut cipher_text = vec![];
//                 let mut next_states = hasher_chip.state.0.to_vec().clone();
//                 (0..MESSAGE_CAPACITY).for_each(|i| {
//                     //let mut current_states = hasher_chip.absorbing.clone();
//                     // println!("length : {}", current_states.len());
//                     if i < message_state.len() {
//                         next_states[i + 1] = main_gate
//                             .add(ctx, &next_states[i + 1], &message_state[i])
//                             .unwrap();
//                     } else {
//                         let zero = main_gate.assign_constant(ctx, F::ZERO).unwrap();
//                         next_states[i + 1] =
//                             main_gate.add(ctx, &next_states[i + 1], &zero).unwrap();
//                     }

//                     cipher_text.push(next_states[i + 1].clone());
//                     /*
//                     // [WIP] cipher[i] = state[i + 1];
//                     next_states[i+1].value().map(|e| {
//                         //cipher_text.push(main_gate.assign_value(ctx, Value::known(*e)).unwrap());
//                         cipher_text.push(next_states[i + 1].clone());
//                     });
//                     */
//                 });

//                 // [Native] hasher.update(&state);
//                 //let mut hasher_chip_2 = HasherChip::<F, NUMBER_OF_LIMBS, BIT_LEN_LIMB, T, RATE>::new(ctx, &self.spec, &config.main_gate_config)?;
//                 hasher_chip.update(&next_states[..]);
//                 hasher_chip.hash(ctx);

//                 // [Native] cipher[MESSAGE_CAPACITY] = state[1];
//                 let mut next_states_2 = hasher_chip.state.0.to_vec().clone();

//                 cipher_text.push(next_states_2[1].clone());
//                 /*
//                 let tmp = next_states_2[1].value().map(|e| {
//                     cipher_text.push(main_gate.assign_value(ctx, Value::known(*e)).unwrap());
//                 });
//                 */

//                 println!("cipher: {:?}", cipher_text);
//                 println!("native cipher: {:?}", native_cipher);
//                 // [WIP]
//                 // should be equal : cipher.cipher vs cipher_text
//                 //if cipher_text.len() > 0 {
//                 println!("check out equality..");
//                 main_gate.assert_equal(ctx, &cipher_text[0], &native_cipher[0]);
//                 main_gate.assert_equal(ctx, &cipher_text[1], &native_cipher[1]);
//                 main_gate.assert_equal(ctx, &cipher_text[2], &native_cipher[2]); // Should be Equal!!
//                                                                                  //}

//                 Ok(())
//             },
//         )?;

//         // Poseidon Hash Test : Passed!!
//         /*
//         layouter.assign_region(
//             || "poseidon encryption",
//             |region| {

//                 let offset = 0;
//                 let ctx = &mut RegionCtx::new(region, offset);

//                 let mut cipher = PoseidonCipherTest::<F, T, RATE> {
//                     r_f: 8,
//                     r_p: 57,
//                     cipherKey: self.key.clone(),
//                     cipherByteSize: CIPHER_SIZE * (F::NUM_BITS as usize) / (8 as usize),
//                     cipher: [F::ZERO; CIPHER_SIZE],
//                 };
//                 self.inputs.clone().map(|e| {
//                     // == Native - Poseidon Encryption ==//
//                     println!("native_hash : {:?}",cipher.hash(&e[..]));
//                 });

//                 let mut hasher_chip = HasherChip::<F, NUMBER_OF_LIMBS, BIT_LEN_LIMB, T, RATE>::new(ctx, &self.spec, &config.main_gate_config)?;

//                 for e in self.inputs.as_ref().transpose_vec(self.n_hash) {
//                     let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
//                     // println!("intpus_cell : {:?}", e.value());
//                     hasher_chip.update(&[e.clone()]);
//                 }
//                 // constrain squeezing new challenge
//                 let challenge = hasher_chip.hash(ctx)?;

//                 println!("circuit hash : {:?}", challenge);
//                 Ok(())
//         })?;
//         */

//         Ok(())
//     }
// }

// #[test]
// fn test_poseidon_encryption() {
//     use crate::encryption::poseidon_enc::*;

//     fn run<F: FromUniformBytes<64> + Ord, const T: usize, const RATE: usize>() {
//         let mut ref_hasher = Poseidon::<F, T, RATE>::new(8, 57);

//         let spec = Spec::<F, T, RATE>::new(8, 57);
//         let inputs = (0..(3 * T)).map(|_| F::random(OsRng)).collect::<Vec<F>>();
//         ref_hasher.perm_with_input(&inputs[..]);
//         let expected = ref_hasher.perm_remain();

//         //======== Poseidon Encryption ============//
//         let key = PoseidonCipherKey::<F> {
//             key0: F::random(OsRng),
//             key1: F::random(OsRng),
//         };

//         let mut cipher = PoseidonCipherTest::<F, T, RATE> {
//             cipherKey: key.clone(),
//             cipherByteSize: CIPHER_SIZE * (F::NUM_BITS as usize) / 8,
//             cipher: [F::ZERO; CIPHER_SIZE],
//         };

//         let message = [F::random(OsRng), F::random(OsRng)];
//         cipher.encrypt(&message, &F::ONE);
//         println!("Messages.: {:?}", message);
//         println!("Encrypted: {:?}", cipher.cipher);
//         println!("Decrypted: {:?}", cipher.decrypt(&F::ONE).unwrap());

//         //========== Circuit =============//
//         let key = PoseidonCipherKey::<F> {
//             key0: F::random(OsRng),
//             key1: F::random(OsRng),
//         };

//         let circuit = PECircuit::<F, T, RATE> {
//             spec: spec.clone(),
//             n_hash: 3 * T,
//             inputs: Value::known(inputs),
//             key: key.clone(),
//             expected: Value::known(expected),
//             encrypted: Value::known(cipher.cipher.to_vec()), // Encrypted
//         };

//         let public_inputs = vec![vec![]];
//         mock_prover_verify(&circuit, public_inputs);
//     }
//     use halo2wrong::curves::bn256::Fr as BnFr;

//     run::<BnFr, 5, 4>();
// }
