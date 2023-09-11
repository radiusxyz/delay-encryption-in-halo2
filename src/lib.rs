pub mod big_integer;
use std::marker::PhantomData;
pub use big_integer::*;
pub mod hash;
use halo2_proofs::circuit::AssignedCell;
pub use hash::*;
use poseidon::chip::{FULL_ROUND, PARTIAL_ROUND};
pub mod rsa;
pub use crate::rsa::*;
use crate::{encryption::poseidon_enc::PoseidonCipher, hash::chip::HasherChip};
use encryption::{
    chip::*,
    poseidon_enc::{PoseidonEncKey, CIPHER_SIZE, MESSAGE_CAPACITY},
};
use rand_core::OsRng;
pub mod poseidon;
pub use crate::poseidon::*;
pub mod encryption;
use ff::{FromUniformBytes, PrimeField, Field};
use num_bigint::{BigUint, RandomBits};
use halo2wrong::{
    halo2::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    RegionCtx,
};
use maingate::{
    decompose_big, mock_prover_verify, MainGate, MainGateConfig, MainGateInstructions, RangeChip,
    RangeConfig, RangeInstructions,
};

#[derive(Clone, Debug)]
pub struct DelayEncCircuitConfig {
    // RSA
    rsa_config: RSAConfig,
    // Poseidon Encryption
    enc_config: MainGateConfig,
    // Hash
    hash_config: MainGateConfig
}

#[derive(Debug, Clone)]
struct DelayEncChip<F: PrimeField + ff::FromUniformBytes<64>, const T: usize, const RATE: usize> {
    // rsa_chip: RSAChip<F>,
    // enc_chip: PoseidonChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>,
    // hash_chip: HasherChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>
    delay_enc_config: DelayEncCircuitConfig,
    _f: PhantomData<F>,
}

impl<F: PrimeField + ff::FromUniformBytes<64>, const T: usize, const RATE: usize>
    DelayEncChip<F, T, RATE>
{
    pub fn new_rsa(config: RSAConfig, bits_len: usize, exp_limb_bits: usize) -> RSAChip<F> {
        RSAChip {
            config,
            bits_len,
            exp_limb_bits,
            _f: PhantomData,
        }
    }


    pub fn new_hash(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<HasherChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>, Error> {
        let pos_hash_chip =
            PoseidonChip::<F, T, RATE,FULL_ROUND, PARTIAL_ROUND>::new_hash(ctx, spec, main_gate_config)?;

        Ok(HasherChip {
            pose_chip: pos_hash_chip,
        })
    }

    pub fn new_enc(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
        sk: [F; 2],
    ) -> Result<PoseidonEncChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>, Error> {
        let enc_chip = PoseidonChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new_enc(
            ctx,
            spec,
            &main_gate_config,
            &sk[0],
            &sk[1],
        )?;

        Ok(PoseidonEncChip {
            pose_chip: enc_chip,
            pose_key0: sk[0],
            pose_key1: sk[1],
        })
    }
}
#[derive(Clone)]
pub struct DelayEncryptCircuit<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    // Mod power
    pub n: BigUint,
    pub e: BigUint,
    pub x: BigUint,
    //
    // Poseidon Enc
    pub spec: Spec<F, T, RATE>,
    pub num_input: usize,
    pub message: Vec<F>,
    // pub key: PoseidonEncKey<F>, // set as private
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    DelayEncryptCircuit<F, T, RATE>
{
    pub const BITS_LEN: usize = 2048;
    pub const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH; // 64
    pub const EXP_LIMB_BITS: usize = 5;
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
        let maingate_config = MainGate::<F>::configure(meta);
        // let enc_config = MainGate::<F>::configure(meta);
        // let hash_config = MainGate::<F>::configure(meta);
        
        // rsa config
        // let rsa_gate_config = MainGate::<F>::configure(meta);
        let rsa_gate_config = maingate_config.clone();
        let (composition_bit_lens, overflow_bit_lens) =
            RSAChip::<F>::compute_range_lens(Self::BITS_LEN / Self::LIMB_WIDTH);

        let range_config = RangeChip::<F>::configure(
            meta,
            &rsa_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        let bigint_config = BigIntConfig::new(range_config, rsa_gate_config.clone());
        let rsa_config = RSAConfig::new(bigint_config);

        let enc_config = maingate_config.clone();
        let hash_config = maingate_config.clone();

        DelayEncCircuitConfig {
            rsa_config,
            enc_config,
            hash_config
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), halo2wrong::halo2::plonk::Error> {
        // === RSA based Time-lock === //
        let rsa_chip: RSAChip<F> = DelayEncChip::<F, T, RATE>::new_rsa(
            config.rsa_config,
            Self::BITS_LEN,
            Self::EXP_LIMB_BITS,
        );
        let bigint_chip = rsa_chip.bigint_chip();
        let main_gate_chip = rsa_chip.main_gate();
        let limb_width = Self::LIMB_WIDTH;
        let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
        let rsa_output = layouter.assign_region(
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
                // Returns a new AssignedInteger. The bit length of each limb is less than self.limb_width, and the number of its limbs is self.num_limbs.
                let x_assigned = bigint_chip.assign_integer(ctx, x_unssigned)?;
                // Given a base x, a RSA public key (e,n), performs the modular power x^e mod n.
                let powed_var = rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
                let valid_powed_var_biguint = big_pow_mod(&self.x, &self.e, &self.n);
                let valid_powed_var =
                    bigint_chip.assign_constant_fresh(ctx, valid_powed_var_biguint.clone())?;
                bigint_chip.assert_equal_fresh(ctx, &powed_var, &valid_powed_var)?;

                println!("RSA RESULT: {:#6x}\n", valid_powed_var_biguint);
                Ok(valid_powed_var)
            },
        )?;
        let range_chip = bigint_chip.range_chip();
        range_chip.load_table(&mut layouter)?;

        // let h_spec = Spec::<F, T, RATE>::new(8, 57);
        let h_out = layouter.assign_region(
            || "hash mapping from 2048bit",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut hasher = DelayEncChip::<F, T, RATE>::new_hash(
                    ctx,
                    &self.spec,
                    &config.hash_config,
                )?;
                for i in 0..rsa_output.num_limbs() {
                    let e = main_gate_chip.assign_value(ctx, rsa_output.limb(i).value().map(|e| *e))?;
                    println!("{:?}", e);
                    hasher.update(&[e.clone()]);
                    // hash_gate.assert_equal(ctx, e, b); giving equality constraint
                }
                let mut h_out: Vec<AssignedCell<F, F>> = vec![];
                let h_assiged = hasher.hash(ctx)?;
                h_out.push(h_assiged.clone());
                // let expected = main_gate.assign_value(ctx, self.expected)?;
                let h_value = h_assiged.value().map(|e| *e);
                println!("\nhash_output1: {:?}", h_value);
                hasher.pose_chip.perm_hash(ctx, vec![])?;
                let h_assiged = hasher.pose_chip.state.0[1].clone();
                let h_value = h_assiged.value().map(|e| *e);
                h_out.push(h_assiged.clone());
                println!("\nhash_output2: {:?}", h_value);
                Ok(h_out)
            }
        )?;
        layouter.assign_region(
            || "poseidon region",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut pose_key = [F::ZERO; 2];
                // set poseidon enc key as the ouput of rsa
                h_out[0].value().map(|e| *e).map(|v| pose_key[0] = v);
                h_out[1].value().map(|e| *e).map(|v| pose_key[1] = v);
                // == Encryption Scheme == //
                let mut ref_enc =
                    PoseidonCipher::<F, FULL_ROUND, PARTIAL_ROUND, T, RATE>::new(pose_key);
                let encryption_result = ref_enc.encrypt(&self.message, &F::ONE);
                let mut expected_result = vec![];
                // assign expected result
                for result in &encryption_result {
                    let result = main_gate_chip.assign_value(ctx, Value::known(result.clone()))?;
                    expected_result.push(result);
                }
                // == Encryption ciruit ==//
                // new assigns initial_state into cells.
                let mut enc = DelayEncChip::<F, T, RATE>::new_enc(
                    ctx,
                    &self.spec,
                    &config.enc_config,
                    pose_key,
                )?;
                let _ = main_gate_chip.assert_equal(ctx, &enc.pose_chip.state.0[2], &h_out[0]);
                let _ = main_gate_chip.assert_equal(ctx, &enc.pose_chip.state.0[3], &h_out[1]);
                // check the assigned initial state
                println!("\nzk_state: {:?}", enc.pose_chip.state.0);
                println!("\npose_key: {:?}", pose_key);
                // permute before state message addtion
                enc.pose_chip.permutation(ctx, vec![])?;
                // check the permuted state
                // println!("\nzk_state2: {:?}", enc.pose_chip.state.0);
                let message = Value::known(self.message.clone());
                // println!("\nassigned message: {:?}", message);
                // set the message to be an input to the encryption
                for e in message.as_ref().transpose_vec(self.num_input) {
                    let e = main_gate_chip.assign_value(ctx, e.map(|v| *v))?;
                    enc.pose_chip.set_inputs(&[e.clone()]);
                }
                // add the input to the currentn state and output encrypted result
                let cipher_text = enc.absorb_and_relese(ctx)?;
                println!("\ncipher: {:?}", cipher_text);
                println!("\nexpected cipher: {:?}\n", expected_result);
                // println!("cipher len: {:?}", cipher_text.len());
                // constrain with encryption result
                // println!("check out equality..");
                for i in 0..cipher_text.len() {
                    main_gate_chip.assert_equal(ctx, &cipher_text[i], &expected_result[i])?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

#[test]
fn test_de_circuit() {
    use halo2wrong::curves::bn256::Fr;
    use rand::{thread_rng, Rng};
    // FromUniformBytes : Trait for constructing a PrimeField element from a fixed-length uniform byte array.
    // fn run<F: FromUniformBytes<64> + Ord, const T: usize, const RATE: usize>() {
        let mut rng = thread_rng();
        let bits_len = DelayEncryptCircuit::<Fr, 5, 4>::BITS_LEN as u64;
        let mut n = BigUint::default();
        while n.bits() != bits_len {
            n = rng.sample(RandomBits::new(bits_len));
        }
        let e = rng.sample::<BigUint, _>(RandomBits::new(
            DelayEncryptCircuit::<Fr, 5, 4>::EXP_LIMB_BITS as u64,
        )) % &n;
        let x = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
        // let key: PoseidonEncKey<Fr> = PoseidonEncKey::init();
        let spec = Spec::<Fr, 5, 4>::new(8, 57);
        let inputs = (0..(MESSAGE_CAPACITY)).map(|_| Fr::ZERO).collect::<Vec<Fr>>();
        //== Circuit ==//
        let circuit = DelayEncryptCircuit::<Fr, 5, 4> {
            n: n,
            e: e,
            x: x,
            spec: spec.clone(),
            num_input: MESSAGE_CAPACITY,
            message: inputs,
            // key: key,
            // expected: ref_cipher.to_vec(),
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
    // }
}
