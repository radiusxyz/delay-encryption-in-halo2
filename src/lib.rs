pub mod big_integer;
pub use big_integer::*;
use std::{marker::PhantomData, str::FromStr};
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
use ff::{Field, FromUniformBytes, PrimeField};
use halo2wrong::{
    halo2::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    RegionCtx,
};
use maingate::{
    big_to_fe, decompose_big, mock_prover_verify, MainGate, MainGateConfig, MainGateInstructions,
    RangeChip, RangeConfig, RangeInstructions,
};
use num_bigint::{BigUint, RandomBits};

#[derive(Clone, Debug)]
pub struct DelayHashCircuitConfig {
    // RSA
    rsa_config: RSAConfig,
    // Hash
    hash_config: MainGateConfig,
}

#[derive(Debug, Clone)]
struct DelayHashChip<F: PrimeField + ff::FromUniformBytes<64>, const T: usize, const RATE: usize> {
    rsa_chip: RSAChip<F>,
    hash_chip: HasherChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>,
    delay_config: DelayHashCircuitConfig,
    _f: PhantomData<F>,
}

impl<F: PrimeField + ff::FromUniformBytes<64>, const T: usize, const RATE: usize>
    DelayHashChip<F, T, RATE>
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
        let pos_hash_chip = PoseidonChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new_hash(
            ctx,
            spec,
            main_gate_config,
        )?;

        Ok(HasherChip {
            pose_chip: pos_hash_chip,
        })
    }
}
#[derive(Clone)]
pub struct DelayHashCircuit<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
{
    // Mod power
    pub n: BigUint,
    pub e: BigUint,
    pub x: BigUint,
    pub spec: Spec<F, T, RATE>,
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    DelayHashCircuit<F, T, RATE>
{
    pub const BITS_LEN: usize = 2048;
    pub const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH; // 64
    pub const EXP_LIMB_BITS: usize = 5;
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for DelayHashCircuit<F, T, RATE>
{
    type Config = DelayHashCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let maingate_config = MainGate::<F>::configure(meta);

        // rsa config
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
        let hash_config = maingate_config.clone();

        DelayHashCircuitConfig {
            rsa_config,
            hash_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), halo2wrong::halo2::plonk::Error> {
        // === RSA based Time-lock === //
        let rsa_chip: RSAChip<F> = DelayHashChip::<F, T, RATE>::new_rsa(
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

                // println!("RSA RESULT: {:#6x}\n", valid_powed_var_biguint);
                Ok(valid_powed_var)
            },
        )?;
        let range_chip = bigint_chip.range_chip();
        range_chip.load_table(&mut layouter)?;

        // let h_spec = Spec::<F, T, RATE>::new(8, 57);
        let _ = layouter.assign_region(
            || "hash mapping from 2048bit",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut hasher =
                    DelayHashChip::<F, T, RATE>::new_hash(ctx, &self.spec, &config.hash_config)?;
                let base1 = main_gate_chip.assign_constant(
                    ctx,
                    big_to_fe(BigUint::from(
                        2_u128.pow((Self::LIMB_WIDTH as u128).try_into().unwrap()),
                    )),
                )?;
                let base2 = main_gate_chip.mul(ctx, &base1, &base1)?;

                for i in 0..rsa_output.num_limbs() / 3 {
                    // println!("limb({:?}) = {:?}", 3 * i, rsa_output.limb(3 * i));
                    // println!("limb({:?}) = {:?}", 3 * i + 1, rsa_output.limb(3 * i + 1));
                    // println!("limb({:?}) = {:?}", 3 * i + 2, rsa_output.limb(3 * i + 2));
                    let mut a_poly = rsa_output.limb(3 * i);
                    a_poly = main_gate_chip.mul_add(
                        ctx,
                        &rsa_output.limb(3 * i + 1),
                        &base1,
                        &a_poly,
                    )?;
                    a_poly = main_gate_chip.mul_add(
                        ctx,
                        &rsa_output.limb(3 * i + 2),
                        &base2,
                        &a_poly,
                    )?;
                    // println!("a_ploy value:{:?}", a_poly);
                    let e = a_poly;
                    hasher.update(&[e.clone()]);
                }

                // println!("limb({:?}) = {:?}", 30, rsa_output.limb(30));
                // println!("limb({:?}) = {:?}", 31, rsa_output.limb(31));

                let mut a_poly = rsa_output.limb(30);

                a_poly = main_gate_chip.mul_add(ctx, &rsa_output.limb(31), &base1, &a_poly)?;
                // println!("a_ploy value:{:?}", a_poly);
                let e = a_poly;
                hasher.update(&[e.clone()]);
                let mut h_out: Vec<AssignedCell<F, F>> = vec![];
                let h_assiged = hasher.hash(ctx)?;
                h_out.push(h_assiged[1].clone());
                h_out.push(h_assiged[2].clone());
                Ok(h_out)
            },
        )?;
        Ok(())
    }
}

#[test]
fn test_delay_hash_circuit() {
    use halo2wrong::curves::bn256::Fr;
    use rand::{thread_rng, Rng};
    // FromUniformBytes : Trait for constructing a PrimeField element from a fixed-length uniform byte array.
    // fn run<F: FromUniformBytes<64> + Ord, const T: usize, const RATE: usize>() {
    let mut rng = thread_rng();
    let bits_len = DelayHashCircuit::<Fr, 5, 4>::BITS_LEN as u64;
    let exp_bits_len = DelayHashCircuit::<Fr, 5, 4>::EXP_LIMB_BITS as u64;
    let mut n = BigUint::default();
    // while n.bits() != bits_len {
    //     n = rng.sample(RandomBits::new(bits_len));
    // }
    let n_str = "28141118042488171683987085893211082804547182666411246751337957267627558325129270330807659495514264338871223789031440720139180803733320226406635801449559950970087353523577760632122524678886536083540653820517634151217669740804658149941194334498468585115598056022894824000564759100914428766446911582784226594512494865226014687406850139565901085662563386726638023666446733572417196288564062132135743994340713579794991722437324889056330710414609865584214617641132959519604135720246837517503204052876056954435290082921145473013444909281654990920221537036155612731037755885349760654536476906879837696864230364460391341668670";
    let n = BigUint::from_str(n_str).unwrap();
    let x_str = "24650706664647931530779790429812129663869332754789266306158402037263290618338615894318077070662068939846182179152844640270417210711833492210100625516277641377677816064687763537135723039567086447071844905269065609239209538377271609214978223287482730200871692097595642746779321147199017060877634534874033895585738414721760468042547485849199815622615157505225465318315634070761313731513338481891309086632034503563697072988465701171746764490611067236477615542800480161501913250528817677375138108229918777711366364515909433475521608671818710661086927109380390268813293786392619090435467441423410332463795623697110602606609";
    let x = BigUint::from_str(x_str).unwrap();
    let e = BigUint::from(22_u32);
    // let e = rng.sample::<BigUint, _>(RandomBits::new(exp_bits_len)) % &n;
    // let x = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
    // print!("\nBase length: {:?}\n", bits_len);
    // print!("\nExp length: {:?}\n", exp_bits_len);
    // print!("\nBase: {:?}\n", x);
    // print!("\nExp : {:?}\n", e);
    // print!("\nModulus: {:?}\n", n);
    let spec = Spec::<Fr, 5, 4>::new(8, 57);
    let inputs = (0..(MESSAGE_CAPACITY))
        .map(|_| Fr::ZERO)
        .collect::<Vec<Fr>>();
    //== Circuit ==//
    let circuit = DelayHashCircuit::<Fr, 5, 4> {
        n: n,
        e: e,
        x: x,
        spec: spec.clone(),
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

#[derive(Clone, Debug)]
pub struct HashEncCircuitConfig {
    // Poseidon Encryption
    enc_config: MainGateConfig,
    // Hash
    hash_config: MainGateConfig,
}

#[derive(Debug, Clone)]
struct HashEncChip<F: PrimeField + ff::FromUniformBytes<64>, const T: usize, const RATE: usize> {
    enc_chip: PoseidonChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>,
    hash_chip: HasherChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>,
    enc_config: HashEncCircuitConfig,
    _f: PhantomData<F>,
}

impl<F: PrimeField + ff::FromUniformBytes<64>, const T: usize, const RATE: usize>
    HashEncChip<F, T, RATE>
{
    pub fn new_hash(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<HasherChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>, Error> {
        let pos_hash_chip = PoseidonChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new_hash(
            ctx,
            spec,
            main_gate_config,
        )?;

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
        let enc_chip = PoseidonChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new_enc_de(
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
pub struct HashEncCircuit<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> {
    // Poseidon Enc
    pub spec: Spec<F, T, RATE>,
    pub num_input: usize,
    pub message: Vec<F>,
    // Hash related
    pub hashed: Vec<F>,
    num_hash_input: usize,
    hash_input: Vec<F>,
    // pub key: PoseidonEncKey<F>, // set as private
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    HashEncCircuit<F, T, RATE>
{
    pub const BITS_LEN: usize = 2048;
    pub const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH; // 64
    pub const EXP_LIMB_BITS: usize = 5;

    pub fn set_hash_input(mut self, num_hash_in: usize, hash_in: Vec<F>) {
        self.num_hash_input = num_hash_in;
        self.hash_input = hash_in;
    }
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for HashEncCircuit<F, T, RATE>
{
    type Config = HashEncCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let maingate_config = MainGate::<F>::configure(meta);

        let enc_config = maingate_config.clone();
        let hash_config = maingate_config.clone();

        HashEncCircuitConfig {
            enc_config,
            hash_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), halo2wrong::halo2::plonk::Error> {
        let h_out = layouter.assign_region(
            || "hash mapping from 2048bit",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut hasher =
                    HashEncChip::<F, T, RATE>::new_hash(ctx, &self.spec, &config.hash_config)?;
                let main_gate_chip = hasher.pose_chip.main_gate();

                let base1 = main_gate_chip.assign_constant(
                    ctx,
                    big_to_fe(BigUint::from(
                        2_u128.pow((Self::LIMB_WIDTH as u128).try_into().unwrap()),
                    )),
                )?;
                let base2 = main_gate_chip.mul(ctx, &base1, &base1)?;

                for i in 0..self.num_hash_input / 3 {
                    let in0 =
                        main_gate_chip.assign_value(ctx, Value::known(self.hash_input[3 * i]))?;
                    let in1 = main_gate_chip
                        .assign_value(ctx, Value::known(self.hash_input[3 * i + 1]))?;
                    let in2 = main_gate_chip
                        .assign_value(ctx, Value::known(self.hash_input[3 * i + 2]))?;

                    // println!("***in0({:?}) = {:?}", 3 * i, in0);
                    // println!("***in1({:?}) = {:?}", 3 * i + 1, in1);
                    // println!("***in2({:?}) = {:?}", 3 * i + 2, in2);

                    let mut a_poly = in0;
                    a_poly = main_gate_chip.mul_add(ctx, &in1, &base1, &a_poly)?;
                    a_poly = main_gate_chip.mul_add(ctx, &in2, &base2, &a_poly)?;
                    // println!("a_ploy value:{:?}", a_poly);
                    let e = a_poly;
                    hasher.update(&[e.clone()]);
                }

                // println!("({:?}) = {:?}", 30, self.hash_input[30]);
                // println!("({:?}) = {:?}", 31, self.hash_input[31]);

                let in0 = main_gate_chip.assign_value(ctx, Value::known(self.hash_input[30]))?;
                let in1 = main_gate_chip.assign_value(ctx, Value::known(self.hash_input[31]))?;

                let mut a_poly = in0;

                a_poly = main_gate_chip.mul_add(ctx, &in1, &base1, &a_poly)?;
                // println!("a_ploy value:{:?}", a_poly);
                let e = a_poly;
                hasher.update(&[e.clone()]);

                let mut h_out: Vec<AssignedCell<F, F>> = vec![];
                let h_assiged = hasher.hash(ctx)?;

                let expected_hash1 = main_gate_chip.assign_constant(ctx, self.hashed[0])?;
                let expected_hash2 = main_gate_chip.assign_constant(ctx, self.hashed[1])?;

                let _ = main_gate_chip.assert_equal(ctx, &h_assiged[1], &expected_hash1);
                let _ = main_gate_chip.assert_equal(ctx, &h_assiged[2], &expected_hash2);
                h_out.push(h_assiged[1].clone());
                h_out.push(h_assiged[2].clone());

                Ok(h_out)
            },
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
                // // == Encryption Scheme == //
                let mut ref_enc =
                    PoseidonCipher::<F, FULL_ROUND, PARTIAL_ROUND, T, RATE>::new(pose_key);
                let encryption_result = ref_enc.encrypt(&self.message, &F::ONE).unwrap();

                // == Encryption ciruit ==//
                // new assigns initial_state into cells.
                let mut enc = HashEncChip::<F, T, RATE>::new_enc(
                    ctx,
                    &self.spec,
                    &config.enc_config,
                    pose_key,
                )?;
                let main_gate_chip = enc.pose_chip.main_gate();

                let mut expected_result = vec![];
                // assign expected result
                for result in &encryption_result {
                    let result = main_gate_chip.assign_value(ctx, Value::known(result.clone()))?;
                    expected_result.push(result);
                }

                let _ = main_gate_chip.assert_equal(ctx, &enc.pose_chip.state.0[2], &h_out[0])?;
                let _ = main_gate_chip.assert_equal(ctx, &enc.pose_chip.state.0[3], &h_out[1])?;
                // check the assigned initial state
                // println!("\nzk_state: {:?}", enc.pose_chip.state.0);
                // println!("\npose_key: {:?}", pose_key);
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
                // println!("\ncipher: {:?}", cipher_text);
                // println!("\nexpected cipher: {:?}\n", expected_result);
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
fn test_hash_enc_circuit() {
    use halo2wrong::curves::bn256::Fr;
    use rand::{thread_rng, Rng};
    // FromUniformBytes : Trait for constructing a PrimeField element from a fixed-length uniform byte array.
    // fn run<F: FromUniformBytes<64> + Ord, const T: usize, const RATE: usize>() {
    let mut rng = thread_rng();
    let bits_len = HashEncCircuit::<Fr, 5, 4>::BITS_LEN as u64;
    let exp_bits_len = HashEncCircuit::<Fr, 5, 4>::EXP_LIMB_BITS as u64;
    let mut n = BigUint::default();
    // while n.bits() != bits_len {
    //     n = rng.sample(RandomBits::new(bits_len));
    // }
    // let e = rng.sample::<BigUint, _>(RandomBits::new(exp_bits_len)) % &n;
    // let x = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
    let n_str = "28141118042488171683987085893211082804547182666411246751337957267627558325129270330807659495514264338871223789031440720139180803733320226406635801449559950970087353523577760632122524678886536083540653820517634151217669740804658149941194334498468585115598056022894824000564759100914428766446911582784226594512494865226014687406850139565901085662563386726638023666446733572417196288564062132135743994340713579794991722437324889056330710414609865584214617641132959519604135720246837517503204052876056954435290082921145473013444909281654990920221537036155612731037755885349760654536476906879837696864230364460391341668670";
    let n = BigUint::from_str(n_str).unwrap();
    let x_str = "24650706664647931530779790429812129663869332754789266306158402037263290618338615894318077070662068939846182179152844640270417210711833492210100625516277641377677816064687763537135723039567086447071844905269065609239209538377271609214978223287482730200871692097595642746779321147199017060877634534874033895585738414721760468042547485849199815622615157505225465318315634070761313731513338481891309086632034503563697072988465701171746764490611067236477615542800480161501913250528817677375138108229918777711366364515909433475521608671818710661086927109380390268813293786392619090435467441423410332463795623697110602606609";
    let x = BigUint::from_str(x_str).unwrap();
    let e = BigUint::from(22_u32);
    print!("\nBase length: {:?}\n", bits_len);
    print!("\nExp length: {:?}\n", exp_bits_len);
    let spec = Spec::<Fr, 5, 4>::new(8, 57);
    let inputs = (0..(MESSAGE_CAPACITY))
        .map(|_| Fr::ZERO)
        .collect::<Vec<Fr>>();
    let h_inputs = vec![
        Fr::from_u128(0xee32954fc8091d39_u128),
        Fr::from_u128(0x1ca8bd5f0682ccd4_u128),
        Fr::from_u128(0x727542c247759887_u128),
        Fr::from_u128(0x05581067eb87ad38_u128),
        Fr::from_u128(0xc83e8d1e4bb755d6_u128),
        Fr::from_u128(0xec26a4f4676ba7ed_u128),
        Fr::from_u128(0xfd96b0213175dd76_u128),
        Fr::from_u128(0xf2fb3670eaaf6df2_u128),
        Fr::from_u128(0x76476b1e375092eb_u128),
        Fr::from_u128(0x85659738b32775e6_u128),
        Fr::from_u128(0x720d7d5d63ccaf3f_u128),
        Fr::from_u128(0x801dc77875b2964e_u128),
        Fr::from_u128(0x2fdcaef2b939a117_u128),
        Fr::from_u128(0xcf68bdd026eb1714_u128),
        Fr::from_u128(0x980e645ada564c88_u128),
        Fr::from_u128(0xe71edd77cac0666f_u128),
        Fr::from_u128(0x0a2633441b5532c4_u128),
        Fr::from_u128(0xca7085ea12691bdf_u128),
        Fr::from_u128(0xdbcafde1c9f97850_u128),
        Fr::from_u128(0x9f57a6e4831eac0c_u128),
        Fr::from_u128(0x5f88c159cc14e815_u128),
        Fr::from_u128(0x45639a204a60f44b_u128),
        Fr::from_u128(0xbe35d4afcba17cf4_u128),
        Fr::from_u128(0x2114e56e8c1753bf_u128),
        Fr::from_u128(0xf2fcac52e5f4e661_u128),
        Fr::from_u128(0x0bbdc5eecf9f99aa_u128),
        Fr::from_u128(0xfbbaf128fd9935f2_u128),
        Fr::from_u128(0x6a76d860c630b3ac_u128),
        Fr::from_u128(0x9ef79831b1665d01_u128),
        Fr::from_u128(0xa83328e4fef9c09d_u128),
        Fr::from_u128(0x684db49ca302e9a5_u128),
        Fr::from_u128(0x2cfc013f0d93fcf7_u128),
    ];

    let hash_value = vec![
        Fr::from_raw([
            0x2b12a4170b3933b9,
            0xcc9cfd822e51ce24,
            0xa2102b4f85398da9,
            0x05c3e3a94ba653bb,
        ]),
        Fr::from_raw([
            0x2efed6e89247b6e9,
            0x7ec411e9491083ae,
            0x73c8e5f180a69a96,
            0x1e772e6b879ef435,
        ]),
    ];
    //== Circuit ==//
    let circuit = HashEncCircuit::<Fr, 5, 4> {
        spec: spec.clone(),
        num_input: MESSAGE_CAPACITY,
        message: inputs,
        hashed: hash_value,
        num_hash_input: HashEncCircuit::<Fr, 5, 4>::BITS_LEN
            / HashEncCircuit::<Fr, 5, 4>::LIMB_WIDTH,
        hash_input: h_inputs,
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
