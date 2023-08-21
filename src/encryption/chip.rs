use std::marker::PhantomData;

use ff::{PrimeField, FromUniformBytes};

use halo2wrong::{halo2::{ 
    plonk::{Circuit, ConstraintSystem},
    circuit::{SimpleFloorPlanner, Layouter, Chip},
}, RegionCtx, curves::{CurveAffine, bn256::{self, G1Affine}}};

use maingate::{MainGateConfig, decompose_big, MainGateInstructions, MainGate, RangeChip, mock_prover_verify, RangeInstructions};
use num_bigint::{BigUint, RandomBits};
use poseidon::Spec;

use halo2wrong::halo2::plonk::Error;
use rand_core::OsRng;
//use proptest::bits::usize;

use crate::{RSAConfig, RSAChip, hasher::HasherChip, AssignedInteger, Fresh, AssignedRSAPublicKey, UnassignedInteger, RSAPubE, RSAPublicKey, RSAInstructions, BigIntInstructions, big_pow_mod, encryption::poseidon::{PoseidonCipher, MESSAGE_CAPACITY}, BigIntConfig};

use super::{PoseidonCipherInstructions, poseidon::{CIPHER_SIZE, PoseidonCipherKey}};

use halo2wrong::halo2::circuit::Value;


#[derive(Clone, Debug)]
pub struct PoseidonCipherConfig {
    pub rsa_config: RSAConfig,
    pub main_gate_config: MainGateConfig,
}

impl PoseidonCipherConfig {
    pub fn new(rsa_config: RSAConfig, main_gate_config: MainGateConfig) -> Self {
        Self {rsa_config, main_gate_config }
    }
}

pub struct PoseidonCipherChip<
    F: PrimeField + FromUniformBytes<64> ,
    const BITS_LEN_RSA: usize,          // 2048 (in zeroknight's testing)
    const EXP_LIMB_BITS_RSA: usize,     // 5 
    const NUMBER_OF_LIMBS_HASH: usize,  // 4
    const BITS_LEN_HASH: usize,         // 68
    const T: usize, 
    const RATE: usize,
> {
    // Chip configuration
    /*  // zeroknight 0821
    config: PoseidonCipherConfig,
    spec: Spec<F, T, RATE>,
    n_hash: usize,
    _data: PhantomData<F>, 
    */

    // Chip
    rsa_chip: RSAChip<F>,
    hasher_chip: HasherChip<F, NUMBER_OF_LIMBS_HASH, BITS_LEN_HASH, T, RATE>,

}

impl<    
    F: PrimeField + FromUniformBytes<64> ,
    const BITS_LEN_RSA: usize,          
    const EXP_LIMB_BITS_RSA: usize,      
    const NUMBER_OF_LIMBS_HASH: usize,  
    const BITS_LEN_HASH: usize,         
    const T: usize,
    const RATE: usize
> PoseidonCipherChip<F, BITS_LEN_RSA, EXP_LIMB_BITS_RSA, NUMBER_OF_LIMBS_HASH, BITS_LEN_HASH, T, RATE> {

    // Constant value for RSAchip
        // pub const BITS_LEN: usize = 2048;
        // pub const EXP_LIMB_BITS: usize = 5;
    // Constant value for Poseidon Hash chip
    const DEFAULT_E: u128 = 65537;
    const LIMB_WIDTH_RSA: usize = RSAChip::<F>::LIMB_WIDTH; // 64
    const R_F : usize = 8;
    const R_P : usize = 57;

    // create a new PoseidonCipherChip from the configuration and parameters
    // Arguments
    // config - a configuration for PoseidonCipherChip
    // ??!! 
    pub fn new(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        rsa_chip: RSAChip<F>,
    ) -> Result<Self, Error> {
        let main_gate = rsa_chip.main_gate();
        let main_gate_config = main_gate.config();

        let hasher_chip = HasherChip::new(ctx, spec, main_gate_config)?;
        Ok(Self { rsa_chip: rsa_chip, hasher_chip})
    }
    /*
    fn new(config: PoseidonCipherConfig, n_hash: usize) -> Self {
        let spec = Spec::<F, T, RATE>::new(config.r_f, config.r_p);
        PoseidonCipherChip {
            config,
            spec,
            n_hash,
            _data: PhantomData,
        }
    }
    */

    // Getter for RSAChip
    pub fn rsa_chip(&self) -> &RSAChip<F> {
        // RSAChip - new()
            // config - a configuration for [RSAChip].
            // bits_len - the default bit length of [Fresh] type integers in this chip.
            // exp_limb_bits - the width of each limb when the exponent is decomposed.
/*        
        RSAChip::<F>::new(
            self.config.rsa_config.clone(), 
            BITS_LEN_RSA, 
            EXP_LIMB_BITS_RSA,
        )
*/
        &self.rsa_chip
    }

    pub fn poseidonhash_chip(&self, 
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> HasherChip<F, NUMBER_OF_LIMBS_HASH, BITS_LEN_HASH, T, RATE> {
        // 
        HasherChip::<F, NUMBER_OF_LIMBS_HASH, BITS_LEN_HASH, T, RATE>::new( // ctx, spec, main_gate_config)
            ctx,
            spec,
            main_gate_config,
        ).unwrap()
    }

}

impl<
    F: PrimeField + FromUniformBytes<64> ,
    const BITS_LEN_RSA: usize,          
    const EXP_LIMB_BITS_RSA: usize,      
    const NUMBER_OF_LIMBS_HASH: usize,  
    const BITS_LEN_HASH: usize,         
    const T: usize,
    const RATE: usize
>  PoseidonCipherInstructions<F> for PoseidonCipherChip<F, BITS_LEN_RSA, EXP_LIMB_BITS_RSA, NUMBER_OF_LIMBS_HASH, BITS_LEN_HASH, T, RATE>{

    fn calculate_cipher_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: BigUint,
        e: BigUint,
        n: BigUint,
    ) -> Result<AssignedInteger<F, Fresh>, Error> {

        // zeroknight - commented out things with 'fix' 
            // todo : figure out What 'fix' does 

        let rsa_chip = self.rsa_chip(); 
        let bigint_chip = rsa_chip.bigint_chip();

        let num_limbs = BITS_LEN_RSA / Self::LIMB_WIDTH_RSA;

        // exponent - e
        let e_limbs = decompose_big::<F>   //(e, number_of_limbs, bit_len)
            (e.clone(), 1, EXP_LIMB_BITS_RSA);
        let e_unassigned = UnassignedInteger::from(e_limbs);
        let e_var = RSAPubE::Var(e_unassigned);
        // let e_fix = RSAPubE::<F>::Fix(BigUint::from(Self::DEFAULT_E));

        // modulous - n
        let n_limbs = decompose_big::<F> //(e, number_of_limbs, bit_len)
            (n.clone(), num_limbs, Self::LIMB_WIDTH_RSA);
        let n_unassigned = UnassignedInteger::from(n_limbs);

        // public key - e,n
        let public_key_var = RSAPublicKey::new(n_unassigned.clone(), e_var);
        let public_key_var = rsa_chip.assign_public_key(ctx, public_key_var)?;
        // let public_key_fix = RSAPublicKey::new(n_unassigned, e_fix);
        // let public_key_fix = rsa_chip.assign_public_key(ctx, public_key_fix)?;

        // x - base
        let x_limbs = decompose_big::<F>
            (x.clone(), num_limbs, Self::LIMB_WIDTH_RSA);
        let x_unassigned = UnassignedInteger::from(x_limbs);

        let x_assigned = bigint_chip.assign_integer(ctx, x_unassigned)?;
        // Given a base x, a RSA public key (e,n), performs the modular power x^e mod n
        let powed_var = rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_var)?;
        // let powed_fix = rsa_chip.modpow_public_key(ctx, &x_assigned, &public_key_fix)?;

        let valid_powed_var = big_pow_mod(&x, &e, &n);
        // let valid_powed_fix = big_pow_mod(&x, &BigUint::from(Self::DEFAULT_E), &n);

        let valid_powed_var = bigint_chip.assign_constant_fresh(ctx, valid_powed_var)?;
        // let valid_powed_fix = bigint_chip.assign_constant_fresh(ctx, valid_powed_fix)?;

        bigint_chip.assert_equal_fresh(ctx, &powed_var, &valid_powed_var)?;
        // bigint_chip.assert_equal_fresh(ctx, &powed_fix, &valid_powed_fix)?;

        Ok(valid_powed_var) // zeroknight - mean anything?!
    }
/*
    fn initial_state(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        key: &PoseidonCipherKey<F>,
        nonce: F,
    ) -> Result<Vec<F>, Error> {
        /* [
            // Domain - Maximum plaintext length of the elements of Fq, as defined
            F::from_u128(0x100000000 as u128),
            F::from_u128(MESSAGE_CAPACITY as u128),
            self.cipherKey.key0,
            self.cipherKey.key1,
            nonce,
        ] */
        vec![

        ]
    }
*/
    fn encrypt_message(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        n_hash: usize, 
        key: &PoseidonCipherKey<F>, 
        nonce: F,
        message: &Vec<F>,                      // zeroknight - todo : wrap as a specific type
    ) -> Result<Vec<F>, Error> {

        let spec = Spec::<F, T, RATE>::new(Self::R_F, Self::R_P);
        let main_gate = self.hasher_chip.main_gate();
        let main_gate_config = main_gate.config();
        
        let mut hasher_chip = HasherChip::<F, NUMBER_OF_LIMBS_HASH, BITS_LEN_HASH, T, RATE>::new(
            ctx,
            &spec,
            &main_gate_config,
        )?;
        let mut main_gate = hasher_chip.main_gate();

        // initial state
        // fn initial_state(key: &PoseidonCipherKey<F>, nonce: F) -> [F; 5]
        let mut state = PoseidonCipher::<F, 8, 57, T, RATE>::initial_state(key, nonce);
        let mut state_cells = vec![];
        for e in state {
            let e = main_gate.assign_value(ctx, Value::known(e))?;
            state_cells.push(e.clone());
            hasher_chip.update(&[e.clone()]);
        }

        // permutation on inputs
        let mut message_cells = vec![];
        let inputs = Value::known(message.clone());
        for e in inputs.as_ref().transpose_vec(n_hash) {
            let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
            message_cells.push(e.clone());
            hasher_chip.update(&[e.clone()]);
        }

        (0..MESSAGE_CAPACITY).for_each(|i|{

            if i < message.len() {
                // state[i+1] += message[i]
                state_cells[i+1] = main_gate.add(ctx, &state_cells[i+1], &message_cells[i]).unwrap();
            } else {
                // state[i+1] += F::ZERO
            }

            // cipher[i] = state[i+1];

        });

        // hasher.update(&state);

        // cipher[MESSAGE_CAPACITY] = state[1];



        /*
        // Poseidon Hash on inputs
        let inputs = Value::known(message.clone());
        for e in inputs.as_ref().transpose_vec(self.n_hash) {
            let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
            hasher_chip.update(&[e.clone()]);
        }
        */

        unimplemented!()
    }
}

//============//


// Poseidon Constants
const NUMBER_OF_LIMBS_HASH: usize = 4;
const BIT_LEN_LIMB_HASH: usize = 68;
const BITS_LEN_RSA: usize = 2048;
const LIMB_WIDTH_RSA: usize = 64;
const EXP_LIMB_BITS: usize = 5;

#[derive(Clone)]
struct PoseidonCipherCircuitConfig{
    poseidonCipherConfig : PoseidonCipherConfig,
}

struct PoseidonCipherCircuit<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> {
     // RSA time lock puzzle : secret = x^e mod n
     n : BigUint,
     e : BigUint,
     x : BigUint,        // base integer
 
     // Poseidon
     spec: Spec<F, T, RATE>,    // Spec for Poseidon Hash 
     n_hash: usize,             // zeroknight - ??
     message: Value<Vec<F>>,    // message to be encrypted
     cipher: Value<Vec<F>>,     // cipher text from the message
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> PoseidonCipherCircuit<F, T, RATE> {

    const BITS_LEN_RSA: usize = 2048;
    const LIMB_WIDTH_RSA: usize = RSAChip::<F>::LIMB_WIDTH; // 64
    const EXP_LIMB_BITS_RSA: usize = 5;
    const DEFAULT_E: u128 = 65537;

    fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
        RSAChip::new(config, Self::BITS_LEN_RSA, Self::EXP_LIMB_BITS_RSA)
    }

}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for PoseidonCipherCircuit<F, T, RATE> {

    type Config = PoseidonCipherCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        /*
        pub struct PoseidonCipherConfig {
            rsa_config: RSAConfig,
            main_gate_config: MainGateConfig,
        }
        */
        // configurate for RSA chip 
        let main_gate_config = MainGate::<F>::configure(meta);
        let (composition_bit_lens, overflow_bit_lens) =
                RSAChip::<F>::compute_range_lens(Self::BITS_LEN_RSA / Self::LIMB_WIDTH_RSA);
        let range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );
        let bigint_config = BigIntConfig::new(range_config, main_gate_config.clone());
        let rsa_config = RSAConfig::new(bigint_config);


        let poseidonCipherConfig = PoseidonCipherConfig::new(rsa_config, main_gate_config);

        PoseidonCipherCircuitConfig {
            poseidonCipherConfig
        }        
        
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut main_gate = MainGate::<F>::new(config.poseidonCipherConfig.main_gate_config.clone());
        let rsa_chip = self.rsa_chip(config.poseidonCipherConfig.rsa_config.clone());


        // zeroknight - from DK
        rsa_chip.bigint_chip().range_chip().load_table(&mut layouter)?;

        let x = self.x.clone();

        layouter.assign_region(
            || "poseidon cipher", 
        |region| {

            let offset = 0;
            let ctx = &mut RegionCtx::new(region, offset);
/*
halo2_delay_enc::encryption::chip
pub struct PoseidonCipherChip<F, 
    const BITS_LEN_RSA: usize, 
    const EXP_LIMB_BITS_RSA: usize, 
    const NUMBER_OF_LIMBS_HASH: usize, 
    const BITS_LEN_HASH: usize, 
    const T: usize, const RATE: usize>
*/
            let poseidon_cipher_chip = PoseidonCipherChip::<F,BITS_LEN_RSA, EXP_LIMB_BITS, NUMBER_OF_LIMBS_HASH, BIT_LEN_LIMB_HASH, T, RATE>
                ::new(ctx, &self.spec, rsa_chip.clone())?;
            let secret = poseidon_cipher_chip.calculate_cipher_key(ctx, self.x.clone(), self.e.clone(), self.n.clone())?;

            let temp = secret.to_big_uint(LIMB_WIDTH_RSA).map(|e| e);

/* // zeroknight : 먼저 위 calculate_cipher_key 테스트!!!

            let key = PoseidonCipherKey::<F>{
                key0: F::random(OsRng), // zeroknight : should be derived from 'secret'
                key1: F::random(OsRng),
            };
            let nonce = F::random(OsRng);
            let message = vec![F::random(OsRng);2];
            poseidon_cipher_chip.encrypt_message(ctx, self.n_hash, &key, nonce, &message);
*/
            Ok(())
        })?;
        Ok(())
    }
}


#[test]
fn test_poseidon_encryption() {

    use rand::{thread_rng, Rng};
    use halo2wrong::halo2::dev::MockProver;

    fn run<F: PrimeField + FromUniformBytes<64> + Ord, const T: usize, const RATE: usize>() {
        let mut rng = thread_rng();
        let bits_len = PoseidonCipherCircuit::<F, T, RATE>::BITS_LEN_RSA as u64;

        let mut n = BigUint::default();
        while n.bits() != bits_len {
            n = rng.sample(RandomBits::new(bits_len));
        }

        let e = rng.sample::<BigUint, _>(RandomBits::new( PoseidonCipherCircuit::<F, T, RATE>::EXP_LIMB_BITS_RSA as u64)) % &n;
        let x = rng.sample::<BigUint,_>(RandomBits::new(bits_len)) % &n;


/*
struct PoseidonCipherCircuit<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> {
     // RSA time lock puzzle : secret = x^e mod n
     n : BigUint,
     e : BigUint,
     x : BigUint,        // base integer
 
     // Poseidon
     spec: Spec<F, T, RATE>,    // Spec for Poseidon Hash 
     n_hash: usize,             // zeroknight - ??
     message: Value<Vec<F>>,    // message to be encrypted
     cipher: Value<Vec<F>>,     // cipher text from the message
}
*/
        let spec = Spec::<F, T, RATE>::new(8, 57);
        let n_hash = 2;

        let circuit = PoseidonCipherCircuit::<F, T, RATE> {
            // RSA timelock puzzle
            n,
            e,
            x,
            // Poseidon Hash
            spec,
            n_hash,
            message : Value::known(vec![]),
            cipher : Value::known(vec![]),
        };

        let public_inputs = vec![vec![]];
        mock_prover_verify(&circuit, public_inputs);

    }

    use halo2wrong::curves::bn256::Fr as BnFr;
    run::<BnFr, 5, 4>();

}
