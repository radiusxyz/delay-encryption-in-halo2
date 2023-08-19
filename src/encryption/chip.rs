use std::marker::PhantomData;

use ff::{PrimeField, FromUniformBytes};
use halo2wrong::RegionCtx;
use maingate::{MainGateConfig, decompose_big};
use num_bigint::BigUint;
use poseidon::Spec;

use halo2wrong::halo2::plonk::Error;

use crate::{RSAConfig, RSAChip, hasher::HasherChip, AssignedInteger, Fresh, AssignedRSAPublicKey, UnassignedInteger, RSAPubE, RSAPublicKey, RSAInstructions, BigIntInstructions, big_pow_mod};

use super::{PoseidonCipherInstructions, poseidon::{CIPHER_SIZE, PoseidonCipherKey}};


#[derive(Clone, Debug)]
pub struct PoseidonCipherConfig {
    rsa_config: RSAConfig,
    main_gate_config: MainGateConfig,
    r_f: usize,
    r_p: usize,
}

impl PoseidonCipherConfig {
    pub fn new(rsa_config: RSAConfig, main_gate_config: MainGateConfig, r_f: usize, r_p: usize) -> Self {
        Self {rsa_config, main_gate_config, r_f, r_p}
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
    config: PoseidonCipherConfig,
    spec: Spec<F, T, RATE>,
    _data: PhantomData<F>, 

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

    // create a new PoseidonCipherChip from the configuration and parameters
    // Arguments
    // config - a configuration for PoseidonCipherChip
    // ??!! 
    fn new(config: PoseidonCipherConfig) -> Self {
        let spec = Spec::<F, T, RATE>::new(config.r_f, config.r_p);
        PoseidonCipherChip {
            config,
            spec,
            _data: PhantomData,
        }
    }

    // Getter for RSAChip
    pub fn rsa_chip(&self) -> RSAChip<F> {
        // RSAChip - new()
            // config - a configuration for [RSAChip].
            // bits_len - the default bit length of [Fresh] type integers in this chip.
            // exp_limb_bits - the width of each limb when the exponent is decomposed.
        RSAChip::<F>::new(
            self.config.rsa_config.clone(), 
            BITS_LEN_RSA, 
            EXP_LIMB_BITS_RSA,
        )
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
        //let e_fix = RSAPubE::<F>::Fix(BigUint::from(Self::DEFAULT_E));

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

        let valid_powed_var = big_pow_mod(&x, &e, &e);
        //let valid_powed_fix = big_pow_mod(&x, &BigUint::from(Self::DEFAULT_E), &n);

        let valid_powed_var = bigint_chip.assign_constant_fresh(ctx, valid_powed_var)?;
        //let valid_powed_fix = bigint_chip.assign_constant_fresh(ctx, valid_powed_fix)?;

        bigint_chip.assert_equal_fresh(ctx, &powed_var, &valid_powed_var)?;
        //bigint_chip.assert_equal_fresh(ctx, &powed_fix, &valid_powed_fix)?;

        Ok(valid_powed_var) // zeroknight - mean anything?!
    }

    fn encrypt_message(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        key: &PoseidonCipherKey<F>, 
        message: &[F],                      // zeroknight - todo : wrap as a specific type
    ) -> Result<[F; CIPHER_SIZE ], Error> {

        let mut hasher_chip = HasherChip::<F, NUMBER_OF_LIMBS_HASH, BITS_LEN_HASH, T, RATE>::new(
            ctx,
            &self.spec,
            &self.config.main_gate_config
        )?;

        unimplemented!()
    }
}