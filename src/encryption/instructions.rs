use ff::PrimeField;
use halo2wrong::halo2::{arithmetic::Field, plonk::Error};
use maingate::{AssignedValue, RegionCtx};
use num_bigint::BigUint;
use crate::{AssignedInteger, Fresh, AssignedRSAPublicKey};

use super::poseidon::{PoseidonCipherKey, CIPHER_SIZE};

// Instructions for Poseidon Cipher operations 
pub trait PoseidonCipherInstructions<F: PrimeField> {
    // Given a base 'x', a exponent 'e' and modular 'n', calculate a cipher key
    fn calculate_cipher_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        x: BigUint,
        e: BigUint,
        n: BigUint,
    ) -> Result<AssignedInteger<F, Fresh>, Error>;

    // Given a cipher key and a message, calculate a cipher text using poseidon encryption
    fn encrypt_message(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        key: &PoseidonCipherKey<F>, 
        message: &[F],                      // zeroknight - todo : wrap as a specific type
    ) -> Result<[F; CIPHER_SIZE ], Error>;
}