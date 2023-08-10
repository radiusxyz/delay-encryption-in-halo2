pub mod big_integer;
use std::marker::PhantomData;

pub use big_integer::*;

pub mod rsa;
pub use rsa::*;

pub mod hash;
pub use hash::*;

use ff::PrimeField;
use num_bigint::BigUint;

use halo2wrong::halo2::{ 
    plonk::{Circuit, ConstraintSystem},
    circuit::SimpleFloorPlanner,
};

use maingate::{MainGate, RangeChip};

struct delay_enc_circuit<F: PrimeField> {
    n : BigUint,
    e : BigUint,
    x : BigUint,
    _f: PhantomData<F>
}

impl<F: PrimeField> delay_enc_circuit<F> {
    const BITS_LEN: usize = 2048;
    const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH; // 64
    const EXP_LIMB_BITS: usize = 5;
    const DEFAULT_E: u128 = 65537;

    fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
        RSAChip::new(config, Self::BITS_LEN, Self::EXP_LIMB_BITS)
    }
}

impl<F: PrimeField> Circuit<F> for delay_enc_circuit<F> {
    type Config = RSAConfig;
    type FloorPlanner = SimpleFloorPlanner;

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

        let bigint_config = BigIntConfig::new(range_config, main_gate_config);
        RSAConfig::new(bigint_config)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl halo2wrong::halo2::circuit::Layouter<F>) -> Result<(), halo2wrong::halo2::plonk::Error> {
        let rsa_chip = self.rsa_chip(config);
        let bigint_chip = rsa_chip.bigint_chip();

        Ok(())
    }
}