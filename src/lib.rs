pub mod big_integer;
use big_integer::*;


pub mod poseidon;
use ff::Field;
use poseidon::*;
pub mod rsa;
use rsa::*;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

use halo2curves::pasta::Fp; // zeroknight : Should be changed to anything else

// In struct DelayEncCircuit : the trait `ff::PrimeField` cannot be made into an object
// `ff::PrimeField` cannot be made into an objectrustcClick for full compiler diagnostic
//use halo2curves::group::ff::PrimeField; // zeroknight - Primefield is a trait.
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Column, Advice, Instance, Circuit};

use poseidon::gadget::primitives::{Spec as Spec_trait, Mds, generate_constants};
use poseidon::gadget::pow5::Pow5Config;

use rsa::RSAConfig;

use std::marker::PhantomData;

//=== by zeroknight
#[derive(Debug, Clone)]
struct DelayEncCircuit<S, const WIDTH: usize, const RATE: usize, const L: usize> 
where
    S: Spec_trait<Fp, WIDTH, RATE> + Clone + Copy,
{
    message: Value<[Fp; L]>,
    _spec: PhantomData<S>,
}

#[derive(Debug, Clone)]
struct DelayEncConfig< const WIDTH: usize, const RATE: usize, const L: usize>  {
    // RSA
    rsa_config : RSAConfig,

    // Poseidon
    input: [Column<Advice>; L],
    expected: Column<Instance>, // zeroknight : input - Advice, expected - Instance ??
    poseidon_config : Pow5Config<Fp, WIDTH, RATE>,
}

impl<S, const WIDTH: usize, const RATE: usize, const L:usize> Circuit<Fp> 
    for DelayEncCircuit<S, WIDTH, RATE, L>
where
    S: Spec_trait<Fp, WIDTH, RATE> + Clone + Copy,
{
    type Config = DelayEncConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            message : Value::unknown(),
            _spec : PhantomData,
        }
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<Fp>) -> Self::Config {
        todo!()
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), halo2_proofs::plonk::Error> {
        todo!()
    }



}

#[test]
fn test_delay_encryption() {

}

#[derive(Debug, Clone, Copy)]
struct MySpec<const WIDTH: usize, const RATE: usize>;

impl<const WIDTH: usize, const RATE: usize> Spec_trait<Fp, WIDTH, RATE> for MySpec<WIDTH, RATE> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        0
    }

    fn constants() -> (Vec<[Fp; WIDTH]>, Mds<Fp, WIDTH>, Mds<Fp, WIDTH>) {
        generate_constants::<_, Self, WIDTH, RATE>()
    }
}


fn bench_delayencryption<S, const WIDTH: usize, const RATE: usize, const L: usize>(
    name: &str
) where 
    S: Spec_trait<Fp, WIDTH, RATE> + Copy + Clone,
{
    use halo2_proofs::poly::ipa::commitment::ParamsIPA;
    use halo2curves::pasta::vesta;
    use halo2_proofs::poly::commitment::ParamsProver;

    const K : u32 = 7;

    // Initialize the polynomial commitment parameters
    let params: ParamsIPA<vesta::Affine> = ParamsIPA::new(K);   // poly::commitment::ParamsProver

    let empty_circuit = DelayEncCircuit::<S, WIDTH, RATE, L> {
        message: Value::unknown(),
        _spec: PhantomData,
    };
}




//===




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
