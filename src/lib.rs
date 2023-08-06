pub mod big_integer;
use big_integer::*;


pub mod hash;

use ff::{Field, PrimeField};
use halo2_gadgets::utilities::RangeConstrained;
use hash::*;
pub mod rsa;
use hash::gadget::transcript::LimbRepresentation;
use rsa::*;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

//use halo2curves::pasta::Fp; // zeroknight : Should be changed to anything else

// In struct DelayEncCircuit : the trait `ff::PrimeField` cannot be made into an object
// `ff::PrimeField` cannot be made into an objectrustcClick for full compiler diagnostic
//use halo2curves::group::ff::PrimeField; // zeroknight - Primefield is a trait.
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Column, Advice, Instance, Circuit, Error, ConstraintSystem};

use rsa::RSAConfig;

use std::marker::PhantomData;

// zeroknight : Curve-related.. sortof conflict : halo2_proofs vs halo2wrong
use halo2wrong::curves::pasta::Fp;
use halo2wrong::curves::FieldExt;
use halo2wrong::RegionCtx;

use maingate::{MainGate, RangeChip, MainGateInstructions, RangeInstructions, MainGateConfig, RangeConfig};

// This trait is the affine counterpart to Curve and is used for serialization, storage in memory, and inspection of $x$ and $y$ coordinates.
use halo2_proofs::arithmetic::CurveAffine;

use hash::spec::Spec;

use ecc::{EccConfig, BaseFieldEccChip};
use ecc::integer::rns::Rns;

use crate::hash::gadget::transcript::TranscriptChip;

const NUMBER_OF_LIMBS: usize = 4;
const BIT_LEN_LIMB: usize = 68;

//=== by zeroknight
 // halo2wrong::curves::FieldExt : This trait is a common interface for dealing with elements of a finite field.
#[derive(Debug, Clone)]
struct DelayEncCircuit<F: FieldExt, C: CurveAffine, const T: usize, const RATE: usize> 
{
    // RSA
    signature: RSASignature<F>,
    public_key: RSAPublicKey<F>,
    msg: Vec<u8>,

    // Poseidon Hash
        // Spec holds construction parameters as well as constants that are used in permutation step. 
            // Constants are planned to be hardcoded once transcript design matures. Number of partial rounds can be deriven from number of constants.
        // type Scalar: PrimeField;
    spec: Spec<C::Scalar, T, RATE>,
    n : usize,
    inputs: Value<Vec<C::Scalar>>,
    expected: Value<C::Scalar>,

}

//
impl<F: FieldExt, C: CurveAffine, const T: usize, const RATE: usize> DelayEncCircuit<F, C, T, RATE>
{
    const BITS_LEN: usize = 2048;
    const LIMB_WIDTH: usize = RSAChip::<F>::LIMB_WIDTH;
    const EXP_LIMB_BITS: usize = 5;

    //
    fn rsa_chip(&self, config: RSAConfig) -> RSAChip<F> {
        // Create a new RSAChip from the configuration and parameters.
        RSAChip::new(config, Self::BITS_LEN, Self::EXP_LIMB_BITS)
    }
}


#[derive(Debug, Clone)]
struct DelayEncConfig{
    // RSA
    rsa_config : RSAConfig,

    // Poseidon Hash
    main_gate_config : MainGateConfig,
    range_config : RangeConfig,

}

impl DelayEncConfig {

    // Config for Ecc Chip
    fn ecc_chip_config(&self) -> EccConfig {
        // Returns new EccConfig given RangeConfig and MainGateConfig
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    // halo2_proofs::plonk::circuit::ConstraintSystem<F> (F: Field)
        // This is a description of the circuit environment, such as the gate, column and permutation arrangements
    fn new<C: CurveAffine>(meta: &mut ConstraintSystem<C::Scalar>, rsa_config: RSAConfig) -> Self {
        // Residue Numeral System Representation of an integer holding its values modulo several coprime integers.
        //Contains all the necessary values to carry out operations such as multiplication and reduction in this representation.
        let rns = Rns::<C::Base, C::Scalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct();

        let main_gate_config = MainGate::<C::Scalar>::configure(meta);
        let overflow_bit_lens = rns.overflow_lengths(); //--
        let composition_bit_lens = vec![BIT_LEN_LIMB/NUMBER_OF_LIMBS];

        let range_config = RangeChip::<C::Scalar>::configure ( // (meta, main_gate_config, composition_bit_lens, overflow_bit_lens)
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        DelayEncConfig { 
            rsa_config: rsa_config,
            main_gate_config: main_gate_config, 
            range_config: range_config,
        }
    }

    fn config_range<N: PrimeField> (
        &self,
        layouter: &mut impl Layouter<N>,
    ) -> Result<(), Error> {
        let range_chip = RangeChip::<N>::new(self.range_config.clone());
        range_chip.load_table(layouter)?;

        Ok(())
    }

}


// impl<F: FieldExt, C: CurveAffine, const T: usize, const RATE: usize> DelayEncCircuit<F, C, T, RATE>
impl<F: FieldExt, C: CurveAffine, const T: usize, const RATE: usize> Circuit<C::Scalar> 
    for DelayEncCircuit<F, C, T, RATE>
{
    type Config = DelayEncConfig;
    type FloorPlanner = SimpleFloorPlanner;

    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        //-- 
        unimplemented!();
    }
/*
    // zeroknight : setting up a table for Halo2
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // configure 'RSAConfig' : BigIntConfig (Rangeconfig and Maingate needed)
        let main_gate_config = MainGate::<Fp>::configure(meta);
        // Compute bit length parameters by calling 'RSAChip::<F>::compute_range_lens' function
        let (composition_bit_lens, overflow_bit_lens) = 
            RSAChip::<Fp>::compute_range_lens(Self::BITS_LEN / Self::LIMB_WIDTH) ; // num_limbs = BITS_LEN / LIMB_WIDTH
        // configure RangeChip and RangeConfig : Configures subset argument and returns the resuiting config
        let range_config = RangeChip::<Fp>::configure (   // (meta, main_gate_config, composition_bit_lens, overflow_bit_lens)
            meta, 
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        // configure BigIntConfig : Creates new BigIntConfig from RangeConfig and MainGateConfig
        let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
        // configure RSAConfig : Creates new RSAConfig from BigIntConfig.
        let rsa_config = RSAConfig::new(bigint_config);

        //== Poseidon Hash ==//
    }
*/
    // zeroknight : setting up a table for Halo2
    fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
        // configure 'RSAConfig' : BigIntConfig (Rangeconfig and Maingate needed)
        let main_gate_config = MainGate::<C::Scalar>::configure(meta);
        // Compute bit length parameters by calling 'RSAChip::<F>::compute_range_lens' function
        let (composition_bit_lens, overflow_bit_lens) = 
            RSAChip::<Fp>::compute_range_lens(Self::BITS_LEN / Self::LIMB_WIDTH) ; // num_limbs = BITS_LEN / LIMB_WIDTH
        // configure RangeChip and RangeConfig : Configures subset argument and returns the resuiting config
        let range_config = RangeChip::<C::Scalar>::configure (   // (meta, main_gate_config, composition_bit_lens, overflow_bit_lens)
            meta, 
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        // configure BigIntConfig : Creates new BigIntConfig from RangeConfig and MainGateConfig
        let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
        // configure RSAConfig : Creates new RSAConfig from BigIntConfig.
        let rsa_config = RSAConfig::new(bigint_config);

        //== Poseidon Hash ==//
        let config = DelayEncConfig::new::<C>(meta, rsa_config);
        config
    }

    // zeroknight : construct constraints. Assign values into cells in the table
    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<C::Scalar>) -> Result<(), halo2_proofs::plonk::Error> {  // zeroknight - use C::Scalar instead of Fp

        // RSA Chip!!
        let rsa_chip = self.rsa_chip(config.rsa_config);
        let bigint_chip = rsa_chip.bigint_chip();
        let main_gate = rsa_chip.main_gate();

        // random e
        // private key : d = e^(-1) mod phi(N)
            // phi(N) = (p-1)(q-1)
        // public key : (e, N)
        // signing (Signature) : S (= M^d mod N)
        // verifying : S^e mod N = M' , is M' equal M??

        // assign a public key and signature
        let (public_key, signature) = layouter.assign_region ( // (name, assignment)
            || "rsa signature with hash test using 2048 bits public keys",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let sign = rsa_chip.assign_signature(ctx, self.signature.clone())?;
                let public_key = rsa_chip.assign_public_key(ctx, self.public_key.clone())?;
                Ok((public_key, sign))
            },
        );

        // Create a RSA signature verifier from 'RSAChip'
            // this verifier does (S^e mod N = M')
            // in DelayEncryption <M'> is encryption key and <e> is delay-parameter
        let verifier = RSASignatureVerifier::new(rsa_chip);
        // Receive the verification result and the resulting hash of 'self.msg' from Verifier
        /* 
            pub fn verify_pkcs1v15_signature(
                &self,
                mut layouter: impl Layouter<F>,
                public_key: &AssignedRSAPublicKey<F>,
                msg: &[u8],
                signature: &AssignedRSASignature<F>,
            ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
        */
        let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature ( // (layouter, public_key, msg, signature)
            layouter.namespace(|| "verify pkcs1v15 signature"), // namespace : Enters into a namespace.
            &public_key,
            &self.msg,
            &signature,
        )?;

        // Expose the RSA public key as public input
        /*
        pub struct AssignedRSAPublicKey<F: FieldExt> {
            /// a modulus parameter
            pub n: AssignedInteger<F, Fresh>,
            /// an exponent parameter
            pub e: AssignedRSAPubE<F>,
        }
         */
        for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
            // zeroknight : why main_gate?
            // expose_public : Expect an assigned value to be equal to a public input
                // layouter.constrain_instance
                    // => Constrains a Cell to equal an instance column's row value at an absolute position.
            main_gate.expose_public ( // (layouter, value, row)
                layouter.namespace(|| format!("expose {}th public key limb", i)),
                limb.assigned_val(),
                i,
            )?;
        }

        // Expose the resulting hash as public input
        let num_limb_n = Self::BITS_LEN / RSAChip::<F>::LIMB_WIDTH;
        for (i, val) in hashed_msg.into_iter().enumerate() {
            main_gate.expose_public ( // (layouter, value, row)
                layouter.namespace(|| format!("expose {}th hashed msg limb",i )),
                val,
                num_limb_n + i,
            )?;
        }

        // zeroknight - this part is not needed here
            // the verification result must be one.
            /*
            Assign a region of gates to an absolute row number.

            Inside the closure, the chip may freely use relative offsets; the Layouter will treat these assignments as a single "region" within the circuit. Outside this closure, the Layouter is allowed to optimise as it sees fit.

            fn assign_region(&mut self, || "region name", |region| {
                let config = chip.config();
                region.assign_advice(config.a, offset, || { Some(value)});
            });
             */
        layouter.assign_region(
            || "assert is_valid == 1",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                main_gate.assert_one(ctx, &is_valid)?;
                Ok(())
            },
        )?;

        // Create lookup tables for range check in 'range_chip'
        let range_chip = bigint_chip.range_chip();
        range_chip.load_table(&mut layouter)?;  // zeroknight : ??? : Load table in sythnesis time
        

        //poseidon_config
        let main_gate = MainGate::<C::Scalar>::new(config.main_gate_config.clone());
        let ecc_chip_config = config.ecc_chip_config();
        // BaseFieldEccChip : Constaints elliptic curve operations such as assigment, addition and
            /// multiplication. Elliptic curves constrained here is the same curve in the
            /// proof system where base field is the non native field.
        let ecc_chip = BaseFieldEccChip::<C, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);

        layouter.assign_region(
            || "region 0", 
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                // delay_encryption_in_halo2::hash::gadget::transcript::TranscriptChip
                    // pub fn new(ctx: &mut RegionCtx<'_, N>, spec: &Spec<N, T, RATE>, ecc_chip: BaseFieldEccChip<C, NUMBER_OF_LIMBS, BIT_LEN>, _point_repr: E) -> Result<Self, Error>

                let mut transcript_chip = 
                    TranscriptChip::<_, _, _, NUMBER_OF_LIMBS, BIT_LEN_LIMB, T, RATE>::new(
                        ctx,
                        &self.spec,
                        ecc_chip.clone(),
                        LimbRepresentation::default(),
                    )?;
                // input : Value<Vec<C::Scalar>>
                for e in self.inputs.as_ref().transpose_vec(self.n) {
                    let e = main_gate.assign_value(ctx, e.map(|e| *e))?;
                    transcript_chip.write_scalar(&e);
                }

                let challenge = transcript_chip.squeeze(ctx)?;
                let expected = main_gate.assign_value(ctx, self.expected)?;
                main_gate.assert_equal(ctx, &challenge, &expected)?;

                Ok(())
            }
        )?;

        config.config_range(&mut layouter)?;


        Ok(())
    }



}

#[test]
fn test_delay_encryption() {

}

/*
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

    // zeroknight copied from halo2_gadget/benches/poseidon.rs/bench_poseidon
    // Initialize the proving key
    // Creat a proof
}
*/




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
