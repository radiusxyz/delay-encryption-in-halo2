pub mod big_integer;
use big_integer::*;


pub mod poseidon;
use ff::Field;
use maingate::{MainGate, RangeChip, MainGateInstructions, RangeInstructions};
use poseidon::*;
pub mod rsa;
use rsa::*;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

//use halo2curves::pasta::Fp; // zeroknight : Should be changed to anything else

// In struct DelayEncCircuit : the trait `ff::PrimeField` cannot be made into an object
// `ff::PrimeField` cannot be made into an objectrustcClick for full compiler diagnostic
//use halo2curves::group::ff::PrimeField; // zeroknight - Primefield is a trait.
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Column, Advice, Instance, Circuit, Error};

use rsa::RSAConfig;

use std::marker::PhantomData;

// zeroknight : Curve-related.. sortof conflict : halo2_proofs vs halo2wrong
use halo2wrong::curves::pasta::Fp;
use halo2wrong::curves::FieldExt;
use halo2wrong::RegionCtx;

//=== by zeroknight
#[derive(Debug, Clone)]
struct DelayEncCircuit<F: FieldExt, S, const WIDTH: usize, const RATE: usize, const L: usize> 
where
    S: Spec_trait<Fp, WIDTH, RATE> + Clone + Copy,
{
    // RSA
    signature: RSASignature<F>,
    public_key: RSAPublicKey<F>,
    msg: Vec<u8>,

    // Poseidon Hash
    message: Value<[Fp; L]>,
    _spec: PhantomData<S>,
}

//
impl<F: FieldExt, S, const WIDTH: usize, const RATE: usize, const L: usize> DelayEncCircuit<F, S, WIDTH, RATE, L> 
    where 
    S: Spec_trait<Fp, WIDTH, RATE> + Clone + Copy,
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
struct DelayEncConfig< const WIDTH: usize, const RATE: usize, const L: usize>  {
    // RSA
    rsa_config : RSAConfig,

    // Poseidon
    input: [Column<Advice>; L],
    expected: Column<Instance>, // zeroknight : input - Advice, expected - Instance ??
    poseidon_config : Pow5Config<Fp, WIDTH, RATE>,
}

impl<F: FieldExt, S, const WIDTH: usize, const RATE: usize, const L:usize> Circuit<Fp> 
    for DelayEncCircuit<F, S, WIDTH, RATE, L>
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

    // zeroknight : setting up a table for Halo2
    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<Fp>) -> Self::Config {
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

        // ConstraintSystem.advice_column : Allocate a new advice column at "FirstPhase?"
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        // ConstraintSystem.instance_column : Allocate a new instance column
        let expected = meta.instance_column();
        // ConstraintSystem.enable_equality(-column-) : Enable the ability to enforce equality over cells in this column
        meta.enable_equality(expected); // which columns should be equaled?!

        let partial_sbox = meta.advice_column();

        // ConstraintSystem.fixed_column : Allocate a new fixed column
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        // ConstraintSystem.enable_constant : Enables this fixed column to be used for global constant assignments.
                                            // (Side-effects) The column will be equality-enabled.
        meta.enable_constant(rc_b[0]);

        // Config
        Self::Config {
            rsa_config,
            input: state[..RATE].try_into().unwrap(),   // try_into
            expected,
            poseidon_config: Pow5Chip::configure::<S>( // (meta, state, partial_sbox, rc_a, rc_b),
                meta,
                state.try_into().unwrap(),
                partial_sbox,
                rc_a.try_into().unwrap(),
                rc_b.try_into().unwrap(),
            ),
        }
    }

    // zeroknight : construct constraints. Assign values into cells in the table
    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), halo2_proofs::plonk::Error> {

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
        

        //poseidon_config => pow5config
        let chip = Pow5Chip::construct(config.poseidon_config.clone());

        // assign_region
        /*
            Assign a region of gates to an absolute row number.

            Inside the closure, the chip may freely use relative offsets; the Layouter will treat these assignments as a single "region" within the circuit. Outside this closure, the Layouter is allowed to optimise as it sees fit.

            fn assign_region(&mut self, || "region name", |region| {
                let config = chip.config();
                region.assign_advice(config.a, offset, || { Some(value)});
            });
        */
        let message = layouter.assign_region(
            || "load message", 
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.message.map(|message_vals| message_vals[i]);
                    region.assign_advice ( //(annotation, column, offset, to)
                        || format!("load message_{}", i),
                        config.input[i],
                        0,
                        || value,
                    )
                };

                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().unwrap())

            },
        )?;

        // Poseidon Hasher
        /*
        pub struct Hash<F, PoseidonChip, S, D, const T: usize, const RATE: usize>
            where
                F: Field,
                PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, RATE>,
                S: Spec<F, T, RATE>,
                D: Domain<F, RATE>,
            A Poseidon hash function, built around a sponge.
        */
        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init( //(chip, layouter)
            chip,
            layouter.namespace(|| "init"),
        )?;
        /*
        pub fn hash(self, layouter: impl Layouter<F>, message: [AssignedCell<F, F>; L]) -> Result<AssignedCell<F, F>, Error>
        => Hashes the given input.
         */
        let output = hasher.hash (  //(layouter, message)
            // Layouter.namespace : Enters into a namespace. -> return namespaced_Layouter
            layouter.namespace(|| "hash"),
            message
        )?;

        /*
        pub fn constrain_instance(&mut self, cell: Cell, column: Column<Instance>, row: usize) -> Result<(), Error>
        => Constrains a Cell to equal an instance column's row value at an absolute position. 
        */

        layouter.constrain_instance (   // (cell, column, row)
            output.cell(),
            config.expected,
            0
        )
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

    // zeroknight copied from halo2_gadget/benches/poseidon.rs/bench_poseidon
    // Initialize the proving key
    // Creat a proof
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
