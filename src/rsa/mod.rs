//! This library provides a RSA verification circuit compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).
//!
//! A chip in this library, [`RSAChip`], defines constraints for verifying the RSA relations, specifically modular power `x^e mod n` and [pkcs1v15 signature](https://www.rfc-editor.org/rfc/rfc3447) verification.
//! Its circuit configuration differs depending on whether the exponent parameter `e` of the RSA public key is variable or fixed.
//! For example, since `e` is often fixed to `65537` in the case of pkcs1v15 signature verification, defining `e` as a fixed parameter [`RSAPubE::Fix`] can optimize the number of constraints.
//!
//! In addition to [`RSAChip`], this library also provides a high-level circuit implementation to verify pkcs1v15 signatures, [`RSASignatureVerifier`].  
//! The verification function in [`RSAChip`] requires as input a hashed message, whereas the function in [`RSASignatureVerifier`] computes a SHA256 hash of the given message and verifies the given signature for that hash.

//-- unnecessary lines commented out by zeroknight with "//--"
use crate::big_integer::*;

mod chip;
mod instructions;
pub use chip::*;
// zeroknight - FieldExt has been removed
//use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value, plonk::Error};
use halo2wrong::halo2::{circuit::Value, plonk::Error};
use halo2_proofs::arithmetic::CurveAffine;

pub use instructions::*;
use maingate::{
    big_to_fe, decompose_big, fe_to_big, AssignedValue, MainGate, MainGateConfig,
    MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
};
use num_bigint::BigUint;

/// A parameter `e` in the RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub enum RSAPubE<C: CurveAffine> { // zeroknight : CurveAffine instead of F: FieldExt
    /// A variable parameter `e`.
    Var(UnassignedInteger<C>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// A parameter `e` in the assigned RSA public key.
#[derive(Clone, Debug)]
pub enum AssignedRSAPubE<C: CurveAffine> {
    /// A variable parameter `e`.
    Var(AssignedInteger<C, Fresh>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSAPublicKey<C: CurveAffine> {
    /// a modulus parameter
    pub n: UnassignedInteger<C>,
    /// an exponent parameter
    pub e: RSAPubE<C>,
}

impl<C: CurveAffine> RSAPublicKey<C> {
    /// Creates new [`RSAPublicKey`] from `n` and `e`.
    ///
    /// # Arguments
    /// * n - an integer of `n`.
    /// * e - a parameter `e`.
    ///
    /// # Return values
    /// Returns new [`RSAPublicKey`].
    pub fn new(n: UnassignedInteger<C>, e: RSAPubE<C>) -> Self {
        Self { n, e }
    }

    pub fn without_witness(num_limbs: usize, fix_e: BigUint) -> Self {
        let n = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        let e = RSAPubE::<C>::Fix(fix_e);
        Self { n, e }
    }
}

/// An assigned RSA public key.
#[derive(Clone, Debug)]
pub struct AssignedRSAPublicKey<C: CurveAffine> {
    /// a modulus parameter
    pub n: AssignedInteger<C, Fresh>,
    /// an exponent parameter
    pub e: AssignedRSAPubE<C>,
}

impl<C: CurveAffine> AssignedRSAPublicKey<C> {
    /// Creates new [`AssignedRSAPublicKey`] from assigned `n` and `e`.
    ///
    /// # Arguments
    /// * n - an assigned integer of `n`.
    /// * e - an assigned parameter `e`.
    ///
    /// # Return values
    /// Returns new [`AssignedRSAPublicKey`].
    pub fn new(n: AssignedInteger<C, Fresh>, e: AssignedRSAPubE<C>) -> Self {
        Self { n, e }
    }
}

/// RSA signature that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSASignature<C: CurveAffine> {
    c: UnassignedInteger<C>,
}

impl<C: CurveAffine> RSASignature<C> {
    /// Creates new [`RSASignature`] from its integer.
    ///
    /// # Arguments
    /// * c - an integer of the signature.
    ///
    /// # Return values
    /// Returns new [`RSASignature`].
    pub fn new(c: UnassignedInteger<C>) -> Self {
        Self { c }
    }

    pub fn without_witness(num_limbs: usize) -> Self {
        let c = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        Self { c }
    }
}

/// An assigned RSA signature.
#[derive(Clone, Debug)]
pub struct AssignedRSASignature<C: CurveAffine> {
    c: AssignedInteger<C, Fresh>,
}

impl<C: CurveAffine> AssignedRSASignature<C> {
    /// Creates new [`AssignedRSASignature`] from its assigned integer.
    ///
    /// # Arguments
    /// * c - an assigned integer of the signature.
    ///
    /// # Return values
    /// Returns new [`AssignedRSASignature`].
    pub fn new(c: AssignedInteger<C, Fresh>) -> Self {
        Self { c }
    }
}

use halo2wrong::halo2::circuit::Layouter;
//pub use zkevm_circuits::sha256_circuit::sha256_bit::{Sha256BitChip, Sha256BitConfig};
//-- sha is not used here
//-- pub use halo2_dynamic_sha256;
//-- use halo2_dynamic_sha256::Sha256Chip;
//-- use sha2::digest::crypto_common::KeyInit;

/// A circuit implementation to verify pkcs1v15 signatures.
#[derive(Clone, Debug)]
pub struct RSASignatureVerifier<C: CurveAffine> {
    rsa_chip: RSAChip<C>,
    //-- sha256_chip: Sha256Chip<F>,
}

impl<C: CurveAffine> RSASignatureVerifier<C> {
    /// Creates new [`RSASignatureVerifier`] from [`RSAChip`] and [`Sha256BitChip`].
    ///
    /// # Arguments
    /// * rsa_chip - a [`RSAChip`].
    /// * sha256_chip - a [`Sha256Chip`]
    ///
    /// # Return values
    /// Returns new [`RSASignatureVerifier`].
    //-- pub fn new(rsa_chip: RSAChip<F>, sha256_chip: Sha256Chip<F>) -> Self {
    pub fn new(rsa_chip: RSAChip<C>) -> Self {
        Self {
            rsa_chip,
            //-- sha256_chip,
        }
    }

    /// Given a RSA public key, signed message bytes, and a pkcs1v15 signature, verifies the signature with SHA256 hash function.
    ///
    /// # Arguments
    /// * layouter - a layouter of the constraints system.
    /// * public_key - an assigned public key used for the verification.
    /// * msg - signed message bytes.
    /// * signature - a pkcs1v15 signature to be verified.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `signature` is valid for `public_key` and `msg`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    pub fn verify_pkcs1v15_signature(
        &self,
        mut layouter: impl Layouter<C::Scalar>,
        public_key: &AssignedRSAPublicKey<C>,
        msg: &[u8],
        signature: &AssignedRSASignature<C>,
    ) -> Result<(AssignedValue<C::Scalar>, Vec<AssignedValue<C::Scalar>>), Error> {
        // 1. Compute the SHA256 hash of the input bytes.
        /*let input_byte_size_with_9 = msg.len() + 9;
        let one_round_size = 4 * 16;
        let num_round = if input_byte_size_with_9 % one_round_size == 0 {
            input_byte_size_with_9 / one_round_size
        } else {
            input_byte_size_with_9 / one_round_size + 1
        };
        let padded_size = one_round_size * num_round;
        println!(
            "input_byte_size_with_9 {}, num_round {}, padded_size {}",
            input_byte_size_with_9, num_round, padded_size
        );*/

        /* //--
        let mut sha256 = self.sha256_chip.clone();
        sha256.init(&mut layouter)?;
        let inputs = msg
            .into_iter()
            .map(|byte| Value::known(*byte))
            .collect::<Vec<Value<u8>>>();
        let (digest, _) = sha256.finalize(&mut layouter, &inputs)?;
        let mut hashed_bytes = sha256
            .decompose_digest_to_bytes(&mut layouter, &digest)?
            .to_vec();
        hashed_bytes.reverse();
        */

        let limb_bytes = RSAChip::<C>::LIMB_WIDTH / 8;
        let rsa_chip = self.rsa_chip.clone();
        let main_gate = rsa_chip.main_gate();
        // by zeroknight
        let input = msg
                    .into_iter()
                    .map(|byte: &u8| Value::known(*byte))
                    .collect::<Vec<Value<u8>>>();
        let hashed_bytes = layouter.assign_region(
            || "digest: assigned_padded_input",
            |region | {
                let ctx = &mut RegionCtx::new(region, 0);
                input
                    .iter()
                    .map(|val| {
                        main_gate.assign_value(
                            ctx, 
                            val.map(|v| C::from_u128(v as u128)))
                    })
                    .collect::<Result<Vec<AssignedValue<C>>, Error>>()
            }
        )?;  
        //let hashed_bytes = msg.clone(); // expected reference `&AssignedCell<F, F>`, found reference `&u8`
        
        let bytes_len = hashed_bytes.len();

        // 2. Verify `signature` with `public_key` and `hashed_bytes`.
        let is_valid = layouter.assign_region(
            || "verify pkcs1v15 signature",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut assigned_limbs = Vec::with_capacity(bytes_len / limb_bytes);
                for i in 0..(bytes_len / limb_bytes) {
                    let mut limb_val = main_gate.assign_constant(ctx, C::zero())?;
                    for j in 0..limb_bytes {
                        let coeff = main_gate
                            .assign_constant(ctx, big_to_fe(BigUint::from(1usize) << (8 * j)))?;
                        limb_val = main_gate.mul_add(
                            ctx,
                            &coeff,
                            &hashed_bytes[limb_bytes * i + j],
                            &limb_val,
                        )?;
                    }
                    assigned_limbs.push(AssignedLimb::from(limb_val));
                }
                let hashed_msg = AssignedInteger::new(&assigned_limbs);
                let is_sign_valid =
                    rsa_chip.verify_pkcs1v15_signature(ctx, public_key, &hashed_msg, signature)?;
                Ok(is_sign_valid)
            },
        )?;
        //-- hashed_bytes.reverse();
        
        Ok((is_valid, hashed_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    //-- use halo2_dynamic_sha256::{Sha256Config, Table16Chip};
    use halo2wrong::curves::bn256::Fr as BnFr;
    use halo2wrong::halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem},
    };
    use num_bigint::BigUint;
    use rand::{thread_rng, Rng};
    use rsa::*;
    //-- use sha2::{Digest, Sha256};
    use std::marker::PhantomData;

    macro_rules! impl_rsa_signature_test_circuit {
        ($config_name:ident, $circuit_name:ident, $test_fn_name:ident, $bits_len:expr, $should_be_error:expr, $( $synth:tt )*) => {
            #[derive(Debug,Clone)]
            struct $config_name {
                rsa_config: RSAConfig,
                //-- sha256_config: Sha256Config
            }

            struct $circuit_name<C: CurveAffine> {
                private_key: RsaPrivateKey,
                public_key: RsaPublicKey,
                msg: Vec<u8>,
                _f: PhantomData<C>
            }

            impl<C: CurveAffine> $circuit_name<C> {
                const BITS_LEN:usize = $bits_len;
                const LIMB_WIDTH:usize = RSAChip::<C>::LIMB_WIDTH;
                const EXP_LIMB_BITS:usize = 5;
                const DEFAULT_E: u128 = 65537;
                fn rsa_chip(&self, config: RSAConfig) -> RSAChip<C> {
                    RSAChip::new(config, Self::BITS_LEN,Self::EXP_LIMB_BITS)
                }

                //-- fn sha256_chip(&self, config: Sha256Config) -> Sha256Chip<F> {
                //--    Sha256Chip::new(config)
                //--}
            }

            impl<C: CurveAffine> Circuit<C::Scalar> for $circuit_name<C> {
                type Config = $config_name;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    unimplemented!();
                }

                fn configure(meta: &mut ConstraintSystem<C::Scalar>) -> Self::Config {
                    let main_gate_config = MainGate::<C>::configure(meta);
                    let (mut composition_bit_lens, mut overflow_bit_lens) =
                        RSAChip::<C>::compute_range_lens(
                            Self::BITS_LEN / Self::LIMB_WIDTH,
                        );
                    
                    //-- let (mut sha_composition_bit_lens, mut sha_overflow_bit_lens) =Sha256Chip::<F>::compute_range_lens();
                    //-- .append(&mut sha_composition_bit_lens);
                    //-- overflow_bit_lenscomposition_bit_lens.append(&mut sha_overflow_bit_lens);
                    
                    let range_config = RangeChip::<C>::configure(
                        meta,
                        &main_gate_config,
                        composition_bit_lens,
                        overflow_bit_lens,
                    );
                    let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
                    let rsa_config = RSAConfig::new(bigint_config);
                    //-- 
                    //-- let table16_congig = Table16Chip::configure(meta);
                    //-- let sha256_config = Sha256Config::new(main_gate_config, range_config, table16_congig, 128+64);
                    Self::Config {
                        rsa_config,
                        //-- sha256_config
                    }
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
                use halo2wrong::halo2::dev::MockProver;
                fn run<C: CurveAffine>() {
                    let mut rng = thread_rng();
                    let private_key = RsaPrivateKey::new(&mut rng, $circuit_name::<C>::BITS_LEN).expect("failed to generate a key");
                    let public_key = RsaPublicKey::from(&private_key);
                    let n = BigUint::from_radix_le(&public_key.n().to_radix_le(16),16).unwrap();
                    let mut msg:[u8;128] = [0;128];
                    for i in 0..128 {
                        msg[i] = rng.gen();
                    }
                    //-- let hashed_msg = Sha256::digest(&msg);
                    let hashed_msg = msg.clone();

                    let circuit = $circuit_name::<C> {
                        private_key,
                        public_key,
                        msg: msg.to_vec(),
                        _f: PhantomData
                    };
                    let num_limbs = $circuit_name::<C>::BITS_LEN / $circuit_name::<C>::LIMB_WIDTH;
                    let limb_width = $circuit_name::<C>::LIMB_WIDTH;
                    let n_fes = decompose_big::<C>(n, num_limbs, limb_width);
                    let mut hash_fes = hashed_msg.iter().map(|byte| C::from(*byte as u64)).collect::<Vec<C>>();
                    let mut column0_public_inputs = n_fes;
                    column0_public_inputs.append(&mut hash_fes);
                    let public_inputs = vec![column0_public_inputs];
                    let k = 18;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    if $should_be_error {
                        assert!(prover.verify().is_err());
                    } else {
                        assert_eq!(prover.verify(), Ok(()))
                    }
                }
                run::<BnFr>();
            }
        };
    }

    impl_rsa_signature_test_circuit!(
        TestRSASignatureWithHashConfig,
        TestRSASignatureWithHashCircuit,
        test_rsa_signature_with_hash_circuit,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config.rsa_config);
            //-- let sha256_chip = self.sha256_chip(config.sha256_config);

            let bigint_chip = rsa_chip.bigint_chip();
            let main_gate = rsa_chip.main_gate();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            let (public_key, signature) = layouter.assign_region(
                || "rsa signature with hash test using 2048 bits public keys",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    //-- let hashed_msg = Sha256::digest(&self.msg);
                    let hashed_msg = self.msg.clone();

                    let padding = PaddingScheme::PKCS1v15Sign {
                        hash: Some(Hash::SHA2_256),
                    };
                    let mut sign = self
                        .private_key
                        .sign(padding, &hashed_msg)
                        .expect("fail to sign a hashed message.");
                    sign.reverse();
                    let sign_big = BigUint::from_bytes_le(&sign);
                    let sign_limbs = decompose_big::<C>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let n_limbs = decompose_big::<C>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    Ok((public_key, sign))
                },
            )?;
            //-- let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
            let verifier = RSASignatureVerifier::new(rsa_chip);

            let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
                layouter.namespace(|| "verify pkcs1v15 signature"),
                &public_key,
                &self.msg,
                &signature,
            )?;
            for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th public key limb", i)),
                    limb.assigned_val(),
                    i,
                )?;
            }
            let num_limb_n = public_key.n.num_limbs();
            for (i, val) in hashed_msg.into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
                    val,
                    num_limb_n + i,
                )?;
            }
            layouter.assign_region(
                || "assert is_valid==1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    main_gate.assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestRSASignatureWithHashConfig2,
        TestRSASignatureWithHashCircuit2,
        test_rsa_signature_with_hash_circuit2,
        1024,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config.rsa_config);
            //-- let sha256_chip = self.sha256_chip(config.sha256_config);

            let bigint_chip = rsa_chip.bigint_chip();
            let main_gate = rsa_chip.main_gate();
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            let (public_key, signature) = layouter.assign_region(
                || "rsa signature with hash test using 1024 bits public keys",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    //-- let hashed_msg = Sha256::digest(&self.msg);
                    let hashed_msg = self.msg.clone();

                    let padding = PaddingScheme::PKCS1v15Sign {
                        hash: Some(Hash::SHA2_256),
                    };
                    let mut sign = self
                        .private_key
                        .sign(padding, &hashed_msg)
                        .expect("fail to sign a hashed message.");
                    sign.reverse();
                    let sign_big = BigUint::from_bytes_le(&sign);
                    let sign_limbs = decompose_big::<C>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let n_limbs = decompose_big::<C>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    Ok((public_key, sign))
                },
            )?;
            //-- let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
            let verifier = RSASignatureVerifier::new(rsa_chip);

            let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
                layouter.namespace(|| "verify pkcs1v15 signature"),
                &public_key,
                &self.msg,
                &signature,
            )?;
            for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th public key limb", i)),
                    limb.assigned_val(),
                    i,
                )?;
            }
            let num_limb_n = public_key.n.num_limbs();
            for (i, val) in hashed_msg.into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
                    val,
                    num_limb_n + i,
                )?;
            }
            layouter.assign_region(
                || "assert is_valid==1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    main_gate.assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestRSASignatureWithHashConfig3,
        TestRSASignatureWithHashCircuit3,
        test_rsa_signature_with_hash_circuit3,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config.rsa_config);
            //-- let sha256_chip = self.sha256_chip(config.sha256_config);

            let bigint_chip = rsa_chip.bigint_chip();
            let main_gate = rsa_chip.main_gate();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            let (public_key, signature) = layouter.assign_region(
                || "rsa signature with hash test using 2048 bits public keys: invalid signed message case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    //-- let hashed_msg = Sha256::digest(&self.msg);
                    let hashed_msg = self.msg.clone();

                    let padding = PaddingScheme::PKCS1v15Sign {
                        hash: Some(Hash::SHA2_256),
                    };
                    let mut rng = thread_rng();
                    let invalid_private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
                    let mut sign = invalid_private_key
                        .sign(padding, &hashed_msg)
                        .expect("fail to sign a hashed message.");
                    sign.reverse();
                    let sign_big = BigUint::from_bytes_le(&sign);
                    let sign_limbs = decompose_big::<C>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let n_limbs = decompose_big::<C>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    Ok((public_key, sign))
                },
            )?;
            // let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
            let verifier = RSASignatureVerifier::new(rsa_chip);

            let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
                layouter.namespace(|| "verify pkcs1v15 signature"),
                &public_key,
                &self.msg,
                &signature,
            )?;
            for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th public key limb", i)),
                    limb.assigned_val(),
                    i,
                )?;
            }
            let num_limb_n = public_key.n.num_limbs();
            for (i, val) in hashed_msg.into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
                    val,
                    num_limb_n + i,
                )?;
            }
            layouter.assign_region(
                || "assert is_valid==1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    main_gate.assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestRSASignatureWithHashConfig4,
        TestRSASignatureWithHashCircuit4,
        test_rsa_signature_with_hash_circuit4,
        2048,
        true,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            let rsa_chip = self.rsa_chip(config.rsa_config);
            //-- let sha256_chip = self.sha256_chip(config.sha256_config);
            let bigint_chip = rsa_chip.bigint_chip();
            let main_gate = rsa_chip.main_gate();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            let (public_key, signature) = layouter.assign_region(
                || "rsa signature with hash test using 2048 bits public keys: invalid private key case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let padding = PaddingScheme::PKCS1v15Sign {
                        hash: Some(Hash::SHA2_256),
                    };
                    let invalid_msg = [1; 32];
                    let mut sign = self
                        .private_key
                        .sign(padding, &invalid_msg)
                        .expect("fail to sign a hashed message.");
                    sign.reverse();
                    let sign_big = BigUint::from_bytes_le(&sign);
                    let sign_limbs = decompose_big::<C>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned);
                    let sign = rsa_chip.assign_signature(ctx, sign)?;
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let n_limbs = decompose_big::<C>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix);
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?;
                    Ok((public_key, sign))
                },
            )?;
            //-- let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip);
            let verifier = RSASignatureVerifier::new(rsa_chip);

            let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(
                layouter.namespace(|| "verify pkcs1v15 signature"),
                &public_key,
                &self.msg,
                &signature,
            )?;
            for (i, limb) in public_key.n.limbs().into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th public key limb", i)),
                    limb.assigned_val(),
                    i,
                )?;
            }
            let num_limb_n = public_key.n.num_limbs();
            for (i, val) in hashed_msg.into_iter().enumerate() {
                main_gate.expose_public(
                    layouter.namespace(|| format!("expose {} th hashed_msg limb", i)),
                    val,
                    num_limb_n + i,
                )?;
            }
            layouter.assign_region(
                || "assert is_valid==1",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    main_gate.assert_one(ctx, &is_valid)?;
                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestDeriveTraitsConfig,
        TestDeriveTraitsCircuit,
        test_derive_traits,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            let config = config.clone();
            format!("{config:?}");
            let rsa_chip = self.rsa_chip(config.rsa_config);
            //-- let sha256_chip = self.sha256_chip(config.sha256_config);
            let bigint_chip = rsa_chip.bigint_chip();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "rsa signature with hash test using 2048 bits public keys: invalid private key case",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    //-- let hashed_msg = Sha256::digest(&self.msg);
                    let hashed_msg = self.msg.clone();

                    let padding = PaddingScheme::PKCS1v15Sign {
                        hash: Some(Hash::SHA2_256),
                    };
                    let mut sign = self
                        .private_key
                        .sign(padding, &hashed_msg)
                        .expect("fail to sign a hashed message.");
                    sign.reverse();
                    let sign_big = BigUint::from_bytes_le(&sign);
                    let sign_limbs = decompose_big::<C>(sign_big.clone(), num_limbs, limb_width);
                    let sign_unassigned = UnassignedInteger::from(sign_limbs);
                    let sign = RSASignature::new(sign_unassigned).clone();
                    format!("{sign:?}");
                    let sign = rsa_chip.assign_signature(ctx, sign)?.clone();
                    format!("{sign:?}");
                    let n_big =
                        BigUint::from_radix_le(&self.public_key.n().clone().to_radix_le(16), 16)
                            .unwrap();
                    let n_limbs = decompose_big::<C>(n_big.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);
                    let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                    let public_key = RSAPublicKey::new(n_unassigned, e_fix).clone();
                    format!("{public_key:?}");
                    let public_key = rsa_chip.assign_public_key(ctx, public_key)?.clone();
                    format!("{public_key:?}");
                    Ok((public_key, sign))
                },
            )?;
            //-- let verifier = RSASignatureVerifier::new(rsa_chip, sha256_chip).clone();
            let verifier = RSASignatureVerifier::new(rsa_chip).clone();
            format!("{verifier:?}");
            let range_chip = bigint_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            Ok(())
        }
    );

    impl_rsa_signature_test_circuit!(
        TestUnimplementedConfig,
        TestUnimplemented,
        test_rsa_signature_with_hash_unimplemented,
        2048,
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<C::Scalar>,
        ) -> Result<(), Error> {
            Ok(())
        }
    );

    /*#[test]
    #[should_panic]
    fn test_unimplemented() {
        let mut rng = thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, TestUnimplemented::<BnFr>::BITS_LEN)
            .expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);
        let mut msg: [u8; 128] = [0; 128];
        for i in 0..128 {
            msg[i] = rng.gen();
        }
        let circuit = TestUnimplemented::<BnFr> {
            private_key,
            public_key,
            msg: msg.to_vec(),
            _f: PhantomData,
        };
        circuit.without_witnesses();
    }*/
}
