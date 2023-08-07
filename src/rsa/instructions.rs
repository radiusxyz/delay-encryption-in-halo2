use crate::{
    AssignedInteger, AssignedRSAPublicKey, AssignedRSASignature, Fresh, RSAPublicKey, RSASignature,
};
//use halo2wrong::halo2::{arithmetic::FieldExt, plonk::Error};
use halo2wrong::halo2::plonk::Error;
use halo2_proofs::arithmetic::CurveAffine;  // zeroknight instead of arithmeti::FieldExt

use maingate::{AssignedValue, RegionCtx};

/// Instructions for RSA operations.
pub trait RSAInstructions<C: CurveAffine> {
    /// Assigns a [`AssignedRSAPublicKey`].
    fn assign_public_key(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        public_key: RSAPublicKey<C>,
    ) -> Result<AssignedRSAPublicKey<C>, Error>;

    /// Assigns a [`AssignedRSASignature`].
    fn assign_signature(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        signature: RSASignature<C>,
    ) -> Result<AssignedRSASignature<C>, Error>;

    /// Given a base `x`, a RSA public key (e,n), performs the modular power `x^e mod n`.
    fn modpow_public_key(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        x: &AssignedInteger<C, Fresh>,
        public_key: &AssignedRSAPublicKey<C>,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Given a RSA public key, a message hashed with SHA256, and a pkcs1v15 signature, verifies the signature with the public key and the hashed messaged.
    fn verify_pkcs1v15_signature(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        public_key: &AssignedRSAPublicKey<C>,
        hashed_msg: &AssignedInteger<C, Fresh>,
        signature: &AssignedRSASignature<C>,
    ) -> Result<AssignedValue<C::Scalar>, Error>;
}
