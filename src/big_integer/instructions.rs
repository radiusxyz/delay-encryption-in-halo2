use crate::{AssignedInteger, Fresh, Muled, RangeType, RefreshAux, UnassignedInteger};
//use halo2wrong::halo2::{arithmetic::FieldExt, plonk::Error};
use halo2wrong::halo2::plonk::Error;
use halo2_proofs::halo2curves::CurveAffine; //-- zeroknight : instead of arithmetic::FieldExt

use maingate::{AssignedValue, RegionCtx};
use num_bigint::BigUint;

/// Instructions for big-integer operations.
pub trait BigIntInstructions<C: CurveAffine> {
    /// Assigns a variable [`AssignedInteger`] whose [`RangeType`] is [`Fresh`].
    fn assign_integer(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        integer: UnassignedInteger<C>,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Assigns a constant [`AssignedInteger`] whose [`RangeType`] is [`Fresh`].
    fn assign_constant_fresh(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        integer: BigUint,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Assigns a constant [`AssignedInteger`] whose [`RangeType`] is [`Muled`].
    fn assign_constant_muled(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        integer: BigUint,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedInteger<C, Muled>, Error>;

    /// Assigns the maximum integer whose number of limbs is `num_limbs`.
    fn max_value(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        num_limbs: usize,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Converts a [`Muled`] type integer to a [`Fresh`] type integer.
    fn refresh(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Muled>,
        aux: &RefreshAux,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Given two inputs `a,b`, performs the addition `a + b`.
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Given two inputs `a,b`, performs the subtraction `a - b`.
    fn sub(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<(AssignedInteger<C, Fresh>, AssignedValue<C::Scalar>), Error>;

    /// Given two inputs `a,b`, performs the multiplication `a * b`.
    fn mul(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedInteger<C, Muled>, Error>;

    /// Given a inputs `a`, performs the square `a^2`.
    fn square(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedInteger<C, Muled>, Error>;

    /// Given two inputs `a,b` and a modulus `n`, performs the modular addition `a + b mod n`.
    fn add_mod(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
        n: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Given two inputs `a,b` and a modulus `n`, performs the modular subtraction `a - b mod n`.
    fn sub_mod(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
        n: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Given two inputs `a,b` and a modulus `n`, performs the modular multiplication `a * b mod n`.
    fn mul_mod(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
        n: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Given a input `a` and a modulus `n`, performs the modular square `a^2 mod n`.
    fn square_mod(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        n: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Given a base `a`, a variable exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        e: &AssignedInteger<C, Fresh>,
        n: &AssignedInteger<C, Fresh>,
        exp_limb_bits: usize,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Given a base `a`, a fixed exponent `e`, and a modulus `n`, performs the modular power `a^e mod n`.
    fn pow_mod_fixed_exp(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        e: &BigUint,
        n: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedInteger<C, Fresh>, Error>;

    /// Returns an assigned bit representing whether `a` is zero or not.
    fn is_zero(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedValue<C::Scalar>, Error>;

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn is_equal_fresh(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedValue<C::Scalar>, Error>;

    /// Returns an assigned bit representing whether `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    fn is_equal_muled(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Muled>,
        b: &AssignedInteger<C, Muled>,
        num_limbs_l: usize,
        num_limbs_r: usize,
    ) -> Result<AssignedValue<C::Scalar>, Error>;

    /// Returns an assigned bit representing whether `a` is less than `b` (`a<b`).
    fn is_less_than(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedValue<C::Scalar>, Error>;

    /// Returns an assigned bit representing whether `a` is less than or equal to `b` (`a<=b`).
    fn is_less_than_or_equal(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedValue<C::Scalar>, Error>;

    /// Returns an assigned bit representing whether `a` is greater than `b` (`a>b`).
    fn is_greater_than(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedValue<C::Scalar>, Error>;

    /// Returns an assigned bit representing whether `a` is greater than or equal to `b` (`a>=b`).
    fn is_greater_than_or_equal(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedValue<C::Scalar>, Error>;

    /// Returns an assigned bit representing whether `a` is in the order-`n` finite field.
    fn is_in_field(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        n: &AssignedInteger<C, Fresh>,
    ) -> Result<AssignedValue<C::Scalar>, Error>;

    /// Asserts that that `a` is zero or not.
    fn assert_zero(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
    ) -> Result<(), Error>;

    /// Asserts that `a` and `b` are equivalent, whose [`RangeType`] is [`Fresh`].
    fn assert_equal_fresh(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<(), Error>;

    /// Asserts that `a` and `b` are equivalent, whose [`RangeType`] is [`Muled`].
    fn assert_equal_muled(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Muled>,
        b: &AssignedInteger<C, Muled>,
        n1: usize,
        n2: usize,
    ) -> Result<(), Error>;

    /// Asserts that `a` is less than `b` (`a<b`).
    fn assert_less_than(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<(), Error>;

    /// Asserts that `a` is less than or equal to `b` (`a<=b`).
    fn assert_less_than_or_equal(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<(), Error>;

    /// Asserts that`a` is greater than `b` (`a>b`).
    fn assert_greater_than(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<(), Error>;

    /// Asserts that `a` is greater than or equal to `b` (`a>=b`).
    fn assert_greater_than_or_equal(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        b: &AssignedInteger<C, Fresh>,
    ) -> Result<(), Error>;

    /// Asserts that `a` is in the order-`n` finite field.
    fn assert_in_field(
        &self,
        ctx: &mut RegionCtx<'_, C::Scalar>,
        a: &AssignedInteger<C, Fresh>,
        n: &AssignedInteger<C, Fresh>,
    ) -> Result<(), Error>;
}
