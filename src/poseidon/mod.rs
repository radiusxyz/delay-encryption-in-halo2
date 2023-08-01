//! Poseidon hashing implementation with variable length input setting. This
//! crate also exposes constant parameters for circuit implementations

#![deny(missing_debug_implementations)]
//-- #![deny(missing_docs)]

pub mod grain;
pub mod matrix;
pub mod permutation;
pub mod poseidon;
pub mod spec;

pub mod gadget;
pub use gadget::sinsemilla;

pub use poseidon::Poseidon;
pub use spec::{MDSMatrices, MDSMatrix, SparseMDSMatrix, Spec, State};

