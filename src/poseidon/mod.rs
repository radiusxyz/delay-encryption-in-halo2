//! Poseidon hashing implementation with variable length input setting. This
//! crate also exposes constant parameters for circuit implementations

#![deny(missing_debug_implementations)]
//-- #![deny(missing_docs)]

mod grain;
mod matrix;
mod permutation;
mod poseidon;
mod spec;

mod gadget;
pub use gadget::sinsemilla;

pub use poseidon::Poseidon;
pub use spec::{MDSMatrices, MDSMatrix, SparseMDSMatrix, Spec, State};

