use ff::{FromUniformBytes, PrimeField};

use halo2wrong::{
    halo2::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    RegionCtx,
};

use maingate::{
    mock_prover_verify, AssignedValue, MainGate, MainGateConfig, MainGateInstructions, Term,
};

use poseidon::{Poseidon, SparseMDSMatrix, Spec, State};
use rand_core::OsRng;

use crate::poseidon;

///
#[derive(Debug, Clone)]
pub struct AssignedState<F: PrimeField, const T: usize>(pub [AssignedValue<F>; T]);
/// number of full round
pub const FULL_ROUND: usize = 8;
/// number of partial round
pub const PARTIAL_ROUND: usize = 57;

/// poseidon chip constrains permutation operations
#[derive(Debug, Clone)]
pub struct PoseidonChip<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
    const R_F: usize,
    const R_P: usize,
> {
    /// state
    pub state: AssignedState<F, T>,
    /// input buffer
    pub absorbing: Vec<AssignedValue<F>>,
    spec: Spec<F, T, RATE>,
    main_gate_config: MainGateConfig,
}

impl<
        F: PrimeField + FromUniformBytes<64>,
        const R_F: usize,
        const R_P: usize,
        const T: usize,
        const RATE: usize,
    > PoseidonChip<F, T, RATE, R_F, R_P>
{
    /// Construct main gate
    pub fn main_gate(&self) -> MainGate<F> {
        MainGate::<_>::new(self.main_gate_config.clone())
    }

    /// Construct PoseidonChip
    pub fn new_enc(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
        key0: &F,
        key1: &F,
    ) -> Result<Self, Error> {
        let main_gate = MainGate::<_>::new(main_gate_config.clone());
        let state = [
            // Domain - Maximum plaintext length of the elements of Fq, as defined
            // [F::from_u128(0x100000000 as u128),
            // F::from_u128(MESSAGE_CAPACITY_TEST as u128),

            // nonce]
            // debuging purpose
            F::ZERO,
            F::ZERO,
            *key0,
            *key1,
            F::ONE,
        ];
        let initial_state = State::<F, T>::init_state(state)
            .words()
            .iter()
            .map(|word| main_gate.assign_constant(ctx, *word))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        Ok(Self {
            state: AssignedState(initial_state.try_into().unwrap()),
            spec: spec.clone(),
            absorbing: vec![],
            main_gate_config: main_gate_config.clone(),
        })
    }

    /// encryption for delay encryption
    pub fn new_enc_de(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
        key0: &F,
        key1: &F,
    ) -> Result<Self, Error> {
        let main_gate = MainGate::<_>::new(main_gate_config.clone());
        let state = [
            // Domain - Maximum plaintext length of the elements of Fq, as defined
            // [F::from_u128(0x100000000 as u128),
            // F::from_u128(MESSAGE_CAPACITY_TEST as u128),

            // nonce]
            // debuging purpose
            F::ZERO,
            F::ZERO,
            *key0,
            *key1,
            F::ONE,
        ];
        let initial_state = State::<F, T>::init_state(state)
            .words()
            .iter()
            .map(|word| main_gate.assign_value(ctx, Value::known(*word)))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        Ok(Self {
            state: AssignedState(initial_state.try_into().unwrap()),
            spec: spec.clone(),
            absorbing: vec![],
            main_gate_config: main_gate_config.clone(),
        })
    }

    /// Construct PoseidonChip
    pub fn new_hash(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
        // key0: &F,
        // key1: &F,
    ) -> Result<Self, Error> {
        let main_gate = MainGate::<_>::new(main_gate_config.clone());

        let initial_state = State::<_, T>::default()
            .words()
            .iter()
            .map(|word| main_gate.assign_constant(ctx, *word))
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        Ok(Self {
            state: AssignedState(initial_state.try_into().unwrap()),
            spec: spec.clone(),
            absorbing: vec![],
            main_gate_config: main_gate_config.clone(),
        })
    }

    /// add inputs to encrypt
    pub fn set_inputs(&mut self, elements: &[AssignedValue<F>]) {
        self.absorbing.extend_from_slice(elements);
    }
    /*
        Internally expose poseidion parameters and matrices
    */
    pub(super) fn r_f_half(&self) -> usize {
        self.spec.r_f() / 2
    }

    pub(super) fn constants_start(&self) -> Vec<[F; T]> {
        self.spec.constants().start().clone()
    }

    pub(super) fn constants_partial(&self) -> Vec<F> {
        self.spec.constants().partial().clone()
    }

    pub(super) fn constants_end(&self) -> Vec<[F; T]> {
        self.spec.constants().end().clone()
    }

    pub(super) fn mds(&self) -> [[F; T]; T] {
        self.spec.mds_matrices().mds().rows()
    }

    pub(super) fn pre_sparse_mds(&self) -> [[F; T]; T] {
        self.spec.mds_matrices().pre_sparse_mds().rows()
    }

    pub(super) fn sparse_matrices(&self) -> Vec<SparseMDSMatrix<F, T, RATE>> {
        self.spec.mds_matrices().sparse_matrices().clone()
    }
}

impl<
        F: PrimeField + FromUniformBytes<64>,
        const R_F: usize,
        const R_P: usize,
        const T: usize,
        const RATE: usize,
    > PoseidonChip<F, T, RATE, R_F, R_P>
{
    /// Applies full state sbox then adds constants to each word in the state
    fn sbox_full(&mut self, ctx: &mut RegionCtx<'_, F>, constants: &[F; T]) -> Result<(), Error> {
        let main_gate = self.main_gate();
        for (word, constant) in self.state.0.iter_mut().zip(constants.iter()) {
            let t = main_gate.mul(ctx, word, word)?;
            let t = main_gate.mul(ctx, &t, &t)?;
            *word = main_gate.mul_add_constant(ctx, &t, word, *constant)?;
        }
        Ok(())
    }

    /// Applies sbox to the first word then adds constants to each word in the
    /// state
    fn sbox_part(&mut self, ctx: &mut RegionCtx<'_, F>, constant: F) -> Result<(), Error> {
        let main_gate = self.main_gate();
        let word = &mut self.state.0[0];
        let t = main_gate.mul(ctx, word, word)?;
        let t = main_gate.mul(ctx, &t, &t)?;
        *word = main_gate.mul_add_constant(ctx, &t, word, constant)?;

        Ok(())
    }

    // Adds pre constants and chunked inputs to the state.
    fn absorb_with_pre_constants(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        //
        // * inputs size equals to RATE: absorbing
        // * inputs size is less then RATE but not 0: padding
        // * inputs size is 0: extra permutation to avoid collution
        // state = [s1, s2, s3, s4, s5]
        // pre_constants = [c1, c2, c3, c4, c5]
        // inputs = [i1, i2]
        // offset = inputs.len() + 1 = 2 + 1 = 3
        // state = [s1 + c1, s2 + i1 + c2, s3 + i2 + c3, s4 + c4, s5 + c5 + 1]
        inputs: Vec<AssignedValue<F>>,
        pre_constants: &[F; T],
        h_flag: bool,
    ) -> Result<(), Error> {
        assert!(inputs.len() < T);
        let offset = inputs.len() + 1;
        let main_gate = self.main_gate();

        // Add the first constant to the first word
        self.state.0[0] = main_gate.add_constant(ctx, &self.state.0[0], pre_constants[0])?;

        // println!("Before adding:{:?}", self.state.0[0]);

        // Add inputs along with constants
        for ((word, constant), input) in self
            .state
            .0
            .iter_mut()
            .skip(1)
            .zip(pre_constants.iter().skip(1))
            .zip(inputs.iter())
        {
            *word = main_gate.add_with_constant(ctx, word, input, *constant)?;
        }

        // println!("After adding:{:?}", self.state.0[0]);

        // Remaining part
        for (i, (word, constant)) in self
            .state
            .0
            .iter_mut()
            .skip(offset)
            .zip(pre_constants.iter().skip(offset))
            .enumerate()
        {
            let constant_to_add = if h_flag && i == 0 { F::ONE } else { F::ZERO };
            *word = main_gate.add_constant(ctx, word, *constant + constant_to_add)?;
        }

        Ok(())
    }

    /// Applies MDS State multiplication
    fn apply_mds(&mut self, ctx: &mut RegionCtx<'_, F>, mds: &[[F; T]; T]) -> Result<(), Error> {
        // Calculate new state
        let new_state = mds
            .iter()
            .map(|row| {
                // term_i = s_0 * e_i_0 + s_1 * e_i_1 + ....
                let terms = self
                    .state
                    .0
                    .iter()
                    .zip(row.iter())
                    .map(|(e, word)| Term::Assigned(e, *word))
                    .collect::<Vec<Term<F>>>();

                self.main_gate().compose(ctx, &terms[..], F::ZERO)
            })
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        // Assign new state
        for (word, new_word) in self.state.0.iter_mut().zip(new_state.into_iter()) {
            *word = new_word
        }

        Ok(())
    }

    /// Applies sparse MDS to the state
    fn apply_sparse_mds(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        mds: &SparseMDSMatrix<F, T, RATE>,
    ) -> Result<(), Error> {
        // For the 0th word
        let terms = self
            .state
            .0
            .iter()
            .zip(mds.row().iter())
            .map(|(e, word)| Term::Assigned(e, *word))
            .collect::<Vec<Term<F>>>();
        let mut new_state = vec![self.main_gate().compose(ctx, &terms[..], F::ZERO)?];

        // Rest of the trainsition ie the sparse part
        for (e, word) in mds.col_hat().iter().zip(self.state.0.iter().skip(1)) {
            new_state.push(self.main_gate().compose(
                ctx,
                &[
                    Term::Assigned(&self.state.0[0], *e),
                    Term::Assigned(word, F::ONE),
                ],
                F::ZERO,
            )?);
        }

        // Assign new state
        for (word, new_word) in self.state.0.iter_mut().zip(new_state.into_iter()) {
            *word = new_word
        }

        Ok(())
    }

    /// Constrains poseidon permutation while mutating the given state
    pub fn permutation(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        inputs: Vec<AssignedValue<F>>,
    ) -> Result<(), Error> {
        let r_f = self.r_f_half();
        let mds = self.mds();
        let pre_sparse_mds = self.pre_sparse_mds();
        let sparse_matrices = self.sparse_matrices();

        // First half of the full rounds
        let constants = self.constants_start();
        self.absorb_with_pre_constants(ctx, inputs, &constants[0], false)?;
        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.sbox_full(ctx, constants)?;
            self.apply_mds(ctx, &mds)?;
        }
        self.sbox_full(ctx, constants.last().unwrap())?;
        self.apply_mds(ctx, &pre_sparse_mds)?;

        // Partial rounds
        let constants = self.constants_partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.sbox_part(ctx, *constant)?;
            self.apply_sparse_mds(ctx, sparse_mds)?;
        }

        // Second half of the full rounds
        let constants = self.constants_end();
        for constants in constants.iter() {
            self.sbox_full(ctx, constants)?;
            self.apply_mds(ctx, &mds)?;
        }
        self.sbox_full(ctx, &[F::ZERO; T])?;
        self.apply_mds(ctx, &mds)?;

        Ok(()) // zeroknight
    }

    /// Constrains poseidon permutation while mutating the given state
    pub fn perm_hash(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        inputs: Vec<AssignedValue<F>>,
    ) -> Result<(), Error> {
        let r_f = self.r_f_half();
        let mds = self.mds();
        let pre_sparse_mds = self.pre_sparse_mds();
        let sparse_matrices = self.sparse_matrices();

        // First half of the full rounds
        let constants = self.constants_start();
        self.absorb_with_pre_constants(ctx, inputs, &constants[0], true)?;
        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.sbox_full(ctx, constants)?;
            self.apply_mds(ctx, &mds)?;
        }
        self.sbox_full(ctx, constants.last().unwrap())?;
        self.apply_mds(ctx, &pre_sparse_mds)?;

        // Partial rounds
        let constants = self.constants_partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.sbox_part(ctx, *constant)?;
            self.apply_sparse_mds(ctx, sparse_mds)?;
        }

        // Second half of the full rounds
        let constants = self.constants_end();
        for constants in constants.iter() {
            self.sbox_full(ctx, constants)?;
            self.apply_mds(ctx, &mds)?;
        }
        self.sbox_full(ctx, &[F::ZERO; T])?;
        self.apply_mds(ctx, &mds)?;

        Ok(()) // zeroknight
    }
}
