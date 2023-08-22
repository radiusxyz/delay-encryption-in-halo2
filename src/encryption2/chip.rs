use maingate::{AssignedValue, MainGate, MainGateConfig, MainGateInstructions, RegionCtx, Term};
//use halo2::{halo2curves::ff::PrimeField, plonk::Error};
use halo2::{circuit::AssignedCell, halo2curves::ff::PrimeField};
use halo2wrong::halo2::plonk::{ConstraintSystem, Error};
use poseidon::{SparseMDSMatrix, Spec, State};

use crate::encryption::poseidon::MESSAGE_CAPACITY;

use halo2wrong::halo2::circuit::Value;

/// `AssignedState` is composed of `T` sized assigned values
#[derive(Debug, Clone)]
pub struct AssignedState<F: PrimeField, const T: usize>(pub(super) [AssignedValue<F>; T]);

#[derive(Copy, Clone, Debug, Default)]
pub struct PoseidonEncKey<F: PrimeField> {
    key0: F,
    key1: F,
}

#[derive(Clone, Debug)]
pub struct PoseidonEncConfig {
    main_gate_config: MainGateConfig,
}

impl PoseidonEncConfig {
    pub fn new<F: PrimeField>(meta: &mut ConstraintSystem<F>) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);

        Self { main_gate_config }
    }
}

#[derive(Debug, Clone)]
pub struct PoseidonEncChip<
    F: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN: usize,
    const T: usize,
    const RATE: usize,
> {
    state: AssignedState<F, T>,
    absorbing: Vec<AssignedValue<F>>,
    spec: Spec<F, T, RATE>,
    main_gate_config: MainGateConfig,
}

impl<
        F: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN: usize,
        const T: usize,
        const RATE: usize,
    > PoseidonEncChip<F, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>
{
    // Constructs new encryption chip with assigned initial state
    pub fn configure(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
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

    /// Appends field elements to the absorbation line. It won't perform
    /// permutation here
    pub fn update(&mut self, elements: &[AssignedValue<F>]) {
        self.absorbing.extend_from_slice(elements);
    }
}

impl<
        F: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN: usize,
        const T: usize,
        const RATE: usize,
    > PoseidonEncChip<F, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>
{
    /// Construct main gate
    pub fn main_gate(&self) -> MainGate<F> {
        MainGate::<_>::new(self.main_gate_config.clone())
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
        F: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN: usize,
        const T: usize,
        const RATE: usize,
    > PoseidonEncChip<F, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>
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
        inputs: Vec<AssignedValue<F>>,
        pre_constants: &[F; T],
    ) -> Result<(), Error> {
        assert!(inputs.len() < T);
        let offset = inputs.len() + 1;
        let main_gate = self.main_gate();

        // Add the first constant to the first word
        self.state.0[0] = self
            .main_gate()
            .add_constant(ctx, &self.state.0[0], pre_constants[0])?;

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

        // Padding
        for (i, (word, constant)) in self
            .state
            .0
            .iter_mut()
            .skip(offset)
            .zip(pre_constants.iter().skip(offset))
            .enumerate()
        {
            *word = main_gate.add_constant(
                ctx,
                word,
                if i == 0 {
                    // Mark
                    *constant + F::ONE
                } else {
                    *constant
                },
            )?;
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
        self.absorb_with_pre_constants(ctx, inputs, &constants[0])?;
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

        Ok(())
    }

    // pub fn write_scalar(&mut self, scalar: &AssignedValue<N>) {
    //     self.hasher_chip.update(&[scalar.clone()]);
    // }

    // for e in self.inputs.as_ref().transpose_vec(self.n) {
    //     let e = main_gate.assign_value(ctx, e.map(|e| *e))?;
    //     // println!("{:?}", e);
    //     self.hasher_chip.update(&[e.clone()]);
    // }

    // pub fn update(&mut self, elements: &[AssignedValue<F>]) {
    //     self.absorbing.extend_from_slice(elements);
    // }

    pub fn encrypt(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        key: &PoseidonEncKey<F>,
        nonce: F,
        message: &Vec<F>,
    ) -> Result<AssignedValue<F>, Error> {
        // Get elements to encrypt
        let input_elements = self.absorbing.clone();
        // Flush the input que
        self.absorbing.clear();

        self.state.0[0] = self.main_gate().add_constant(
            ctx,
            &self.state.0[0],
            F::from_u128(0x100000000 as u128),
        )?;

        self.state.0[1] = self.main_gate().add_constant(
            ctx,
            &self.state.0[1],
            F::from_u128(MESSAGE_CAPACITY as u128),
        )?;

        self.state.0[2] = self
            .main_gate()
            .add_constant(ctx, &self.state.0[2], key.key0)?;

        self.state.0[3] = self
            .main_gate()
            .add_constant(ctx, &self.state.0[3], key.key1)?;

        self.state.0[4] = self
            .main_gate()
            .add_constant(ctx, &self.state.0[4], nonce)?;

        println!("STATE?{:?}", self.state.0[1]);

        let mut message_cells = vec![];
        let inputs = Value::known(message.clone());
        for e in inputs.as_ref().transpose_vec(2) {
            let e = self.main_gate().assign_value(ctx, e.map(|v| *v))?;
            message_cells.push(e.clone());
            self.update(&[e.clone()]);
        }

        let mut padding_offset = 0;
        // Apply permutation to `RATE`Ï sized chunks
        for chunk in input_elements.chunks(RATE) {
            padding_offset = RATE - chunk.len();
            self.permutation(ctx, chunk.to_vec())?;

            // (0..MESSAGE_CAPACITY).for_each(|i| {
            self.state.0[1] = self
                .main_gate()
                .add(ctx, &self.state.0[1], &input_elements[0])?;

            // });

            self.state.0[2] = self
                .main_gate()
                .add(ctx, &self.state.0[2], &input_elements[1])?;

            self.state.0[3] = self
                .main_gate()
                .add(ctx, &self.state.0[3], &input_elements[2])?;
        }

        // If last chunking is full apply another permutation for collution resistance
        if padding_offset == 0 {
            self.permutation(ctx, vec![])?;
        }

        Ok(self.state.0[1].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{PoseidonEncChip, PoseidonEncConfig, PoseidonEncKey};

    const NUMBER_OF_LIMBS: usize = 4;
    const BIT_LEN: usize = 68;
    const T: i32 = 5;
    const RATE: i32 = 4;

    const MESSAGE_CAPACITY: usize = 2;

    use ff::{Field, PrimeField};
    use halo2wrong::halo2::plonk::{Circuit, ConstraintSystem};
    use maingate::{
        mock_prover_verify, AssignedValue, MainGate, MainGateConfig, MainGateInstructions,
        RegionCtx, Term,
    };
    // use halo2::{halo2curves::ff::PrimeField, circuit::AssignedCell};
    use halo2wrong::halo2::plonk::Error;
    use poseidon::{Poseidon, SparseMDSMatrix, Spec, State};

    // use crate::encryption::poseidon::MESSAGE_CAPACITY;

    use halo2wrong::curves::bn256;
    use halo2wrong::halo2::circuit::{Chip, Layouter, SimpleFloorPlanner, Value};
    use proptest::test_runner::Config;
    use rand_core::OsRng;

    struct PoseidonEncCircuit<F: PrimeField, const T: usize, const RATE: usize> {
        spec: Spec<F, T, RATE>,
        n: usize,
        inputs: Value<Vec<F>>,
        expected: Value<F>,
    }

    // #[derive(Debug, Clone)]
    // pub struct PoseidonEncChip<
    //     F: PrimeField,
    //     const NUMBER_OF_LIMBS: usize,
    //     const BIT_LEN: usize,
    //     const T: usize,
    //     const RATE: usize,
    // > {
    //     state: AssignedState<F, T>,
    //     absorbing: Vec<AssignedValue<F>>,
    //     spec: Spec<F, T, RATE>,
    //     main_gate_config: MainGateConfig,
    // }

    impl<F: PrimeField, const T: usize, const RATE: usize> Circuit<F>
        for PoseidonEncCircuit<F, T, RATE>
    {
        type Config = PoseidonEncConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            todo!()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            PoseidonEncConfig::new::<F>(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let main_gate = MainGate::<F>::new(config.main_gate_config.clone());

            layouter.assign_region(
                || "region 0",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let mut pose_enc_chip =
                        PoseidonEncChip::<F, NUMBER_OF_LIMBS, BIT_LEN, T, RATE>::configure(
                            ctx,
                            &self.spec,
                            &config.main_gate_config.clone(),
                        )?;

                    for e in self.inputs.as_ref().transpose_vec(self.n) {
                        let e = main_gate.assign_value(ctx, e.map(|e| *e))?;
                        println!("{:?}", e);
                        pose_enc_chip.update(&[e.clone()]);
                    }

                    let nonce = F::random(OsRng);
                    // let mut message = [F::ZERO; MESSAGE_CAPACITY];
                    let message = vec![F::ZERO, F::ZERO];

                    let key = PoseidonEncKey::<F> {
                        key0: F::random(OsRng),
                        key1: F::random(OsRng),
                    };

                    let challenge = pose_enc_chip.encrypt(ctx, &key, nonce, &message)?;
                    let expected = main_gate.assign_value(ctx, self.expected)?;
                    main_gate.assert_equal(ctx, &challenge, &expected)?;

                    Ok(())
                },
            )?;

            // config.config_range(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn enc_example() {
        //use crate::curves::bn256::{Fr, G1Affine};
        use halo2wrong::curves::bn256::Fr;
        for number_of_inputs in 0..3 * 3 {
            println!("{:?}", number_of_inputs);
            let mut ref_hasher = Poseidon::<Fr, 5, 4>::new(8, 57);
            let spec = Spec::<Fr, 5, 4>::new(8, 57);

            let inputs: Vec<Fr> = (0..number_of_inputs)
                .map(|_| Fr::random(OsRng))
                .collect::<Vec<Fr>>();

            ref_hasher.update(&inputs[..]);
            let expected = ref_hasher.squeeze();

            let circuit: PoseidonEncCircuit<Fr, 5, 4> = PoseidonEncCircuit {
                spec: spec.clone(),
                n: number_of_inputs,
                inputs: Value::known(inputs),
                expected: Value::known(expected),
            };
            let instance = vec![vec![]];
            mock_prover_verify(&circuit, instance);
        }
    }
}
