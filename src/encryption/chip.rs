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

use crate::{
    encryption::poseidon_enc::{
        PoseidonCipher, PoseidonCipherKey, CIPHER_SIZE, FULL_ROUND, MESSAGE_CAPACITY, PARTIAL_ROUND,
    },
    poseidon,
};

#[derive(Debug, Clone)]
pub struct AssignedState<F: PrimeField, const T: usize>(pub [AssignedValue<F>; T]);

#[derive(Clone, Debug)]
pub struct PoseidonCipherConfig {
    pub main_gate_config: MainGateConfig,
}

#[derive(Debug, Clone)]
pub struct PoseidonChip<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
    const R_F: usize,
    const R_P: usize,
> {
    pub state: AssignedState<F, T>,
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
    // Construct main gate
    pub fn main_gate(&self) -> MainGate<F> {
        MainGate::<_>::new(self.main_gate_config.clone())
    }

    // Construct PoseidonChip
    pub fn new(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
        key0: &F,
        key1: &F,
    ) -> Result<Self, Error> {
        let main_gate = MainGate::<_>::new(main_gate_config.clone());
        let state = [
            // Domain - Maximum plaintext length of the elements of Fq, as defined
            // F::from_u128(0x100000000 as u128),
            // F::from_u128(MESSAGE_CAPACITY_TEST as u128),
            // *key0,
            // *key1,

            // debuging purpose
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
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
            *word = main_gate.add_constant(ctx, word, *constant)?;
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

        Ok(()) // zeroknight
    }

    pub fn absorb_and_relese(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mut cipher_text = vec![];
        // Get elements to be encrypted
        let input_elements = self.absorbing.clone();
        let main_gate = self.main_gate();

        println!("input_elements len: {:?}", input_elements.len());

        // Flush the input que
        self.absorbing.clear();
        // Apply permutation to `RATE` sized chunks
        for inputs in input_elements.chunks(RATE) {
            // let pre_constants = &[F::ZERO;T];

            let mut i = 0;

            // Add inputs along with constants
            for (word, input) in self.state.0.iter_mut().skip(1).zip(inputs.iter()) {
                *word = main_gate.add(ctx, word, input)?;
                if i < MESSAGE_CAPACITY {
                    cipher_text.push(word.clone());
                    i += 1;
                }
            }

            self.permutation(ctx, inputs.to_vec())?;
            cipher_text.push(self.state.0[1].clone());
        }

        Ok(cipher_text)
    }
}

pub(crate) struct PoseidonCipherCircuit<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    // Poseidon
    pub spec: Spec<F, T, RATE>, // Spec for Poseidon Encryption
    pub num_input: usize,       // zeroknight - ??
    pub message: Value<Vec<F>>, // message to be encrypted
    pub key: PoseidonCipherKey<F>,
    pub expected: Vec<F>, // expected cipher text
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for PoseidonCipherCircuit<F, T, RATE>
{
    type Config = PoseidonCipherConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);
        PoseidonCipherConfig { main_gate_config }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let main_gate = MainGate::<F>::new(config.main_gate_config.clone());

        layouter.assign_region(
            || "poseidon cipher",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let mut expected_result = vec![];

                // assign expected result
                for result in &self.expected {
                    let result = main_gate.assign_value(ctx, Value::known(result.clone()))?;
                    expected_result.push(result);
                }

                // == Encryption ciruit ==//

                // new assigns initial_state into cells.
                let mut pos_enc_chip = PoseidonChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new(
                    ctx,
                    &self.spec,
                    &config.main_gate_config,
                    &self.key.key0,
                    &self.key.key1,
                )?;

                // check the assigned initial state
                println!("\nzk_state: {:?}", pos_enc_chip.state.0);

                // permute before state message addtion
                pos_enc_chip.permutation(ctx, vec![])?;

                // check the permuted state
                println!("zk_state2: {:?}\n", pos_enc_chip.state.0);

                // set the message to be an input to the encryption
                for e in self.message.as_ref().transpose_vec(self.num_input) {
                    let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
                    pos_enc_chip.set_inputs(&[e.clone()]);
                }

                // add the input to the currentn state and output encrypted result
                let cipher_text = pos_enc_chip.absorb_and_relese(ctx)?;

                println!("cipher: {:?}", cipher_text);
                println!("expected cipher: {:?}\n", expected_result);
                println!("cipher len: {:?}", cipher_text.len());

                // constrain with encryption result
                println!("check out equality..");
                let _ = main_gate.assert_equal(ctx, &cipher_text[0], &expected_result[0])?;
                let _ = main_gate.assert_equal(ctx, &cipher_text[1], &expected_result[1])?;
                let _ = main_gate.assert_equal(ctx, &cipher_text[2], &expected_result[2])?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

#[test]
fn test_pos_enc() {
    use crate::encryption::poseidon_enc::*;

    fn run<F: FromUniformBytes<64> + Ord, const T: usize, const RATE: usize>() {
        let mut ref_pos_enc = PoseidonCipher::<F, FULL_ROUND, PARTIAL_ROUND, T, RATE>::new();

        let spec = Spec::<F, T, RATE>::new(8, 57);
        let inputs = (0..(MESSAGE_CAPACITY)).map(|_| F::ZERO).collect::<Vec<F>>();

        //== Poseidon Encryption ==//

        let ref_cipher = ref_pos_enc.encrypt(&inputs, &F::ONE);

        let key = PoseidonCipherKey::<F> {
            key0: F::random(OsRng),
            key1: F::random(OsRng),
        };
        //== Circuit ==//

        let circuit = PoseidonCipherCircuit::<F, T, RATE> {
            spec: spec.clone(),
            num_input: MESSAGE_CAPACITY,
            message: Value::known(inputs),
            key: key.clone(),
            expected: ref_cipher.to_vec(),
        };

        let public_inputs = vec![vec![]];
        mock_prover_verify(&circuit, public_inputs);
    }
    use halo2wrong::curves::bn256::Fr as BnFr;

    run::<BnFr, 5, 4>();
}
