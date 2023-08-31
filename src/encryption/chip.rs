use std::{marker::PhantomData, sync::Arc};

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

use crate::poseidon::{
    chip::{FULL_ROUND, PARTIAL_ROUND},
    *,
};
use rand_core::OsRng;

use crate::encryption::poseidon_enc::{
    PoseidonCipher, PoseidonEncKey, CIPHER_SIZE, MESSAGE_CAPACITY,
};

#[derive(Clone, Debug)]
pub struct PoseidonEncChip<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
    const R_F: usize,
    const R_P: usize,
> {
    pub pose_chip: PoseidonChip<F, T, RATE, R_F, R_P>,
    pose_key0: F,
    pose_key1: F,
}

impl<
        F: PrimeField + FromUniformBytes<64>,
        const R_F: usize,
        const R_P: usize,
        const T: usize,
        const RATE: usize,
    > PoseidonEncChip<F, T, RATE, R_F, R_P>
{
    pub fn new(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
        sk: [F; 2],
    ) -> Result<Self, Error> {
        let enc_chip = PoseidonChip::<F, T, RATE, R_F, R_P>::new_enc(
            ctx,
            spec,
            &main_gate_config,
            &sk[0],
            &sk[1],
        )?;

        // let enc_key = PoseidonEncKey::<F>::init();

        Ok(Self {
            pose_chip: enc_chip,
            pose_key0: sk[0],
            pose_key1: sk[1],
        })
    }

    /// add the inputs in absorbing and return
    pub fn absorb_and_relese(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mut cipher_text = vec![];
        // Get elements to be encrypted
        let input_elements = self.pose_chip.absorbing.clone();
        let main_gate = self.pose_chip.main_gate();

        // println!("input_elements len: {:?}", input_elements.len());

        // Flush the input que
        self.pose_chip.absorbing.clear();

        let mut i = 0;

        // Apply permutation to `RATE` sized chunks
        for inputs in input_elements.chunks(RATE) {
            // let pre_constants = &[F::ZERO;T];
            println!("chunklen{:?}", inputs.len());

            

            // Add inputs along with constants
            for (word, input) in self.pose_chip.state.0.iter_mut().skip(1).zip(inputs.iter()) {
                *word = main_gate.add(ctx, word, input)?;
                if i < MESSAGE_CAPACITY {
                    cipher_text.push(word.clone());
                    i += 1;
                }
            }

            println!("i counter{:?}", i);

            self.pose_chip.permutation(ctx, inputs.to_vec())?;
            
        }

        cipher_text.push(self.pose_chip.state.0[1].clone());

        Ok(cipher_text)
    }
}

pub(crate) struct PoseidonEncCircuit<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    // Poseidon
    pub spec: Spec<F, T, RATE>, // Spec for Poseidon Encryption
    pub num_input: usize,       // zeroknight - ??
    pub message: Value<Vec<F>>, // message to be encrypted
    pub key: [F; 2],            // the pub setting depend on usage
    pub expected: Vec<F>,       // expected cipher text
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for PoseidonEncCircuit<F, T, RATE>
{
    type Config = MainGateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);

        main_gate_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let main_gate = MainGate::<F>::new(config.clone());

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
                let mut pos_enc_chip =
                    PoseidonEncChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new(
                        ctx, &self.spec, &config, self.key,
                    )?;

                // check the assigned initial state
                // println!("\nzk_state: {:?}", pos_enc_chip.state.0);

                // permute before state message addtion
                pos_enc_chip.pose_chip.permutation(ctx, vec![])?;

                // check the permuted state
                // println!("zk_state2: {:?}\n", pos_enc_chip.state.0);

                // set the message to be an input to the encryption
                for e in self.message.as_ref().transpose_vec(self.num_input) {
                    let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
                    pos_enc_chip.pose_chip.set_inputs(&[e.clone()]);
                }

                // add the input to the currentn state and output encrypted result
                let cipher_text = pos_enc_chip.absorb_and_relese(ctx)?;

                println!("cipher: {:?}", cipher_text);
                println!("expected cipher: {:?}\n", expected_result);
                println!("cipher len: {:?}", cipher_text.len());

                // constrain with encryption result
                // println!("check out equality..");
                for i in 0..cipher_text.len() {
                    main_gate.assert_equal(ctx, &cipher_text[i], &expected_result[i])?;
                }
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
        let key = PoseidonEncKey::<F> {
            key0: F::random(OsRng),
            key1: F::random(OsRng),
        };

        let mut ref_pos_enc =
            PoseidonCipher::<F, FULL_ROUND, PARTIAL_ROUND, T, RATE>::new([key.key0, key.key1]);

        let spec = Spec::<F, T, RATE>::new(8, 57);
        let inputs = (0..(MESSAGE_CAPACITY)).map(|_| F::ZERO).collect::<Vec<F>>();

        //== Poseidon Encryption ==//

        let ref_cipher = ref_pos_enc.encrypt(&inputs, &F::ONE);

        //== Circuit ==//

        let circuit = PoseidonEncCircuit::<F, T, RATE> {
            spec: spec.clone(),
            num_input: MESSAGE_CAPACITY,
            message: Value::known(inputs),
            key: [key.key0, key.key1],
            expected: ref_cipher.to_vec(),
        };

        let public_inputs = vec![vec![]];
        mock_prover_verify(&circuit, public_inputs);
    }
    use halo2wrong::curves::bn256::Fr as BnFr;

    run::<BnFr, 5, 4>();
}
