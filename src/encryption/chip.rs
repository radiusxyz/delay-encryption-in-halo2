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
    PoseidonCipher, PoseidonCipherKey, CIPHER_SIZE, MESSAGE_CAPACITY,
};

// wooju - TODO: making as instruction? a form of trait impl
//               and making EncChip
impl<
        F: PrimeField + FromUniformBytes<64>,
        const R_F: usize,
        const R_P: usize,
        const T: usize,
        const RATE: usize,
    > PoseidonChip<F, T, RATE, R_F, R_P>
{
    /// add the inputs in absorbing and return
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

#[derive(Clone, Debug)]
pub struct PoseidonCipherConfig {
    pub main_gate_config: MainGateConfig,
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
