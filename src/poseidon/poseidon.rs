use crate::poseidon::spec::{Spec, State};
use halo2curves::group::ff::{FromUniformBytes, PrimeField};
use maingate::AssignedValue;

/// output when desired
#[derive(Debug, Clone)]
pub struct Poseidon<F: PrimeField, const T: usize, const RATE: usize> {
    /// publify state for usage
    pub state: State<F, T>,
    spec: Spec<F, T, RATE>,
    absorbing: Vec<F>,
}

impl<F: FromUniformBytes<64>, const T: usize, const RATE: usize> Poseidon<F, T, RATE> {
    /// Constructs a clear state poseidon instance
    pub fn new_enc(r_f: usize, r_p: usize, k0: F, k1: F) -> Self {
        Self {
            spec: Spec::new(r_f, r_p),
            state: State::init_state([F::ZERO, F::ZERO, k0, k1, F::ONE]),
            // state: State::default(),
            absorbing: Vec::new(),
        }
    }
    /// Constructs a state for poseidon hash
    pub fn new_hash(r_f: usize, r_p: usize) -> Self {
        Self {
            spec: Spec::new(r_f, r_p),
            state: State::default(),
            absorbing: Vec::new(),
        }
    }

    /// perm_with_input
    pub fn perm_with_input(&mut self, elements: &[F]) {
        let mut input_elements = self.absorbing.clone();
        input_elements.extend_from_slice(elements);

        for chunk in input_elements.chunks(RATE) {
            if chunk.len() < RATE {
                // Must be the last iteration of this update. Feed unpermutaed inputs to the
                // absorbation line
                self.absorbing = chunk.to_vec();
            } else {
                // Add new chunk of inputs for the next permutation cycle.
                for (input_element, state) in chunk.iter().zip(self.state.0.iter_mut().skip(1)) {
                    state.add_assign(input_element);
                }
                // Perform intermediate permutation
                self.spec.permute(&mut self.state);
                // Flush the absorption line
                self.absorbing.clear();
            }
        }
    }

    /// Results a single element by absorbing already added inputs
    /// if set h_flag = 1, the add additional padding F::ONE
    pub fn perm_remain(&mut self, h_flag: usize) -> F {
        let mut last_chunk = self.absorbing.clone();
        {
            // Expect padding offset to be in [0, RATE)
            debug_assert!(last_chunk.len() < RATE);
        }
        // Add the finishing sign of the variable length hashing. Note that this mut
        // also apply when absorbing line is empty
        if h_flag == 1 {
            last_chunk.push(F::ONE);
        }

        for (input_element, state) in last_chunk.iter().zip(self.state.0.iter_mut().skip(1)) {
            state.add_assign(input_element);
        }

        // Perform final permutation
        self.spec.permute(&mut self.state);
        // Flush the absorption line
        self.absorbing.clear();
        // Returns the challenge while preserving internal state
        self.state.result()
    }
}
