use std::{default, marker::PhantomData};

use ff::{Field, FromUniformBytes, PrimeField};
use halo2wrong::curves::bn256;
use poseidon::{Poseidon, Spec};
use rand_core::OsRng;

use crate::poseidon::{
    self,
    chip::{FULL_ROUND, PARTIAL_ROUND},
};

pub const MESSAGE_CAPACITY: usize = 2; //max 31
pub const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;

#[derive(Copy, Clone, Debug, Default)]
pub struct PoseidonEncKey<F: PrimeField> {
    pub key0: F,
    pub key1: F,
}

impl<F: PrimeField> PoseidonEncKey<F> {
    /// The default impl for key
    pub const fn init() -> Self {
        PoseidonEncKey {
            // wooju - TODO: randomize
            key0: F::ZERO,
            key1: F::ZERO,
        }
    }

    pub fn set_key(&mut self, k0: F, k1: F) {
        self.key0 = k0;
        self.key1 = k1;
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PoseidonCipher<
    F: PrimeField + FromUniformBytes<64>,
    const r_f: usize,
    const r_p: usize,
    const T: usize,
    const RATE: usize,
> {
    // cipher_bytes_size: usize,
    pub cipherKey: [F; 2],
    pub cipherByteSize: usize,
    pub cipher: [F; CIPHER_SIZE],
}

impl<F, const r_f: usize, const r_p: usize, const T: usize, const RATE: usize>
    PoseidonCipher<F, r_f, r_p, T, RATE>
where
    F: PrimeField + FromUniformBytes<64>,
{
    pub const fn new(enc_key: [F; 2]) -> Self {
        Self {
            cipherKey: enc_key,
            cipherByteSize: CIPHER_SIZE * (F::NUM_BITS as usize) / 8,
            cipher: [F::ZERO; CIPHER_SIZE],
            // _spec: PhantomData,
        }
    }

    pub const fn capacity() -> usize {
        MESSAGE_CAPACITY
    }
    pub const fn cipher_size() -> usize {
        CIPHER_SIZE
    }

    pub fn initial_state(&self, nonce: F) -> [F; 5] {
        // zeroknight - 5 : T ?!
        [
            // Domain - Maximum plaintext length of the elements of Fq, as defined
            // F::from_u128(0x100000000 as u128),
            // F::from_u128(MESSAGE_CAPACITY as u128),
            F::ZERO,
            F::ZERO,
            // F::ZERO,
            // F::ZERO,
            self.cipherKey[0],
            self.cipherKey[1],
            nonce,
        ]
    }

    pub fn encrypt(&mut self, message: &[F], nonce: &F) -> [F; CIPHER_SIZE] {
        let mut encrypter = Poseidon::<F, T, RATE>::new_enc(
            FULL_ROUND,
            PARTIAL_ROUND,
            self.cipherKey[0],
            self.cipherKey[1],
        );

        // println!("ref_hahser state: {:?}", encrypter.state.words().clone());

        let mut cipher = [F::ZERO; CIPHER_SIZE];

        // zeroknight : permutation is update in Poseidon
        encrypter.perm_with_input(&vec![]);
        encrypter.perm_remain(0);

        // println!("ref_hahser state2: {:?}", encrypter.state.words().clone());

        let mut i = 0;

        for inputs in message.chunks(RATE) {
            for (word, input) in encrypter
                .state
                .words()
                .iter_mut()
                .skip(1)
                .zip(inputs.iter())
            {
                *word = word.add(input);
                if i < MESSAGE_CAPACITY {
                    cipher[i] = word.clone();
                    i += 1;
                }
            }
            if inputs.len() == RATE {
                encrypter.perm_with_input(&inputs);
            } else {
                encrypter.perm_remain(0);
            }
        }
        // encrypter.perm_with_input(&[]);

        cipher[MESSAGE_CAPACITY] = encrypter.state.words()[1].clone();

        self.cipher = cipher;

        cipher
    }

    pub fn decrypt(&mut self, nonce: &F) -> Option<[F; MESSAGE_CAPACITY]> {
        let mut encrypter = Poseidon::<F, T, RATE>::new_enc(
            FULL_ROUND,
            PARTIAL_ROUND,
            self.cipherKey[0],
            self.cipherKey[1],
        );

        let mut message = [F::ZERO; MESSAGE_CAPACITY];

        encrypter.perm_with_input(&vec![]);
        encrypter.perm_remain(0);

        let mut state_2 = encrypter.state.words().clone();

        (0..MESSAGE_CAPACITY).for_each(|i| {
            message[i] = self.cipher[i] - state_2[(i + 1) % T];
            state_2[(i + 1) % T] = self.cipher[i];
        });

        encrypter.perm_with_input(&mut message);
        encrypter.perm_remain(0);

        let state_3 = encrypter.state.words().clone();

        if self.cipher[MESSAGE_CAPACITY] != state_3[1] {
            return None;
        }
        Some(message)
    }
}

#[test]
fn test_encryption() {
    let mut cipher = PoseidonCipher::<bn256::Fr, 8, 57, 5, 4>::new([bn256::Fr::ZERO; 2]);
    let message = [bn256::Fr::ZERO; MESSAGE_CAPACITY];

    println!("message: {:?}", message);

    let cipherText = cipher.encrypt(&message, &bn256::Fr::ONE);
    println!("encrypted: {:?}", cipherText);
    println!("decrypted: {:?}", cipher.decrypt(&bn256::Fr::ONE));
}
