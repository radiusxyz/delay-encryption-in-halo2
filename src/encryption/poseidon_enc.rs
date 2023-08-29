use std::{default, marker::PhantomData};

use ff::{Field, FromUniformBytes, PrimeField};
use halo2wrong::curves::bn256;
use poseidon::{Poseidon, Spec};
use rand_core::OsRng;

use crate::poseidon;

pub const MESSAGE_CAPACITY: usize = 2;
pub const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;
pub(crate) const FULL_ROUND: usize = 8;
pub(crate) const PARTIAL_ROUND: usize = 57;

#[derive(Copy, Clone, Debug, Default)]
pub struct PoseidonCipherKey<F: PrimeField> {
    pub key0: F,
    pub key1: F,
}

impl<F: PrimeField> PoseidonCipherKey<F> {
    /// The default impl for key
    const fn init() -> Self {
        PoseidonCipherKey {
            key0: F::ZERO,
            key1: F::ZERO,
        }
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
    pub cipherKey: PoseidonCipherKey<F>,
    pub cipherByteSize: usize,
    pub cipher: [F; CIPHER_SIZE],
    _spec: PhantomData<F>,
}

impl<F, const r_f: usize, const r_p: usize, const T: usize, const RATE: usize>
    PoseidonCipher<F, r_f, r_p, T, RATE>
where
    F: PrimeField + FromUniformBytes<64>,
{
    pub const fn new() -> Self {
        Self {
            cipherKey: PoseidonCipherKey::<F>::init(),
            cipherByteSize: CIPHER_SIZE * (F::NUM_BITS as usize) / 8,
            cipher: [F::ZERO; CIPHER_SIZE],
            _spec: PhantomData,
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
            F::ZERO,
            F::ZERO,
            // self.cipherKey.key0,
            // self.cipherKey.key1,
            nonce,
        ]
    }

    pub fn encrypt(&mut self, message: &[F], nonce: &F) -> [F; CIPHER_SIZE] {
        let mut encrypter = Poseidon::<F, T, RATE>::new_enc(FULL_ROUND, PARTIAL_ROUND);

        println!("ref_hahser state: {:?}", encrypter.state.words().clone());

        let mut cipher = [F::ZERO; CIPHER_SIZE];

        // zeroknight : permutation is update in Poseidon
        encrypter.perm_with_input(&vec![]);
        encrypter.perm_remain(0);

        println!("ref_hahser state2: {:?}", encrypter.state.words().clone());

        let mut state_2 = encrypter.state.words().clone();

        (0..MESSAGE_CAPACITY).for_each(|i| {
            state_2[i + 1] += if i < message.len() {
                message[i]
            } else {
                F::ZERO
            };
            cipher[i] = state_2[i + 1];
        });
        encrypter.perm_with_input(&message);
        encrypter.perm_remain(0);

        let state_3 = encrypter.state.words().clone();
        cipher[MESSAGE_CAPACITY] = state_3[1];

        self.cipher = cipher;

        cipher
    }

    pub fn decrypt(&mut self, nonce: &F) -> Option<[F; MESSAGE_CAPACITY]> {
        let mut encrypter = Poseidon::<F, T, RATE>::new_enc(FULL_ROUND, PARTIAL_ROUND);

        let mut message = [F::ZERO; MESSAGE_CAPACITY];

        encrypter.perm_with_input(&vec![]);
        encrypter.perm_remain(0);

        let mut state_2 = encrypter.state.words().clone();

        (0..MESSAGE_CAPACITY).for_each(|i| {
            message[i] = self.cipher[i] - state_2[i + 1];
            state_2[i + 1] = self.cipher[i];
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
    let mut cipher = PoseidonCipher::<bn256::Fr, 8, 57, 5, 4>::new();
    let message = [bn256::Fr::ZERO; MESSAGE_CAPACITY];

    println!("message: {:?}", message);

    let cipherText = cipher.encrypt(&message, &bn256::Fr::ONE);
    println!("encrypted: {:?}", cipherText);
    println!("decrypted: {:?}", cipher.decrypt(&bn256::Fr::ONE));
}
