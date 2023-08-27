use std::marker::PhantomData;

use ff::{Field, FromUniformBytes, PrimeField};
use halo2wrong::curves::bn256;
use poseidon::{Poseidon, Spec};
use rand_core::OsRng;

use std::str::FromStr;

use crate::poseidon;

pub const MESSAGE_CAPACITY: usize = 10;
pub const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;
pub(crate) const FULL_ROUND: usize = 8;
pub(crate) const PARTIAL_ROUND: usize = 57;

#[derive(Copy, Clone, Debug, Default)]
pub struct PoseidonCipherKey<F: PrimeField> {
    pub key0: F,
    pub key1: F,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PoseidonCipher<
    F: PrimeField + FromUniformBytes<64>,
    const r_f: usize,
    const r_p: usize,
    const T: usize,
    const RATE: usize,
> {
    cipher_bytes_size: usize,
    _spec: PhantomData<F>,
}

impl<F, const r_f: usize, const r_p: usize, const T: usize, const RATE: usize>
    PoseidonCipher<F, r_f, r_p, T, RATE>
where
    F: PrimeField + FromUniformBytes<64>,
{
    pub const fn new() -> Self {
        Self {
            cipher_bytes_size: CIPHER_SIZE * (F::NUM_BITS as usize) / 8,
            _spec: PhantomData,
        }
    }

    pub const fn capacity() -> usize {
        MESSAGE_CAPACITY
    }
    pub const fn cipher_size() -> usize {
        CIPHER_SIZE
    }

    pub fn initial_state(key: &PoseidonCipherKey<F>, nonce: F) -> [F; 5] {
        // zeroknight : 5?!
        [
            // Domain - Maximum plaintext length of the elements of Fq, as defined
            // F::from_u128(0x100000000 as u128),
            // F::from_u128(MESSAGE_CAPACITY_TEST as u128),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            // *key0,
            // *key1,
            F::ONE,
        ]
    }

    /*
    pub fn encrypt_string(&self, message: String, key: &PoseidonCipherKey<F>) -> (Vec<String>, F, [F; MESSAGE_CAPACITY], [F;CIPHER_SIZE]) {
        let message_bn256_vector = self.get_message_bn256_vector(message.as_bytes());

        let (cipher_field, nonce) = self.encrypt(message_bn256_vector as [F], key);
    }
    */
    /*
    pub fn to_bytes(cipherText: [F; CIPHER_SIZE]) -> Vec<u8> {
        let mut bytes : Vec<u8> = vec![];
        cipherText.iter().enumerate().for_each(|(i, c)| {
            let n = i * (F::NUM_BITS as usize) / 8;
            let mut currentBytes = c.to_repr().
            bytes.append(currentBytes);
        });

        bytes
    }
    */

    pub fn encrypt(&self, message: &[F], key: &PoseidonCipherKey<F>) -> ([F; CIPHER_SIZE], F) {
        let nonce = F::random(OsRng);

        let mut hasher = Poseidon::<F, T, RATE>::new(r_f, r_p);
        // let mut state = PoseidonCipher::<F, r_f, r_p, T, RATE>::initial_state(key, nonce);
        let mut state = hasher.state.0;

        let mut cipher = [F::ZERO; CIPHER_SIZE];
        let count = (MESSAGE_CAPACITY + 3) / 4;

        (0..count).for_each(|i| {
            hasher.perm_with_input(&vec![]);

            (0..4).for_each(|j| {
                if 4 * i + j < MESSAGE_CAPACITY {
                    state[j + 1] += if 4 * i + j < message.len() {
                        message[4 * i + j]
                    } else {
                        F::ZERO
                    };

                    cipher[4 * i + j] = state[j + 1];
                }
            })
        });
        hasher.perm_with_input(&state);
        cipher[MESSAGE_CAPACITY] = state[1];

        (cipher, nonce)
    }

    pub fn decrypt(
        &self,
        cipherText: &[F; CIPHER_SIZE],
        key: &PoseidonCipherKey<F>,
        nonce: F,
    ) -> Option<[F; MESSAGE_CAPACITY]> {
        let mut hasher = Poseidon::<F, T, RATE>::new(r_f, r_p);

        // let mut state = PoseidonCipher::<F, r_f, r_p, T, RATE>::initial_state(key, nonce);
        let mut state = hasher.state.0;

        let mut message = [F::ZERO; MESSAGE_CAPACITY];

        let count = (MESSAGE_CAPACITY + 3) / 4;

        (0..count).for_each(|i| {
            hasher.perm_with_input(&state);

            (0..4).for_each(|j| {
                if 4 * i + j < MESSAGE_CAPACITY {
                    message[4 * i + j] = cipherText[4 * i + j] - state[j + 1];
                    state[j + 1] = cipherText[4 * i + j];
                }
            });
        });
        hasher.perm_with_input(&state);

        if cipherText[MESSAGE_CAPACITY] != state[1] {
            return None;
        }

        Some(message)
    }
}

#[test]
fn test() {
    let key = PoseidonCipherKey::<bn256::Fr> {
        key0: bn256::Fr::random(OsRng),
        key1: bn256::Fr::random(OsRng),
    };

    let cipher = PoseidonCipher::<bn256::Fr, 8, 57, 5, 4>::new();
    let message = [bn256::Fr::random(OsRng); MESSAGE_CAPACITY];

    println!("message: {:?}", message);

    let (cipherText, nonce) = cipher.encrypt(&message, &key);
    println!("encrypted: {:?}", cipherText);
    println!("decrypted: {:?}", cipher.decrypt(&cipherText, &key, nonce));
}

// zeroknight - test : only support for poseidon encryption with message of length 2.
pub const MESSAGE_CAPACITY_TEST: usize = 2;
pub const CIPHER_SIZE_TEST: usize = MESSAGE_CAPACITY_TEST + 1;

pub struct PoseidonCipherTest<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    pub cipherKey: PoseidonCipherKey<F>,
    pub cipherByteSize: usize,
    pub cipher: [F; CIPHER_SIZE_TEST],
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    PoseidonCipherTest<F, T, RATE>
{
    pub fn new(key: &PoseidonCipherKey<F>, cipherByteSize: usize, r_f: usize, r_p: usize) -> Self {
        //let mut hasher = Poseidon::<F, T, RATE>::new(r_f, r_p);
        Self {
            cipherKey: *key,
            cipherByteSize,
            cipher: [F::ZERO; CIPHER_SIZE_TEST],
        }
    }

    pub const fn cipher_size_bytes(&self) -> usize {
        self.cipherByteSize
    }

    pub fn initial_state(&self, nonce: F) -> [F; 5] {
        // zeroknight - 5 : T ?!
        [
            // Domain - Maximum plaintext length of the elements of Fq, as defined
            // F::from_u128(0x100000000 as u128),
            // F::from_u128(MESSAGE_CAPACITY_TEST as u128),
            F::ZERO,
            F::ZERO,
            self.cipherKey.key0,
            self.cipherKey.key1,
            nonce,
        ]
    }

    pub fn hash(&mut self, message: &[F]) -> F {
        let mut hasher = Poseidon::<F, T, RATE>::new(FULL_ROUND, PARTIAL_ROUND);
        hasher.perm_with_input(&message[..]);
        hasher.perm_remain().clone()
    }

    pub fn encrypt(&mut self, message: &[F], nonce: &F) {
        let mut hasher = Poseidon::<F, T, RATE>::new(FULL_ROUND, PARTIAL_ROUND);

        println!("ref_hahser state: {:?}", hasher.state.words().clone());

        let mut cipher = [F::ZERO; CIPHER_SIZE_TEST];
        let mut state = self.initial_state(*nonce);

        // zeroknight : permutation is update in Poseidon
        hasher.perm_with_input(&vec![]);
        hasher.perm_remain();

        println!("ref_hahser state2: {:?}", hasher.state.words().clone());

        let mut state_2 = hasher.state.words().clone();

        (0..MESSAGE_CAPACITY_TEST).for_each(|i| {
            state_2[i + 1] += if i < message.len() {
                message[i]
            } else {
                F::ZERO
            };
            cipher[i] = state_2[i + 1];
        });
        hasher.perm_with_input(&message);
        hasher.perm_remain();

        let mut state_3 = hasher.state.words().clone();
        cipher[MESSAGE_CAPACITY_TEST] = state_3[1];

        self.cipher = cipher;
    }

    pub fn decrypt(&mut self, nonce: &F) -> Option<[F; MESSAGE_CAPACITY_TEST]> {
        let mut hasher = Poseidon::<F, T, RATE>::new(FULL_ROUND, PARTIAL_ROUND);

        let mut message = [F::ZERO; MESSAGE_CAPACITY_TEST];
        let mut state = self.initial_state(*nonce);

        hasher.perm_with_input(&vec![]);
        hasher.perm_remain();

        let mut state_2 = hasher.state.words().clone();

        (0..MESSAGE_CAPACITY_TEST).for_each(|i| {
            message[i] = self.cipher[i] - state_2[i + 1];
            state_2[i + 1] = self.cipher[i];
        });

        hasher.perm_with_input(&mut message);
        hasher.perm_remain();

        let mut state_3 = hasher.state.words().clone();

        if self.cipher[MESSAGE_CAPACITY_TEST] != state_3[1] {
            return None;
        }
        Some(message)
    }
}

#[test]
fn test_poseidon_encryption_simple() {
    use rand_core::OsRng;

    let key = PoseidonCipherKey::<bn256::Fr> {
        // key0: bn256::Fr::random(OsRng),
        // key1: bn256::Fr::random(OsRng),
        key0: bn256::Fr::ZERO,
        key1: bn256::Fr::ZERO,
    };

    println!("key : {:?}", key);

    let mut cipher = PoseidonCipherTest::<bn256::Fr, 5, 4> {
        cipherKey: key.clone(),
        cipherByteSize: CIPHER_SIZE_TEST * (bn256::Fr::NUM_BITS as usize) / (8 as usize),
        cipher: [bn256::Fr::ZERO; CIPHER_SIZE_TEST],
    };

    let message = [bn256::Fr::random(OsRng), bn256::Fr::random(OsRng)];
    println!("message : {:?}", message);

    cipher.encrypt(&message, &bn256::Fr::ONE);
    println!("encrypted: {:?}", cipher.cipher);
    println!("decrypted : {:?}", cipher.decrypt(&bn256::Fr::ONE));
}
