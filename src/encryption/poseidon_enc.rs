use ff::{Field, FromUniformBytes, PrimeField};
use halo2wrong::curves::bn256;
use poseidon::Poseidon;
use rand_core::Error;

use crate::poseidon::{
    self,
    chip::{FULL_ROUND, PARTIAL_ROUND},
};

pub const MESSAGE_CAPACITY: usize = 33;
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

#[derive(Debug, Clone, Copy)]
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

impl<F, const r_f: usize, const r_p: usize, const T: usize, const RATE: usize> Default
    for PoseidonCipher<F, r_f, r_p, T, RATE>
where
    F: PrimeField + FromUniformBytes<64> + Default,
{
    fn default() -> Self {
        PoseidonCipher {
            cipherKey: [F::default(); 2],
            cipherByteSize: Default::default(),
            cipher: [F::default(); CIPHER_SIZE], // CIPHER_SIZE에 따라
        }
    }
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

    pub fn encrypt(&mut self, message: &[F], nonce: &F) -> Result<[F; CIPHER_SIZE], Error> {
        let mut encrypter = Poseidon::<F, T, RATE>::new_enc(
            FULL_ROUND,
            PARTIAL_ROUND,
            self.cipherKey[0],
            self.cipherKey[1],
        );

        // println!("ref_hahser state: {:?}", encrypter.state.words().clone());

        let mut cipher = [F::ZERO; CIPHER_SIZE];

        // zeroknight : permutation is update in Poseidon
        encrypter.update(&vec![]);
        encrypter.squeeze(0);

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
                *word = word.add(input); // c = s + m, m = c - s
                if i < MESSAGE_CAPACITY {
                    // c_n = p(s+m) + m_n
                    cipher[i] = word.clone();
                    i += 1;
                }
            }

            encrypter.update(&inputs);
            if inputs.len() < RATE {
                encrypter.squeeze(0);
            }
        }
        cipher[MESSAGE_CAPACITY] = encrypter.state.words()[1].clone();

        // println!("enc_cipher[MESSAGE_CAPACITY]:{:?}", cipher[MESSAGE_CAPACITY]);

        self.cipher = cipher;

        Ok(cipher)
    }
    pub fn decrypt(
        &mut self,
        cipher: &[F; CIPHER_SIZE],
        nonce: &F,
    ) -> Result<[F; MESSAGE_CAPACITY], Error> {
        let mut decrypter = Poseidon::<F, T, RATE>::new_enc(
            FULL_ROUND,
            PARTIAL_ROUND,
            self.cipherKey[0],
            self.cipherKey[1],
        );

        decrypter.update(&vec![]);
        decrypter.squeeze(0);

        let mut message = [F::ZERO; MESSAGE_CAPACITY];
        let mut i = 0;

        let parity = cipher[MESSAGE_CAPACITY];

        for chunk in cipher[..MESSAGE_CAPACITY].chunks(RATE) {
            for (word, encrypted_word) in
                decrypter.state.words().iter_mut().skip(1).zip(chunk.iter())
            {
                if i < MESSAGE_CAPACITY {
                    message[i] = encrypted_word.sub(word.clone());
                    i += 1;
                }
            }
            // println!(">>1. state:{:?}", decrypter.state.words());
            let offset = i % RATE;
            if offset == 0 {
                decrypter.update(&message[i - RATE..i]);
            } else {
                // if chunk.len() < RATE {
                decrypter.update(&message[i - offset..i]);
                decrypter.squeeze(0);
                // }
            }
        }
        if parity != decrypter.state.words()[1] {
            return Err(Error::new("Invalid cipher text"));
        }
        // println!(">>2. state:{:?}", decrypter.state.words());
        Ok(message)
    }
}

#[test]
fn test_encryption() {
    let mut cipher = PoseidonCipher::<bn256::Fr, 8, 57, 5, 4>::new([bn256::Fr::ZERO; 2]);
    let message = [bn256::Fr::ONE; MESSAGE_CAPACITY];

    println!("message: {:?}", message);

    let cipher_text = cipher.encrypt(&message, &bn256::Fr::ONE).unwrap();
    println!("encrypted: {:?}", cipher_text);
    println!(
        "decrypted: {:?}",
        cipher.decrypt(&cipher_text, &bn256::Fr::ONE).unwrap()
    );
}
