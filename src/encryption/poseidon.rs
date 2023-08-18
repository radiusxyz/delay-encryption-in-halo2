// halo2curves::group::ff::{FromUniformBytes, PrimeField}
use ff::{PrimeField, FromUniformBytes, Field};

use halo2wrong::curves::bn256;
use poseidon::{Spec, State, Poseidon};

// zeroknight - temp
const MESSAGE_CAPACITY: usize = 2;
const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;

#[derive(Copy, Clone, Debug, Default)]
pub struct SymmetricKey<F: PrimeField> {
    key0: F,
    key1: F,
}

pub struct PoseidonCipher<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> {
    // hasher: Poseidon<F, T, RATE>,
    r_f : usize,
    r_p : usize,
    cipherKey: SymmetricKey<F>,
    cipherByteSize: usize,

    // 
    pub cipher: [F; CIPHER_SIZE],
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> PoseidonCipher<F, T, RATE> {
    pub fn new(key: &SymmetricKey<F>, cipherByteSize: usize, r_f: usize, r_p: usize) -> Self {

        //let mut hasher = Poseidon::<F, T, RATE>::new(r_f, r_p);
        Self {
            r_f ,
            r_p ,
            cipherKey: *key,
            cipherByteSize,
            cipher: [F::ZERO; CIPHER_SIZE],
        }
    }

    pub const fn cipher_size_bytes(&self) -> usize {
        self.cipherByteSize
    }

    pub fn initial_state(&self, nonce: F) -> [F; 5] {  // zeroknight - 5 : T ?!
        [
            // Domain - Maximum plaintext length of the elements of Fq, as defined
            F::from_u128(0x100000000 as u128),
            F::from_u128(MESSAGE_CAPACITY as u128),
            self.cipherKey.key0,
            self.cipherKey.key1,
            nonce,
        ]
    }

    pub fn encrypt(&mut self, message:&[F], nonce: &F) {

        let mut hasher = Poseidon::<F, T, RATE>::new(self.r_f, self.r_p);

        let mut cipher = [F::ZERO; CIPHER_SIZE];
        let mut state = self.initial_state(*nonce);

        // zeroknight : permutation is update in Poseidon
        hasher.update(&state);
        (0..MESSAGE_CAPACITY).for_each(|i| {
            state[i + 1] += if i < message.len() {
                message[i]
            } else {
                F::ZERO
            };

            cipher[i] = state[i + 1];
        });
        hasher.update(&state);

        cipher[MESSAGE_CAPACITY] = state[1];

        self.cipher = cipher;
    }

    pub fn decrypt(&mut self, nonce: &F) -> Option<[F; MESSAGE_CAPACITY]>{
        let mut hasher = Poseidon::<F, T, RATE>::new(self.r_f, self.r_p);

        let mut message = [F::ZERO; MESSAGE_CAPACITY];
        let mut state = self.initial_state(*nonce);

        hasher.update(&mut state);

        (0..MESSAGE_CAPACITY).for_each(|i|{
            message[i] = self.cipher[i] - state[i+1];
            state[i+1] = self.cipher[i];
        });

        hasher.update(&mut state);
        
        if self.cipher[MESSAGE_CAPACITY] != state[1] {
            return None;
        }
        Some(message)

    }
}

#[test]
fn test() {
    use rand_core::OsRng;

    let key = SymmetricKey::<bn256::Fr> {
        key0 : bn256::Fr::random(OsRng),
        key1 : bn256::Fr::random(OsRng),
    };

    println!("key : {:?}", key);

    let mut cipher = PoseidonCipher::<bn256::Fr, 5, 4>  {
        r_f: 8,
        r_p: 57,
        cipherKey: key.clone(),
        cipherByteSize : CIPHER_SIZE * (bn256::Fr::NUM_BITS as usize) / (8 as usize),
        cipher: [bn256::Fr::ZERO; CIPHER_SIZE],
    };

    let message = [bn256::Fr::random(OsRng), bn256::Fr::random(OsRng)];
    println!("message : {:?}", message);

    cipher.encrypt(&message, &bn256::Fr::ONE);
    println!("encrypted: {:?}", );

    println!("decrypted : {:?}", cipher.decrypt(&bn256::Fr::ONE));

}