
use std::marker::PhantomData;

use ff::{PrimeField, FromUniformBytes, Field};
use halo2wrong::curves::bn256;
use poseidon::{Poseidon, Spec};
use rand_core::OsRng;

use super::Bn256MessageInfo;

use std::str::FromStr;

pub const MESSAGE_CAPACITY: usize = 10;
pub const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;

#[derive(Copy, Clone, Debug, Default)]
pub struct PoseidonCipherKey<F: PrimeField> {
    key0: F,
    key1: F,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PoseidonCipher<F: PrimeField + FromUniformBytes<64>, const r_f: usize, const r_p: usize,
                        const T: usize, const RATE: usize> {
                            cipher_bytes_size: usize,
                            _spec : PhantomData<F>,
                        }

impl<F, const r_f: usize, const r_p: usize, const T: usize, const RATE:usize> PoseidonCipher<F, r_f, r_p, T, RATE>
    where F: PrimeField + FromUniformBytes<64>,
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

    fn initial_state(key: &PoseidonCipherKey<F>, nonce: F) -> [F; 5]  {   // zeroknight : 5?!
        [
            // Domain - Maximum plaintext length of the elements of Fq, as defined
            F::from_u128(0x100000000 as u128),
            // The size of the message is constant because any absent input is replaced by zero
            F::from_u128(MESSAGE_CAPACITY as u128),
            key.key0,
            key.key1,
            nonce,
        ]
    }

    // zeroknight - need to generalize..
    pub fn get_message_bn256_vector(&self, message_bytes: &[u8]) -> [bn256::Fr; MESSAGE_CAPACITY] {// PoseidonCipher::capacity()] {
        let mut message_vecs: Vec<Vec<u8>> = message_bytes.to_vec().chunks(32).map(|s| s.into()).collect();
        let mut fields = Vec::new();

        for( _, message_vec) in message_vecs.iter_mut().enumerate() {
            let byte_length = message_vec.len();
            message_vec.resize(32, 0);
            
            let temp = &*message_vec;
            let message: [u8; 32] = temp.as_slice().try_into().unwrap();

            fields.push( Bn256MessageInfo::new(bn256::Fr::from_bytes(&message).unwrap(), byte_length));

        }

        let mut messages = [bn256::Fr::ZERO; MESSAGE_CAPACITY];
        let mut index = 0;

        for(_, bn256_info) in fields.iter().enumerate() {
            messages[index] = bn256_info.message;
            index += 1;
        }
        messages

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

    pub fn encrypt(&self, message:&[F], key: &PoseidonCipherKey<F>) -> ([F; CIPHER_SIZE], F) {
        let mut hasher = Poseidon::<F, T, RATE>::new(r_f, r_p);
        let nonce = F::random(OsRng);
        
        let mut cipher = [F::ZERO; CIPHER_SIZE];
        let count = (MESSAGE_CAPACITY +3) / 4;

        let mut state = PoseidonCipher::<F, r_f, r_p, T, RATE>::initial_state(key, nonce);

        (0..count).for_each(|i| {
            hasher.update(&state);

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
        hasher.update(&state);
        cipher[MESSAGE_CAPACITY] = state[1];

        (cipher, nonce)

    }

    pub fn decrypt(&self, cipherText: &[F;CIPHER_SIZE], key: &PoseidonCipherKey<F>, nonce: F ) -> Option<[F; MESSAGE_CAPACITY]> {
        let mut hasher = Poseidon::<F, T, RATE>::new(r_f,r_p);

        let mut message = [F::ZERO; MESSAGE_CAPACITY];
        let mut state = PoseidonCipher::<F, r_f, r_p, T, RATE>::initial_state(key, nonce);

        let count = (MESSAGE_CAPACITY + 3) / 4;

        (0..count).for_each(|i| {
            hasher.update(&state);

            (0..4).for_each(|j| {
                if 4 * i + j < MESSAGE_CAPACITY {
                    message[4 * i + j] = cipherText[4 * i + j] - state[j + 1];
                    state[j + 1] = cipherText[4 * i + j];
                }
            });
        });
        hasher.update(&state);

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

    let mut cipher = PoseidonCipher::<bn256::Fr, 8, 57, 5, 4>::new();
    let message = [bn256::Fr::random(OsRng); MESSAGE_CAPACITY];

    println!("message: {:?}", message);

    let (cipherText, nonce)  = cipher.encrypt(&message, &key);
    println!("encrypted: {:?}", cipherText );
    println!("decrypted: {:?}", cipher.decrypt(&cipherText, &key, nonce));
}


/*
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
*/