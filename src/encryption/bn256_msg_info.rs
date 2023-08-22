use std::fmt;

use halo2wrong::curves::bn256;

pub struct Bn256MessageInfo {
    pub message: bn256::Fr,
    byte_length: usize,
}

impl Bn256MessageInfo {
    pub const fn new(bn256_message: bn256::Fr, byte_length: usize) -> Self {
        Self {
            message: bn256_message,
            byte_length,
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        // zeroknight - must be some parameter 32 for bn256
        self.message.to_bytes()
    }
}

impl fmt::Debug for Bn256MessageInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //f.debug_struct("Bn256MessageInfo").field("message", &self.message).field("byte_length", &self.byte_length).finish()
        write!(
            f,
            "{{bn256: {:?}, bytelength: {}}}",
            self.message, self.byte_length
        )
    }
}
