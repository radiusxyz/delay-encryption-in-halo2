pub mod big_integer;
use big_integer::*;

pub mod rsa;
use rsa::*;

pub mod poseidon;
use poseidon::*;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
