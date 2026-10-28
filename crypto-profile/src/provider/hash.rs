// Ported from rustls 0.23.46 (src/crypto/ring/hash.rs), Copyright (c) 2016 Joseph Birr-Pixton,
// used under the MIT license. See LICENSE-THIRD-PARTY.
use aws_lc_rs::digest;
use rustls::crypto;
use rustls::crypto::hash::HashAlgorithm;

pub(crate) static SHA256: Hash = Hash(&digest::SHA256, HashAlgorithm::SHA256);
pub(crate) static SHA384: Hash = Hash(&digest::SHA384, HashAlgorithm::SHA384);

pub(crate) struct Hash(&'static digest::Algorithm, HashAlgorithm);

impl crypto::hash::Hash for Hash {
    fn start(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(HashContext(digest::Context::new(self.0)))
    }

    fn hash(&self, bytes: &[u8]) -> crypto::hash::Output {
        let mut ctx = digest::Context::new(self.0);
        ctx.update(bytes);
        convert(ctx.finish())
    }

    fn output_len(&self) -> usize {
        self.0.output_len()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.1
    }

    fn fips(&self) -> bool {
        super::assembly::fips()
    }
}

struct HashContext(digest::Context);

impl crypto::hash::Context for HashContext {
    fn fork_finish(&self) -> crypto::hash::Output {
        convert(self.0.clone().finish())
    }

    fn fork(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> crypto::hash::Output {
        convert(self.0.finish())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

fn convert(val: digest::Digest) -> crypto::hash::Output {
    crypto::hash::Output::new(val.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::hash::Hash as _;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha2_of_abc_and_the_streaming_paths_agree() {
        for (h, len, alg, want) in [
            (
                &SHA256,
                32,
                HashAlgorithm::SHA256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                &SHA384,
                48,
                HashAlgorithm::SHA384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
        ] {
            assert_eq!(hex(h.hash(b"abc").as_ref()), want);
            assert_eq!((h.output_len(), h.algorithm()), (len, alg));
            let mut ctx = h.start();
            ctx.update(b"a");
            let fork = ctx.fork();
            ctx.update(b"bc");
            assert_eq!(hex(ctx.fork_finish().as_ref()), want);
            assert_eq!(hex(ctx.finish().as_ref()), want);
            assert_eq!(fork.finish().as_ref(), h.hash(b"a").as_ref());
            assert!(h.fips());
        }
    }
}
