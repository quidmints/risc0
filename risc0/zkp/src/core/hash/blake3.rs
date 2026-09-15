// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A Blake3 HashSuite.
//!
//! ⭐ WHY THIS EXISTS, AND IT IS A DEPLOYMENT REASON RATHER THAN A CRYPTOGRAPHIC ONE.
//! Solana exposes `sol_blake3` as a SYSCALL. Measured on real SBPF: **146 CU** against
//! **4,392** for this crate's blake2b in software and **7,239** for sha-256 — 30x and
//! 49.6x. A verifier running on that chain can therefore hash almost for free, but ONLY
//! if the seal it checks was hashed the same way.
//!
//! 🔑 AND THE SHAPE IS WHAT MAKES IT REACHABLE AT ALL. `sha/mod.rs`'s `hash_pair` is
//! `compress(SHA256_INIT, a, b)` — a RAW UNPADDED COMPRESSION, which no syscall on any
//! chain computes. The blake family's is a FULL HASH OF THE CONCATENATION, which is
//! exactly a syscall's shape. That is the whole reason blake3 is the useful one here and
//! sha-256 is not, regardless of which is faster in software.
//!
//! ⚠️ `default-features = false` ON THE `blake3` CRATE IS LOAD-BEARING, NOT TIDINESS. Its
//! default features pull `rayon`, and a rayon registry is a WRITABLE STATIC, which the
//! Solana loader refuses outright ("Section or symbol name ... longer than 16 bytes").
//! That is the exact failure that made SP1's verifier ELF unloadable. Do not re-enable them.
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::marker::PhantomData;

use rand_core::{impls, RngCore};
use risc0_core::field::{
    baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem},
    Elem, ExtElem,
};

use super::super::hash::poseidon2::meter;
use super::{HashFn, HashSuite, Rng, RngFactory};
use crate::core::digest::Digest;

/// Hash function trait.
pub trait Blake3: Send + Sync {
    /// A function producing a hash from a list of u8.
    fn blake3<T: AsRef<[u8]>>(data: T) -> [u8; 32];
}

/// Implementation of blake3 using CPU.
pub struct Blake3CpuImpl;

/// Type alias for Blake3 HashSuite using CPU.
pub type Blake3CpuHashSuite = Blake3HashSuite<Blake3CpuImpl>;

impl Blake3 for Blake3CpuImpl {
    fn blake3<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
        *::blake3::hash(data.as_ref()).as_bytes()
    }
}

struct Blake3RngFactory<T: Blake3> {
    phantom: PhantomData<T>,
}

impl<T: Blake3> Blake3RngFactory<T> {
    fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<T: Blake3 + 'static> RngFactory<BabyBear> for Blake3RngFactory<T> {
    fn new_rng(&self) -> Box<dyn Rng<BabyBear>> {
        let rng: Blake3Rng<T> = Blake3Rng::new();
        Box::new(rng)
    }
}

/// Blake3 HashSuite.
/// Generic over the hasher, to allow different implementations.
pub struct Blake3HashSuite<T: Blake3> {
    phantom: PhantomData<T>,
}

impl<T: Blake3 + 'static> Blake3HashSuite<T> {
    /// Create a new HashSuite
    pub fn new_suite() -> HashSuite<BabyBear> {
        HashSuite {
            name: "blake3".into(),
            hashfn: Rc::new(Blake3HashFn::<T>::new()),
            rng: Rc::new(Blake3RngFactory::<T>::new()),
        }
    }
}

/// Blake3 HashFn.
struct Blake3HashFn<T: Blake3> {
    phantom: PhantomData<T>,
}

impl<T: Blake3> Blake3HashFn<T> {
    fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<T: Blake3> HashFn<BabyBear> for Blake3HashFn<T> {
    /// 🔑 THE SYSCALL-SHAPED ONE: `blake3(a ‖ b)`, byte for byte what
    /// `solana_program::blake3::hashv(&[a, b])` computes.
    ///
    /// ⚠️ METERED ON POSEIDON2'S SLOT 2/3 ON PURPOSE. A receipt is sealed with ONE suite, so
    /// the two can never both be counting — and reusing the slots means the SBPF probe's
    /// existing `hashfn_cu`/`hashfn_calls` report works unchanged. Counting the calls is the
    /// whole point: the shipping figure was inferred from a hash COUNT derived off a split
    /// measured on a different circuit, and that inference has already been wrong by 15% once.
    fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest> {
        let __t = meter::now();
        let concat = [a.as_bytes(), b.as_bytes()].concat();
        let __r = Box::new(Digest::from(T::blake3(concat)));
        meter::account(2, __t);
        __r
    }

    /// ⚠️ BIG-ENDIAN MONTGOMERY, mirroring `blake2b.rs` exactly. The serialisation is
    /// part of the hash, so a verifier that reads elements back any other way computes a
    /// different digest and fails with no clue why.
    fn hash_elem_slice(&self, slice: &[BabyBearElem]) -> Box<Digest> {
        // ⚠️ TIMER ABOVE THE SERIALISATION, NOT BELOW IT. poseidon2's meter wraps its WHOLE
        // body; starting after the Vec build would make blake3 look cheaper than it is, and
        // the comparison is the entire point of the instrument.
        let __t2 = meter::now();
        let mut data = Vec::<u8>::new();
        for el in slice {
            data.extend_from_slice(el.as_u32_montgomery().to_be_bytes().as_slice());
        }
        let __r2 = Box::new(Digest::from(T::blake3(data)));
        meter::account(2, __t2);
        __r2
    }

    fn hash_ext_elem_slice(&self, slice: &[BabyBearExtElem]) -> Box<Digest> {
        let __t2 = meter::now();
        let mut data = Vec::<u8>::new();
        for ext_el in slice {
            for el in ext_el.subelems() {
                data.extend_from_slice(el.as_u32_montgomery().to_be_bytes().as_slice());
            }
        }
        let __r2 = Box::new(Digest::from(T::blake3(data)));
        meter::account(2, __t2);
        __r2
    }
}

/// Blake3-based random number generator.
pub struct Blake3Rng<T: Blake3> {
    current: [u8; 32],
    hasher: PhantomData<T>,
}

impl<T: Blake3> Blake3Rng<T> {
    fn new() -> Self {
        Self {
            current: [0; 32],
            hasher: Default::default(),
        }
    }
}

impl<T: Blake3> Rng<BabyBear> for Blake3Rng<T> {
    fn mix(&mut self, val: &Digest) {
        let concat = [self.current.as_ref(), val.as_bytes()].concat();
        self.current = T::blake3(concat);
    }

    fn random_bits(&mut self, bits: usize) -> u32 {
        ((1 << bits) - 1) & self.next_u32()
    }

    fn random_elem(&mut self) -> BabyBearElem {
        BabyBearElem::random(self)
    }

    fn random_ext_elem(&mut self) -> BabyBearExtElem {
        BabyBearExtElem::random(self)
    }
}

impl<T: Blake3> RngCore for Blake3Rng<T> {
    fn next_u32(&mut self) -> u32 {
        let next = T::blake3(self.current);
        self.current = next;
        ((next[0] as u32) << 24)
            + ((next[1] as u32) << 16)
            + ((next[2] as u32) << 8)
            + (next[3] as u32)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest);
    }
}
