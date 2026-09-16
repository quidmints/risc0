// Copyright 2026 RISC Zero, Inc.
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

//! An implementation of Poseidon2 targeting the Baby Bear.

// Thank you to https://github.com/nhukc for the initial implementation of this code

pub(crate) mod consts;
mod rng;

use alloc::{boxed::Box, rc::Rc, vec::Vec};

use bytemuck::CheckedBitPattern;
use risc0_core::field::{
    baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem},
    Elem, ExtElem,
};

use super::{HashFn, HashSuite, Rng, RngFactory};
use crate::core::digest::{Digest, DIGEST_WORDS};

pub use self::{
    consts::{CELLS, M_INT_DIAG_HZN, ROUNDS_HALF_FULL, ROUNDS_PARTIAL, ROUND_CONSTANTS},
    rng::Poseidon2Rng,
};

/// The 'rate' of the sponge, i.e. how much we can safely add/remove per mixing.
pub const CELLS_RATE: usize = 16;


#[allow(missing_docs)]
/// [sbf-meter] CU accounting for the hashing side of verification. Six u64 words at a fixed
/// runtime-heap address (writable statics are rejected by the SBF loader):
/// [perm_cu, perm_calls, hashfn_cu, hashfn_calls, rng_cu, rng_calls].
#[cfg(target_os = "solana")]
pub mod meter {
    extern "C" {
        fn sol_remaining_compute_units() -> u64;
    }
    const BASE: *mut u64 = 0x300000040 as *mut u64;
    /// Slots 13.. live at their own base: widening BASE past ~word 21 collided with
    /// runtime-owned memory (a stored counter got dereferenced as a pointer).
    const BASE2: *mut u64 = 0x300001000 as *mut u64;
    #[inline(always)]
    fn slot(i: usize) -> *mut u64 { unsafe { if i < 13 { BASE.add(i) } else { BASE2.add(i - 13) } } }
    #[inline(always)]
    pub fn now() -> u64 { unsafe { sol_remaining_compute_units() } }
    #[inline(always)]
    pub fn account(s: usize, start: u64) {
        let spent = start.saturating_sub(now());
        unsafe { *slot(s) += spent; *slot(s + 1) += 1; }
    }
    pub fn read() -> [u64; 38] { unsafe { core::array::from_fn(|i| *slot(i)) } }
    pub fn reset() { unsafe { for i in 0..38 { *slot(i) = 0; } *BASE.add(7) = u64::MAX; } }
    /// per-query: 6 max, 7 min, 8 sum, 9 count, 10 perm CU inside the max query, 11 CU at loop start, 12 CU at loop end
    pub fn qaccount(q0: u64, p0: u64) {
        let spent = q0.saturating_sub(now());
        let perm = read()[0] - p0;
        unsafe {
            if spent > *BASE.add(6) { *BASE.add(6) = spent; *BASE.add(10) = perm; }
            if spent < *BASE.add(7) { *BASE.add(7) = spent; }
            *BASE.add(8) += spent; *BASE.add(9) += 1;
        }
    }
    /// 29 = CU remaining at risc0-zkp verify() entry; 30 = at end of globals/code-root read
    pub fn mark(i: usize) { unsafe { *slot(i) = now(); } }
    /// 36/37 also capture the HASH bill at the loop boundary. Without this the query loop is one
    /// opaque 25.6M number and there is no way to say how it responds to putting blake3 on the
    /// `sol_blake3` syscall — which is the whole question when choosing QUERIES.
    pub fn qmark_before_loop() { unsafe { *BASE.add(11) = now(); *slot(36) = *slot(2); } }
    pub fn qmark_after_loop() { unsafe { *BASE.add(12) = now(); *slot(37) = *slot(2); } }
}
#[cfg(not(target_os = "solana"))]
#[allow(missing_docs)]
pub mod meter {
    #[inline(always)] pub fn now() -> u64 { 0 }
    #[inline(always)] pub fn account(_slot: usize, _start: u64) {}
    pub fn read() -> [u64; 38] { [0; 38] }
    pub fn reset() {}
    pub fn qaccount(_q0: u64, _p0: u64) {}
    pub fn mark(_i: usize) {}
    pub fn qmark_before_loop() {}
    pub fn qmark_after_loop() {}
}

/// The size of the hash output in cells (~ 248 bits)
pub const CELLS_OUT: usize = 8;

/// A hash implementation for Poseidon2
struct Poseidon2HashFn;

impl HashFn<BabyBear> for Poseidon2HashFn {
    fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest> {
        let __t = meter::now();
        let __r = (|| {        let both: Vec<BabyBearElem> = a
            .as_words()
            .iter()
            .chain(b.as_words())
            .map(|w| BabyBearElem::new_raw(*w))
            .collect();
        assert!(both.len() == DIGEST_WORDS * 2);
        for elem in &both {
            assert!(elem.is_reduced());
        }
        to_digest(unpadded_hash(both.iter()))
        })();
        meter::account(2, __t);
        __r
    }

    fn hash_elem_slice(&self, slice: &[BabyBearElem]) -> Box<Digest> {
        let __t = meter::now();
        let __r = (|| {        to_digest(unpadded_hash(slice.iter()))
        })();
        meter::account(2, __t);
        __r
    }

    fn hash_ext_elem_slice(&self, slice: &[BabyBearExtElem]) -> Box<Digest> {
        let __t = meter::now();
        let __r = (|| {        to_digest(unpadded_hash(
            slice.iter().flat_map(|ee| ee.subelems().iter()),
        ))
        })();
        meter::account(2, __t);
        __r
    }

    /// Checks if all words in the digest are less than the Baby Bear modulus.
    fn is_digest_valid(&self, digest: &Digest) -> bool {
        digest
            .as_words()
            .iter()
            .all(<BabyBearElem as CheckedBitPattern>::is_valid_bit_pattern)
    }
}

struct Poseidon2RngFactory;

impl RngFactory<BabyBear> for Poseidon2RngFactory {
    fn new_rng(&self) -> Box<dyn Rng<BabyBear>> {
        Box::new(Poseidon2Rng::new())
    }
}

/// A hash suite using Poseidon2 for both MT hashes and RNG
pub struct Poseidon2HashSuite;

impl Poseidon2HashSuite {
    /// Construct a new Poseidon2HashSuite
    pub fn new_suite() -> HashSuite<BabyBear> {
        HashSuite {
            name: "poseidon2".into(),
            hashfn: Rc::new(Poseidon2HashFn {}),
            rng: Rc::new(Poseidon2RngFactory {}),
        }
    }
}

fn to_digest(elems: [BabyBearElem; CELLS_OUT]) -> Box<Digest> {
    let mut state: [u32; DIGEST_WORDS] = [0; DIGEST_WORDS];
    for i in 0..DIGEST_WORDS {
        state[i] = elems[i].as_u32_montgomery();
    }
    Box::new(Digest::from(state))
}

fn add_round_constants_full(cells: &mut [BabyBearElem; CELLS], round: usize) {
    for i in 0..CELLS {
        cells[i] += ROUND_CONSTANTS[round * CELLS + i];
    }
}

fn add_round_constants_partial(cells: &mut [BabyBearElem; CELLS], round: usize) {
    cells[0] += ROUND_CONSTANTS[round * CELLS];
}

fn sbox(x: BabyBearElem) -> BabyBearElem {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    x6 * x
}

fn do_full_sboxes(cells: &mut [BabyBearElem; CELLS]) {
    for cell in cells.iter_mut() {
        *cell = sbox(*cell);
    }
}

fn do_partial_sboxes(cells: &mut [BabyBearElem; CELLS]) {
    cells[0] = sbox(cells[0]);
}

fn multiply_by_m_int(cells: &mut [BabyBearElem; CELLS]) {
    // Exploit the fact that off-diagonal entries of M_INT are all 1.
    let sum: BabyBearElem = cells.iter().fold(BabyBearElem::ZERO, |acc, x| acc + *x);
    for i in 0..CELLS {
        cells[i] = sum + M_INT_DIAG_HZN[i] * cells[i];
    }
}

fn multiply_by_4x4_circulant(x: &[BabyBearElem; 4]) -> [BabyBearElem; 4] {
    // See appendix B of Poseidon2 paper.
    let t0 = x[0] + x[1];
    let t1 = x[2] + x[3];
    let t2 = BabyBearElem::new(2) * x[1] + t1;
    let t3 = BabyBearElem::new(2) * x[3] + t0;
    let t4 = BabyBearElem::new(4) * t1 + t3;
    let t5 = BabyBearElem::new(4) * t0 + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    [t6, t5, t7, t4]
}

fn multiply_by_m_ext(cells: &mut [BabyBearElem; CELLS]) {
    // Optimized method for multiplication by M_EXT.
    // See appendix B of Poseidon2 paper for additional details.
    let old_cells = *cells;
    cells.fill(BabyBearElem::ZERO);
    let mut tmp_sums = [BabyBearElem::ZERO; 4];

    for i in 0..CELLS / 4 {
        let chunk_array: [BabyBearElem; 4] = [
            old_cells[i * 4],
            old_cells[i * 4 + 1],
            old_cells[i * 4 + 2],
            old_cells[i * 4 + 3],
        ];
        let out = multiply_by_4x4_circulant(&chunk_array);
        for j in 0..4 {
            tmp_sums[j] += out[j];
            cells[i * 4 + j] += out[j];
        }
    }
    for i in 0..CELLS {
        cells[i] += tmp_sums[i % 4];
    }
}

fn full_round(cells: &mut [BabyBearElem; CELLS], round: usize) {
    add_round_constants_full(cells, round);
    // if round == 0 {
    //     tracing::trace!("After constants in full round 0: {cells:?}");
    // }

    do_full_sboxes(cells);
    multiply_by_m_ext(cells);
    // tracing::trace!("After mExt in full round {round}: {cells:?}");
}

fn partial_round(cells: &mut [BabyBearElem; CELLS], round: usize) {
    add_round_constants_partial(cells, round);
    do_partial_sboxes(cells);
    multiply_by_m_int(cells);
}

/// The raw sponge mixing function
pub fn poseidon2_mix(cells: &mut [BabyBearElem; CELLS]) {
    let __t = meter::now();
    poseidon2_mix_inner(cells);
    meter::account(0, __t);
}

#[inline(never)]
fn poseidon2_mix_inner(cells: &mut [BabyBearElem; CELLS]) {
    let mut round = 0;

    // First linear layer.
    multiply_by_m_ext(cells);
    // tracing::trace!("After initial mExt: {cells:?}");

    // Do initial full rounds
    for _i in 0..ROUNDS_HALF_FULL {
        full_round(cells, round);
        round += 1;
    }
    // Do partial rounds
    for _i in 0..ROUNDS_PARTIAL {
        partial_round(cells, round);
        round += 1;
    }
    // tracing::trace!("After partial rounds: {cells:?}");
    // Do remaining full rounds
    for _i in 0..ROUNDS_HALF_FULL {
        full_round(cells, round);
        round += 1;
    }
}

/// Perform an unpadded hash of a vector of elements.  Because this is unpadded
/// collision resistance is only true for vectors of the same size.  If the size
/// is variable, this is subject to length extension attacks.
pub fn unpadded_hash<'a, I>(iter: I) -> [BabyBearElem; CELLS_OUT]
where
    I: Iterator<Item = &'a BabyBearElem>,
{
    let mut state = [BabyBearElem::ZERO; CELLS];
    let mut count = 0;
    let mut unmixed = 0;
    for val in iter {
        state[unmixed] = *val;
        count += 1;
        unmixed += 1;
        if unmixed == CELLS_RATE {
            poseidon2_mix(&mut state);
            unmixed = 0;
        }
    }
    if unmixed != 0 || count == 0 {
        // Zero pad to get a CELLS_RATE-aligned number of inputs
        for elem in state.iter_mut().take(CELLS_RATE).skip(unmixed) {
            *elem = BabyBearElem::ZERO;
        }
        poseidon2_mix(&mut state);
    }
    state.as_slice()[0..CELLS_OUT].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use test_log::test;

    use super::*;
    use crate::core::hash::poseidon2::consts::_M_EXT;

    fn do_partial_sboxes(cells: &mut [BabyBearElem; CELLS]) {
        cells[0] = sbox(cells[0]);
    }

    fn partial_round_naive(cells: &mut [BabyBearElem; CELLS], round: usize) {
        add_round_constants_partial(cells, round);
        do_partial_sboxes(cells);
        multiply_by_m_int_naive(cells);
    }

    fn multiply_by_m_ext_naive(cells: &mut [BabyBearElem; CELLS]) {
        let old_cells = *cells;
        for i in 0..CELLS {
            let mut tot = BabyBearElem::ZERO;
            for j in 0..CELLS {
                tot += _M_EXT[i * CELLS + j] * old_cells[j];
            }
            cells[i] = tot;
        }
    }

    fn multiply_by_m_int_naive(cells: &mut [BabyBearElem; CELLS]) {
        let old_cells = *cells;
        for i in 0..CELLS {
            let mut tot = BabyBearElem::ZERO;
            for (j, old_cell) in old_cells.iter().enumerate().take(CELLS) {
                if i == j {
                    tot += (M_INT_DIAG_HZN[i] + BabyBearElem::ONE) * *old_cell;
                } else {
                    tot += *old_cell;
                }
            }
            cells[i] = tot;
        }
    }

    // Naive version of poseidon2
    fn poseidon2_mix_naive(cells: &mut [BabyBearElem; CELLS]) {
        let mut round = 0;
        multiply_by_m_ext_naive(cells);
        for _i in 0..ROUNDS_HALF_FULL {
            full_round(cells, round);
            round += 1;
        }
        for _i in 0..ROUNDS_PARTIAL {
            partial_round_naive(cells, round);
            round += 1;
        }
        for _i in 0..ROUNDS_HALF_FULL {
            full_round(cells, round);
            round += 1;
        }
    }

    #[test]
    fn compare_naive() {
        // Make a fixed input
        let mut test_in_1 = [BabyBearElem::ONE; CELLS];
        // Copy it
        let mut test_in_2 = test_in_1;
        // Try two versions
        poseidon2_mix_naive(&mut test_in_1);
        poseidon2_mix(&mut test_in_2);
        tracing::debug!("test_in_1: {:?}", test_in_1);
        tracing::debug!("test_in_2: {:?}", test_in_2);
        // Verify they are the same
        assert_eq!(test_in_1, test_in_2);
    }

    macro_rules! baby_bear_array {
        [$($x:literal),* $(,)?] => {
            [$(BabyBearElem::new($x)),* ]
        }
    }

    #[test]
    fn poseidon2_test_vectors() {
        let buf: &mut [BabyBearElem; CELLS] = &mut baby_bear_array![
            0x00000000, 0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000005, 0x00000006,
            0x00000007, 0x00000008, 0x00000009, 0x0000000A, 0x0000000B, 0x0000000C, 0x0000000D,
            0x0000000E, 0x0000000F, 0x00000010, 0x00000011, 0x00000012, 0x00000013, 0x00000014,
            0x00000015, 0x00000016, 0x00000017,
        ];
        tracing::debug!("input: {:?}", buf);
        poseidon2_mix(buf);
        let goal: [u32; CELLS] = [
            0x2ed3e23d, 0x12921fb0, 0x0e659e79, 0x61d81dc9, 0x32bae33b, 0x62486ae3, 0x1e681b60,
            0x24b91325, 0x2a2ef5b9, 0x50e8593e, 0x5bc818ec, 0x10691997, 0x35a14520, 0x2ba6a3c5,
            0x279d47ec, 0x55014e81, 0x5953a67f, 0x2f403111, 0x6b8828ff, 0x1801301f, 0x2749207a,
            0x3dc9cf21, 0x3c985ba2, 0x57a99864,
        ];
        for i in 0..CELLS {
            assert_eq!(buf[i].as_u32(), goal[i]);
        }

        tracing::debug!("output: {:?}", buf);
    }

    // Test against golden values from an independent interpreter version of Poseidon2
    #[test]
    fn hash_elem_slice_compare_golden() {
        let buf: [BabyBearElem; 32] = baby_bear_array![
            943718400, 1887436800, 2013125296, 1761607679, 692060158, 1761607634, 566231037,
            1509949437, 440401916, 1384120316, 314572795, 1258291195, 188743674, 1132462074,
            62914553, 1006632953, 1950351353, 880803832, 1824522232, 754974711, 1698693111,
            629145590, 1572863990, 503316469, 1447034869, 377487348, 1321205748, 251658227,
            1195376627, 125829106, 1069547506, 2013265906,
        ];
        let suite = Poseidon2HashSuite::new_suite();
        let result = suite.hashfn.hash_elem_slice(&buf);
        let goal: [u32; DIGEST_WORDS] = [
            (BabyBearElem::from(0x722baada_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x5b352fed_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x3684017b_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x540d4a7b_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x44ffd422_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x48615f97_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x1a496f45_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x203ca999_u32)).as_u32_montgomery(),
        ];
        for (i, word) in goal.iter().enumerate() {
            assert_eq!(result.as_words()[i], *word, "At entry {i}");
        }
    }

    #[test]
    fn hash_elem_slice_compare_golden_unaligned() {
        let buf: [BabyBearElem; 17] = baby_bear_array![
            943718400, 1887436800, 2013125296, 1761607679, 692060158, 1635778558, 566231037,
            1509949437, 440401916, 1384120316, 314572795, 1258291195, 188743674, 1132462074,
            62914553, 1006632953, 1950351353,
        ];
        let suite = Poseidon2HashSuite::new_suite();
        let result = suite.hashfn.hash_elem_slice(&buf);
        let goal: [u32; DIGEST_WORDS] = [
            (BabyBearElem::from(0x622615d7_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x1cfe9764_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x166cb1c9_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x76febcde_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x6056219f_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x326359cf_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x5c2cca75_u32)).as_u32_montgomery(),
            (BabyBearElem::from(0x233dc3ff_u32)).as_u32_montgomery(),
        ];
        for (i, word) in goal.iter().enumerate() {
            assert_eq!(result.as_words()[i], *word, "At entry {i}");
        }
    }
}
