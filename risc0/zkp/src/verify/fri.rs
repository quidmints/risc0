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

use alloc::vec::Vec;
use core::ops::DerefMut;

use risc0_core::field::{Elem, ExtElem, Field, RootsOfUnity};

use super::Verifier;
use crate::core::hash::poseidon2::meter as pmeter;
use crate::{
    core::{
        hash::HashFn,
        log2_ceil,
        ntt::{bit_reverse, interpolate_ntt},
    },
    verify::{merkle::MerkleTreeVerifier, read_iop::ReadIOP, VerificationError},
    FRI_FOLD, FRI_FOLD_PO2, FRI_MIN_DEGREE, INV_RATE, QUERIES,
};

/// VerifyRoundInfo contains the data against which the queries for a particular
/// round are checked. This includes the Merkle tree top row data, as well as
/// the size of the domain of the polynomial, and the mixing parameter.
struct VerifyRoundInfo<'a, F: Field> {
    domain: usize,
    merkle: MerkleTreeVerifier<'a>,
    mix: F::ExtElem,
}

impl<'a, F: Field> VerifyRoundInfo<'a, F> {
    pub fn new(
        iop: &mut ReadIOP<'a, F>,
        hashfn: &dyn HashFn<F>,
        in_domain: usize,
    ) -> Result<Self, VerificationError> {
        let domain = in_domain / FRI_FOLD;
        Ok(VerifyRoundInfo {
            domain,
            merkle: MerkleTreeVerifier::new(
                iop,
                hashfn,
                domain,
                FRI_FOLD * F::ExtElem::EXT_SIZE,
                QUERIES,
            )?,
            mix: iop.random_ext_elem(),
        })
    }
}

impl<'a, F> Verifier<'a, F>
where
    F: Field,
{
    fn verify_query(
        &self,
        round: &mut VerifyRoundInfo<'a, F>,
        pos: &mut usize,
        goal: &mut F::ExtElem,
    ) -> Result<(), VerificationError> {
        let quot = *pos / round.domain;
        let group = *pos % round.domain;
        // Get the column data
        let hashfn = self.suite.hashfn.as_ref();
        // [sbf-meter] 42/44/46: split the per-round fold. ~16,000 CU per round is unaccounted by
        // the operations I can see (4-element NTT, 4 multiplies, one pow), and guessing which is
        // the expensive one is what produced the wall.
        let __f0 = crate::core::hash::poseidon2::meter::now();
        let data = round.merkle.verify(self.iop().deref_mut(), hashfn, group)?;
        crate::core::hash::poseidon2::meter::account(42, __f0);
        let __f1 = crate::core::hash::poseidon2::meter::now();
        // ⚠️ NO INTERMEDIATE `Vec` — `from_subelems` takes an ITERATOR, and this runs
        // FRI_FOLD times per round per query (the hottest loop in the verifier). The sibling
        // repack in `fri_verify` already passed an iterator; this one allocated.
        let mut data_ext: Vec<F::ExtElem> = (0..FRI_FOLD)
            .map(|i| {
                F::ExtElem::from_subelems(
                    (0..F::ExtElem::EXT_SIZE).map(|j| data[j * FRI_FOLD + i]),
                )
            })
            .collect();
        // Check the existing goal
        if data_ext[quot] != *goal {
            return Err(VerificationError::InvalidProof);
        }
        // Compute the new goal + pos
        crate::core::hash::poseidon2::meter::account(44, __f1);
        let __f2 = crate::core::hash::poseidon2::meter::now();
        let root_po2 = log2_ceil(FRI_FOLD * round.domain);
        let inv_wk = F::Elem::ROU_REV[root_po2].pow(group);

        interpolate_ntt::<F::Elem, F::ExtElem>(&mut data_ext);
        bit_reverse(&mut data_ext);
        *goal = self.poly_eval(&data_ext, round.mix * inv_wk);
        crate::core::hash::poseidon2::meter::account(46, __f2);

        *pos = group;
        Ok(())
    }

    pub fn fri_verify<InnerFn>(&self, mut inner: InnerFn) -> Result<(), VerificationError>
    where
        InnerFn: FnMut(usize) -> Result<F::ExtElem, VerificationError>,
    {
        let mut degree: usize = self.tot_cycles;
        let hashfn = self.suite.hashfn.as_ref();
        let orig_domain = INV_RATE * degree;
        let mut domain = orig_domain;
        // Prep the folding verifiers
        let rounds_capacity = log2_ceil(degree.div_ceil(FRI_FOLD).div_ceil(FRI_FOLD_PO2));
        let mut rounds = Vec::with_capacity(rounds_capacity);
        let __m = pmeter::now();
        while degree > FRI_MIN_DEGREE {
            rounds.push(VerifyRoundInfo::new(
                self.iop().deref_mut(),
                hashfn,
                domain,
            )?);
            domain /= FRI_FOLD;
            degree /= FRI_FOLD;
        }
        // We want to minimize reallocation in verify, so make sure we
        // didn't have to reallocate.
        assert!(
            rounds.len() <= rounds_capacity,
            "Did not allocate enough rounds; needed {} for degree {} but only allocated {}",
            rounds.len(),
            degree,
            rounds_capacity
        );
        pmeter::account(25, __m);
        let __m = pmeter::now();
        // Grab the final coeffs + commit
        let final_coeffs = self
            .iop()
            .read_field_elem_slice(F::ExtElem::EXT_SIZE * degree)?;
        let final_digest = hashfn.hash_elem_slice(final_coeffs);
        self.iop().commit(&final_digest);
        // Get the generator for the final polynomial evaluations
        let gen = <F::Elem as RootsOfUnity>::ROU_FWD[log2_ceil(domain)];
        pmeter::account(27, __m);
        // Do queries
        // ⭐ LOOP-INVARIANT, AND IT WAS BEING REBUILT ONCE PER QUERY. `final_coeffs` and `degree`
        // are both fixed before the query loop starts — only `x` changes per query — so this repack
        // of `degree` ExtElems out of subelements was being performed identically 50 TIMES.
        // Hoisting it is exact by construction: the same inputs produce the same buffer.
        let mut poly_buf: Vec<F::ExtElem> = Vec::with_capacity(degree);
        poly_buf.extend((0..degree).map(|i| {
            F::ExtElem::from_subelems((0..F::ExtElem::EXT_SIZE).map(|j| final_coeffs[j * degree + i]))
        }));
        // [sbf-meter] per-query CU: slots 6..10 = [q_max, q_min, q_sum, q_count, q_max_perm]
        crate::core::hash::poseidon2::meter::qmark_before_loop();
        for _ in 0..QUERIES {
            let __q0 = crate::core::hash::poseidon2::meter::now();
            let __p0 = crate::core::hash::poseidon2::meter::read()[0];
            let mut pos = self.iop().random_bits(log2_ceil(orig_domain)) as usize;
            // Do the 'inner' verification for this index
            let mut goal = inner(pos)?;
            // Verify the per-round proofs
            for round in &mut rounds {
                self.verify_query(round, &mut pos, &mut goal)?;
            }
            // Do final verification
            let x = gen.pow(pos);

            let fx = self.poly_eval(poly_buf.as_slice(), F::ExtElem::from_subfield(&x));
            if fx != goal {
                return Err(VerificationError::InvalidProof);
            }
            crate::core::hash::poseidon2::meter::qaccount(__q0, __p0);
        }
        crate::core::hash::poseidon2::meter::qmark_after_loop();
        Ok(())
    }
}
