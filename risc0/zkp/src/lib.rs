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

#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

pub mod adapter;
pub mod core;
#[cfg(feature = "prove")]
pub mod hal;
pub mod layout;
mod merkle;
#[cfg(feature = "prove")]
pub mod prove;
pub mod taps;
pub mod verify;

pub use risc0_core::field;

pub const MIN_CYCLES_PO2: usize = 13;
pub const MIN_CYCLES: usize = 1 << MIN_CYCLES_PO2; // 8K
pub const MAX_CYCLES_PO2: usize = 24;
pub const MAX_CYCLES: usize = 1 << MAX_CYCLES_PO2; // 16M

/// 50 FRI queries is sufficient to achieve our security target of 97 bits (conjectured security)
pub const QUERIES: usize = 50;
pub const ZK_CYCLES: usize = 1024; // TODO: Ideally we'd compute ZK_CYCLES programmatically
pub const MIN_PO2: usize = core::log2_ceil(1 + ZK_CYCLES);

/// Inverse of Reed-Solomon Expansion Rate
///
/// ⛔⛔ DO NOT TUNE THIS AS AN FRI PARAMETER. IT IS NOT ONE — IT IS TWO THINGS.
///
/// The obvious trade looks free: a query is worth log2(1/rate) bits, so rate 1/8 with 34 queries
/// gives 102 raw bits against 50 queries at 1/4 giving 100 — MORE security and ~2.75M CU less
/// verifier work. The arithmetic is right. The premise is not.
///
/// 🔑 `CHECK_SIZE = INV_RATE * EXT_SIZE` in BOTH `verify/mod.rs` and `hal/mod.rs`. So INV_RATE also
/// sets how many columns the QUOTIENT polynomial is split into — and that split is fixed by the
/// circuit's MAX CONSTRAINT DEGREE, not by anything about FRI. rv32im is degree 5, so the quotient
/// is 4 x cycles and wants exactly 4 columns. Asking for 8 demands 32 check columns from a
/// polynomial holding 16 columns' worth of degree.
///
/// ⚠️ IT DOES NOT FAIL LOUDLY. Prover and verifier simply disagree, and the prover's own native
/// check rejects the proof it just produced: "verify segment: verification indicates proof is
/// invalid". Tried, measured, reverted — and the commit that made the change was removed from this
/// branch rather than left to mislead, because its subject line asserted the opposite.
///
/// ⇒ To take the trade the two uses must be DECOUPLED: a separate constant for the FRI blowup,
/// leaving CHECK_SIZE tied to the constraint degree. That is a soundness-structural change, not a
/// constant swap.
pub const INV_RATE: usize = 4;

const FRI_FOLD_PO2: usize = 4;

/// FRI folding factor is 2 ^ FRI_FOLD_PO2
pub const FRI_FOLD: usize = 1 << FRI_FOLD_PO2;

/// FRI continues until the degree of the FRI polynomial reaches FRI_MIN_DEGREE
const FRI_MIN_DEGREE: usize = 256;
