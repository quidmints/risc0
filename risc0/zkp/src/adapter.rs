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

//! Interface between the circuit and prover/verifier

use alloc::{str::from_utf8, vec::Vec};
use core::fmt;

use risc0_core::field::{Elem, ExtElem, Field};
use serde::{Deserialize, Serialize};

use crate::taps::TapSet;

// TODO: Remove references to these constants so we don't depend on a
// fixed set of register groups.
pub const REGISTER_GROUP_ACCUM: usize = 0;
pub const REGISTER_GROUP_CODE: usize = 1;
pub const REGISTER_GROUP_DATA: usize = 2;

// If true, enable tracing of adapter internals.
const ADAPTER_TRACE_ENABLED: bool = false;

/// Highest `mix` power held in the executor's lookup table. 256 is not arbitrary: measured over
/// rv32im's block, 95% of the 6,465 mix-chain steps sit at exponent <= 256, and the table costs one
/// multiply per entry to build. 512 covers 98% but costs 256 more muls to save 166 — past the
/// optimum. Anything above the table falls back to a multiply, so the value is a speed choice
/// only; correctness does not depend on it.
pub const MIX_POW_MAX: usize = 256;

macro_rules! trace_if_enabled {
    ($($args:tt)*) => {
        if ADAPTER_TRACE_ENABLED {
            tracing::trace!($($args)*)
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct MixState<EE: ExtElem> {
    pub tot: EE,
    pub mul: EE,
}

pub trait PolyFp<F: Field> {
    fn poly_fp(
        &self,
        cycle: usize,
        steps: usize,
        mix: &[F::ExtElem],
        args: &[&[F::Elem]],
    ) -> F::ExtElem;
}

pub trait PolyExt<F: Field> {
    fn poly_ext(
        &self,
        mix: &F::ExtElem,
        u: &[F::ExtElem],
        args: &[&[F::Elem]],
    ) -> MixState<F::ExtElem>;
}

pub trait TapsProvider {
    fn get_taps(&self) -> &'static TapSet<'static>;

    fn accum_size(&self) -> usize {
        self.get_taps().group_size(REGISTER_GROUP_ACCUM)
    }

    fn code_size(&self) -> usize {
        self.get_taps().group_size(REGISTER_GROUP_CODE)
    }

    fn ctrl_size(&self) -> usize {
        self.get_taps().group_size(REGISTER_GROUP_CODE)
    }

    fn data_size(&self) -> usize {
        self.get_taps().group_size(REGISTER_GROUP_DATA)
    }
}

/// A protocol info string for the proof system and circuits.
/// Used to seed the Fiat-Shamir transcript and provide domain separation between different
/// protocol and circuit versions.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInfo(pub [u8; 16]);

impl ProtocolInfo {
    /// Encode a fixed context byte-string to elements, with one element per byte.
    // NOTE: This function is intended to be compatible with const, but is not const currently because
    // E::from_u64 is not const, as const functions on traits is not stable.
    pub fn encode<E: Elem>(&self) -> [E; 16] {
        let mut elems = [E::ZERO; 16];
        for (i, elem) in elems.iter_mut().enumerate().take(self.0.len()) {
            *elem = E::from_u64(self.0[i] as u64);
        }
        elems
    }
}

impl fmt::Display for ProtocolInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match from_utf8(&self.0) {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "0x{}", hex::encode(self.0)),
        }
    }
}

/// Versioned info string for the proof system.
///
/// NOTE: This string should be bumped with every change to the proof system, as defined by a
/// change to checks applied by the verifier.
pub const PROOF_SYSTEM_INFO: ProtocolInfo = ProtocolInfo(*b"RISC0_STARK:v1__");

pub trait CircuitInfo {
    const CIRCUIT_INFO: ProtocolInfo;
    const OUTPUT_SIZE: usize;
    const MIX_SIZE: usize;
}

/// traits implemented by generated rust code used in both prover and verifier
pub trait CircuitCoreDef<F: Field>: CircuitInfo + PolyExt<F> + TapsProvider {}

pub type Arg = usize;
pub type Var = usize;

pub struct PolyExtStepDef {
    pub block: &'static [PolyExtStep],
    pub ret: Var,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum PolyExtStep {
    Const(u32),
    ConstExt(u32, u32, u32, u32),
    Get(usize),
    GetGlobal(Arg, usize),
    Add(Var, Var),
    Sub(Var, Var),
    Mul(Var, Var),
    True,
    AndEqz(Var, Var),
    AndCond(Var, Var, Var),
}

impl PolyExtStepDef {
    pub fn step<F: Field>(
        &self,
        mix: &F::ExtElem,
        u: &[F::ExtElem],
        args: &[&[F::Elem]],
    ) -> MixState<F::ExtElem> {
        PolyExtExecutor::<F>::new(self).run(mix, u, args)
    }

    /// ⭐ RESUMABLE EVALUATION — run only steps `[from, to)`, carrying state in and out.
    ///
    /// WHY THIS EXISTS: on Solana the whole evaluation is a SINGLE span measured at 6,532,319 CU,
    /// which is 4.7x the 1.4M per-transaction cap and therefore not payable however many
    /// transactions you are willing to send — unless it can be cut. It can: `block` is a flat step
    /// list, `run` is a plain `for` over it, and the only mutable state is `fp_vars` and
    /// `mix_vars`, both append-only. So a prefix can be executed, the two vectors persisted, and
    /// the remainder resumed against them.
    ///
    /// 🔑 THE STATE IS BOUNDED AND SMALL, which is what makes this viable rather than merely
    /// possible: `fp_vars` reaches `block.len() - (ret + 1)` elements and `mix_vars` `ret + 1`.
    /// For the recursion circuit that is 11,130 ExtElem + 1,229 MixState = ~212 KB, or 2.1% of the
    /// 10 MB account limit.
    ///
    /// ⚠️ Steps index earlier results by absolute position, so the vectors must be carried WHOLE;
    /// no sliding window is possible. Callers must pass the same `mix`, `u` and `args` every call
    /// — they are read-only inputs, not state.
    pub fn step_range<F: Field>(
        &self,
        from: usize,
        to: usize,
        fp_vars: &mut Vec<F::ExtElem>,
        mix_vars: &mut Vec<MixState<F::ExtElem>>,
        // Carried alongside `mix_vars`: the mix-power EXPONENT of each MixState. Part of the
        // resumable state, because `AndEqz`/`AndCond` derive their exponent from their chain's and
        // a later chunk will reference a MixState an earlier chunk pushed.
        mix_exp: &mut Vec<usize>,
        mix: &F::ExtElem,
        u: &[F::ExtElem],
        args: &[&[F::Elem]],
    ) {
        let mut exec = PolyExtExecutor::<F> {
            def: self,
            fp_expected: self.block.len() - (self.ret + 1),
            mix_expected: self.ret + 1,
            fp_vars: core::mem::take(fp_vars),
            #[cfg(feature = "circuit_debug")]
            fp_index: alloc::vec::Vec::new(),
            mix_exp: core::mem::take(mix_exp),
            mix_pows: alloc::vec::Vec::new(),
            mix_vars: core::mem::take(mix_vars),
            #[cfg(feature = "circuit_debug")]
            mix_index: alloc::vec::Vec::new(),
        };
        exec.build_mix_pows(mix);
        for idx in from..to {
            let op = &self.block[idx];
            exec.step(idx, op, mix, u, args);
        }
        *fp_vars = core::mem::take(&mut exec.fp_vars);
        *mix_vars = core::mem::take(&mut exec.mix_vars);
        *mix_exp = core::mem::take(&mut exec.mix_exp);
    }

    /// The result, once `step_range` has covered the whole block.
    pub fn result<F: Field>(&self, mix_vars: &[MixState<F::ExtElem>]) -> MixState<F::ExtElem> {
        mix_vars[self.ret]
    }

    /// Number of steps in the block, so a caller can pick its own chunk boundaries.
    pub fn len(&self) -> usize {
        self.block.len()
    }

    /// Clippy asks for this whenever `len` exists.
    pub fn is_empty(&self) -> bool {
        self.block.is_empty()
    }
}

struct PolyExtExecutor<'a, F: Field> {
    def: &'a PolyExtStepDef,
    fp_expected: usize,
    mix_expected: usize,
    fp_vars: Vec<F::ExtElem>,
    #[cfg(feature = "circuit_debug")]
    fp_index: Vec<usize>,
    /// ⭐ `MixState::mul` IS ALWAYS A POWER OF `mix`, and that is what makes the table below sound.
    /// `True` gives mix^0; `AndEqz` multiplies the chain by mix, so exponent+1; `AndCond`
    /// multiplies two chains, so exponent+exponent. No other constructor exists. So the VALUE can
    /// be looked up from the EXPONENT instead of being recomputed with a multiply each step.
    mix_exp: Vec<usize>,
    /// mix^0 ..= mix^MIX_POW_MAX. Costs MIX_POW_MAX muls once; saves one per AndEqz/AndCond whose
    /// exponent it covers. Measured on rv32im's 20,202-step block: 6,465 mix-chain steps, 95% of
    /// them at exponent <= 256, so a 257-entry table replaces 6,184 multiplies for 256 — a net
    /// 5,928 ExtElem muls, about 1.78M CU of validity_fn's 6,532,319.
    mix_pows: Vec<F::ExtElem>,
    mix_vars: Vec<MixState<F::ExtElem>>,
    #[cfg(feature = "circuit_debug")]
    mix_index: Vec<usize>,
}

impl<'a, F: Field> PolyExtExecutor<'a, F> {
    pub fn new(def: &'a PolyExtStepDef) -> Self {
        let fp_expected = def.block.len() - (def.ret + 1);
        let mix_expected = def.ret + 1;
        Self {
            def,
            fp_expected,
            mix_expected,
            fp_vars: Vec::with_capacity(fp_expected),
            #[cfg(feature = "circuit_debug")]
            fp_index: Vec::with_capacity(fp_expected),
            mix_exp: Vec::with_capacity(mix_expected),
            mix_pows: Vec::new(),
            mix_vars: Vec::with_capacity(mix_expected),
            #[cfg(feature = "circuit_debug")]
            mix_index: Vec::with_capacity(mix_expected),
        }
    }

    /// Fill `mix_pows` with mix^0 ..= mix^MIX_POW_MAX. Idempotent, so `step_range` can call it on
    /// every chunk without rebuilding.
    fn build_mix_pows(&mut self, mix: &F::ExtElem) {
        if !self.mix_pows.is_empty() {
            return;
        }
        self.mix_pows.reserve_exact(MIX_POW_MAX + 1);
        let mut cur = F::ExtElem::ONE;
        for _ in 0..=MIX_POW_MAX {
            self.mix_pows.push(cur);
            cur *= *mix;
        }
    }

    pub fn run(
        &mut self,
        mix: &F::ExtElem,
        u: &[F::ExtElem],
        args: &[&[F::Elem]],
    ) -> MixState<F::ExtElem> {
        self.build_mix_pows(mix);
        for (idx, op) in self.def.block.iter().enumerate() {
            self.step(idx, op, mix, u, args);
        }
        assert_eq!(
            self.fp_vars.len(),
            self.fp_expected,
            "Miscalculated capacity for fp_vars"
        );
        assert_eq!(
            self.mix_vars.len(),
            self.mix_expected,
            "Miscalculated capacity for mix_vars"
        );

        #[cfg(feature = "circuit_debug")]
        self.debug(self.def.ret);

        self.mix_vars[self.def.ret]
    }

    #[cfg(feature = "circuit_debug")]
    fn debug(&mut self, next: Var) {
        let op_index = self.mix_index[next];
        let op = &self.def.block[op_index];
        tracing::debug!("chain: [m:{next}] {op:?}");
        match op {
            PolyExtStep::True => {
                tracing::debug!("PolyExtStep::True");
            }
            PolyExtStep::AndEqz(chain, inner) => {
                let inner_val = self.fp_vars[*inner];
                // inner should be zero
                if inner_val != F::ExtElem::ZERO {
                    // this is the first expression that is broken
                    tracing::debug!("expr: {}", self.debug_expr(*inner));
                    let inner_idx = self.fp_index[*inner];
                    let op = &self.def.block[inner_idx];
                    panic!("eqz failure: [f:{}] {op:?}", *inner);
                }
                self.debug(*chain);
            }
            PolyExtStep::AndCond(chain, cond, inner) => {
                let cond = self.fp_vars[*cond];
                if cond != F::ExtElem::ZERO {
                    tracing::debug!("true conditional");
                    // conditional is true
                    let inner_val = self.fp_vars[*inner];
                    // inner should be zero
                    if inner_val != F::ExtElem::ZERO {
                        tracing::debug!("inner != 0");
                        // follow inner to find out where it went bad
                        self.debug(*inner);
                    } else {
                        // follow chain
                        self.debug(*chain)
                    }
                } else {
                    // conditional is false, follow chain
                    self.debug(*chain)
                }
            }
            _ => unreachable!(),
        }
    }

    #[cfg(feature = "circuit_debug")]
    fn debug_expr(&self, next: Var) -> String {
        let op_index = self.fp_index[next];
        let op = &self.def.block[op_index];
        match op {
            PolyExtStep::Const(x) => format!("{x:?}"),
            PolyExtStep::ConstExt(x0, x1, x2, x3) => format!("({x0:?}, {x1:?}, {x2:?}, {x3:?})"),
            PolyExtStep::Get(x) => format!("Get({x})"),
            PolyExtStep::GetGlobal(arg, x) => format!("GetGlobal({arg}, {x})"),
            PolyExtStep::Add(x, y) => {
                format!("({} + {})", self.debug_expr(*x), self.debug_expr(*y))
            }
            PolyExtStep::Sub(x, y) => {
                format!("({} - {})", self.debug_expr(*x), self.debug_expr(*y))
            }
            PolyExtStep::Mul(x, y) => {
                format!("({} * {})", self.debug_expr(*x), self.debug_expr(*y))
            }
            _ => String::new(),
        }
    }

    fn fp_index(&self) -> usize {
        self.fp_vars.len()
    }

    fn mix_index(&self) -> usize {
        self.mix_vars.len()
    }

    fn push_fp(&mut self, _idx: usize, val: F::ExtElem) {
        #[cfg(feature = "circuit_debug")]
        self.fp_index.push(_idx);
        self.fp_vars.push(val);
    }

    fn push_mix(&mut self, _idx: usize, mix: MixState<F::ExtElem>) {
        #[cfg(feature = "circuit_debug")]
        self.mix_index.push(_idx);
        self.mix_vars.push(mix);
    }

    fn step(
        &mut self,
        idx: usize,
        op: &PolyExtStep,
        mix: &F::ExtElem,
        u: &[F::ExtElem],
        args: &[&[F::Elem]],
    ) {
        match op {
            PolyExtStep::Const(value) => {
                let val = F::Elem::from_u64(*value as u64);
                trace_if_enabled!("[f:{}] {op:?} -> {val:?}", self.fp_index());
                self.push_fp(idx, val.into());
            }
            PolyExtStep::ConstExt(x0, x1, x2, x3) => {
                let val = F::ExtElem::from_subelems([
                    F::Elem::from_u64(*x0 as u64),
                    F::Elem::from_u64(*x1 as u64),
                    F::Elem::from_u64(*x2 as u64),
                    F::Elem::from_u64(*x3 as u64),
                ]);
                trace_if_enabled!("[f:{}] {op:?} -> {val:?}", self.fp_index());
                self.push_fp(idx, val);
            }
            PolyExtStep::Get(tap) => {
                let val = u[*tap];
                trace_if_enabled!("[f:{}] {op:?} -> {val:?}", self.fp_index());
                self.push_fp(idx, val);
            }
            PolyExtStep::GetGlobal(base, offset) => {
                let val = F::ExtElem::from_subfield(&args[*base][*offset]);
                trace_if_enabled!("[f:{}] {op:?} -> {val:?}", self.fp_index());
                self.push_fp(idx, val);
            }
            PolyExtStep::Add(x1, x2) => {
                let val = self.fp_vars[*x1] + self.fp_vars[*x2];
                trace_if_enabled!("[f:{}] {op:?} -> {val:?}", self.fp_index());
                self.push_fp(idx, val);
            }
            PolyExtStep::Sub(x1, x2) => {
                let val = self.fp_vars[*x1] - self.fp_vars[*x2];
                trace_if_enabled!("[f:{}] {op:?} -> {val:?}", self.fp_index());
                self.push_fp(idx, val);
            }
            PolyExtStep::Mul(x1, x2) => {
                let val = self.fp_vars[*x1] * self.fp_vars[*x2];
                trace_if_enabled!("[f:{}] {op:?} -> {val:?}", self.fp_index());
                self.push_fp(idx, val);
            }
            PolyExtStep::True => {
                let mix_val = MixState {
                    tot: F::ExtElem::ZERO,
                    mul: F::ExtElem::ONE,
                };
                trace_if_enabled!("[m:{}] {op:?}", self.mix_index());
                self.mix_exp.push(0);
                self.push_mix(idx, mix_val);
            }
            PolyExtStep::AndEqz(chain, inner) => {
                let exp = self.mix_exp[*chain] + 1;
                let chain = self.mix_vars[*chain];
                let inner = self.fp_vars[*inner];
                let mix_val = MixState {
                    tot: chain.tot + chain.mul * inner,
                    // WAS `chain.mul * *mix`. chain.mul is mix^(exp-1), so this is mix^exp.
                    mul: match self.mix_pows.get(exp) {
                        Some(p) => *p,
                        None => chain.mul * *mix,
                    },
                };
                self.mix_exp.push(exp);
                trace_if_enabled!("[m:{}] {op:?}, inner: {inner:?}", self.mix_index());
                self.push_mix(idx, mix_val);
            }
            PolyExtStep::AndCond(chain, cond, inner) => {
                let exp = self.mix_exp[*chain] + self.mix_exp[*inner];
                let chain = self.mix_vars[*chain];
                let cond = self.fp_vars[*cond];
                let inner = self.mix_vars[*inner];
                let mix_val = MixState {
                    tot: chain.tot + cond * inner.tot * chain.mul,
                    // WAS `chain.mul * inner.mul`; mix^a * mix^b = mix^(a+b).
                    mul: match self.mix_pows.get(exp) {
                        Some(p) => *p,
                        None => chain.mul * inner.mul,
                    },
                };
                self.mix_exp.push(exp);
                trace_if_enabled!(
                    "[m:{}] {op:?}, cond: {}, inner: {}",
                    self.mix_index(),
                    cond != F::ExtElem::ZERO,
                    inner.tot != F::ExtElem::ZERO,
                );
                self.push_mix(idx, mix_val);
            }
        }
    }
}

