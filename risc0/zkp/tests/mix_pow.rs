//! Correctness of the mix-power lookup table in the poly_ext interpreter.
//!
//! `MixState::mul` is always a power of `mix` — `True` gives mix^0, `AndEqz` multiplies the chain
//! by mix (exponent+1), `AndCond` multiplies two chains (exponents add), and no other constructor
//! exists. So the VALUE can be read from a table indexed by the EXPONENT instead of recomputed
//! with a multiply every step. This asserts the table agrees with the multiply it replaced.
//!
//! An INTEGRATION test on purpose: risc0-zkp's own `#[cfg(test)]` modules do not compile in this
//! fork (poseidon2/mod.rs reaches for `std`, merkle.rs for a removed field), which would block any
//! unit test from running. An integration test compiles the lib without them.
use risc0_core::field::{Elem as _, ExtElem as _};
use risc0_zkp::adapter::{PolyExtStep, PolyExtStepDef, MIX_POW_MAX};
use risc0_zkp::field::baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem};

type E = BabyBearExtElem;

/// The interpreter BEFORE the table: `mul` derived by an actual multiply at every step.
// Returns (tot, mul) as a plain pair: MixState is #[non_exhaustive] and cannot be built
// outside the crate, which is exactly the sort of thing an integration test discovers.
fn reference(block: &[PolyExtStep], ret: usize, mix: E, u: &[E]) -> (E, E) {
    let (mut fp, mut mx): (Vec<E>, Vec<(E, E)>) = (Vec::new(), Vec::new());
    for op in block {
        match op {
            PolyExtStep::Const(v) => fp.push(E::from_subfield(&BabyBearElem::new(*v))),
            PolyExtStep::Get(t) => fp.push(u[*t]),
            PolyExtStep::Mul(a, b) => { let v = fp[*a] * fp[*b]; fp.push(v) }
            PolyExtStep::Add(a, b) => { let v = fp[*a] + fp[*b]; fp.push(v) }
            PolyExtStep::True => mx.push((E::ZERO, E::ONE)),
            PolyExtStep::AndEqz(c, i) => {
                let (ctot, cmul) = mx[*c];
                let i = fp[*i];
                mx.push((ctot + cmul * i, cmul * mix))
            }
            PolyExtStep::AndCond(c, cond, i) => {
                let (ctot, cmul) = mx[*c];
                let cd = fp[*cond];
                let (itot, imul) = mx[*i];
                mx.push((ctot + cd * itot * cmul, cmul * imul))
            }
            _ => unreachable!("op not used by this test"),
        }
    }
    mx[ret]
}

/// Chain longer than MIX_POW_MAX so BOTH paths run: the table below 256, the multiply fallback
/// above it. A test that stayed under the table would pass while the fallback was broken.
fn build(n: usize) -> (Vec<PolyExtStep>, usize) {
    let mut b = vec![
        PolyExtStep::Const(7),
        PolyExtStep::Get(0),
        PolyExtStep::Get(1),
        PolyExtStep::Mul(1, 2),
        PolyExtStep::Add(0, 3),
    ];
    b.push(PolyExtStep::True);
    for i in 0..n {
        b.push(PolyExtStep::AndEqz(i, i % 5));
    }
    b.push(PolyExtStep::AndCond(n, 3, n.saturating_sub(1)));
    (b, n + 1)
}

fn check(n: usize) {
    let (block, ret) = build(n);
    let leaked: &'static [PolyExtStep] = Box::leak(block.into_boxed_slice());
    let def = PolyExtStepDef { block: leaked, ret };
    let e = |a, b, c, d| E::new(BabyBearElem::new(a), BabyBearElem::new(b),
                                BabyBearElem::new(c), BabyBearElem::new(d));
    let mix = e(3, 5, 7, 11);
    let u = [e(2, 4, 6, 8), e(9, 1, 3, 5)];
    let got = def.step::<BabyBear>(&mix, &u, &[]);
    let (want_tot, want_mul) = reference(leaked, ret, mix, &u);
    assert_eq!(got.tot, want_tot, "tot diverged at n={n}");
    assert_eq!(got.mul, want_mul, "mul diverged at n={n} — the power table is WRONG");
}

#[test]
fn table_path_matches_reference() { check(64); }

#[test]
fn boundary_at_mix_pow_max_matches_reference() { check(MIX_POW_MAX); }

#[test]
fn fallback_beyond_table_matches_reference() { check(MIX_POW_MAX + 200); }
