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

use risc0_zkp::core::digest::Digest;
use risc0_zkp::digest;

/// Smallest cycle limit, as a power of two (po2), supported as a lift program.
pub const MIN_LIFT_PO2: usize = 14;

/// Control IDs allowed in the default set of recursion programs. Includes control IDs for the base
/// set of recursion programs, and each power-of-two of the rv32im circuit, using Poseidon2.
pub const ALLOWED_CONTROL_IDS: &[Digest] = &[
    digest!("0d79bc33b4760b4783cbb96fdc87724c7e0c463eb0ba1b2705d39f43c698bd2d"), // recursion identity.zkr
    digest!("7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e"), // recursion join.zkr
    digest!("96cdf605f755f175a5661812810f2d491507c05f2ea4a83e4c3cad693d26651e"), // recursion join_povw.zkr
    digest!("f74a894ff593584f65847630ead1a23af78c5f5fed2b61090866e01fa5767f12"), // recursion join_unwrap_povw.zkr
    digest!("411fa636f2d364648f035174d3778d6340d9ae1dd648fc35657c173f01e27e5f"), // recursion lift_rv32im_v2_14.zkr
    digest!("1ca3ca03030719064ba61b3125bdd326fc57f74e799ef860bdea6f3227381e16"), // recursion lift_rv32im_v2_15.zkr
    digest!("c32b3627d2b3d60c64adf523a98bd16c0ff607471f3d6630d1f26d5e9406d841"), // recursion lift_rv32im_v2_16.zkr
    digest!("c9b08054994f542a6310b00d9b6fc6528ed7bb6f4ca5476a686847127cdfdc5b"), // recursion lift_rv32im_v2_17.zkr
    digest!("e7934a23ddce1423b425cf32aa23be29f48cd40e0b6ff9376dce6f3bf9d0bc35"), // recursion lift_rv32im_v2_18.zkr
    digest!("8c2fdd36ede09a4b9d316a43c51f1160cbd8876659c5f35810c3a119c60d3843"), // recursion lift_rv32im_v2_19.zkr
    digest!("34530b42028fb631c90e1226bb0e750d4b9b593840d45216f75dca449dac7734"), // recursion lift_rv32im_v2_20.zkr
    digest!("fd84d83092a1e1244d423a26d89c892ab098b467c6d82229912deb26e37d2562"), // recursion lift_rv32im_v2_21.zkr
    digest!("9d9dbf33535ab11f52a93839dfd23b352b7626009e81d9459fd04e488898ec6a"), // recursion lift_rv32im_v2_22.zkr
    digest!("c6972402cc81bc6c1122e65aa7cf463f3ac3f477c7dd860582ca7420fc7b8b02"), // recursion lift_rv32im_v2_povw_14.zkr
    digest!("2f6ea1104bdd5955faa135611e8f803e7b4461703b937e704da70955ec115467"), // recursion lift_rv32im_v2_povw_15.zkr
    digest!("a7b55654228123448cd67c400d9bf80b4e54eb3997ee92103e900903b6578862"), // recursion lift_rv32im_v2_povw_16.zkr
    digest!("2adab2445391035b21f255606a1ba060a7d5a64db5cdf13d9fda7f22a2853270"), // recursion lift_rv32im_v2_povw_17.zkr
    digest!("58b27422240db834c08b8e6c12000c093efce8613263f05825c380009c41da48"), // recursion lift_rv32im_v2_povw_18.zkr
    digest!("26c84437d3e26875b259880d0f29da47ed5ca869133637701d33fb15a83dce4b"), // recursion lift_rv32im_v2_povw_19.zkr
    digest!("177fde1441dc735dbd6a58245d82b2036623ac41547dc345f1fd7c486ac51462"), // recursion lift_rv32im_v2_povw_20.zkr
    digest!("eac3fb487080a62e6ff85d331dd72a4706e50e55c9cb842dea48d71e3e119a04"), // recursion lift_rv32im_v2_povw_21.zkr
    digest!("0344cd54d62d2a1b6538b674d5aa141250ff4c5be08c6e3d16cb5e1de632252d"), // recursion lift_rv32im_v2_povw_22.zkr
    digest!("53a7b23d07f99e5d5685e85874f5181e8486aa267a0ae607ffe9ba47c8bdda4a"), // recursion resolve.zkr
    digest!("20ac6e29b1806a143b508414140e2e15e461f93e04e3830af39cca362b8f005d"), // recursion resolve_povw.zkr
    digest!("ba1d7275d5840e4f998e2c5120810c0eb197e90219696e2a64dec7662aa3cb06"), // recursion resolve_unwrap_povw.zkr
    digest!("7771415b778fea1923440e2eb22c4a1e1d7ada2d42cbe03d13402743c0988a31"), // recursion union.zkr
    digest!("1688f04cca489638862dba455c1d5c561513f975c885a3491f0fe12df761c847"), // recursion unwrap_povw.zkr
];

/// Root of the Merkle tree constructed from [ALLOWED_CONTROL_IDS], using Poseidon2.
pub const ALLOWED_CONTROL_ROOT: Digest =
    digest!("a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56");

/// Control ID for the identity recursion programs (ZKR), using Poseidon over the BN254 scalar field.
pub const BN254_IDENTITY_CONTROL_ID: Digest =
    digest!("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404");

/// Control IDs for included recursion programs (ZKRs), using Poseidon2 over BabyBear.
pub const POSEIDON2_CONTROL_IDS: [(&str, Digest); 32] = [
    (
        "identity.zkr",
        digest!("0d79bc33b4760b4783cbb96fdc87724c7e0c463eb0ba1b2705d39f43c698bd2d"),
    ),
    (
        "join.zkr",
        digest!("7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e"),
    ),
    (
        "join_povw.zkr",
        digest!("96cdf605f755f175a5661812810f2d491507c05f2ea4a83e4c3cad693d26651e"),
    ),
    (
        "join_unwrap_povw.zkr",
        digest!("f74a894ff593584f65847630ead1a23af78c5f5fed2b61090866e01fa5767f12"),
    ),
    (
        "lift_rv32im_v2_14.zkr",
        digest!("411fa636f2d364648f035174d3778d6340d9ae1dd648fc35657c173f01e27e5f"),
    ),
    (
        "lift_rv32im_v2_15.zkr",
        digest!("1ca3ca03030719064ba61b3125bdd326fc57f74e799ef860bdea6f3227381e16"),
    ),
    (
        "lift_rv32im_v2_16.zkr",
        digest!("c32b3627d2b3d60c64adf523a98bd16c0ff607471f3d6630d1f26d5e9406d841"),
    ),
    (
        "lift_rv32im_v2_17.zkr",
        digest!("c9b08054994f542a6310b00d9b6fc6528ed7bb6f4ca5476a686847127cdfdc5b"),
    ),
    (
        "lift_rv32im_v2_18.zkr",
        digest!("e7934a23ddce1423b425cf32aa23be29f48cd40e0b6ff9376dce6f3bf9d0bc35"),
    ),
    (
        "lift_rv32im_v2_19.zkr",
        digest!("8c2fdd36ede09a4b9d316a43c51f1160cbd8876659c5f35810c3a119c60d3843"),
    ),
    (
        "lift_rv32im_v2_20.zkr",
        digest!("34530b42028fb631c90e1226bb0e750d4b9b593840d45216f75dca449dac7734"),
    ),
    (
        "lift_rv32im_v2_21.zkr",
        digest!("fd84d83092a1e1244d423a26d89c892ab098b467c6d82229912deb26e37d2562"),
    ),
    (
        "lift_rv32im_v2_22.zkr",
        digest!("9d9dbf33535ab11f52a93839dfd23b352b7626009e81d9459fd04e488898ec6a"),
    ),
    (
        "lift_rv32im_v2_23.zkr",
        digest!("817a4b13453eac5a4e67ea1bdcc0677681faa94e386bdd4b510429363685f067"),
    ),
    (
        "lift_rv32im_v2_24.zkr",
        digest!("6c4f9e2ae5d3d5375956f608a54112418333ad2008052b059f3b500ba8df9d63"),
    ),
    (
        "lift_rv32im_v2_povw_14.zkr",
        digest!("c6972402cc81bc6c1122e65aa7cf463f3ac3f477c7dd860582ca7420fc7b8b02"),
    ),
    (
        "lift_rv32im_v2_povw_15.zkr",
        digest!("2f6ea1104bdd5955faa135611e8f803e7b4461703b937e704da70955ec115467"),
    ),
    (
        "lift_rv32im_v2_povw_16.zkr",
        digest!("a7b55654228123448cd67c400d9bf80b4e54eb3997ee92103e900903b6578862"),
    ),
    (
        "lift_rv32im_v2_povw_17.zkr",
        digest!("2adab2445391035b21f255606a1ba060a7d5a64db5cdf13d9fda7f22a2853270"),
    ),
    (
        "lift_rv32im_v2_povw_18.zkr",
        digest!("58b27422240db834c08b8e6c12000c093efce8613263f05825c380009c41da48"),
    ),
    (
        "lift_rv32im_v2_povw_19.zkr",
        digest!("26c84437d3e26875b259880d0f29da47ed5ca869133637701d33fb15a83dce4b"),
    ),
    (
        "lift_rv32im_v2_povw_20.zkr",
        digest!("177fde1441dc735dbd6a58245d82b2036623ac41547dc345f1fd7c486ac51462"),
    ),
    (
        "lift_rv32im_v2_povw_21.zkr",
        digest!("eac3fb487080a62e6ff85d331dd72a4706e50e55c9cb842dea48d71e3e119a04"),
    ),
    (
        "lift_rv32im_v2_povw_22.zkr",
        digest!("0344cd54d62d2a1b6538b674d5aa141250ff4c5be08c6e3d16cb5e1de632252d"),
    ),
    (
        "lift_rv32im_v2_povw_23.zkr",
        digest!("bd19f156d23811155241e10f7d03ab483949e5039a512d75b7e3da40fcb5490e"),
    ),
    (
        "lift_rv32im_v2_povw_24.zkr",
        digest!("7898f8140d13c04781c2073b2b28541dfa40f23fa824c30228b80b2601d7114a"),
    ),
    (
        "resolve.zkr",
        digest!("53a7b23d07f99e5d5685e85874f5181e8486aa267a0ae607ffe9ba47c8bdda4a"),
    ),
    (
        "resolve_povw.zkr",
        digest!("20ac6e29b1806a143b508414140e2e15e461f93e04e3830af39cca362b8f005d"),
    ),
    (
        "resolve_unwrap_povw.zkr",
        digest!("ba1d7275d5840e4f998e2c5120810c0eb197e90219696e2a64dec7662aa3cb06"),
    ),
    (
        "test_recursion_circuit.zkr",
        digest!("6d55102aa73086602f7039412200124bdec91f0c497c606f9aa09040403e030b"),
    ),
    (
        "union.zkr",
        digest!("7771415b778fea1923440e2eb22c4a1e1d7ada2d42cbe03d13402743c0988a31"),
    ),
    (
        "unwrap_povw.zkr",
        digest!("1688f04cca489638862dba455c1d5c561513f975c885a3491f0fe12df761c847"),
    ),
];

/// Control IDs for included recursion programs (ZKRs), using Blake2b.
///
/// ⭐ **DERIVED, NOT TRANSCRIBED FROM ANYWHERE — there is no upstream blake2b table.**
/// `risc0-zkp` ships `Blake2bCpuHashSuite` as a first-class named suite and
/// `Program::compute_control_id` already takes a `HashSuite`, so these are simply the
/// same 32 programs hashed under it, at `RECURSION_PO2 = 18`.
///
/// 🔴 **THE GENERATOR REPRODUCES ALL 64 PUBLISHED DIGESTS BEFORE EMITTING THESE** —
/// every name under both `POSEIDON2_CONTROL_IDS` and `SHA256_CONTROL_IDS` — and it
/// rebuilds `ALLOWED_CONTROL_ROOT` by the same `BTreeSet`-ordered construction
/// `receipt/succinct.rs` uses, requiring a match, before computing the blake2b root.
/// A table from a harness that could not reproduce what is published would be a list
/// of numbers rather than a result.
pub const BLAKE2B_CONTROL_IDS: [(&str, Digest); 32] = [
    (
        "identity.zkr",
        digest!("a6d3e3d1746d3457e07adf6553de73d52cf28734d16a8376f1c5553773f08e98"),
    ),
    (
        "join.zkr",
        digest!("77f3bf93e12604dc60b86f652931b00262443968c1decb5557acca3ae58b6b11"),
    ),
    (
        "join_povw.zkr",
        digest!("2ddbad2c9cb70844ed2ae08181e3e98fab886785801597de54cb87407be026d0"),
    ),
    (
        "join_unwrap_povw.zkr",
        digest!("c368d516f29d1b32d01a59908a61629325bbabee0f1c9e6b0ac536cf30efb76d"),
    ),
    (
        "lift_rv32im_v2_14.zkr",
        digest!("afd025b4515c4f3ddcb17c013068b347ddba930d8a0e134aea50247e5f58373e"),
    ),
    (
        "lift_rv32im_v2_15.zkr",
        digest!("01ceeb8b43b51451069232ba1044b33062acda1e6dd0bfff5fbebfe9f74b5933"),
    ),
    (
        "lift_rv32im_v2_16.zkr",
        digest!("45c50826bea70f5eb3c841177d2ede664eacd8795cae1f33daac655b678815fc"),
    ),
    (
        "lift_rv32im_v2_17.zkr",
        digest!("4ecbbeb734216cec3083612c1e937d4f343d1d166c3aee80f8dc1552ac9f289d"),
    ),
    (
        "lift_rv32im_v2_18.zkr",
        digest!("c223ed157f0bd011452461399af57a724f4437133f5f48340dd7b1ef4682448d"),
    ),
    (
        "lift_rv32im_v2_19.zkr",
        digest!("4d25ae695a0cbc67f3c14b21747424a28460c9d96894a070bd665729d3b60886"),
    ),
    (
        "lift_rv32im_v2_20.zkr",
        digest!("8d3cbb389bcdd0ddab2f0f8db3fc5a4400a82bfd6920835ff54a6eee7484c83a"),
    ),
    (
        "lift_rv32im_v2_21.zkr",
        digest!("3100f33e509588b494406f2e206ab4fc9ae77410ea23dd9de91e8db89519e81e"),
    ),
    (
        "lift_rv32im_v2_22.zkr",
        digest!("919c7b9b20333a556c57b5f045918d71c6a4eebba701b420d5a849ff9d6a4088"),
    ),
    (
        "lift_rv32im_v2_23.zkr",
        digest!("ab8110d2291a55c73ff554221dee33d66d283124516666864b976fb59b519175"),
    ),
    (
        "lift_rv32im_v2_24.zkr",
        digest!("044f3956070ed8d073e1324aeeea12874765e8b80d90beb716c4a06321e9c7f4"),
    ),
    (
        "lift_rv32im_v2_povw_14.zkr",
        digest!("c99ccf3c9e5d948e36c84af71b8a276daf66b8455d7caa30e3ff89bfb6c7ef57"),
    ),
    (
        "lift_rv32im_v2_povw_15.zkr",
        digest!("e0c5925f501f01b042064ee667e1c56ddcfa807267535cb509226443835b8d06"),
    ),
    (
        "lift_rv32im_v2_povw_16.zkr",
        digest!("8f4d1df23d60b021ca0a20ea97ddef749ee8688b5c59124b869f5e50664e7886"),
    ),
    (
        "lift_rv32im_v2_povw_17.zkr",
        digest!("fa9d593f0f1a1bf887da38cd15ac74115e294d3433946bf03fd952f17ed9a737"),
    ),
    (
        "lift_rv32im_v2_povw_18.zkr",
        digest!("6c1ec5fc485b43780e070547c2cf84a57ae1aef7083a08eab189195f1a212385"),
    ),
    (
        "lift_rv32im_v2_povw_19.zkr",
        digest!("26635227ae11f58d3e1a0863421946bdf30883e0524377d59434636ad53ba0ae"),
    ),
    (
        "lift_rv32im_v2_povw_20.zkr",
        digest!("09a35538bbc29dc9aae0507457294525e348e0397a2439a15821d8290d3cd9f7"),
    ),
    (
        "lift_rv32im_v2_povw_21.zkr",
        digest!("d249a580dadb0483d0a0852ca424f32359c494334ea264ee4bebce6c193a35b9"),
    ),
    (
        "lift_rv32im_v2_povw_22.zkr",
        digest!("9339c1483a7e322f497a5b2e19d429104c6c6d8dc1f521249720fdbe9de9bea2"),
    ),
    (
        "lift_rv32im_v2_povw_23.zkr",
        digest!("bc5e679268706e6d2c85d701dc502da924ea1e8ec4bf82085b292c305fc83198"),
    ),
    (
        "lift_rv32im_v2_povw_24.zkr",
        digest!("f6208f5e63f7d69df153559d3abea06ba39f79e0dda9f6d6864c01f76b173467"),
    ),
    (
        "resolve.zkr",
        digest!("c99a543f206a0e8bb19e0153b1e236318ad5120fed53a4fc1f4c7b3ae1e8eda5"),
    ),
    (
        "resolve_povw.zkr",
        digest!("a6e3ed4784ac7c6f6782781c85fbddb8fdbba0932039ff12e17298f7634afeeb"),
    ),
    (
        "resolve_unwrap_povw.zkr",
        digest!("2fb99c02797a72c74b5cbdef6b807cf6e0ded6240892d7293b3f63e97fef647f"),
    ),
    (
        "test_recursion_circuit.zkr",
        digest!("7b35d8fc23d4639906b2a6b19ce9d00abcdaccf2dfc766ef56e2529058c3c00d"),
    ),
    (
        "union.zkr",
        digest!("a7d559722c4e02493d77cd8dc1f1346e1180e2d93abd214e91926be747b0649e"),
    ),
    (
        "unwrap_povw.zkr",
        digest!("7c0b38439d0d3350fcf9dd0126a0d44112e3a43fa706b09f385c13930aeb0c06"),
    ),
];

/// Root of the Merkle tree over the blake2b control IDs of the allowed set, using
/// Blake2b. Same leaf set and same `po2_max` (`DEFAULT_MAX_PO2 = 22`) as
/// [ALLOWED_CONTROL_ROOT], which is poseidon2.
pub const BLAKE2B_ALLOWED_CONTROL_ROOT: Digest =
    digest!("7baaf327af40c2ce2f11d55fc91d1a29d1003827310534d58244f2d19eb28ddd");

/// Control IDs for included recursion programs (ZKRs), using SHA-256.
/// Control IDs for each recursion program, under the blake3 hash suite.
///
/// A control ID is the digest of the ZKR under the hash function that seals the recursion proof,
/// so the same 32 programs have a different ID per suite. Generated by
/// `svm/probes/zkvm/risc0-blake2b-arm/src/bin/control-ids.rs`, which refuses to emit unless it
/// first reproduces all 64 published poseidon2+sha-256 digests and rebuilds the published
/// `ALLOWED_CONTROL_ROOT` — so these values are derived by the same path that regenerates the
/// upstream ones, not by a parallel implementation.
pub const BLAKE3_CONTROL_IDS: [(&str, Digest); 32] = [
    ("identity.zkr", digest!("80545be57a4978a2f123793f7427cd7ec49c8f52250ef4504a0166117057a94d")),
    ("join.zkr", digest!("8b11b083964de3442056abe0366a5188ff799ff23c1c5591f35a44f049d13891")),
    ("join_povw.zkr", digest!("a80f97a0fe1525eb1272ce83aa6093849dbfd1d342a68dbcb0a0366fee05fdfc")),
    ("join_unwrap_povw.zkr", digest!("ae8c435a53f0c3158e68fc788467d9f30d2ef6958d6d11b06ac431527f98d098")),
    ("lift_rv32im_v2_14.zkr", digest!("889167b6fe0b41b5a8dbed10c125c561f89ee4f92f63b363bd41d6cb1aff8507")),
    ("lift_rv32im_v2_15.zkr", digest!("aaf99658ab61fa63e0b23770063e2f5dc3e00f359d0aafd956ab30d196b34cbc")),
    ("lift_rv32im_v2_16.zkr", digest!("cce567349103136edd445f23f7266d1a4d99018fad86290f11f3392c6afd32b8")),
    ("lift_rv32im_v2_17.zkr", digest!("0796761319c6343b5223fda0c2c5a2e82840bb1d177639468b17398a53011ceb")),
    ("lift_rv32im_v2_18.zkr", digest!("2c4591aed1919513f66a8cbd886d72e11946c5630118a2b04d2117fab28bd702")),
    ("lift_rv32im_v2_19.zkr", digest!("039fea725119b51fa4518fc0a6cf402ccafa3c14ad313e7de441e8e5ff0c671c")),
    ("lift_rv32im_v2_20.zkr", digest!("1ad54311fd3eac415a731efbd6b8e3d0cb563862ea3b9edcdd6a071b0dab7f91")),
    ("lift_rv32im_v2_21.zkr", digest!("cd711a6fbdd6f502bac1512f5090b7ccd36bd69885d62e55c8dbe34b21cf56a3")),
    ("lift_rv32im_v2_22.zkr", digest!("8c7920717ed5189546f266021d6bcd94bd093d551862a427ff4d834b1187e875")),
    ("lift_rv32im_v2_23.zkr", digest!("8abcb9b688155d97e61530e2f1285836d0ac5b83cff0f06ab2857185eb193c0f")),
    ("lift_rv32im_v2_24.zkr", digest!("937b8ef16095e4de030202a0cefee742778d62cc0cdb865a3f356ac65a473841")),
    ("lift_rv32im_v2_povw_14.zkr", digest!("b2713a0df3180be571b71913142c932ce47dccbbe64ae4d359c21e3d5e5d12ba")),
    ("lift_rv32im_v2_povw_15.zkr", digest!("a72adf9316c85ac011b7a8555e27fb36487c33e9ac1420df7f61267acf756545")),
    ("lift_rv32im_v2_povw_16.zkr", digest!("3bd4b39387f06ef36b15f87ba3070b162cec3780d16d4aa9a76fb3a876342fba")),
    ("lift_rv32im_v2_povw_17.zkr", digest!("61a23c122302b156fccdeb895692932db03459d035b9d3b9f1aa2c54f4d6e051")),
    ("lift_rv32im_v2_povw_18.zkr", digest!("e5358c986f39dbe8dae5b6ccd123c4cab5c51572ffb3f72c2e0bc20077225f04")),
    ("lift_rv32im_v2_povw_19.zkr", digest!("2a49b327bbfb0c010831f12c0067b7bc8a541cd4b8cf68b19837d7982d9a55df")),
    ("lift_rv32im_v2_povw_20.zkr", digest!("990c60b7cdd11520ad637b93002a49587ec7488144c2780c77de4456d9d0fbde")),
    ("lift_rv32im_v2_povw_21.zkr", digest!("804c45b8098a12f14be4a9b72324a172ab77cf2fb0c2dff6f280c270e6b1b04c")),
    ("lift_rv32im_v2_povw_22.zkr", digest!("4604f80db17cd70f9cf641ed7586a17d961fca432772a7c398351d7a0adaf868")),
    ("lift_rv32im_v2_povw_23.zkr", digest!("a858ebb3970bcc4ec525d5658954ad117fd063e7487e36d1e7f1674407bc5ae9")),
    ("lift_rv32im_v2_povw_24.zkr", digest!("9f57ad8eb0625b2f6553fe673e36538be60b52ef1c89ffb87d67f3eee8ed9830")),
    ("resolve.zkr", digest!("fd4f2b3dc4d8a506246b27c8a7e6b3c95d4f76abd35c8b9b9438c080b5b41415")),
    ("resolve_povw.zkr", digest!("485a4857ac811ac334305986995e15ebb52c90c0f35c7f192daa27bff500269b")),
    ("resolve_unwrap_povw.zkr", digest!("1bc1c5a74f91b7c2ba81fdba886a184d6f09da66f1bbe660b373bb67472f1f32")),
    ("test_recursion_circuit.zkr", digest!("a709f373060970e2618993e0be41b05776a7199510618b012d4929ba251d684f")),
    ("union.zkr", digest!("c2127b7d2345580b9e38eb9ccd240a79f979accc536cc160103078801cc372be")),
    ("unwrap_povw.zkr", digest!("0f1f96c8e565b3e8abb283ef9eeca2905e31e981140e70b6151997322252dd47")),
];

/// Root of the Merkle tree over the allowed blake3 control IDs, at `DEFAULT_MAX_PO2 = 22`.
/// The blake3 counterpart of [ALLOWED_CONTROL_ROOT]: same 27 allowed names, different leaves and
/// a different tree hash, so a blake3-sealed receipt verifies against this root and never the
/// poseidon2 one.
pub const BLAKE3_ALLOWED_CONTROL_ROOT: Digest =
    digest!("baf1b07e5a1c61a1601c9f0bb86ef4718eea83c8ceea210b9122915852555c9c");

pub const SHA256_CONTROL_IDS: [(&str, Digest); 32] = [
    (
        "identity.zkr",
        digest!("d7ecd18c7d06fc468166147cf20869aa10f32e097a0c166146a5a62dd2d975ea"),
    ),
    (
        "join.zkr",
        digest!("dc44002689aa7852410ad1c840388d66b8b9a2f6d0c4fb6b3ac6ec2ea17d9855"),
    ),
    (
        "join_povw.zkr",
        digest!("9e97b7ba610dc00ec2628d53274c303eb0d78e6e5c33ef118cf60a5135efa97f"),
    ),
    (
        "join_unwrap_povw.zkr",
        digest!("8cae4f60f8b44780351ec5740118fcc348d8fa0d029f07d2c77a3f9239165319"),
    ),
    (
        "lift_rv32im_v2_14.zkr",
        digest!("52d814fea0ff156f2b8b34f7c47d7bfb5c09c527d7907a8664bd95f104633852"),
    ),
    (
        "lift_rv32im_v2_15.zkr",
        digest!("ca0c7e2ffb7cc226f544dfbebd420a898ba1ec42cb6da27c1446f7dafc41c534"),
    ),
    (
        "lift_rv32im_v2_16.zkr",
        digest!("b20d5da6ac0f4bface80e6f902cd0f77e3f5e3a8174379595ac74d6f052acae5"),
    ),
    (
        "lift_rv32im_v2_17.zkr",
        digest!("7e81c18847d0693f69eaffe6a43e3883f81f57ecea2b740a682870d9d810faaf"),
    ),
    (
        "lift_rv32im_v2_18.zkr",
        digest!("b8f1d3b165d1a9eab7c6c37d3e9583b9907af5ef847c90ca2e4d18c689897a95"),
    ),
    (
        "lift_rv32im_v2_19.zkr",
        digest!("9385cfb4c04bb8a7afca8b2d1bf083cb5d7d975d8a47b92f02710a81cd49d2cb"),
    ),
    (
        "lift_rv32im_v2_20.zkr",
        digest!("771619915ed607e737578315c855ba70c322ac02cfdd01da0e4d1bed4c51cb0d"),
    ),
    (
        "lift_rv32im_v2_21.zkr",
        digest!("c662b29a03a3475a3dae43ef30b0e4234a9e00d99b49d1f61d8ae91c7957a148"),
    ),
    (
        "lift_rv32im_v2_22.zkr",
        digest!("5d68f47ef1f5ab04588c370a79d1216eeec96c5d75fcf73af3a2a59b76bd2879"),
    ),
    (
        "lift_rv32im_v2_23.zkr",
        digest!("bb5ced4a8480a2347cfa43125a9c5b165e2ff3bc99b42927d43f49d23d8b3208"),
    ),
    (
        "lift_rv32im_v2_24.zkr",
        digest!("3e6ac6e4ca5d76858edae7a4f080a2a34649ea6ce0870d0d77ec18b7299b1dbd"),
    ),
    (
        "lift_rv32im_v2_povw_14.zkr",
        digest!("e5e64a61ebe66ad5361417b2c5b879f555567b8b27f24263b285fd2a44e9d879"),
    ),
    (
        "lift_rv32im_v2_povw_15.zkr",
        digest!("058a1436c07037e4b02856b51a09a4b8b81f0653dacde6efbead574d2ccc877c"),
    ),
    (
        "lift_rv32im_v2_povw_16.zkr",
        digest!("39ac8603e8fdd8b1571546cf21afc4fecbd763abdc83c6f556f865f1639cf793"),
    ),
    (
        "lift_rv32im_v2_povw_17.zkr",
        digest!("2f83f136dff007043e04c793946ec7b1d6fc85aa80fd56b3cddfd41e5b5e80cd"),
    ),
    (
        "lift_rv32im_v2_povw_18.zkr",
        digest!("8fc29c56e18387c39b45a6ad5efe70c4b05f4755dafe79ceb503f00d99711171"),
    ),
    (
        "lift_rv32im_v2_povw_19.zkr",
        digest!("a6e06036f3b4c84aac96b2c43b18fba7328a0f1c6d0a1a92f6601ceb7f136a23"),
    ),
    (
        "lift_rv32im_v2_povw_20.zkr",
        digest!("97a1d6b0d9c7cbc754a24b76a068c43a3dd0a194708e88b5ba061617c3bff7b4"),
    ),
    (
        "lift_rv32im_v2_povw_21.zkr",
        digest!("268d25ef3fa8fc664c1a9629870be677b66e537d8b56fceddf4e55cea3ec8167"),
    ),
    (
        "lift_rv32im_v2_povw_22.zkr",
        digest!("e836234e551bf0404665c68a6489527e0f38d77e058a702911298912d4fdfee0"),
    ),
    (
        "lift_rv32im_v2_povw_23.zkr",
        digest!("5544f519c4d65a1546475b23860e26ff7299059e24cacb3b10854cc2872e7736"),
    ),
    (
        "lift_rv32im_v2_povw_24.zkr",
        digest!("ae43f6e6b2565ef910c9736eb616a1d045ff049571c37ac728ad70d8cca2d66d"),
    ),
    (
        "resolve.zkr",
        digest!("ecc34946284eb02d1e119ef0878ae65ba5e855d6e0b5db4e462a694007b2a0f4"),
    ),
    (
        "resolve_povw.zkr",
        digest!("51fe537675d705e759c0cb0862f0cb7c5d70ce3dc483efc3cb1646c2b6f0cba3"),
    ),
    (
        "resolve_unwrap_povw.zkr",
        digest!("1332cc7a1cb90467d849db4ebc4fcc201f81fe0a2ab06d6a398d76b7dd8aa694"),
    ),
    (
        "test_recursion_circuit.zkr",
        digest!("3c7b9195e051f01d9dc21d96a1dd26c7035bc225511a715cf8c7ba83f8df7687"),
    ),
    (
        "union.zkr",
        digest!("44bfa51c5030508d7eddc1b1489145a6e519842f7283098a17f13fe9113497dc"),
    ),
    (
        "unwrap_povw.zkr",
        digest!("3b5de70ddecc2fabcd3b9b9150ff64e7fc084ecb80f97cac2f9ee11e326087d1"),
    ),
];
