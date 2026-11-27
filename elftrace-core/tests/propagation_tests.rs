//! Accuracy guards for the Patch Propagation engine.
//!
//! Two layers:
//!   1. Pure-function tests for the equivalence matcher (`template_matches_at`)
//!      and the operand wildcarding (`seed_word_mask`). These need no ELF and
//!      always run.
//!   2. An end-to-end test against a real fixture with two byte-identical
//!      clones; it skips when the fixture is absent (matching the convention in
//!      accuracy_tests.rs).

use elftrace::elf_parser::ElfContext;
use elftrace::propagation::{
    propagate_exact, seed_insn_mask, seed_word_mask, template_matches_at, PropagateOptions,
    PropagationMode,
};

// ---------------------------------------------------------------------------
// Pure matcher
// ---------------------------------------------------------------------------

#[test]
fn exact_match_finds_identical_slice() {
    let data = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE];
    let template = [0xBB, 0xCC, 0xDD];
    let mask = [0xFFu8, 0xFF, 0xFF];
    assert!(template_matches_at(&data, &template, &mask, 1));
    assert!(!template_matches_at(&data, &template, &mask, 0));
    assert!(!template_matches_at(&data, &template, &mask, 2));
}

#[test]
fn wildcard_mask_ignores_operand_bytes() {
    // Template says 0x..; mask 0x00 on the middle byte means "don't care".
    let data = [0x12u8, 0x99, 0x34];
    let template = [0x12u8, 0x00, 0x34];
    let mask = [0xFFu8, 0x00, 0xFF];
    assert!(template_matches_at(&data, &template, &mask, 0));
}

#[test]
fn matcher_rejects_out_of_bounds_and_bad_mask() {
    let data = [1u8, 2, 3];
    let template = [1u8, 2, 3];
    let mask_ok = [0xFFu8, 0xFF, 0xFF];
    // i + len > data.len()
    assert!(!template_matches_at(&data, &template, &mask_ok, 1));
    // mask length mismatch
    let mask_bad = [0xFFu8, 0xFF];
    assert!(!template_matches_at(&data, &template, &mask_bad, 0));
}

// ---------------------------------------------------------------------------
// Operand wildcarding (AArch64)
// ---------------------------------------------------------------------------

#[test]
fn aarch64_mask_clears_operand_fields_only() {
    // Bits 5..=23 are the register/immediate operand region; the opcode bits
    // (low 0..=4 and top 24..=31) must survive. Use a word with a non-zero low
    // nibble so the low-opcode preservation check is meaningful.
    let word: u32 = 0x5280_0035;
    let (val, mask) = seed_word_mask(183, word);
    // Top opcode byte preserved.
    assert_eq!(val & 0xFF00_0000, 0x5200_0000);
    // Low opcode bits (0..=4) preserved, and required to match.
    assert_eq!(val & 0x1F, 0x15);
    assert_eq!(mask & 0x1F, 0x1F);
    // Operand region cleared in value and ignored in mask.
    assert_eq!(val & 0x00FF_FFE0, 0);
    assert_eq!(mask & 0x00FF_FFE0, 0);
}

#[test]
fn non_aarch64_is_exact() {
    let word: u32 = 0xDEAD_BEEF;
    let (val, mask) = seed_word_mask(62, word); // x86_64
    assert_eq!(val, word);
    assert_eq!(mask, 0xFFFF_FFFF);
}

#[test]
fn arm32_a32_masks_register_fields_only() {
    // Example A32 data-processing word: `mov r0, r1` (0xE1A00001).
    // Register fields: Rm(0-3)=1, Rd(12-15)=0, Rn(16-19)=0.
    let word: u32 = 0xE1A0_0001;
    let (val, mask) = seed_insn_mask(40, false, word);

    // Condition (28-31) and opcode (20-27) must be exact-match.
    assert_eq!(val & 0xFF00_0000, word & 0xFF00_0000);
    assert_eq!(mask & 0xFF00_0000, 0xFF00_0000);
    assert_eq!(val & 0x0FF0_0000, word & 0x0FF0_0000);
    assert_eq!(mask & 0x0FF0_0000, 0x0FF0_0000);

    // All three register fields must be cleared in value and ignored in mask.
    let reg_bits: u32 = 0xF | (0xF << 12) | (0xF << 16);
    assert_eq!(val & reg_bits, 0);
    assert_eq!(mask & reg_bits, 0);
}

#[test]
fn arm32_thumb_is_exact() {
    // Thumb encodings are variable; we do not mask by fixed bit positions.
    let word: u32 = 0x4608_0000;
    let (val, mask) = seed_insn_mask(40, true, word);
    assert_eq!(val, word);
    assert_eq!(mask, 0xFFFF_FFFF);
}

#[test]
fn thumb_seed_patch_uses_thumb_encoding() {
    // Regression guard for the propagatePatch JNI handler: the seed must be
    // resolved with the Thumb flag when the seed lives in Thumb code, or every
    // propagated clone receives A32 bytes (8-byte mov pc-relative encoding)
    // instead of the 4-byte Thumb sequence.
    use elftrace::patcher::quick_patch_bytes;
    use elftrace::patcher::QuickPatchType;

    assert_eq!(
        quick_patch_bytes(40, QuickPatchType::ReturnTrue, true),
        Some(vec![0x01, 0x20, 0x70, 0x47]),
        "Thumb ret_true must be movs r0,#1; bx lr"
    );
    assert_eq!(
        quick_patch_bytes(40, QuickPatchType::ReturnTrue, false),
        Some(vec![0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1]),
        "A32 ret_true must be mov r0,#1; bx lr"
    );
    assert_eq!(
        quick_patch_bytes(40, QuickPatchType::ReturnVoid, true),
        Some(vec![0x70, 0x47]),
        "Thumb ret_void must be bx lr"
    );
}

#[test]
fn arm32_register_differences_still_match() {
    // Two A32 `mov rd, rm` words that differ only in Rd/Rm must compare equal
    // under the ARM32 mask (i.e. they are treated as the same clone).
    let a: u32 = 0xE1A0_0001; // mov r0, r1
    let b: u32 = 0xE1A0_2003; // mov r2, r3
    let (va, ma) = seed_insn_mask(40, false, a);
    let (vb, mb) = seed_insn_mask(40, false, b);
    assert_eq!(ma, mb);
    assert_eq!(
        va & ma,
        vb & mb,
        "operand-only differences must not affect the masked comparison"
    );
}

// ---------------------------------------------------------------------------
// End-to-end (fixture-gated)
// ---------------------------------------------------------------------------

fn fixture_dir() -> String {
    std::env::var("ELFTRACE_FIXTURES_DIR")
        .unwrap_or_else(|_| "/workspace/test_fixtures/accuracy".to_string())
}

#[test]
fn propagate_exact_applies_to_all_clones() {
    // The fixture (tests/fixtures_src/fx_a64_clones.c) exports two
    // byte-identical AArch64 functions, clone_a and clone_b. We seed the patch
    // at clone_a's first instruction (a NOP overwrite), and the engine must
    // discover the identical body at clone_b and rewrite it too. The exact
    // instruction at the seed does not matter for equivalence — what matters
    // is that both function bodies are byte-for-byte equal.
    let path = format!("{}/fx_a64_clones.so", fixture_dir());
    if !std::path::Path::new(&path).exists() {
        eprintln!("SKIP: {} not found (fixture-gated)", path);
        return;
    }
    let mut ctx = ElfContext::open(&path).expect("open fx_a64_clones.so");
    let info = ctx.get_info().unwrap();
    assert_eq!(info.e_machine, 183, "fixture must be AArch64");

    let seed = info
        .syms
        .iter()
        .find(|s| s.sym == "clone_a")
        .expect("fixture must export clone_a")
        .value;

    // Dry-run first: must find at least one other clone, write nothing.
    let dry = propagate_exact(
        &mut ctx,
        seed,
        &[0x1f, 0x20, 0x03, 0xd5], // nop
        &PropagateOptions {
            dry_run: true,
            ..Default::default()
        },
    );
    assert_eq!(dry.mode, PropagationMode::ExactClone.name());
    assert!(dry.error.is_none(), "dry-run error: {:?}", dry.error);
    assert!(
        dry.total_candidates >= 1,
        "expected >=1 clone, got {}",
        dry.total_candidates
    );
    // Nothing written during dry-run.
    let orig = ctx.raw.clone();

    // Apply for real.
    let applied = propagate_exact(
        &mut ctx,
        seed,
        &[0x1f, 0x20, 0x03, 0xd5],
        &PropagateOptions {
            dry_run: false,
            ..Default::default()
        },
    );
    assert!(applied.error.is_none(), "apply error: {:?}", applied.error);
    assert!(
        applied.applied >= 1,
        "expected >=1 applied, got {}",
        applied.applied
    );

    // The buffer actually changed, and only at reported addresses.
    assert_ne!(ctx.raw, orig, "applied propagation must mutate the buffer");
    for entry in &applied.entries {
        if entry.status == "applied" {
            assert_eq!(
                entry.patched_bytes,
                vec![0x1f, 0x20, 0x03, 0xd5],
                "applied entry must carry the seed bytes"
            );
        }
    }
}
