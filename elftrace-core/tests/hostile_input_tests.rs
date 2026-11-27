//! Hostile-input regression: mutated ELFs must be rejected, never crash.
//!
//! `audit_tests::test_malformed_and_truncated_elf` covers three hand-picked
//! cases. Real APKs ship damaged or hand-edited libraries, so this walks a
//! deterministic mutation space instead: byte flips, zero/0xFF fills, header
//! word corruption and truncation over a valid ELF, asserting the parser
//! returns an error (or a sane empty answer) rather than panicking.

use elftrace::elf_parser::ElfContext;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

/// Deterministic xorshift64*: same mutation sequence on every run and host.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn find_fixture(rel: &str) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("ELFTRACE_FIXTURES_DIR") {
        let p = Path::new(&dir).join(rel);
        if p.exists() {
            return Some(p);
        }
    }
    for prefix in ["../", "./", "../../"] {
        let candidate = format!("{}{}", prefix, rel);
        let p = Path::new(&candidate);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// A valid ELF to mutate: a repo fixture when present, otherwise one compiled
/// on the spot with the host C compiler.
fn base_elf() -> Option<Vec<u8>> {
    for rel in [
        "app/src/main/jniLibs/arm64-v8a/libelftrace.so",
        "test_fixtures/accuracy/fx_a64_O2.so",
        "test_fixtures/test_arm64.so",
    ] {
        if let Some(p) = find_fixture(rel) {
            if let Ok(bytes) = fs::read(&p) {
                return Some(bytes);
            }
        }
    }

    let dir = std::env::temp_dir().join(format!("elftrace_hostile_src_{}", std::process::id()));
    fs::create_dir_all(&dir).ok()?;
    let src = dir.join("seed.c");
    let out = dir.join("seed.so");
    fs::write(&src, "int seed(int x) { return x * 3 + 1; }\n").ok()?;
    let status = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-O1", "-o"])
        .arg(&out)
        .arg(&src)
        .status()
        .ok()?;
    let bytes = if status.success() {
        fs::read(&out).ok()
    } else {
        None
    };
    let _ = fs::remove_dir_all(&dir);
    bytes
}

fn mutate(bytes: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if out.is_empty() {
        return out;
    }
    let rounds = 1 + rng.below(6);
    for _ in 0..rounds {
        match rng.below(5) {
            // Flip a single bit anywhere in the file.
            0 => {
                let i = rng.below(out.len());
                out[i] ^= 1 << rng.below(8);
            }
            // Zero a byte (truncated tables, cleared magics).
            1 => {
                let i = rng.below(out.len());
                out[i] = 0;
            }
            // Fill a byte with 0xFF (insane counts, huge offsets).
            2 => {
                let i = rng.below(out.len());
                out[i] = 0xFF;
            }
            // Corrupt an ELF header word: e_shoff, e_shnum, e_phnum, e_type...
            3 => {
                let header_len = out.len().min(64);
                if header_len >= 4 {
                    let i = rng.below(header_len - 3);
                    out[i..i + 4].copy_from_slice(&(rng.next() as u32).to_le_bytes());
                }
            }
            // Truncate the file.
            _ => {
                let cut = 1 + rng.below(out.len());
                out.truncate(cut);
            }
        }
    }
    out
}

/// Everything the app does with a freshly opened file, kept cheap so a few
/// hundred mutants fit in a fraction of a second.
fn exercise(ctx: &ElfContext) {
    let _ = ctx.get_info();
    let _ = ctx.extract_strings();
    let _ = ctx.get_section_name_for_vaddr(0x1000);
    let _ = ctx.is_executable_address(0x1000);
    let _ = ctx.enclosing_symbol(0x1000);
    let _ = ctx.read_string_at(0x1000, 64);
    let _ = ctx.vaddr_to_offset(0x1000);
    let _ = ctx.offset_to_vaddr(0x1000);
    let _ = ctx.get_string_at_vaddr(0x1000);
}

#[test]
fn mutated_elfs_are_rejected_or_survived_without_panics() {
    let base = match base_elf() {
        Some(b) => b,
        None => {
            eprintln!("SKIP: no fixture and no host C compiler to build one");
            return;
        }
    };
    assert!(base.len() > 64, "base ELF must be a real file");

    let dir = std::env::temp_dir().join(format!("elftrace_hostile_{}", std::process::id()));
    fs::create_dir_all(&dir).expect("temp dir");
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut rejected = 0usize;
    let mut accepted = 0usize;

    for case in 0..240 {
        let mutant = mutate(&base, &mut rng);
        let path = dir.join(format!("case_{}.so", case));
        fs::write(&path, &mutant).expect("write mutant");

        let path_str = path.to_string_lossy().to_string();
        let result = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(ctx) = ElfContext::open(&path_str) {
                exercise(&ctx);
                true
            } else {
                false
            }
        }));

        let _ = fs::remove_file(&path);
        match result {
            Ok(true) => accepted += 1,
            Ok(false) => rejected += 1,
            Err(_) => panic!(
                "case {}: parser panicked on a {} byte mutant (seed 0x9E3779B97F4A7C15)",
                case,
                mutant.len()
            ),
        }
    }

    let _ = fs::remove_dir_all(&dir);
    // Guard against a vacuous run: the corpus must actually split both ways.
    assert!(
        rejected > 0,
        "no mutant was rejected - the mutations are not reaching the parser"
    );
    assert!(
        accepted > 0,
        "every mutant was rejected - the corpus is not exercising the parser"
    );
}
