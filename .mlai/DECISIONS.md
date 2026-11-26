# Decisions

## 2026-11-26 — Shared-tail goto inlining: terminators generalized, expansion capped
The "46 gotos" in functions like Poweramp's JNI_OnLoad were shared error tails
whose terminator (IrStmt::Return or a noreturn call like __stack_chk_fail) sits
INSIDE a Block's statements — try_region only stopped at StructuredNode::Return,
so the splice entered the cyclic epilogue labels and refused; nothing inlined.
Fixed: `block_terminates()` treats Block-ending Return / noreturn call / Trap as
terminators, and fallback_to_gotos runs inline_shared_joins to a bounded
fixpoint (3 iterations) so nested inlinable tails expand too.
Poweramp JNI_OnLoad: goto loc_00209610 sites 4 → 1; total gotos 36 → 32.
Deliberately NOT zero: the error tails flow through the stack-canary epilogue,
whose full expansion is ~31 stmts per site; inlining it everywhere tripled the
output (398 → 1307 lines). MAX_INLINE_STMTS = 16 caps expansion size, so long
cascading tails stay as single gotos.

## 2026-11-26 — Return-value synthesis keeps the tail's leading calls; goto count counts gotos only
Two follow-ups from the Poweramp JNI_OnLoad output:
- `const_return_stmts` now logs `IrStmt::Call` while walking a shared tail, and
  `leading_calls()` prepends every call that the tail executes BEFORE the first
  statement of the resolved return chain (e.g. the shared `__android_log_print`
  before the error `return -1`). Per-site synthesis reads
  `x1..x4 = ...; __android_log_print(); x19 = -1; a0 = x19; return a0;` instead
  of silently dropping the log call. Calls between chain statements are still
  skipped (reordering is not provably safe); resolve_chain still bails on Call
  when it needs a register, so no value is resolved through a call.
- The header note counter (`count_gotos` in emit.rs) counted Label nodes too;
  it now counts Goto nodes only ("11 goto(s) kept" instead of "22").

## 2026-11-26 — Tail-helper extraction: gotos the inliner kept become static helpers
The last structuring pass (`extract_tail_helpers` in regions.rs, wired in
mod.rs before emit) takes every still-referenced shared exit tail, splices it
(including explicit-Goto chains into the cyclic canary epilogue, bounded by
MAX_JOIN_STMTS + a visited set) into a `static int64_t tail_XXXXXXXX(...)`
helper, and rewrites each goto site into `return tail_...(...)` (void
functions: call then return). Params are registers the body READS before any
write (ordered scan, `classify_tail_regs`); everything else is a declared
local with `(void)` suppression. 4 cyclic tails whose tails end in conditional
branches to other joins are left as single gotos — splicing branch tails is
what cascaded in the abandoned single-ref attempt (11 → 50 gotos).
Poweramp JNI_OnLoad: 11 → 4 gotos, 522 → 698 lines (the inline approach was
501 → 2628). Output passes `aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra
-Werror -pedantic`. Note: the strict host-clang gate in structuring_tests
`assert_compiles` rejects this fixture's `extern int64_t signal();` decls
(-Wstrict-prototypes), so the tail-helper regression test uses the
ladder_tests-style cross-compiler gate with `-w` instead.

## 2026-11-26 — Plugin count: assets are the only source, no local cache
The app reads every .json in app/src/main/assets/plugins at each launch
(ELFTraceViewModel); nothing is extracted to storage. Repo ships 18 manifests
and origin/main matches local HEAD, so a CI-built APK showing more means the
workflow ran on an older commit — rebuild on latest main, no code fix.
