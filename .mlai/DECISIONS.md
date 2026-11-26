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
cascading tails stay as single gotos. Reaching zero requires return-value
synthesis (x19 → `return -1`) via exit-block dataflow — future work.

## 2026-11-26 — Plugin count: assets are the only source, no local cache
The app reads every .json in app/src/main/assets/plugins at each launch
(ELFTraceViewModel); nothing is extracted to storage. Repo ships 18 manifests
and origin/main matches local HEAD, so a CI-built APK showing more means the
workflow ran on an older commit — rebuild on latest main, no code fix.
