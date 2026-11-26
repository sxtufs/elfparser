# Decisions

## 2026-11-26 — Large .so handling: discovery is hard-bounded, open failures are never silent
Crash report: a ~180 MB .so loads, then "Recover Functions" freezes and kills the
process; a 200 MB+ .so shows nothing at all. Causes fixed:
- `discovery.rs` collected every adrp/add string reference from the *whole* exec
  region (the 32 MiB scan budget did not apply to `scan_string_refs_aarch64`),
  and copied `.rodata`/`.data.rel.ro`/`.data` into heap `Vec<u8>` twice. On a
  100+ MB binary the refs list reached millions of entries and the report JSON /
  Gson list blew the Java heap. Now `MAX_STRING_REFS = 100_000` caps the list,
  and `ro_sections`/drr/ro are borrowed `&[u8]` from the mapped image (no copies).
- `ELFTraceViewModel.loadElf` swallowed `JNIBridge.open` returning null
  (`?: return@launch`) — the UI just showed nothing. It now sets
  `openError`, shown as a toast by HomeScreen. The 200 MB+ failure itself is
  still on-device (open or parse OOM) and could not be reproduced on the build box.
DexProtect-protected APKs (e.g. TLS Tunnel): `libtlsvpn.so` has no `.symtab`,
~17 dynsyms, no plaintext strings — zero plugin findings is correct, not a bug.
