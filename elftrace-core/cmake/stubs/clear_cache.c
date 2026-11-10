
/*
 * __clear_cache shim for Android/Bionic.
 *
 * Unicorn's ARM (and ARM64) JIT emits machine code at runtime and must flush
 * the instruction cache before executing it. It calls `__clear_cache`, which
 * compilers normally provide via compiler-rt builtins. Bionic does NOT export
 * this symbol from libc, and Rust's precompiled `compiler_builtins` omits it for
 * the aarch64-linux-android target, so `dlopen` fails with:
 *
 *   cannot locate symbol "__clear_cache" referenced by libelftrace.so
 *
 * clang's `__builtin___clear_cache` emits the correct architecture sequence
 * (dc cvau / ic ivau / dsb / isb on arm64) and is a no-op on x86, so we just
 * forward to it. Signature matches compiler-rt: (char *begin, char *end).
 */

void __clear_cache(char *begin, char *end) {
    __builtin___clear_cache(begin, end);
}
