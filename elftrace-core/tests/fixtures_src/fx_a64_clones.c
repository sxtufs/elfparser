/*
 * fx_a64_clones.c — fixture for propagate_exact_applies_to_all_clones.
 *
 * Produces a shared object exporting two BYTE-IDENTICAL AArch64 functions
 * `clone_a` and `clone_b`. The propagation engine must match one against the
 * other and patch both.
 *
 * Build (see build_clones.sh):
 *   aarch64-linux-gnu-gcc -shared -fPIC -O2 -fno-ipa-icf \
 *       -o fx_a64_clones.so fx_a64_clones.c
 *
 * `-fno-ipa-icf` is essential: GCC's Identical Code Folding would otherwise
 * merge the two identical bodies into one, leaving only a single clone and
 * defeating the test.
 */

#define KEEP __attribute__((noinline, used, visibility("default")))

/* Both bodies are identical so their machine code is byte-for-byte equal.
 * `volatile` prevents the store from being optimised away, guaranteeing a
 * non-trivial (and identical) instruction sequence before the trailing RET. */
KEEP int clone_a(int *p, int v) {
    volatile int *q = p;
    *q = v;
    return v + 1;
}

KEEP int clone_b(int *p, int v) {
    volatile int *q = p;
    *q = v;
    return v + 1;
}
