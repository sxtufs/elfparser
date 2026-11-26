# Conventions

## Guards (added after a mistake repeated)
- Before finishing, stop the servers and background commands you started; long-lived work goes in a job or the preview.
- A check that ran zero tests is not a passing check; make sure the runner collects the tests.
- `ladder_tests.rs` (Poweramp JNI_OnLoad gate) silently SKIPs when the gitignored fixture is missing: copy `libpowerampcore.so` into `elftrace-core/test_fixtures/accuracy/` first. It compiles the structured output with `aarch64-linux-gnu-gcc -std=c11 -Werror`, so generated C must declare all extern calls and cast pointer/int mixes through uintptr_t.
