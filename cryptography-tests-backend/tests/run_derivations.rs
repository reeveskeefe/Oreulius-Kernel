use oreulius_crypto_math_host_tests::run_mathematical_derivation_tests;

fn main() {
    if let Err(failed) = run_mathematical_derivation_tests() {
        eprintln!("\n{} mathematical derivation test(s) failed.", failed.len());
        std::process::exit(1);
    }
}
