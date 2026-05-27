use std::io::{self, Write};

pub type TestCaseResult = (&'static str, bool, String);

pub fn emit_line(line: &str) {
    let _ = writeln!(io::stderr(), "{line}");
    let _ = io::stderr().flush();
}

pub fn emit_banner(title: &str) {
    emit_line("");
    emit_line("================================================================================");
    emit_line(title);
    emit_line("================================================================================");
}

pub fn emit_suite_header(suite: &str) {
    emit_line("");
    emit_line(&format!("--- {suite} ---"));
}

pub fn emit_case(suite: &str, name: &str, passed: bool, detail: &str) {
    if passed {
        if detail == "OK" {
            emit_line(&format!("  [PASS] {suite} :: {name}"));
        } else {
            emit_line(&format!("  [PASS] {suite} :: {name} — {detail}"));
        }
    } else {
        emit_line(&format!("  [FAIL] {suite} :: {name} — {detail}"));
    }
}

pub fn emit_suite_results(suite: &str, results: &[TestCaseResult]) -> (usize, usize) {
    emit_suite_header(suite);
    let mut passed = 0usize;
    let mut failed = 0usize;
    for (name, ok, detail) in results {
        emit_case(suite, name, *ok, detail);
        if *ok {
            passed += 1;
        } else {
            failed += 1;
        }
    }
    (passed, failed)
}

pub fn emit_summary(total_passed: usize, total_failed: usize) {
    let total = total_passed + total_failed;
    emit_line("");
    emit_line("================================================================================");
    emit_line(&format!(
        "SUMMARY: {total_passed} passed, {total_failed} failed, {total} total"
    ));
    emit_line("================================================================================");
    emit_line("");
}
