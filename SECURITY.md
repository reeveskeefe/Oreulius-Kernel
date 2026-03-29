# Security Policy

## Reporting a Vulnerability

Do not report security vulnerabilities in public GitHub issues, discussions,
or pull requests.

Send private vulnerability reports to:

- `reeveskeefe@gmail.com`

Include:

- affected commit or branch
- architecture or runtime involved
- reproduction steps or proof of concept
- impact assessment if known

## Response Expectations

- Initial acknowledgement target: within 7 calendar days
- Triage / severity decision target: within 14 calendar days
- Fix timeline: best effort, depending on severity and reproducibility

## Supported Scope

This project is actively validated on:

- `main`
- the current GitHub Actions regression lanes for `i686`, `x86_64`, `AArch64`, CapNet, and WASM JIT

Older commits, historical tags, experimental branches, and archived artifacts
may not receive fixes.

## Handling Guidance

- Do not post exploit details publicly before a coordinated fix is available.
- Minimize public issue detail if you need to request a private contact path.
- If a report includes working exploitation steps, treat the report as private by default.
