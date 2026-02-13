# Contributing to Oreulia

Thank you for considering a contribution. We welcome all kinds of help: code, documentation, tests, design notes, and bug reports. This guide is intentionally short and clear so you can get started quickly.

**Quick Start**
1. Check open issues or start a short discussion in an issue if the change is non-trivial.
2. Create a focused branch for your work.
3. Keep changes scoped and well-documented.
4. Open a pull request with a clear summary, tests (if any), and rationale.

**What We Accept**
- Bug fixes and correctness improvements.
- Performance improvements with data or reasoning.
- Documentation improvements or clarifications.
- New features that align with the project direction.

**Before You Start**
- If your change affects core kernel behavior, open a brief issue first so we can confirm direction.
- If your change adds a new subsystem or directory, propose the structure before implementation.
- Keep changes small and composable where possible.

**Coding Standards**
- Prefer clear, explicit code over clever tricks.
- Match existing style and naming conventions in nearby files.
- Keep functions short and focused.
- Add comments only when the intent is not obvious from the code.
- Avoid introducing new external dependencies unless clearly justified.

**Testing**
- If you can run tests locally, include results in your PR.
- If tests are not available for your change, explain how you validated it.
- For kernel or assembly changes, include a short note on boot or runtime behavior if applicable.

**Documentation**
- Update docs when behavior, configuration, or public interfaces change.
- Keep documentation concise and concrete, with examples where useful.

**Commit and PR Guidelines**
- Use a clear, descriptive title.
- Describe the problem, the solution, and any tradeoffs.
- Link relevant issues if applicable.
- Include any migration notes or compatibility impacts.

**Security**
- Do not disclose security vulnerabilities publicly.
- If a private security contact is listed in the repository, use it.
- If no security contact is listed, open a minimal issue requesting a private channel and do not include details.

**Respect and Collaboration**
- Be respectful and constructive.
- Assume good intent and focus on the work.
- If you are unsure about anything, ask. We are happy to help.

---

## License and Contribution Header for New Scripts

All new scripts and modules must begin with the full license and contribution header block. This ensures that every file in the Oreulia codebase is clearly licensed, attributed, and provides guidance for future contributors.

**Why is this required?**
- It guarantees that all code is covered by the project’s open source license and contributor agreement.
- It makes the terms of use and contribution clear to anyone reading or reusing the code.
- It helps maintainers and users quickly identify the file’s purpose, authorship, and contribution process.

**How to implement:**
- Copy the entire header block from [`codepageheader.md`](../codepageheader.md) and paste it at the very top of your new script or module.
- Fill in the script/module name and a brief description of its features and purpose.
- Update the feature list and notes as the file evolves.

See [`codepageheader.md`](../codepageheader.md) for the latest template and detailed instructions.

**License**
By contributing, you agree that your contributions are provided under the project license unless a separate agreement is in place.
