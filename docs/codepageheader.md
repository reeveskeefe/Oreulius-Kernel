Below is the canonical first-party header for new scripts or modules. If you
are creating a new file, include the SPDX block and document the file's purpose
and features. If you are contributing to an existing file, keep the header
intact and note material additions in the implementation docs or commit
message.

```rust
/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */
```

```rust
//! Name of script here
//!
//! Fill out line by line features of the file here, and any important notes
//! about the implementation.
//! ...
//! ...
```

## Contribution Instructions for New Scripts

- **License and Copyright:**
  - Every new script must begin with the SPDX header shown above.
  - Do not remove or alter the SPDX notice.

- **Contribution Guidelines:**
  - By contributing, you agree that accepted contributions may be distributed
    and relicensed as part of Oreulius.
  - Follow the [CONTRIBUTING.md](CONTRIBUTING.md) file for code style,
    review, and submission rules.
  - If you add a new feature, update the feature list and notes in the script
    header when practical.

- **Header Template Usage:**
  - Copy and paste the SPDX block at the top of every new script.
  - Fill in the script/module name and a brief description of its features and
    purpose.
  - Keep the header up to date as the file evolves.

---

> For more details, see the main [CONTRIBUTING.md](CONTRIBUTING.md),
> [LICENSE](../LICENSE), [COMMERCIAL.md](../COMMERCIAL.md), and
> [CONTRIBUTOR-LICENSE.md](../CONTRIBUTOR-LICENSE.md) files in the repository.
