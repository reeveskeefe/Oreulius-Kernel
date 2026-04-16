# Headless In-Kernel Fetch Service

fetch_service is the kernel's headless HTTP fetch layer. It owns the privileged parts of network state: sockets, TLS sessions, cookies, cache entries, capability tokens, and audit history. It does not render, layout, parse HTML, or execute scripts. It only moves structured fetch data between kernel and userspace.


## What It Does

fetch_service is the privileged fetch boundary for the system. It performs request dispatch, policy checks, cookie handling, response caching, and download coordination in kernel space. Userspace receives bounded, structured events and decides how to decode, display, or store the data.

That split matters because the kernel can keep control over sensitive state while leaving presentation concerns outside the trusted core. The service is designed for headless clients, system updates, background downloads, and any workflow that needs an auditable fetch path without embedding a renderer in kernel space.

## Why It Exists

Keeping fetch policy and state in kernel gives the system a small, reviewable trusted computing base for privileged network activity. Capability-gated requests reduce ambient authority, fixed-size buffers keep behavior deterministic, and the audit trail makes fetch activity easier to reason about after the fact.

In practice, this module exists so the kernel can safely own the parts of HTTP that must be trusted, while everything that is expensive, untrusted, or presentation-specific stays in userspace.
