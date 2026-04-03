//! Cross-language polyglot kernel service bindings.
//!
//! Oreulius allows WASM modules written in **any** language to register
//! themselves as named kernel services and to call each other securely via
//! capability handoffs — even across language boundaries.
//!
//! ## How it works
//!
//! 1. A WASM module embeds the `oreulius_lang` custom section (see
//!    [`docs/runtime/oreulius-wasm-abi.md`]) to declare its language and version.
//! 2. At startup it calls [`register`] to publish its name in the kernel's
//!    polyglot registry (max 16 entries, IDs 103–105).
//! 3. A *caller* module calls [`resolve`] to look up the target by name and
//!    obtain its instance ID, then calls [`link`] to receive a capability
//!    handle it can pass to `service_invoke` / `service_invoke_typed`.
//!
//! ## Example — service side (e.g. a Python-via-Pyodide module)
//!
//! ```rust,no_run
//! #![no_std]
//! #![no_main]
//!
//! use oreulius_sdk::polyglot;
//!
//! #[no_mangle]
//! pub extern "C" fn _start() {
//!     assert!(polyglot::register("py_math"), "failed to register service");
//!     // … serve requests …
//! }
//! ```
//!
//! ## Example — client side
//!
//! ```rust,no_run
//! #![no_std]
//! #![no_main]
//!
//! use oreulius_sdk::polyglot;
//!
//! #[no_mangle]
//! pub extern "C" fn _start() {
//!     let cap = polyglot::link("py_math", "add")
//!         .expect("py_math service not found");
//!     // pass `cap` to service_invoke(cap, ...) …
//! }
//! ```
//!
//! ## Error codes returned by the kernel
//!
//! | Value | Meaning |
//! |-------|---------|
//! |   0   | Success (register) |
//! |  ≥ 0  | Instance ID (resolve) or cap handle (link) |
//! |  -1   | Bad arguments (null pointer, zero length, name > 32 bytes) |
//! |  -2   | Registry full (register) **or** name not found (resolve / link) |
//! |  -3   | Name already taken by a different, non-singleton module (register) **or** service has no registered export (link) |
//! |  -4   | Capability table full (link) |

use crate::raw::oreulius;

// ---------------------------------------------------------------------------
// High-level typed wrappers
// ---------------------------------------------------------------------------

/// Register this WASM module as a named polyglot kernel service.
///
/// The `name` must be ≤ 32 bytes of UTF-8.  The kernel records the module's
/// language tag (from the `oreulius_lang` custom section) alongside the name.
///
/// **Singletons**: Python (`0x04`) and JavaScript (`0x05`) modules are
/// treated as *singleton* language runtimes — subsequent calls with the same
/// name and language simply refresh the instance/owner reference instead of
/// returning an error.
///
/// Returns `true` on success, `false` on any error.
#[inline]
pub fn register(name: &str) -> bool {
    unsafe { oreulius::polyglot_register(name.as_ptr() as i32, name.len() as i32) == 0 }
}

/// Resolve a registered polyglot service by name.
///
/// Returns `Some(instance_id)` if the name is found, `None` otherwise.
/// The returned `instance_id` can be used with `polyglot_link` or passed
/// directly to low-level `service_invoke` calls.
#[inline]
pub fn resolve(name: &str) -> Option<i32> {
    let result = unsafe {
        oreulius::polyglot_resolve(name.as_ptr() as i32, name.len() as i32)
    };
    if result >= 0 { Some(result) } else { None }
}

/// Obtain a capability handle for calling `export_name` on `module_name`.
///
/// Both `module_name` and `export_name` must be ≤ 32 bytes of UTF-8.
/// The kernel finds the target service in the polyglot registry, locates its
/// service-pointer entry, and injects a cross-language `ServicePointer`
/// capability into this module's capability table.
///
/// Returns `Some(cap_handle)` on success, `None` on any error.
/// Pass the returned handle to `service_invoke` / `service_invoke_typed`.
#[inline]
pub fn link(module_name: &str, export_name: &str) -> Option<u32> {
    let result = unsafe {
        oreulius::polyglot_link(
            module_name.as_ptr()  as i32, module_name.len()  as i32,
            export_name.as_ptr()  as i32, export_name.len()  as i32,
        )
    };
    if result >= 0 { Some(result as u32) } else { None }
}

// ---------------------------------------------------------------------------
// Convenience builder types
// ---------------------------------------------------------------------------

/// A handle to a registered polyglot service, obtained via [`register`].
///
/// Dropping this value does *not* unregister the service — the kernel entry
/// persists until the module instance is torn down.
pub struct PolyglotService {
    name: &'static str,
}

impl PolyglotService {
    /// Register a service and return a handle.  Returns `None` on error.
    #[inline]
    pub fn register(name: &'static str) -> Option<Self> {
        if register(name) { Some(Self { name }) } else { None }
    }

    /// The name this service was registered under.
    #[inline]
    pub fn name(&self) -> &str {
        self.name
    }
}

/// A capability handle obtained via [`link`] that can be used to call a
/// specific export on a remote polyglot service.
pub struct ServiceHandle {
    /// The raw capability handle (index into this module's cap table).
    pub cap: u32,
    /// Name of the remote module, for diagnostics.
    pub module_name: &'static str,
    /// Name of the remote export, for diagnostics.
    pub export_name: &'static str,
}

impl ServiceHandle {
    /// Resolve and link to `export_name` on `module_name`.
    /// Returns `None` if the service is not registered or the export is
    /// not found.
    #[inline]
    pub fn link(module_name: &'static str, export_name: &'static str) -> Option<Self> {
        link(module_name, export_name).map(|cap| Self { cap, module_name, export_name })
    }
}
