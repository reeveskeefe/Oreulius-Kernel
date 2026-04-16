// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0


/*!
 * GPU IOMMU domain management.
 *
 * An IOMMU domain represents the I/O virtual address space visible to one
 * GPU context.  Buffer Objects must be *bound* into a domain before the GPU
 * hardware is allowed to DMA from or to them; binding records a
 * (domain_id, bo_id) → (phys_base, size) mapping.
 *
 * This implementation maintains a software-managed binding table that the
 * kernel consults for access validation.  On systems with a real IOMMU
 * (Intel VT-d, AMD-Vi) this table should be kept in sync with the hardware
 * page tables via the platform's IOMMU driver; for now it enforces policy in
 * software only.
 */

use spin::Mutex;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MAX_IOMMU_DOMAINS: usize = 16;
pub const MAX_IOMMU_BINDINGS: usize = 64; // per-table

// ---------------------------------------------------------------------------
// IommuBinding — a single mapped region inside a domain
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IommuBinding {
    /// Identifier of the domain this binding lives in.
    pub domain_id: u32,
    /// Buffer Object identifier (matches `BufferObject::object_id`).
    pub bo_id: u64,
    /// Physical base address of the mapped region.
    pub phys_base: u64,
    /// Length of the mapped region in bytes.
    pub size: usize,
    /// Binding is live.
    pub enabled: bool,
}

impl IommuBinding {
    const EMPTY: Self = IommuBinding {
        domain_id: 0,
        bo_id: 0,
        phys_base: 0,
        size: 0,
        enabled: false,
    };
}

// ---------------------------------------------------------------------------
// IommuDomain — a logical I/O address space
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct IommuDomain {
    domain_id: u32,
    active: bool,
}

impl IommuDomain {
    const EMPTY: Self = IommuDomain {
        domain_id: 0,
        active: false,
    };
}

// ---------------------------------------------------------------------------
// IommuTable — global binding registry
// ---------------------------------------------------------------------------

struct IommuTable {
    domains: [IommuDomain; MAX_IOMMU_DOMAINS],
    bindings: [IommuBinding; MAX_IOMMU_BINDINGS],
    n_domains: usize,
    n_bindings: usize,
}

impl IommuTable {
    const fn new() -> Self {
        IommuTable {
            domains: [IommuDomain::EMPTY; MAX_IOMMU_DOMAINS],
            bindings: [IommuBinding::EMPTY; MAX_IOMMU_BINDINGS],
            n_domains: 0,
            n_bindings: 0,
        }
    }

    // ------------------------------------------------------------------
    // Domain management
    // ------------------------------------------------------------------

    fn create_domain(&mut self, domain_id: u32) -> bool {
        // Idempotent — already exists?
        if self
            .domains
            .iter()
            .any(|d| d.active && d.domain_id == domain_id)
        {
            return true;
        }
        if self.n_domains >= MAX_IOMMU_DOMAINS {
            return false;
        }
        for slot in self.domains.iter_mut() {
            if !slot.active {
                slot.domain_id = domain_id;
                slot.active = true;
                self.n_domains += 1;
                return true;
            }
        }
        false
    }

    fn destroy_domain(&mut self, domain_id: u32) {
        // Remove all bindings belonging to this domain first.
        for b in self.bindings.iter_mut() {
            if b.enabled && b.domain_id == domain_id {
                b.enabled = false;
                if self.n_bindings > 0 {
                    self.n_bindings -= 1;
                }
            }
        }
        for d in self.domains.iter_mut() {
            if d.active && d.domain_id == domain_id {
                d.active = false;
                if self.n_domains > 0 {
                    self.n_domains -= 1;
                }
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // Binding management
    // ------------------------------------------------------------------

    fn bind(&mut self, domain_id: u32, bo_id: u64, phys_base: u64, size: usize) -> bool {
        // Refuse to bind into non-existent domain.
        if !self
            .domains
            .iter()
            .any(|d| d.active && d.domain_id == domain_id)
        {
            return false;
        }
        // Already bound — update in place.
        for b in self.bindings.iter_mut() {
            if b.enabled && b.domain_id == domain_id && b.bo_id == bo_id {
                b.phys_base = phys_base;
                b.size = size;
                return true;
            }
        }
        if self.n_bindings >= MAX_IOMMU_BINDINGS {
            return false;
        }
        for slot in self.bindings.iter_mut() {
            if !slot.enabled {
                slot.domain_id = domain_id;
                slot.bo_id = bo_id;
                slot.phys_base = phys_base;
                slot.size = size;
                slot.enabled = true;
                self.n_bindings += 1;
                return true;
            }
        }
        false
    }

    fn unbind(&mut self, domain_id: u32, bo_id: u64) {
        for b in self.bindings.iter_mut() {
            if b.enabled && b.domain_id == domain_id && b.bo_id == bo_id {
                b.enabled = false;
                if self.n_bindings > 0 {
                    self.n_bindings -= 1;
                }
                return;
            }
        }
    }

    /// Returns `true` if `phys_addr` falls inside any binding for `domain_id`.
    fn validate_access(&self, domain_id: u32, phys_addr: u64) -> bool {
        for b in self.bindings.iter() {
            if !b.enabled || b.domain_id != domain_id {
                continue;
            }
            let end = b.phys_base.saturating_add(b.size as u64);
            if phys_addr >= b.phys_base && phys_addr < end {
                return true;
            }
        }
        false
    }

    /// Returns the binding for `(domain_id, bo_id)` if live.
    fn get_binding(&self, domain_id: u32, bo_id: u64) -> Option<IommuBinding> {
        self.bindings
            .iter()
            .find(|b| b.enabled && b.domain_id == domain_id && b.bo_id == bo_id)
            .copied()
    }

    fn binding_count(&self) -> usize {
        self.n_bindings
    }
    fn domain_count(&self) -> usize {
        self.n_domains
    }
}

static IOMMU_TABLE: Mutex<IommuTable> = Mutex::new(IommuTable::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create an IOMMU domain.  Idempotent.
pub fn create_domain(domain_id: u32) -> bool {
    IOMMU_TABLE.lock().create_domain(domain_id)
}

/// Destroy an IOMMU domain and all its bindings.
pub fn destroy_domain(domain_id: u32) {
    IOMMU_TABLE.lock().destroy_domain(domain_id);
}

/// Bind buffer object `bo_id` (physical range `[phys_base, phys_base+size)`)
/// into `domain_id`.  Returns `false` if the domain does not exist or the
/// binding table is full.
pub fn bind(domain_id: u32, bo_id: u64, phys_base: u64, size: usize) -> bool {
    IOMMU_TABLE.lock().bind(domain_id, bo_id, phys_base, size)
}

/// Remove the binding for `(domain_id, bo_id)`.
pub fn unbind(domain_id: u32, bo_id: u64) {
    IOMMU_TABLE.lock().unbind(domain_id, bo_id);
}

/// Returns `true` if `phys_addr` is covered by any binding in `domain_id`.
pub fn validate_access(domain_id: u32, phys_addr: u64) -> bool {
    IOMMU_TABLE.lock().validate_access(domain_id, phys_addr)
}

/// Returns the binding record for `(domain_id, bo_id)`.
pub fn get_binding(domain_id: u32, bo_id: u64) -> Option<IommuBinding> {
    IOMMU_TABLE.lock().get_binding(domain_id, bo_id)
}

/// Live binding count.
pub fn binding_count() -> usize {
    IOMMU_TABLE.lock().binding_count()
}

/// Live domain count.
pub fn domain_count() -> usize {
    IOMMU_TABLE.lock().domain_count()
}
