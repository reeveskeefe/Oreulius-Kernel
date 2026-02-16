/*!
 * Oreulia Kernel Project
 * 
 * SPDX-License-Identifier: MIT
 * 
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 * 
 * ---------------------------------------------------------------------------
 */

//! Oreulia Service Registry v0
//!
//! Capability-based service discovery via introduction protocol.
//!
//! Key principles:
//! - No global name lookup (no ambient authority)
//! - Services discovered through explicit introductions
//! - Hierarchical delegation of introduction rights
//! - Auditable and revocable connections

#![allow(dead_code)]

use core::fmt;
use spin::Mutex;
use crate::ipc::{ChannelId, ProcessId};

/// Maximum number of registered services
pub const MAX_SERVICES: usize = 64;

/// Maximum number of introducers
pub const MAX_INTRODUCERS: usize = 32;

/// Maximum introductions per introducer
pub const MAX_INTRODUCTIONS_DEFAULT: usize = 100;

// ============================================================================
// Service Types
// ============================================================================

/// Types of services that can be registered
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ServiceType {
    /// Filesystem service
    Filesystem = 1,
    /// Persistence/storage service
    Persistence = 2,
    /// Network service
    Network = 3,
    /// Timer/clock service
    Timer = 4,
    /// Console/terminal service
    Console = 5,
    /// Temporal/versioned state service
    Temporal = 6,
    /// Custom user service (extensible)
    Custom(u32) = 1000,
}

impl ServiceType {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(ServiceType::Filesystem),
            2 => Some(ServiceType::Persistence),
            3 => Some(ServiceType::Network),
            4 => Some(ServiceType::Timer),
            5 => Some(ServiceType::Console),
            6 => Some(ServiceType::Temporal),
            v if v >= 1000 => Some(ServiceType::Custom(v)),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> u32 {
        match self {
            ServiceType::Filesystem => 1,
            ServiceType::Persistence => 2,
            ServiceType::Network => 3,
            ServiceType::Timer => 4,
            ServiceType::Console => 5,
            ServiceType::Temporal => 6,
            ServiceType::Custom(v) => *v,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ServiceType::Filesystem => "Filesystem",
            ServiceType::Persistence => "Persistence",
            ServiceType::Network => "Network",
            ServiceType::Timer => "Timer",
            ServiceType::Console => "Console",
            ServiceType::Temporal => "Temporal",
            ServiceType::Custom(_) => "Custom",
        }
    }
}

// ============================================================================
// Service Namespaces
// ============================================================================

/// Service namespace for isolation and testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServiceNamespace {
    /// Production services
    Production = 0,
    /// Test/development services
    Test = 1,
    /// Isolated sandbox
    Sandbox = 2,
    /// Custom namespace
    Custom(u32) = 1000,
}

impl ServiceNamespace {
    pub fn from_u32(val: u32) -> Self {
        match val {
            0 => ServiceNamespace::Production,
            1 => ServiceNamespace::Test,
            2 => ServiceNamespace::Sandbox,
            v => ServiceNamespace::Custom(v),
        }
    }

    pub fn as_u32(&self) -> u32 {
        match self {
            ServiceNamespace::Production => 0,
            ServiceNamespace::Test => 1,
            ServiceNamespace::Sandbox => 2,
            ServiceNamespace::Custom(v) => *v,
        }
    }
}

// ============================================================================
// Introduction Scope
// ============================================================================

/// Scope of introduction rights
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntroductionScope {
    /// Can introduce to any namespace
    Global,
    /// Can introduce within specific namespace only
    Namespaced(ServiceNamespace),
    /// Can only introduce to specific service types
    TypeRestricted(u32), // Bitset of allowed ServiceType values
}

// ============================================================================
// Service Metadata
// ============================================================================

/// Metadata about a service
#[derive(Debug, Clone, Copy)]
pub struct ServiceMetadata {
    /// Service version
    pub version: u32,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Service process ID
    pub provider_pid: ProcessId,
}

impl ServiceMetadata {
    pub fn new(version: u32, max_connections: usize, provider_pid: ProcessId) -> Self {
        ServiceMetadata {
            version,
            max_connections,
            provider_pid,
        }
    }
}

// ============================================================================
// Service Registration
// ============================================================================

/// A service offer (registration)
#[derive(Clone, Copy)]
pub struct ServiceOffer {
    /// Type of service being offered
    pub service_type: ServiceType,
    /// Channel to communicate with the service
    pub channel: ChannelId,
    /// Namespace this service belongs to
    pub namespace: ServiceNamespace,
    /// Service metadata
    pub metadata: ServiceMetadata,
    /// Number of active connections
    pub active_connections: usize,
}

impl ServiceOffer {
    pub fn new(
        service_type: ServiceType,
        channel: ChannelId,
        namespace: ServiceNamespace,
        metadata: ServiceMetadata,
    ) -> Self {
        ServiceOffer {
            service_type,
            channel,
            namespace,
            metadata,
            active_connections: 0,
        }
    }

    pub fn can_accept_connection(&self) -> bool {
        self.active_connections < self.metadata.max_connections
    }

    pub fn increment_connections(&mut self) {
        self.active_connections += 1;
    }
}

// ============================================================================
// Introducer Capability
// ============================================================================

/// A capability to introduce processes to services
#[derive(Debug, Clone, Copy)]
pub struct IntroducerCapability {
    /// Capability ID
    pub cap_id: u32,
    /// Which services can be introduced (bitset)
    pub allowed_services: u32,
    /// Maximum number of introductions allowed
    pub max_introductions: usize,
    /// Number of introductions performed
    pub introductions_used: usize,
    /// Scope of introduction rights
    pub scope: IntroductionScope,
    /// Owner of this introducer
    pub owner: ProcessId,
}

impl IntroducerCapability {
    /// Create a new introducer with full rights
    pub fn root(cap_id: u32, owner: ProcessId) -> Self {
        IntroducerCapability {
            cap_id,
            allowed_services: u32::MAX, // All services
            max_introductions: usize::MAX, // Unlimited
            introductions_used: 0,
            scope: IntroductionScope::Global,
            owner,
        }
    }

    /// Create a restricted introducer
    pub fn restricted(
        cap_id: u32,
        allowed_services: u32,
        max_introductions: usize,
        scope: IntroductionScope,
        owner: ProcessId,
    ) -> Self {
        IntroducerCapability {
            cap_id,
            allowed_services,
            max_introductions,
            introductions_used: 0,
            scope,
            owner,
        }
    }

    /// Check if this introducer can introduce to a service type
    pub fn can_introduce(&self, service_type: ServiceType) -> bool {
        if self.introductions_used >= self.max_introductions {
            return false;
        }

        // Check if service type is allowed
        let service_bit = 1u32 << (service_type.as_u32() % 32);
        (self.allowed_services & service_bit) != 0
    }

    /// Check if introducer can access a namespace
    pub fn can_access_namespace(&self, namespace: ServiceNamespace) -> bool {
        match self.scope {
            IntroductionScope::Global => true,
            IntroductionScope::Namespaced(ns) => ns == namespace,
            IntroductionScope::TypeRestricted(_) => true, // Type restriction doesn't affect namespace
        }
    }

    /// Record an introduction
    pub fn record_introduction(&mut self) {
        self.introductions_used += 1;
    }

    /// Attenuate this introducer (reduce rights)
    pub fn attenuate(
        &self,
        allowed_services: u32,
        max_introductions: usize,
        scope: IntroductionScope,
    ) -> Self {
        IntroducerCapability {
            cap_id: self.cap_id,
            allowed_services: self.allowed_services & allowed_services,
            max_introductions: self.max_introductions.min(max_introductions),
            introductions_used: 0, // Reset counter for delegated cap
            scope,
            owner: self.owner,
        }
    }
}

// ============================================================================
// Introduction Protocol Messages
// ============================================================================

/// Request to be introduced to a service
#[derive(Debug, Clone, Copy)]
pub struct IntroductionRequest {
    /// Service type to connect to
    pub service_type: ServiceType,
    /// Preferred namespace (None = any)
    pub namespace: Option<ServiceNamespace>,
    /// Requesting process
    pub requester: ProcessId,
}

impl IntroductionRequest {
    pub fn new(service_type: ServiceType, requester: ProcessId) -> Self {
        IntroductionRequest {
            service_type,
            namespace: None,
            requester,
        }
    }

    pub fn with_namespace(
        service_type: ServiceType,
        namespace: ServiceNamespace,
        requester: ProcessId,
    ) -> Self {
        IntroductionRequest {
            service_type,
            namespace: Some(namespace),
            requester,
        }
    }
}

/// Response to an introduction request
#[derive(Debug, Clone, Copy)]
pub struct IntroductionResponse {
    /// Status of the introduction
    pub status: IntroductionStatus,
    /// Service channel (if successful)
    pub service_channel: Option<ChannelId>,
    /// Service metadata (if successful)
    pub metadata: Option<ServiceMetadata>,
}

impl IntroductionResponse {
    pub fn success(service_channel: ChannelId, metadata: ServiceMetadata) -> Self {
        IntroductionResponse {
            status: IntroductionStatus::Success,
            service_channel: Some(service_channel),
            metadata: Some(metadata),
        }
    }

    pub fn error(status: IntroductionStatus) -> Self {
        IntroductionResponse {
            status,
            service_channel: None,
            metadata: None,
        }
    }
}

/// Status of an introduction attempt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntroductionStatus {
    /// Introduction successful
    Success,
    /// Service not found
    ServiceNotFound,
    /// Permission denied
    PermissionDenied,
    /// Service unavailable (max connections)
    ServiceUnavailable,
    /// Introducer exhausted
    IntroducerExhausted,
    /// Invalid namespace
    InvalidNamespace,
}

impl fmt::Display for IntroductionStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IntroductionStatus::Success => write!(f, "Success"),
            IntroductionStatus::ServiceNotFound => write!(f, "Service not found"),
            IntroductionStatus::PermissionDenied => write!(f, "Permission denied"),
            IntroductionStatus::ServiceUnavailable => write!(f, "Service unavailable"),
            IntroductionStatus::IntroducerExhausted => write!(f, "Introducer exhausted"),
            IntroductionStatus::InvalidNamespace => write!(f, "Invalid namespace"),
        }
    }
}

// ============================================================================
// Service Registry
// ============================================================================

/// The service registry
pub struct ServiceRegistry {
    /// Registered services
    services: [Option<ServiceOffer>; MAX_SERVICES],
    /// Active introducers
    introducers: [Option<IntroducerCapability>; MAX_INTRODUCERS],
    /// Next introducer ID
    next_introducer_id: u32,
}

impl ServiceRegistry {
    pub const fn new() -> Self {
        ServiceRegistry {
            services: [None; MAX_SERVICES],
            introducers: [None; MAX_INTRODUCERS],
            next_introducer_id: 1,
        }
    }

    /// Register a service
    pub fn register_service(&mut self, offer: ServiceOffer) -> Result<(), RegistryError> {
        // Check if service type already registered in this namespace
        for slot in &self.services {
            if let Some(existing) = slot {
                if existing.service_type == offer.service_type
                    && existing.namespace == offer.namespace
                {
                    return Err(RegistryError::ServiceAlreadyRegistered);
                }
            }
        }

        // Find empty slot
        for slot in &mut self.services {
            if slot.is_none() {
                *slot = Some(offer);
                return Ok(());
            }
        }

        Err(RegistryError::RegistryFull)
    }

    /// Unregister a service
    pub fn unregister_service(
        &mut self,
        service_type: ServiceType,
        namespace: ServiceNamespace,
    ) -> Result<(), RegistryError> {
        for slot in &mut self.services {
            if let Some(service) = slot {
                if service.service_type == service_type && service.namespace == namespace {
                    *slot = None;
                    return Ok(());
                }
            }
        }

        Err(RegistryError::ServiceNotFound)
    }

    /// Find a service
    fn find_service_mut(
        &mut self,
        service_type: ServiceType,
        namespace: ServiceNamespace,
    ) -> Option<&mut ServiceOffer> {
        self.services
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|svc| {
                svc.service_type == service_type && svc.namespace == namespace
            }))
    }

    /// Create a root introducer
    pub fn create_root_introducer(&mut self, owner: ProcessId) -> Result<IntroducerCapability, RegistryError> {
        let cap_id = self.next_introducer_id;
        self.next_introducer_id += 1;

        let introducer = IntroducerCapability::root(cap_id, owner);

        // Store in registry
        for slot in &mut self.introducers {
            if slot.is_none() {
                *slot = Some(introducer);
                return Ok(introducer);
            }
        }

        Err(RegistryError::TooManyIntroducers)
    }

    /// Create a restricted introducer
    pub fn create_introducer(
        &mut self,
        allowed_services: u32,
        max_introductions: usize,
        scope: IntroductionScope,
        owner: ProcessId,
    ) -> Result<IntroducerCapability, RegistryError> {
        let cap_id = self.next_introducer_id;
        self.next_introducer_id += 1;

        let introducer = IntroducerCapability::restricted(
            cap_id,
            allowed_services,
            max_introductions,
            scope,
            owner,
        );

        // Store in registry
        for slot in &mut self.introducers {
            if slot.is_none() {
                *slot = Some(introducer);
                return Ok(introducer);
            }
        }

        Err(RegistryError::TooManyIntroducers)
    }

    /// Perform an introduction
    pub fn introduce(
        &mut self,
        request: IntroductionRequest,
        introducer_cap: &mut IntroducerCapability,
    ) -> IntroductionResponse {
        // Check if introducer can perform this introduction
        if !introducer_cap.can_introduce(request.service_type) {
            return IntroductionResponse::error(IntroductionStatus::PermissionDenied);
        }

        // Determine namespace
        let namespace = request.namespace.unwrap_or(ServiceNamespace::Production);

        // Check namespace access
        if !introducer_cap.can_access_namespace(namespace) {
            return IntroductionResponse::error(IntroductionStatus::InvalidNamespace);
        }

        // Find the service
        let service = match self.find_service_mut(request.service_type, namespace) {
            Some(s) => s,
            None => return IntroductionResponse::error(IntroductionStatus::ServiceNotFound),
        };

        // Check if service can accept more connections
        if !service.can_accept_connection() {
            return IntroductionResponse::error(IntroductionStatus::ServiceUnavailable);
        }

        // Record the introduction and extract service info before updating introducer
        introducer_cap.record_introduction();
        service.increment_connections();
        
        let service_channel = service.channel;
        let service_metadata = service.metadata;

        // Update introducer in registry (service borrow is done)
        for slot in &mut self.introducers {
            if let Some(stored) = slot {
                if stored.cap_id == introducer_cap.cap_id {
                    *stored = *introducer_cap;
                    break;
                }
            }
        }

        IntroductionResponse::success(service_channel, service_metadata)
    }

    /// List all registered services
    pub fn list_services(&self) -> impl Iterator<Item = &ServiceOffer> {
        self.services.iter().filter_map(|s| s.as_ref())
    }

    /// Get service count
    pub fn service_count(&self) -> usize {
        self.services.iter().filter(|s| s.is_some()).count()
    }

    /// Get introducer count
    pub fn introducer_count(&self) -> usize {
        self.introducers.iter().filter(|i| i.is_some()).count()
    }
}

// ============================================================================
// Registry Service
// ============================================================================

/// Global service registry
pub struct RegistryService {
    registry: Mutex<ServiceRegistry>,
}

impl RegistryService {
    pub const fn new() -> Self {
        RegistryService {
            registry: Mutex::new(ServiceRegistry::new()),
        }
    }

    /// Register a service
    pub fn register_service(&self, offer: ServiceOffer) -> Result<(), RegistryError> {
        self.registry.lock().register_service(offer)?;
        if !crate::temporal::is_replay_active() {
            let _ = crate::temporal::record_registry_service_event(
                offer.service_type.as_u32(),
                offer.namespace.as_u32(),
                offer.channel.0,
                offer.metadata.provider_pid.0,
                offer.metadata.version,
                offer.metadata.max_connections as u32,
                offer.active_connections as u32,
                crate::temporal::TEMPORAL_REGISTRY_EVENT_REGISTER,
            );
        }
        Ok(())
    }

    /// Unregister a service
    pub fn unregister_service(
        &self,
        service_type: ServiceType,
        namespace: ServiceNamespace,
    ) -> Result<(), RegistryError> {
        self.registry
            .lock()
            .unregister_service(service_type, namespace)?;
        if !crate::temporal::is_replay_active() {
            let _ = crate::temporal::record_registry_service_event(
                service_type.as_u32(),
                namespace.as_u32(),
                0,
                0,
                0,
                0,
                0,
                crate::temporal::TEMPORAL_REGISTRY_EVENT_UNREGISTER,
            );
        }
        Ok(())
    }

    /// Create a root introducer
    pub fn create_root_introducer(&self, owner: ProcessId) -> Result<IntroducerCapability, RegistryError> {
        self.registry.lock().create_root_introducer(owner)
    }

    /// Create a restricted introducer
    pub fn create_introducer(
        &self,
        allowed_services: u32,
        max_introductions: usize,
        scope: IntroductionScope,
        owner: ProcessId,
    ) -> Result<IntroducerCapability, RegistryError> {
        self.registry.lock().create_introducer(
            allowed_services,
            max_introductions,
            scope,
            owner,
        )
    }

    /// Perform an introduction
    pub fn introduce(
        &self,
        request: IntroductionRequest,
        introducer_cap: &mut IntroducerCapability,
    ) -> IntroductionResponse {
        self.registry.lock().introduce(request, introducer_cap)
    }

    /// Get statistics
    pub fn stats(&self) -> (usize, usize, usize, usize) {
        let registry = self.registry.lock();
        (
            registry.service_count(),
            MAX_SERVICES,
            registry.introducer_count(),
            MAX_INTRODUCERS,
        )
    }

    /// List services (for debugging) - Returns array with count
    pub fn list_services(&self) -> ([(ServiceType, ServiceNamespace, usize); MAX_SERVICES], usize) {
        let registry = self.registry.lock();
        let mut result = [(ServiceType::Filesystem, ServiceNamespace::Production, 0); MAX_SERVICES];
        let mut count = 0;
        
        for service in registry.list_services() {
            if count < MAX_SERVICES {
                result[count] = (service.service_type, service.namespace, service.active_connections);
                count += 1;
            }
        }
        
        (result, count)
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Registry errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// Service already registered
    ServiceAlreadyRegistered,
    /// Service not found
    ServiceNotFound,
    /// Registry is full
    RegistryFull,
    /// Too many introducers
    TooManyIntroducers,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RegistryError::ServiceAlreadyRegistered => write!(f, "Service already registered"),
            RegistryError::ServiceNotFound => write!(f, "Service not found"),
            RegistryError::RegistryFull => write!(f, "Registry full"),
            RegistryError::TooManyIntroducers => write!(f, "Too many introducers"),
        }
    }
}

// ============================================================================
// Global Registry Instance
// ============================================================================

/// Global service registry
static REGISTRY: RegistryService = RegistryService::new();

/// Get the global service registry
pub fn registry() -> &'static RegistryService {
    &REGISTRY
}

#[allow(clippy::too_many_arguments)]
pub fn temporal_apply_service_event(
    service_type_raw: u32,
    namespace_raw: u32,
    channel_raw: u32,
    provider_pid_raw: u32,
    version: u32,
    max_connections: u32,
    active_connections: u32,
    event: u8,
) -> Result<(), &'static str> {
    fn registry_err(e: RegistryError) -> &'static str {
        match e {
            RegistryError::ServiceAlreadyRegistered => "Service already registered",
            RegistryError::ServiceNotFound => "Service not found",
            RegistryError::RegistryFull => "Registry full",
            RegistryError::TooManyIntroducers => "Too many introducers",
        }
    }

    let service_type =
        ServiceType::from_u32(service_type_raw).ok_or("Invalid service type for temporal apply")?;
    let namespace = ServiceNamespace::from_u32(namespace_raw);

    match event {
        crate::temporal::TEMPORAL_REGISTRY_EVENT_REGISTER => {
            let metadata =
                ServiceMetadata::new(version, max_connections as usize, ProcessId(provider_pid_raw));
            let mut offer = ServiceOffer::new(
                service_type,
                ChannelId(channel_raw),
                namespace,
                metadata,
            );
            offer.active_connections = core::cmp::min(
                active_connections as usize,
                metadata.max_connections,
            );

            match registry().register_service(offer) {
                Ok(()) => Ok(()),
                Err(RegistryError::ServiceAlreadyRegistered) => {
                    let _ = registry().unregister_service(service_type, namespace);
                    registry()
                        .register_service(offer)
                        .map_err(registry_err)
                }
                Err(e) => Err(registry_err(e)),
            }
        }
        crate::temporal::TEMPORAL_REGISTRY_EVENT_UNREGISTER => {
            let _ = registry().unregister_service(service_type, namespace);
            Ok(())
        }
        _ => Err("Unsupported registry temporal event"),
    }
}

/// Initialize the service registry
pub fn init() {
    // Registry is statically initialized
}
