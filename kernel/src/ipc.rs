//! Oreulia IPC v0
//!
//! Channel-based inter-process communication with capability transfer.
//!
//! Key principles:
//! - Channels are kernel objects with Send/Receive rights
//! - Messages carry data + capabilities
//! - Bounded queues make backpressure explicit
//! - No shared memory - only message passing

#![allow(dead_code)]

use core::fmt;
use spin::Mutex;

/// Maximum message data size (512 bytes - reduced to shrink kernel binary)
pub const MAX_MESSAGE_SIZE: usize = 512;

/// Maximum capabilities per message
pub const MAX_CAPS_PER_MESSAGE: usize = 16;

/// Channel capacity (reduced to shrink kernel binary)
pub const CHANNEL_CAPACITY: usize = 4;

/// Maximum number of channels (reduced to shrink kernel binary)
pub const MAX_CHANNELS: usize = 16;

// ============================================================================
// Core Types
// ============================================================================

/// Channel identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(pub u32);

impl ChannelId {
    pub fn new(id: u32) -> Self {
        ChannelId(id)
    }
}

/// Process identifier (placeholder for v0)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessId(pub u32);

impl ProcessId {
    pub fn new(id: u32) -> Self {
        ProcessId(id)
    }
    
    pub const KERNEL: ProcessId = ProcessId(0);
}

/// Type of capability being transferred
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CapabilityType {
    /// Generic capability
    Generic = 0,
    /// Channel capability
    Channel = 1,
    /// Filesystem capability
    Filesystem = 2,
    /// Store/persistence capability
    Store = 3,
}

/// Generic capability (simplified for v0)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub cap_id: u32,
    pub object_id: u32,
    pub rights: u32,
    pub cap_type: CapabilityType,
    /// Extra data (e.g., for filesystem: key_prefix length + bytes)
    pub extra: [u32; 4],
    /// Cryptographic token (SipHash-2-4 MAC)
    pub token: u64,
}

impl Capability {
    pub fn new(cap_id: u32, object_id: u32, rights: u32) -> Self {
        Capability {
            cap_id,
            object_id,
            rights,
            cap_type: CapabilityType::Generic,
            extra: [0; 4],
            token: 0,
        }
    }

    pub fn with_type(cap_id: u32, object_id: u32, rights: u32, cap_type: CapabilityType) -> Self {
        Capability {
            cap_id,
            object_id,
            rights,
            cap_type,
            extra: [0; 4],
            token: 0,
        }
    }

    pub fn sign(&mut self) {
        let payload = self.token_payload();
        self.token = crate::security::security().cap_token_sign(&payload);
    }

    pub fn verify(&self) -> bool {
        let payload = self.token_payload();
        crate::security::security().cap_token_verify(&payload, self.token)
    }

    fn token_payload(&self) -> [u8; 40] {
        const TOKEN_CONTEXT: u32 = 0x4F43_4150; // "OCAP"
        let mut buf = [0u8; 40];
        let mut offset = 0usize;
        write_u32(&mut buf, &mut offset, TOKEN_CONTEXT);
        write_u32(&mut buf, &mut offset, self.cap_id);
        write_u32(&mut buf, &mut offset, self.object_id);
        write_u32(&mut buf, &mut offset, self.rights);
        write_u32(&mut buf, &mut offset, self.cap_type as u32);
        for word in &self.extra {
            write_u32(&mut buf, &mut offset, *word);
        }
        buf
    }
}

fn write_u32(buf: &mut [u8], offset: &mut usize, value: u32) {
    let bytes = value.to_le_bytes();
    buf[*offset..*offset + 4].copy_from_slice(&bytes);
    *offset += 4;
}

// ============================================================================
// Message Structure
// ============================================================================

/// A message sent through a channel
#[derive(Clone, Copy)]
pub struct Message {
    /// Message payload data
    pub payload: [u8; MAX_MESSAGE_SIZE],
    /// Actual payload length
    pub payload_len: usize,
    /// Capabilities being transferred
    pub caps: [Option<Capability>; MAX_CAPS_PER_MESSAGE],
    /// Number of capabilities
    pub caps_len: usize,
    /// Source process ID
    pub source: ProcessId,
}

impl Message {
    /// Create a new empty message
    pub fn new(source: ProcessId) -> Self {
        Message {
            payload: [0u8; MAX_MESSAGE_SIZE],
            payload_len: 0,
            caps: [None; MAX_CAPS_PER_MESSAGE],
            caps_len: 0,
            source,
        }
    }

    /// Create a message with data
    pub fn with_data(source: ProcessId, data: &[u8]) -> Result<Self, IpcError> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(IpcError::MessageTooLarge);
        }

        let mut msg = Message::new(source);
        // Use fast assembly memcpy for IPC messages (5x faster)
        crate::asm_bindings::fast_memcpy(&mut msg.payload[..data.len()], data);
        msg.payload_len = data.len();
        Ok(msg)
    }

    /// Add a capability to this message
    pub fn add_capability(&mut self, cap: Capability) -> Result<(), IpcError> {
        if self.caps_len >= MAX_CAPS_PER_MESSAGE {
            return Err(IpcError::TooManyCaps);
        }

        let mut signed = cap;
        signed.sign();
        self.caps[self.caps_len] = Some(signed);
        self.caps_len += 1;
        Ok(())
    }

    /// Get the payload as a slice
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }

    /// Get the capabilities
    pub fn capabilities(&self) -> impl Iterator<Item = &Capability> {
        self.caps[..self.caps_len]
            .iter()
            .filter_map(|c| c.as_ref())
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Message")
            .field("payload_len", &self.payload_len)
            .field("caps_len", &self.caps_len)
            .field("source", &self.source)
            .finish()
    }
}

// ============================================================================
// Channel Capabilities
// ============================================================================

/// Channel rights
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelRights {
    bits: u32,
}

impl ChannelRights {
    pub const NONE: u32 = 0;
    pub const SEND: u32 = 1 << 0;
    pub const RECEIVE: u32 = 1 << 1;
    pub const CLOSE: u32 = 1 << 2;
    pub const ALL: u32 = Self::SEND | Self::RECEIVE | Self::CLOSE;

    pub const fn new(bits: u32) -> Self {
        ChannelRights { bits }
    }

    pub const fn has(&self, right: u32) -> bool {
        (self.bits & right) != 0
    }

    pub const fn send_only() -> Self {
        ChannelRights { bits: Self::SEND }
    }

    pub const fn receive_only() -> Self {
        ChannelRights { bits: Self::RECEIVE }
    }

    pub const fn send_receive() -> Self {
        ChannelRights {
            bits: Self::SEND | Self::RECEIVE,
        }
    }

    pub const fn all() -> Self {
        ChannelRights { bits: Self::ALL }
    }
    
    pub const fn full() -> Self {
        Self::all()
    }
}

/// A capability to access a channel
#[derive(Debug, Clone, Copy)]
pub struct ChannelCapability {
    pub cap_id: u32,
    pub channel_id: ChannelId,
    pub rights: ChannelRights,
    pub owner: ProcessId,
}

impl ChannelCapability {
    pub fn new(cap_id: u32, channel_id: ChannelId, rights: ChannelRights, owner: ProcessId) -> Self {
        ChannelCapability {
            cap_id,
            channel_id,
            rights,
            owner,
        }
    }

    pub fn can_send(&self) -> bool {
        self.rights.has(ChannelRights::SEND)
    }

    pub fn can_receive(&self) -> bool {
        self.rights.has(ChannelRights::RECEIVE)
    }

    pub fn can_close(&self) -> bool {
        self.rights.has(ChannelRights::CLOSE)
    }
}

// ============================================================================
// Ring Buffer for Messages
// ============================================================================

/// A bounded ring buffer for messages
#[derive(Clone, Copy)]
struct RingBuffer {
    buffer: [Option<Message>; CHANNEL_CAPACITY],
    head: usize,
    tail: usize,
    count: usize,
}

impl RingBuffer {
    const fn new() -> Self {
        RingBuffer {
            buffer: [None; CHANNEL_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn is_full(&self) -> bool {
        self.count >= CHANNEL_CAPACITY
    }

    fn push(&mut self, msg: Message) -> Result<(), IpcError> {
        if self.is_full() {
            return Err(IpcError::WouldBlock);
        }

        self.buffer[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % CHANNEL_CAPACITY;
        self.count += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<Message> {
        if self.is_empty() {
            return None;
        }

        let msg = self.buffer[self.head].take();
        self.head = (self.head + 1) % CHANNEL_CAPACITY;
        self.count -= 1;
        msg
    }

    fn len(&self) -> usize {
        self.count
    }
}

// ============================================================================
// Channel
// ============================================================================

/// Channel configuration flags (bitfield)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelFlags {
    bits: u32,
}

impl ChannelFlags {
    pub const NONE: u32 = 0;
    pub const BOUNDED: u32 = 1 << 0;      // Bounded queue (default)
    pub const UNBOUNDED: u32 = 1 << 1;    // Unbounded queue (memory permitting)
    pub const HIGH_PRIORITY: u32 = 1 << 2; // High-priority channel for latency-sensitive messages
    pub const RELIABLE: u32 = 1 << 3;     // Guaranteed delivery (block on full)
    pub const ASYNC: u32 = 1 << 4;        // Non-blocking sends (drop on full)
    
    pub const fn new(bits: u32) -> Self {
        ChannelFlags { bits }
    }
    
    pub const fn is_bounded(&self) -> bool {
        (self.bits & Self::UNBOUNDED) == 0
    }
    
    pub const fn is_high_priority(&self) -> bool {
        (self.bits & Self::HIGH_PRIORITY) != 0
    }
    
    pub const fn is_reliable(&self) -> bool {
        (self.bits & Self::RELIABLE) != 0
    }
    
    pub const fn is_async(&self) -> bool {
        (self.bits & Self::ASYNC) != 0
    }
}

/// A bidirectional channel for message passing
#[derive(Clone, Copy)]
pub struct Channel {
    /// Channel identifier
    pub id: ChannelId,
    /// Message queue
    buffer: RingBuffer,
    /// Is the channel closed?
    closed: bool,
    /// Channel creator (for ownership tracking)
    creator: ProcessId,
    /// Channel configuration flags
    flags: ChannelFlags,
    /// Priority level (0-255, higher = more important)
    priority: u8,
}

impl Channel {
    /// Create a new channel with default configuration
    pub fn new(id: ChannelId, creator: ProcessId) -> Self {
        Channel {
            id,
            buffer: RingBuffer::new(),
            closed: false,
            creator,
            flags: ChannelFlags::new(ChannelFlags::BOUNDED | ChannelFlags::RELIABLE),
            priority: 128, // Default medium priority
        }
    }
    
    /// Create a new channel with custom configuration
    pub fn new_with_flags(id: ChannelId, creator: ProcessId, flags: ChannelFlags, priority: u8) -> Self {
        Channel {
            id,
            buffer: RingBuffer::new(),
            closed: false,
            creator,
            flags,
            priority,
        }
    }

    /// Send a message through the channel
    pub fn send(&mut self, msg: Message, capability: &ChannelCapability) -> Result<(), IpcError> {
        // Check permission
        if !capability.can_send() {
            return Err(IpcError::PermissionDenied);
        }

        if capability.channel_id != self.id {
            return Err(IpcError::InvalidCap);
        }

        if self.closed {
            return Err(IpcError::Closed);
        }
        
        // Handle async channels (non-blocking send)
        if self.flags.is_async() && self.buffer.is_full() {
            // Drop message on full buffer for async channels
            return Err(IpcError::WouldBlock);
        }

        self.buffer.push(msg)
    }

    /// Try to receive a message (non-blocking)
    pub fn try_recv(&mut self, capability: &ChannelCapability) -> Result<Message, IpcError> {
        // Check permission
        if !capability.can_receive() {
            return Err(IpcError::PermissionDenied);
        }

        if capability.channel_id != self.id {
            return Err(IpcError::InvalidCap);
        }

        if self.closed && self.buffer.is_empty() {
            return Err(IpcError::Closed);
        }

        self.buffer.pop().ok_or(IpcError::WouldBlock)
    }

    /// Receive a message (blocking - simplified for v0)
    pub fn recv(&mut self, capability: &ChannelCapability) -> Result<Message, IpcError> {
        // In v0, this is the same as try_recv
        // In a real implementation, this would block the calling process
        self.try_recv(capability)
    }

    /// Close the channel
    pub fn close(&mut self, capability: &ChannelCapability) -> Result<(), IpcError> {
        if !capability.can_close() {
            return Err(IpcError::PermissionDenied);
        }

        if capability.channel_id != self.id {
            return Err(IpcError::InvalidCap);
        }

        self.closed = true;
        Ok(())
    }

    /// Check if channel is closed
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Get number of pending messages
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }
    
    /// Get channel priority
    pub fn priority(&self) -> u8 {
        self.priority
    }
    
    /// Get channel flags
    pub fn flags(&self) -> ChannelFlags {
        self.flags
    }

    /// Check if channel is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Check if channel is full
    pub fn is_full(&self) -> bool {
        self.buffer.is_full()
    }
}

// ============================================================================
// Channel Table
// ============================================================================

/// Global channel table
pub struct ChannelTable {
    channels: [Option<Channel>; MAX_CHANNELS],
    next_id: u32,
}

impl ChannelTable {
    pub const fn new() -> Self {
        ChannelTable {
            channels: [None; MAX_CHANNELS],
            next_id: 1,
        }
    }

    /// Create a new channel
    pub fn create_channel(&mut self, creator: ProcessId) -> Result<ChannelId, IpcError> {
        self.create_channel_with_flags(creator, ChannelFlags::new(ChannelFlags::BOUNDED | ChannelFlags::RELIABLE), 128)
    }
    
    /// Create a new channel with custom configuration
    pub fn create_channel_with_flags(&mut self, creator: ProcessId, flags: ChannelFlags, priority: u8) -> Result<ChannelId, IpcError> {
        // Find empty slot
        for slot in &mut self.channels {
            if slot.is_none() {
                let id = ChannelId::new(self.next_id);
                self.next_id += 1;
                *slot = Some(Channel::new_with_flags(id, creator, flags, priority));
                return Ok(id);
            }
        }

        Err(IpcError::TooManyChannels)
    }

    /// Get a mutable reference to a channel
    pub fn get_mut(&mut self, id: ChannelId) -> Option<&mut Channel> {
        self.channels
            .iter_mut()
            .find_map(|c| c.as_mut().filter(|ch| ch.id == id))
    }

    /// Get a reference to a channel
    pub fn get(&self, id: ChannelId) -> Option<&Channel> {
        self.channels
            .iter()
            .find_map(|c| c.as_ref().filter(|ch| ch.id == id))
    }

    /// Delete a channel
    pub fn delete_channel(&mut self, id: ChannelId) -> Result<(), IpcError> {
        for slot in &mut self.channels {
            if let Some(channel) = slot {
                if channel.id == id {
                    *slot = None;
                    return Ok(());
                }
            }
        }

        Err(IpcError::InvalidCap)
    }

    /// Get channel count
    pub fn count(&self) -> usize {
        self.channels.iter().filter(|c| c.is_some()).count()
    }
}

// ============================================================================
// IPC Service
// ============================================================================

/// The main IPC service
pub struct IpcService {
    channels: Mutex<ChannelTable>,
}

impl IpcService {
    pub const fn new() -> Self {
        IpcService {
            channels: Mutex::new(ChannelTable::new()),
        }
    }

    /// Create a new channel and return capabilities
    pub fn create_channel(&self, creator: ProcessId) -> Result<(ChannelCapability, ChannelCapability), IpcError> {
        let mut table = self.channels.lock();
        let channel_id = table.create_channel(creator)?;

        // Create send and receive capabilities
        let send_cap = ChannelCapability::new(
            1, // cap_id - in real impl, this would be from capability table
            channel_id,
            ChannelRights::send_only(),
            creator,
        );

        let recv_cap = ChannelCapability::new(
            2, // cap_id - in real impl, this would be from capability table
            channel_id,
            ChannelRights::receive_only(),
            creator,
        );

        Ok((send_cap, recv_cap))
    }

    /// Send a message
    pub fn send(&self, msg: Message, capability: &ChannelCapability) -> Result<(), IpcError> {
        let mut table = self.channels.lock();
        let channel = table
            .get_mut(capability.channel_id)
            .ok_or(IpcError::InvalidCap)?;

        channel.send(msg, capability)
    }

    /// Receive a message (non-blocking)
    pub fn try_recv(&self, capability: &ChannelCapability) -> Result<Message, IpcError> {
        let mut table = self.channels.lock();
        let channel = table
            .get_mut(capability.channel_id)
            .ok_or(IpcError::InvalidCap)?;

        channel.try_recv(capability)
    }

    /// Receive a message (blocking)
    pub fn recv(&self, capability: &ChannelCapability) -> Result<Message, IpcError> {
        let mut table = self.channels.lock();
        let channel = table
            .get_mut(capability.channel_id)
            .ok_or(IpcError::InvalidCap)?;

        channel.recv(capability)
    }

    /// Close a channel
    pub fn close(&self, capability: &ChannelCapability) -> Result<(), IpcError> {
        let mut table = self.channels.lock();
        let channel = table
            .get_mut(capability.channel_id)
            .ok_or(IpcError::InvalidCap)?;

        channel.close(capability)
    }

    /// Get channel statistics
    pub fn channel_stats(&self, capability: &ChannelCapability) -> Result<(usize, usize, bool), IpcError> {
        let table = self.channels.lock();
        let channel = table
            .get(capability.channel_id)
            .ok_or(IpcError::InvalidCap)?;

        Ok((channel.pending(), CHANNEL_CAPACITY, channel.is_closed()))
    }

    /// Get global IPC statistics
    pub fn stats(&self) -> (usize, usize) {
        let table = self.channels.lock();
        (table.count(), MAX_CHANNELS)
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// IPC errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// Invalid capability ID
    InvalidCap,
    /// Permission denied (rights mismatch)
    PermissionDenied,
    /// Would block (channel full/empty)
    WouldBlock,
    /// Channel is closed
    Closed,
    /// Message too large
    MessageTooLarge,
    /// Too many capabilities in message
    TooManyCaps,
    /// Too many channels
    TooManyChannels,
}

impl IpcError {
    pub fn as_str(&self) -> &'static str {
        match self {
            IpcError::InvalidCap => "Invalid capability",
            IpcError::PermissionDenied => "Permission denied",
            IpcError::WouldBlock => "Would block",
            IpcError::Closed => "Channel closed",
            IpcError::MessageTooLarge => "Message too large",
            IpcError::TooManyCaps => "Too many capabilities",
            IpcError::TooManyChannels => "Too many channels",
        }
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpcError::InvalidCap => write!(f, "Invalid capability"),
            IpcError::PermissionDenied => write!(f, "Permission denied"),
            IpcError::WouldBlock => write!(f, "Would block"),
            IpcError::Closed => write!(f, "Channel closed"),
            IpcError::MessageTooLarge => write!(f, "Message too large"),
            IpcError::TooManyCaps => write!(f, "Too many capabilities"),
            IpcError::TooManyChannels => write!(f, "Too many channels"),
        }
    }
}

// ============================================================================
// Global IPC Instance
// ============================================================================

/// Global IPC service instance
static IPC: IpcService = IpcService::new();

/// Get a reference to the global IPC service
pub fn ipc() -> &'static IpcService {
    &IPC
}

/// Initialize the IPC service
pub fn init() {
    // IPC is statically initialized, nothing to do for v0
}

/// Create a new channel (syscall stub)
pub fn create_channel() -> Result<usize, &'static str> {
    // TODO: Implement channel creation
    Err("Channel creation not yet implemented")
}

/// Create a new channel for a specific process (syscall implementation)
pub fn create_channel_for_process(creator: ProcessId) -> Result<usize, &'static str> {
    create_channel_for_process_with_flags(creator, ChannelFlags::new(ChannelFlags::BOUNDED | ChannelFlags::RELIABLE), 128)
}

/// Create a new channel for a specific process with custom configuration
pub fn create_channel_for_process_with_flags(creator: ProcessId, flags: ChannelFlags, priority: u8) -> Result<usize, &'static str> {
    let mut channels = ipc().channels.lock();
    
    // Create channel in the table with custom flags
    match channels.create_channel_with_flags(creator, flags, priority) {
        Ok(channel_id) => {
            // TODO: Add capability to process's capability table
            // For now, just return the channel ID
            Ok(channel_id.0 as usize)
        }
        Err(_) => Err("Failed to create channel")
    }
}

/// Send message to channel (syscall wrapper)
pub fn send_message(channel_id: ChannelId, data: &[u8]) -> Result<(), &'static str> {
    // Create message from data
    let msg = Message::with_data(ProcessId(0), data).map_err(|_| "Message too large")?;
    
    // TODO: Get capability from caller's process
    // For now, create a temporary capability
    let cap = ChannelCapability::new(
        0,
        channel_id,
        ChannelRights::send_only(),
        msg.source,
    );
    
    ipc().send(msg, &cap).map_err(|_| "Failed to send message")
}

/// Receive message from channel (syscall wrapper)
pub fn receive_message(channel_id: ChannelId, _buffer: &mut [u8]) -> Result<usize, &'static str> {
    // TODO: Get capability from caller's process
    // For now, create a temporary capability
    let cap = ChannelCapability::new(
        0,
        channel_id,
        ChannelRights::receive_only(),
        ProcessId(0),
    );
    
    match ipc().try_recv(&cap) {
        Ok(msg) => {
            // TODO: Copy message to buffer
            Ok(msg.payload().len())
        }
        Err(_) => Err("No message available")
    }
}

/// Close channel (syscall wrapper)
pub fn close_channel(channel_id: ChannelId) -> Result<(), &'static str> {
    // TODO: Get capability from caller's process
    // For now, create a temporary capability
    let cap = ChannelCapability::new(
        0,
        channel_id,
        ChannelRights::full(),
        ProcessId(0),
    );
    
    ipc().close(&cap).map_err(|_| "Failed to close channel")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let msg = Message::with_data(ProcessId::new(1), b"hello").unwrap();
        assert_eq!(msg.payload(), b"hello");
        assert_eq!(msg.caps_len, 0);
    }

    #[test]
    fn test_ring_buffer() {
        let mut buffer = RingBuffer::new();
        assert!(buffer.is_empty());

        let msg = Message::new(ProcessId::new(1));
        buffer.push(msg).unwrap();
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 1);

        let _ = buffer.pop().unwrap();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_channel_send_recv() {
        let id = ChannelId::new(1);
        let mut channel = Channel::new(id, ProcessId::new(1));

        let send_cap = ChannelCapability::new(
            1,
            id,
            ChannelRights::send_only(),
            ProcessId::new(1),
        );

        let recv_cap = ChannelCapability::new(
            2,
            id,
            ChannelRights::receive_only(),
            ProcessId::new(1),
        );

        let msg = Message::with_data(ProcessId::new(1), b"test").unwrap();
        channel.send(msg, &send_cap).unwrap();

        let received = channel.try_recv(&recv_cap).unwrap();
        assert_eq!(received.payload(), b"test");
    }
}
