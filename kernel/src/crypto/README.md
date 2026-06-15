# Cryptographic Primitives | Crypto Folder


## Whats Inside
This folder acts as the kernels own crypto toolbox. It gives the rest of the kernel hashing, MACs, symmetric encryption, TLS key exchange pieces, signature verification, and canonical signed-message formats without pulling in much external machinery.

## Cryptographic status and non-goals

This crate exists so I can test kernel cryptographic integration in a normal host-side `cargo test` environment. The code mirrored here is code under test and regression evidence. It is not a cryptographic proof, not an independent security audit, and not a production cryptographic assurance claim.

I am not trying to design or maintain my own cryptographic primitives. Oreulius is focused on capability-based authority, kernel-mediated isolation, temporal state, and explicit verification boundaries. Cryptographic algorithms are infrastructure dependencies, not the research contribution of this kernel.

Any primitive currently present as kernel scaffolding, including non-cryptographic hashes, xorshift-style random generation, placeholder integrity checks, or hand-written MAC/KDF constructions, is treated as research-only. I will not present these primitives as production cryptography, and I will not rely on them for adversarial security.

Before any production or adversarial deployment, security-critical cryptographic code will be replaced by reviewed, test-vector-covered implementations from established cryptographic libraries or standards-track implementations suitable for the target environment. I am not planning to make homegrown primitives production-ready through a custom audit. The production path is replacement, not ownership of custom cryptography.

The minimum bar for any security-critical cryptographic boundary is:

1. Use reviewed implementations for hashing, MACs, KDFs, AEAD, signatures, key exchange, and random generation.
2. Include official known-answer test vectors for every primitive and mode of operation.
3. Include negative tests for malformed tags, wrong keys, wrong context strings, replayed nonces, corrupted ciphertexts, invalid public keys, and failed transcript binding.
4. Use explicit domain separation for every derived key, token, transcript, capability, and authority context.
5. Use constant-time comparison for authentication tags, MACs, signatures, and capability-token authenticators.
6. Document which kernel paths are protected by each primitive and which primitives are non-security placeholders.
7. Treat this crate as regression evidence only, not as a substitute for reviewed cryptographic implementations.

Until that replacement boundary is complete, I describe the Oreulius cryptographic layer as research scaffolding and test infrastructure, not production cryptography.

In short: I do not want Oreulius to roll its own crypto. Any custom or placeholder primitive in the current tree exists only to support research, testing, or early integration, and must be replaced before the system is described as cryptographically production-ready.

## How it routes and protects through the rest of the kernel 
The crypto folder is routed through  mod.rs file, which acts as the
public surface. 

The job of this folder is to re-export the primitives that the rest of the kernel is
allowed to call.

The primitives being re-exported are as follows:

| Primitive | How it works in Oreulius capability-based authority |
| --- | --- |
| sha256 | Creates stable identities for data, manifests, measurements, and transcripts. A capability can point at a digest instead of trusting raw bytes by name or location. |
| hmac_sha256 | Proves that a caller holds the right secret authority for a message. Oreulius uses it when integrity must depend on possession of key material, not just on a public hash. |
| aes128_gcm_encrypt | Seals data for an authorized path by encrypting the payload and producing an authentication tag over the ciphertext and associated context. |
| aes128_gcm_decrypt | Opens sealed data only after the authentication tag verifies. If the tag fails, the plaintext is not accepted, so unauthorized modification does not become usable authority. |
| x25519_shared_secret | Lets two endpoints derive the same shared secret without sending that secret across the boundary. That shared secret becomes the root material for later scoped keys. |
| ed25519_verify | Checks whether an external signer had the authority to approve a manifest, attestation, or other signed object. Oreulius can reject unsigned or incorrectly signed authority claims. |

The signed message helpers sit beside these primitives so higher-level services
can turn authority-bearing data into deterministic byte strings before
verification. Callers do not reach into each implementation file directly; they
normally use crate::crypto::* as the stable entry point.

### How the network stack (TLS) uses these primitives
The network stack uses this folder when it builds the TLS path. The first job is
agreement: X25519 lets the local side and the peer produce the same shared
secret without sending that secret over the wire. That shared secret is not used
directly as an encryption key. HKDF-SHA256 expands it into the specific traffic
keys and IV material needed for the session.

TLS also has to prove that both sides saw the same handshake. SHA-256 is used to
hash the handshake transcript, which gives the protocol one compact value that
represents everything negotiated so far. HMAC-SHA256 is then used for Finished
message verification, so each side proves it has the right derived secret for
that exact transcript.

Once the session keys exist, AES-128-GCM protects the actual TLS records. The
payload is encrypted for confidentiality, and the authentication tag covers the
ciphertext plus associated record data for integrity. On receive, the tag is
checked before plaintext is accepted. If a record was changed in transit, the
decrypt path rejects it instead of handing modified bytes to the rest of the
kernel.

#### TLS Handshake Flow

The TLS Handshake flow is just a small state machine at the current stage. It has the shape of TLS 1.3 but is not yet a full TLS 1.3 client. Therefore it doesnt have the full security validation yet. 

The handshake is driven by states in order to make the TLS setup predictable, enforce the expected message order, and prevent the kernel from treating encrypted application data as trusted until the required handshake steps have completed. Each state represents one point in the TLS negotiation, and the session only moves forward when the expected message or action for that state succeeds.

The current states used in the TLS handshake flow are as follows:

| State | How the state is used |
| --- | --- |
| Idle | The TLS session exists but is not doing anything yet. No TCP or TLS work is active. |
| TcpConnecting | The session is waiting for the TCP connection to finish before TLS can begin. |
| SendClientHello | The kernel generates client key material, builds the ClientHello message, sends it, and starts the TLS transcript. |
| WaitServerHello | The kernel waits for the server’s plaintext ServerHello, then extracts the server key share. |
| WaitEncryptedExts | The kernel has derived handshake keys and now expects the encrypted EncryptedExtensions message. |
| WaitCertificate | The kernel expects the server Certificate message. In the current code, this advances the state but does not fully validate the certificate yet. |
| WaitCertVerify | The kernel expects CertificateVerify. In the current code, this advances the state but does not verify the signature yet. |
| WaitFinished | The kernel expects the server Finished message and verifies its HMAC against the transcript. |
| SendFinished | The kernel builds and sends its own Finished message to prove it derived the same handshake secrets. |
| Connected | The TLS handshake is complete and application data can be encrypted and decrypted with application traffic keys. |
| Closed | The session has been closed normally and should not send or receive more TLS data. |
| Error | The session hit a failure, such as a bad Finished message or server alert, and should not be trusted. |

The TLS hadnshake is the setup phase that happens before any encrypted application data can move across the connection. It is what allows the client and the server to agree on how they will protect the session, create shared secret material, prove that both sides saw the same negotiation, and then switch into encrypted communication.

The handshake starts after TCP connects. The kernel sends a ClientHello message that says what it supports. These things being TLS 1.3, X25519 for key agreement, AES-128-GCM for record encryption, SHA-256 and HMAC-SHA256 for transcript and Finished verification, plus the hostname it wants to reach.

The server responds with a ServerHello. That message includes the server’s X25519 key share. Oreulius combines its private X25519 key with the server’s public key share to produce a shared secret. That shared secret is not used directly as the encryption key. Instead, HKDF expands it into separate handshake keys, so each direction of traffic has its own key material.

After ServerHello, TLS 1.3 encrypts most of the remaining handshake. The server sends messages like EncryptedExtensions, Certificate, CertificateVerify, and Finished. The transcript hash keeps a running digest of the handshake messages, so both sides can later prove they negotiated the exact same thing.

The Finished message is the proof step. It uses HMAC-SHA256 over the transcript hash with a derived Finished key. If the Finished value verifies, Oreulius knows the peer had the same handshake secrets for the same transcript. After that, Oreulius derives application traffic keys, sends its own Finished message, and moves into the Connected state.

Once connected, normal data is protected as TLS records. AES-128-GCM encrypts the payload and attaches an authentication tag. On receive, Oreulius checks the tag before accepting plaintext. If the record was changed in transit, decryption fails and the modified bytes are not handed to the rest of the kernel.

In terms of the handshake-flow maturity gaps. They mostly come down to making the TLS state machine behave like a complete TLS 1.3 client instead of only handling the simplest successful path. Right now, the implementation assumes a direct ClientHello to ServerHello path, but production TLS also needs HelloRetryRequest handling, exact transcript message-hash behavior, and support for handshake messages that are fragmented across records or packed together.

The next set of issues in the current state is about strictness and failure behavior. The handshake should not silently ignore malformed, unexpected, duplicated, or out-of-order messages. It needs to fail closed, send fatal alerts where appropriate, and move the session into a clear Error state. EncryptedExtensions also needs real validation, because it can carry negotiated parameters that affect what authority and protocol behavior the client is accepting.

The remaining items are about real-world TLS completeness. Certificate messages can be larger than the current scratch buffer, servers may request client certificates, and TLS 1.3 can send post-handshake messages like NewSessionTicket and KeyUpdate. Oreulius needs a clear policy for each: either support it correctly or reject it safely. Finally, the handshake needs a dedicated test matrix and interoperability trace validation, because TLS correctness depends on exact byte-level behavior, transcript hashes, and derived secrets matching real TLS 1.3 expectations.

The current design has the right basic shape, but it still needs maturity work:

- Add HelloRetryRequest support and the required transcript message-hash rule.
- Reassemble fragmented handshake messages before parsing or hashing them.
- Treat malformed, duplicated, out-of-order, or unexpected handshake messages as fatal.
- Validate EncryptedExtensions, Certificate, CertificateVerify, and Finished before Connected.
- Add a full handshake test matrix and compare against known TLS 1.3 traces.

#### TLS ClientHello Crypto Advertisement
The ClientHello is the first TLS message OReulius sends after TCP connects. It advertise the cryptographic choices the kernel is willing to use for this session. In the current implementation, the ClientHello says Oreulius wants TLS 1.3, supports X25519 for key agreement, supports AES-128-GCM-SHA256 for encrypted records, and includes a key share so the server can immediately derive shared secret material if it accepts X25519.

The ClientHello should also reflect the authority the caller was actually granted. If a process only has permission to connect to one host, one port, or one secure transport profile, the kernel should not advertise or attempt anything outside of that permission. The hostname sent through SNI, the TLS version, the cipher suite, the X25519 key share, and the
other advertised options should all stay inside the caller's NetworkConnect
authority.

That means the ClientHello becomes more than a greeting. It becomes the first
place where the kernel turns a network capability into a concrete TLS offer.
Later, if the server accepts the offer and the handshake proves the peer
identity, Oreulius can record what was negotiated inside the TlsSession
capability.

The current design has the right basic shape, but it still needs maturity work:

- Validate host, port, scheme, TLS version, cipher suite, key exchange group, and SNI against NetworkConnect before sending ClientHello.
- Reject ClientHello construction when the requested endpoint exceeds caller authority.
- Record advertised TLS parameters in the session metadata.
- Compare the server-selected parameters against both the ClientHello and the authority policy.
- Add tests for wrong host, wrong port, wrong SNI, unsupported group, and unsupported cipher suite.

#### TLS X25519 Key Agreement
This is the part of the TLS handshake where oreulius and the server creates the same secret without sending that across the network. 

How that is done, is by creating a private X25519 value and matching the public key share. The public key is safe to share in the ClientHello. The private value stays inside the kernel. 

The server does the same thing on its side, **it has its own private value and sends its public key share back in ServerHello.**

Both sides combine their own private value with the other sides public values. Neither sides send the shared secret directly. They independently arrive at the same value because of the Curve25519 math behind X25519. So Oreulius creates the client X25519 key material before building ClientHello. The client public key is placed into the key_share extension. When ServerHello comes back, Oreulius extracts the server’s X25519 key share and calls x25519_shared_secret to compute the shared secret.

That shared secret is not used directly as an AES key. It is raw key agreement material. TLS passes it into HKDF, which turns it into handshake traffic secrets, then into read and write keys. This is important because one shared secret needs to become multiple scoped secrets.

The scoped secrets and what they do are as follows: 

| Traffic secret | What it does |
| --- | --- |
| Client handshake traffic | Protects handshake messages sent by Oreulius before the handshake is complete, such as the client Finished message. |
| Server handshake traffic | Protects encrypted handshake messages sent by the server, such as EncryptedExtensions, Certificate, CertificateVerify, and Finished. |
| Later application traffic | Protects normal data after the handshake completes, such as HTTP request and response bytes inside TLS records. |
| Early secret | The first root secret in the TLS 1.3 key schedule. In this code it is derived from zeros because PSK/resumption is not implemented yet. |
| Derived secret after early secret | A separator value used before mixing in the X25519 shared secret. It prevents different stages of the key schedule from blending together. |
| Handshake secret | The secret created after mixing in the X25519 shared secret. It is the root for client and server handshake traffic secrets. |
| Client handshake traffic | Protects handshake messages sent by Oreulius before the handshake is complete, such as the client Finished message. |
| Server handshake traffic | Protects encrypted handshake messages sent by the server, such as EncryptedExtensions, Certificate, CertificateVerify, and Finished. |
| Finished key | Derived from a handshake traffic secret and used with HMAC-SHA256 to prove both sides saw the same transcript. There is one for the client side and one for the server side. |
| Derived secret after handshake secret | A separator value used before creating the master secret. It marks the transition from handshake protection to application protection. |
| Master secret | The root secret for post-handshake/application traffic. It is not used directly as an encryption key. |
| Client application traffic secret | Root material for application data sent by Oreulius after the handshake completes. |
| Server application traffic secret | Root material for application data sent by the server after the handshake completes. |
| Application write key | AES-128-GCM key used to encrypt records Oreulius sends. |
| Application write IV | Base IV used with the write sequence number to build nonces for records Oreulius sends. |
| Application read key | AES-128-GCM key used to decrypt records received from the server. |
| Application read IV | Base IV used with the read sequence number to build nonces for records received from the server. |

In the terms of the authority design within the kernel X25519 is the first step toward creating a private channel. It does not prove who the server is by itself. It only proves that both sides can derive the same secret for this session. Server identity still needs Certificate and CertificateVerify validation, which are not mature yet in the current TLS stack.

X25519 itself should not become a capability. It is key agreement material, not authority on its own. The authority should attach to the verified TLS session
that comes later. Once the server key share is checked, the shared secret is valid, the transcript verifies, and the peer identity is proven, Oreulius can
record X25519 as the negotiated key agreement method inside the TlsSession capability. That keeps the model clean: the curve math helps create the private
channel, but the capability represents permission to use the verified channel.

The current design has the right basic shape, but it still needs maturity work:

- Replace scheduler-tick private key generation with a real CSPRNG.
- Reject all-zero X25519 shared secrets before deriving TLS keys.
- Validate the server key share length and selected group before using it.
- Zero the private key and shared secret once they are no longer needed.
- Add test coverage for valid key agreement, invalid key shares, and all-zero shared secret rejection.

#### TLS HKDF Key Schedule 
The TLS HKDF key schedule is the part of the handshake that turns one shared secret into many smaller, scoped secrets. X25519 gives Oreulius and the server one shared value, but TLS cannot safely use that one value for every job. The protocol needs separate material for handshake traffic, application traffic, Finished verification, read keys, write keys, and record IVs. HKDF is what creates that separation.

In the code, HKDF has three layers:

| HKDF piece | What it does in the current code |
| --- | --- |
| hkdf_extract | Mixes salt and input key material with HMAC-SHA256 to produce a clean 32-byte secret. |
| hkdf_expand | Expands a 32-byte secret into the number of bytes needed by the caller. |
| hkdf_expand_label_sha256 | Builds the TLS 1.3 label format, adds the tls13 prefix and context, then calls HKDF expand. |

The label step is important. Labels such as derived, c hs traffic, s hs traffic, finished, key, and iv keep each output separate. Even when two values come from the same parent secret, the labels make the final outputs different and tied to their purpose.

The handshake side of the schedule works like this:

| Step | Result | Purpose |
| --- | --- | --- |
| Start with zeros | Early secret | Placeholder root because PSK and resumption are not implemented yet. |
| Expand early secret with derived label | Derived separator | Separates the early stage from the X25519 handshake stage. |
| Extract using the X25519 shared secret | Handshake secret | Main root for encrypted handshake traffic. |
| Expand with c hs traffic and transcript hash | Client handshake traffic secret | Protects handshake messages sent by Oreulius. |
| Expand with s hs traffic and transcript hash | Server handshake traffic secret | Protects encrypted handshake messages sent by the server. |
| Expand each traffic secret with key and iv labels | Handshake keys and IVs | Creates AES-128-GCM material for encrypted handshake records. |

After the server Finished message verifies, the application side of the schedule starts:

| Step | Result | Purpose |
| --- | --- | --- |
| Expand handshake secret with derived label | Derived separator | Marks the move from handshake protection to application protection. |
| Extract using zeros | Master secret | Root for application traffic secrets. |
| Expand with c ap traffic and transcript hash | Client application traffic secret | Root for application data sent by Oreulius. |
| Expand with s ap traffic and transcript hash | Server application traffic secret | Root for application data received from the server. |
| Expand each traffic secret with key and iv labels | Application keys and IVs | Creates AES-128-GCM material for normal TLS records. |

Finished messages also use HKDF. The server Finished key is derived from the server handshake traffic secret, and the client Finished key is derived from the client handshake traffic secret. Those Finished keys are then used with HMAC-SHA256 over the transcript hash to prove that both sides saw the same handshake.

HKDF fits in the security architecture as HKDF is where broad shared secret material becomes scoped session authority. One private channel seed is split into narrower powers: client handshake send, server handshake receive, client application send, server application receive, Finished proof, and later key material. These secrets should not become capabilities themselves. Instead, the verified TlsSession capability should record which phase the session reached and which negotiated secrets were successfully derived.

The current design has the right basic shape, but it still needs maturity work:

- Reject invalid HKDF lengths instead of silently truncating input.
- Add TLS 1.3 key schedule test vectors.
- Zeroize early, handshake, master, traffic, key, and IV material when no longer needed.
- Implement KeyUpdate for long-lived sessions.
- Implement TLS exporter behavior behind a dedicated TLS_EXPORTER right.
- Tie derived key phases to TlsSession capability state.


#### TLS Transcript Hashing
TLS transcript hashing is how the handshake remembers what has been negotiated. Instead of keeping every handshake byte around forever, Oreulius feeds each handshake message into SHA-256. The result is a compact transcript hash that
stands for the handshake so far.

This matters because TLS does not only need encryption keys. It also needs proof that both sides saw the same negotiation. If an attacker changes the ClientHello,
ServerHello, key share, certificate path, or Finished message, the transcript hash changes. Later checks that depend on that hash should fail.

In the current code, the transcript is stored as a running SHA-256 state inside the TLS session. The main updates happen at these points:

| Transcript point | What gets added | Why it matters |
| --- | --- | --- |
| ClientHello sent | The ClientHello handshake bytes | Binds what Oreulius offered into the session. |
| ServerHello received | The ServerHello handshake bytes | Binds what the server selected into the session. |
| Encrypted handshake records | EncryptedExtensions, Certificate, CertificateVerify, and Finished after decryption | Binds the server's encrypted handshake path into the same session history. |
| Server Finished check | The transcript before Finished is used | Verifies the server proved the handshake up to that point. |
| Client Finished sent | The client Finished message is added | Completes the client side of the transcript before application keys are trusted. |

The transcript hash feeds into two important parts of the TLS flow:

| Use | What the transcript hash protects |
| --- | --- |
| Traffic secret derivation | Client and server traffic secrets are tied to the exact handshake messages seen so far. |
| Finished verification | Each side proves it has the right secret for the same transcript, not just any secret. |

In the authority model, the transcript is the record of what authority was
negotiated. It binds the hostname offer, key share, selected crypto, server
messages, and Finished proof into one history. A mature TlsSession capability
should record that the transcript reached a verified point before granting
TLS_READ or TLS_WRITE authority.

The current design has the right basic shape, but it still needs maturity work:

- Handle HelloRetryRequest transcript message-hash rules.
- Reassemble fragmented handshake messages before hashing them.
- Fail closed when transcript bytes are malformed or incomplete.
- Add tests that compare transcript hashes against known TLS 1.3 traces.
- Record transcript verification state inside the eventual TlsSession capability.

#### TLS Finished Message Verification 
The Finished message is the handshake proof step. By the time Oreulius reaches
this point, both sides should have the same transcript hash and the same
handshake traffic secrets. Finished verification checks that the peer really has
the right secret for the exact handshake that just happened.

The server Finished message is checked before Oreulius moves into application
traffic. In the current code, Oreulius derives a Finished key from the server
handshake traffic secret, uses HMAC-SHA256 over the transcript hash, and compares
that expected value with the bytes sent by the server. If the values do not
match, the session moves into Error and application keys are not trusted.

The current Finished flow looks like this:

| Step | What happens | Why it matters |
| --- | --- | --- |
| Snapshot transcript | Oreulius saves the transcript hash before adding server Finished. | Finished must prove the handshake up to, but not including, itself. |
| Derive Finished key | The server handshake traffic secret is expanded with the finished label. | This creates the key used only for the Finished proof. |
| Compute expected value | HMAC-SHA256 runs over the transcript hash. | This ties the proof to the exact handshake history. |
| Constant-time compare | The expected value is compared with the server Finished bytes. | This avoids leaking which byte failed. |
| Advance on success | Application keys are derived only after the proof passes. | This keeps normal data locked behind handshake proof. |

Oreulius also sends its own Finished message. It uses the client handshake traffic
secret to derive the client Finished key, computes HMAC-SHA256 over the current
transcript hash, encrypts that Finished message under the handshake write key,
and sends it to the server. If that send succeeds, the current state moves to
Connected.

In the authority model, Finished verification is the point where the handshake
starts becoming trusted session authority. It proves that the peer had the right
derived secret for the same transcript. That is important, but it is not enough
by itself to prove server identity. Certificate validation and CertificateVerify
still need to prove who owns that side of the channel before Oreulius can treat
the result as a verified TlsSession capability.

The current design has the right basic shape, but it still needs maturity work:

- Verify Certificate and CertificateVerify before treating Finished as trusted identity.
- Fail closed on malformed Finished messages.
- Add test vectors for server Finished and client Finished values.
- Record Finished verification state inside the eventual TlsSession capability.
- Avoid moving to Connected unless the whole identity and transcript chain is valid.

#### TLS AES-GCM Record Protection 
AES-GCM is what protects TLS records after keys exist. It gives the record two
properties at the same time: confidentiality and integrity. Confidentiality
means the payload bytes are encrypted. Integrity means the receiver can detect
whether the record header or ciphertext was changed before accepting plaintext.

TLS uses record encryption to build an inner plaintext first. The
payload is copied into that inner buffer, then one extra byte is appended to say
what kind of content it really is. That inner content type matters because TLS
1.3 sends encrypted handshake records and encrypted application records using
the same outer record type.

The protected record shape is:

| Record part | Protected how | Purpose |
| --- | --- | --- |
| Outer record header | Authenticated as associated data | Lets the receiver detect header tampering. |
| Inner plaintext | Encrypted into ciphertext | Hides handshake or application bytes. |
| Inner content type | Encrypted with the plaintext | Tells the receiver what was inside after decryption. |
| Authentication tag | Appended after ciphertext | Proves the ciphertext and associated data were not modified. |

The record encrypt path works like this: 

| Step | What happens |
| --- | --- |
| Build associated data | The outer TLS record header is prepared. |
| Build nonce | The write IV and write sequence number create a per-record nonce. |
| Build inner plaintext | Payload bytes are followed by the inner content type. |
| Encrypt | AES-128-GCM encrypts the inner plaintext. |
| Authenticate | GHASH creates the authentication tag over associated data and ciphertext. |
| Advance sequence | The write sequence counter moves forward after the record is built. |

The decrypt path is deliberately stricter about release. It reads the record
length, separates ciphertext from the tag, rebuilds the associated data from the
record header, and computes the expected tag. If the tag does not match, the
function returns an error before plaintext is accepted. Only after that check
passes does Oreulius decrypt and return the inner content type and plaintext
length.

AES-GCM record protection is the enforcement point for
TLS_READ and TLS_WRITE. A holder of TLS_WRITE should be allowed to turn plaintext
into protected records. A holder of TLS_READ should be allowed to accept
plaintext only after the tag verifies. The TlsSession capability should record
that record protection is active before any application data rights are granted.

The current design has the right basic shape, but it still needs maturity work:

- Enforce AES-GCM sequence limits before nonce reuse is possible.
- Fail closed on malformed record lengths, bad tags, and unexpected inner content types.
- Avoid accepting application records before the session is fully verified.
- Add record-layer tests for tampered headers, tampered ciphertext, tampered tags, and wrong nonces.
- Prefer hardware AES or a constant-time software fallback where available.

#### TLS Nonce Construction 
TLS does not choose a fresh random nonce for every AES-GCM record. Instead, it
builds a deterministic nonce from two pieces: a static IV derived by HKDF and a
per-record sequence number. This is important because AES-GCM requires every
record under the same key to use a unique nonce. If the same key and nonce are
ever reused, the security of the record layer can collapse.

In the current code, the traffic key object stores separate IVs and sequence
counters for each direction. The write side uses the local write IV and write
sequence number when encrypting records. The read side uses the peer read IV and
read sequence number when decrypting records.

| Nonce piece | Where it comes from | What it does |
| --- | --- | --- |
| Write IV | HKDF expansion from the local write traffic secret | Base nonce material for records Oreulius sends. |
| Read IV | HKDF expansion from the peer read traffic secret | Base nonce material for records Oreulius receives. |
| Write sequence number | Starts at zero and increments after each protected outgoing record | Makes each outgoing nonce unique under the write key. |
| Read sequence number | Starts at zero and increments after each successfully verified incoming record | Makes each expected incoming nonce unique under the read key. |

The nonce construction works by copying the 12-byte IV, encoding the 64-bit
sequence number in network byte order, and XORing that sequence number into the
last 8 bytes of the IV. That produces the final 12-byte AES-GCM nonce for one
record.

| Step | What happens |
| --- | --- |
| Start with the IV | The session uses the read IV or write IV from the current traffic keys. |
| Encode the sequence number | The record counter is converted into an 8-byte big-endian value. |
| Mix it into the IV | Those 8 bytes are XORed into the last 8 bytes of the 12-byte IV. |
| Use the result once | AES-GCM uses that nonce for exactly one record. |
| Advance the counter | The matching read or write sequence counter moves forward. |

TLS has one clean rule: one traffic key, one direction, one monotonically
increasing sequence space. Client writes and server writes do not share the same
key or counter, so their nonces are separate. Handshake traffic and application
traffic also use different traffic keys, so their sequence spaces are separate
too.

In the authority model, nonce construction is part of the safety boundary behind
TLS_READ and TLS_WRITE. A caller should not be able to supply arbitrary nonces
or reset counters. The TlsSession capability should own the traffic keys,
sequence counters, and nonce construction internally. That keeps record
protection tied to the verified session instead of exposing low-level AES-GCM
controls to normal callers.

##### What is the IV in the Nonce Construction? 
The IV is the base value used to build the AES-GCM nonce for each encrypted record. It is not random per record, and it is not the encryption key. Instead, Oreulius derives a 12-byte IV from the current TLS traffic secret using HKDF. The TLS session stores separate IVs for each direction: a write IV for records Oreulius sends, and a read IV for records Oreulius receives.

When Oreulius encrypts or decrypts a record, it copies the correct IV, takes the current record sequence number, encodes that sequence number as 8 bytes, and XORs it into the last 8 bytes of the IV. The result is the final AES-GCM nonce for that one record. After the record succeeds, the matching sequence counter advances. So the IV is the stable base, the sequence number is the per-record changing part, and together they produce a unique nonce for every TLS record under that traffic key.

The current design has the right basic shape, but it still needs maturity work:

- Enforce a hard record limit before the 64-bit sequence counter can wrap.
- Ensure failed decrypts do not advance the read sequence number.
- Keep read and write sequence counters private to the TLS session.
- Reset sequence counters only when new traffic keys are installed.
- Add tests that verify nonce values for sequence zero, sequence one, and high sequence numbers.

#### TLS Read and Write Traffic Keys
Traffic keys are the concrete keys that AES-GCM uses after the HKDF key schedule
has done its work. The handshake creates traffic secrets first. Those secrets
are still not the raw AES keys. Each traffic secret is expanded into an AES key
and an IV. The key encrypts or decrypts records, and the IV helps build the
nonce for each record.

The current TLS code stores these values in a traffic key object. That object
has one set of material for writing records and another set for reading records.
This matters because TLS is directional: the bytes Oreulius sends and the bytes
the server sends are protected with different keys.

| Field | What it is used for |
| --- | --- |
| Write key | AES-128-GCM key used when Oreulius encrypts outgoing records. |
| Write IV | Base IV used to build outgoing record nonces. |
| Read key | AES-128-GCM key used when Oreulius decrypts incoming records. |
| Read IV | Base IV used to build incoming record nonces. |
| Write sequence | Counter for records Oreulius sends under the current write key. |
| Read sequence | Counter for records Oreulius receives under the current read key. |

The current implementation derives those fields from two traffic secrets: a
write secret and a read secret. For each secret, HKDF expands the label key into
a 16-byte AES-128 key and the label IV into a 12-byte IV. The sequence counters
start at zero when the key set is created.

| Traffic secret | Expands into | Direction |
| --- | --- | --- |
| Client handshake traffic secret | Handshake write key and IV for the client side | Used by Oreulius when it sends encrypted handshake records. |
| Server handshake traffic secret | Handshake read key and IV for the client side | Used by Oreulius when it receives encrypted handshake records. |
| Client application traffic secret | Application write key and IV for the client side | Used by Oreulius when it sends HTTPS request data. |
| Server application traffic secret | Application read key and IV for the client side | Used by Oreulius when it receives HTTPS response data. |

The split between read and write keys is also a security boundary. A bug in the
send path should not give authority over received records, and a receive-only
TLS capability should not be able to encrypt outbound data. This is why
TLS_READ and TLS_WRITE should become separate capability rights once TLS becomes
a first-class capability in Oreulius.

The session internally blocks normal read and write until the handshake reaches Connected. But it is still session-local logic rather than a kernel-wide authority rule. Future Dev-cycles should make the TlsSession capability should only grant TLS_READ and TLS_WRITE after the
handshake is complete, the peer identity is verified, and the correct application traffic keys are installed.

The current design has the right basic shape, but it still needs maturity work:

- Keep handshake traffic keys and application traffic keys clearly separated.
- Grant TLS_READ only for decrypting with the current read traffic key.
- Grant TLS_WRITE only for encrypting with the current write traffic key.
- Prevent callers from reading, exporting, cloning, or resetting traffic keys directly.
- Zero old traffic keys when new traffic keys replace them.
- Add tests proving read-only and write-only TLS capabilities cannot cross directions.

#### TLS Record Sequence Counters
TLS record sequence counters are the per-direction counters that make every
record nonce unique under the current traffic key. Oreulius keeps one counter
for records it writes and another counter for records it reads. Both start at
zero when a fresh traffic key set is installed.

The write counter is used when Oreulius encrypts a record. The read counter is
used when Oreulius decrypts a record from the server. The counter is mixed into
the IV to produce the final AES-GCM nonce, so counter correctness is directly
part of record-layer security.

| Counter | Used for | Advances when |
| --- | --- | --- |
| Write sequence | Outgoing TLS records | A protected record is successfully built for sending. |
| Read sequence | Incoming TLS records | A record authenticates successfully and plaintext is accepted. |

The current design has the right basic shape, but it still needs maturity work:

- Enforce hard record limits before sequence counters can wrap.
- Ensure failed decrypts do not advance the read sequence counter.
- Keep sequence counters private to the TLS session.
- Reset counters only when new traffic keys are installed.
- Add tests for counter zero, counter one, high counters, failed decrypts, and rekey transitions.

#### TLS Handshake Keys Versus Application Keys
TLS uses different keys for different phases. Handshake keys protect encrypted
handshake messages before the connection is fully established. Application keys
protect normal data after the handshake has completed and the session has moved
into Connected.

This split matters because the handshake is still proving the channel. The
server can send encrypted handshake records before application data is safe to
accept. Oreulius should not treat application records as trusted until Finished
verification, certificate validation, and CertificateVerify validation have all
succeeded.

| Key phase | Protects | Authority meaning |
| --- | --- | --- |
| Handshake keys | EncryptedExtensions, Certificate, CertificateVerify, Finished | Setup-only protection while identity and transcript proof are still being checked. |
| Application keys | HTTPS request and response payloads after Connected | Normal TLS_READ and TLS_WRITE authority for the verified session. |

The current design has the right basic shape, but it still needs maturity work:

- Keep handshake keys and application keys separate in state and tests.
- Reject application records before the session is verified and Connected.
- Wipe handshake keys after application keys are installed.
- Prevent handshake-only authority from reading or writing application data.
- Add tests for early application data, wrong key phase use, and key cleanup after transition.

#### TLS Failure Behavior
TLS failure behavior is how the stack reacts when something is malformed,
unexpected, unauthenticated, or outside policy. For a kernel TLS path, the safe
default is fail closed: do not release plaintext, do not advance trusted state,
and do not grant session authority after a bad record or bad handshake message.

In the current code, some failures move the session to Error, but other parse
failures can return silently. That is useful during prototyping, but production
TLS needs sharper behavior. A bad ServerHello, wrong Finished value, invalid
certificate, malformed record, unsupported extension, or unexpected state
transition should leave a clear security result.

The current design has the right basic shape, but it still needs maturity work:

- Convert silent parse failures into explicit TLS errors.
- Send fatal alerts where appropriate before closing.
- Ensure bad records do not release plaintext or advance read counters.
- Move the session into Error on fatal handshake or record-layer failures.
- Add negative tests for malformed records, bad tags, unexpected messages, and parser length failures.

#### TLS Capability Authority Interpretation
The TLS path is not only encryption. In Oreulius, it should also become a
kernel authority boundary. A verified TLS session should represent permission to
use one specific secure channel, with separate rights for handshake, read,
write, close, introspection, rekeying, exporter use, delegation, and audit.

The current TLS implementation mostly enforces this internally through session
state. That means the session knows whether it is Connected, Closed, or Error,
but the broader capability system does not yet own the authority decision. A
mature design should make the verified TlsSession capability the thing that
grants TLS_READ and TLS_WRITE.

The current design has the right basic shape, but it still needs maturity work:

- Issue a TlsSession capability only after policy approval and verified handshake completion.
- Bind the capability to owner process, remote identity, transport metadata, and state.
- Require exact TLS rights at read, write, close, introspect, rekey, exporter, and delegate boundaries.
- Route delegation, revocation, and audit through the capability manager.
- Add tests proving raw TLS handles cannot bypass capability checks.

#### Should TLS Become A Capability?
While the TLS handshake does have some broader support for the authority model indirectly, it is important to advance the TLS to be its own capability within the authority model. But right now, the session is only a raw interger handle from the session pool. Mechnically that means it works and does its job in a basic way. It doesnt fully match the Oreulius authority model. 

Therefore, it needs to treat a successful TLS handshake as creating a TlsSession capability. A capability that will represent authority to one verified encrypted channel. 

Here are the fields and their pupose in what the TLS capability should carry:

| Field | Purpose |
| --- | --- |
| Session object id | Identifies the specific TLS session object. |
| Owner process | Prevents another process from using the session accidentally. |
| Rights | Separates connect, read, write, close, introspect, and possibly delegate authority. |
| Remote identity | Records the hostname, certificate identity, or pinned peer key. |
| Transport binding | Records the IP, port, scheme, negotiated TLS version, and cipher suite. |
| State | Makes the session usable only after the handshake reaches Connected. |
| Expiry or lifetime | Allows time-bounded network authority. |
| Audit label | Lets security logs explain what authority was exercised. |


The next important thing it will need is some sort of rights, the important part is that the capability should be issues only after the policy allows the connection and the handshake validates the peer identity. Before that, the caller may have a NetworkConnect capability or FetchSession capability, but not yet a trusted TlsSession capability.


Here are the rights that would be necessary for evolving TLS in the network stack into a capability: 

| Right | What it will allows | Why it should exists |
| --- | --- | --- |
| TLS_CONNECT | Start a TLS connection to an approved remote endpoint. | Separates authority to open a secure channel from authority to use an already-open channel. |
| TLS_HANDSHAKE | Drive the TLS handshake state machine. | Lets the kernel distinguish setup authority from post-handshake read/write authority. |
| TLS_READ | Read decrypted application data from the TLS session. | Allows receive-only delegation without granting send authority. |
| TLS_WRITE | Write application data into the TLS session for encryption and transmission. | Allows send-only delegation without granting receive authority. |
| TLS_CLOSE | Close the TLS session and release its resources. | Prevents arbitrary holders from killing a shared secure channel. |
| TLS_INTROSPECT | Read session metadata such as state, negotiated cipher, peer identity, and error status. | Useful for debugging, monitoring, and policy agents without granting data access. |
| TLS_REKEY | Trigger or accept TLS KeyUpdate for application traffic keys. | Needed for long-lived sessions and AES-GCM sequence safety. |
| TLS_EXPORTER | Derive TLS exporter material from the session. | Powerful right because exporter secrets can bind other protocols to the TLS channel. |
| TLS_DELEGATE | Delegate a reduced TLS capability to another process. | Keeps delegation explicit and attenuable. |
| TLS_BIND_CAPNET | Bind the TLS peer identity to a CapNet peer/session. | Bridges TLS transport security into Oreulius distributed capability authority. |
| TLS_AUDIT | Emit or read detailed audit records for the session. | Allows security tooling to observe channel use without reading plaintext. |

On top of that, it is important to create varying TLS capability profiles in order to not make every TLS capability carry every right. 

| Capability profile | Rights |
| --- | --- |
| TLS connector | TLS_CONNECT, TLS_HANDSHAKE |
| TLS data stream | TLS_READ, TLS_WRITE, TLS_CLOSE |
| TLS receive-only stream | TLS_READ |
| TLS send-only stream | TLS_WRITE |
| TLS monitor | TLS_INTROSPECT, TLS_AUDIT |
| TLS key manager | TLS_REKEY |
| TLS protocol binder | TLS_EXPORTER, TLS_BIND_CAPNET |
| TLS delegator | TLS_DELEGATE plus only the rights it is allowed to pass down |

TLS_CONNECT should not automatically imply TLS_READ or TLS_WRITE. Opening a secure channel, proving the peer identity, reading plaintext, writing plaintext, exporting key material, and delegating the session are different authorities.

Therefore we need to create different capability types running through the proposed TLS channels;

Here are those newly proposed TLS Network Stack Capability types:

| Capability type | Purpose |
| --- | --- |
| TlsSession | Represents a verified, policy-approved TLS channel after successful handshake. |
| NetworkConnect | Represents permission to attempt outbound network connections. |
| NetworkResolve | Represents permission to resolve DNS names. |

Then TLS would follow this authority chain:
```text
Resolve authority
      |
      v
Connect authority
      |
      v
Start TLS authority
      |
      v
Complete handshake authority
      |
      v
Verified TlsSession capability
      |
      v
+--------------------------------------+
| Read / Write / Close session rights  |
+--------------------------------------+
```



Between these rights and the fields, oreulius hshould enforce least authority. Something like a singular process could get ead-only access to a TLS stream, another could get write-only access, and a third could only introspect state for debugging. Delegation would be explicit and done through a version with lesser access permissions, as delegation of the original  capability.

think of The Tls session not being issued, because of Mere AES-GCM keys. It should derive issuance from verified secure authority, not just encrypted bytes. This will add a another layer ontop of the TLS encryption protocol by requiring a verified policy approved secure channel, rather than a slot that acts as a landing point with a key to the door. 

It is important not to make every TLS capability carry every right. The mature default should be split by purpose.

The current design has the right basic shape, but it still needs maturity work:

- Add TlsSession, NetworkConnect, and NetworkResolve capability types.
- Replace raw TLS session handles with capability-checked session authority.
- Split TLS_CONNECT, TLS_HANDSHAKE, TLS_READ, TLS_WRITE, TLS_CLOSE, TLS_INTROSPECT, TLS_REKEY, TLS_EXPORTER, TLS_DELEGATE, TLS_BIND_CAPNET, and TLS_AUDIT into separate rights.
- Bind each verified TLS session to owner process, remote identity, transport metadata, lifetime, and audit label.
- Add tests for rights attenuation, delegation, revocation, expiry, owner mismatch, and raw-handle rejection.


#### Maturity level of the Network stacks (TLS) uses of these cryptographic primitives
So far, it is best to consider it a prototype and experimental rather than something that is production ready. This is because individual primitives are in a better sstate than the composed TLS system. 

The primitives involved;

Such as:
1. SHA-256
2. SHA-512
3. HMAC
4. HKDF
5. X25519
6. AES-GCM
7. GHASH
8. Ed25519

All have their own test vectors and/or standard structure, but the security of TLS mostly comes from the ful composition, randomness, transcript handling, certificate verfication, key schedule correctness, record sequencing, failure behaviour and parser strictness. 

The issues at play in that the TLS implementation not being at ful completeness is that the code does not yet validate server certificates or CertificateVerify signatures. While it advances through certificate and verifies the certificate state, it doesnt actually authenticiate the server identity. 

This poses some security risks in the current state; 

Those security risks being:

Security issues list:
1. No real server authentication
2. Weak randomness for TLS private keys
3. X25519 all-zero shared secret is not checked
4. TLS parser is too permissive
5. Certificate validation is missing
6. Hostname validation is missing
7. CertificateVerify is not verified
8. AES-GCM sequence overflow is not handled
9. AES implementation is table-based and may leak through cache timing
10. HKDF expand silently truncates info
11. Secret wiping and zeroization are incomplete
12. TLS state machine accepts some messages by state transition only
13. ServerHello fields are not strictly validated
14. Malformed or duplicate TLS extensions are not rejected
15. Session secrets remain in long-lived structs after use

The current design has just the basic shape, here are advancement requirements:

- Treat the current TLS path as prototype-level until identity validation, parser strictness, and record limits are complete.
- Promote primitive tests into composed TLS handshake and record-layer tests.
- Add interoperability traces against real TLS 1.3 servers.
- Require capability checks before exposing TLS operations to services or WASM host calls.
- Keep the numbered issue list below as the production maturity roadmap.

#### Other Security vulnerabilities not previously covered in the TLS path 
This extra scrub pass looked at the TLS path as a whole rather than only the cryptographic primitives. The earlier sections already cover the major issues: server authentication, certificate validation, CertificateVerify, weak randomness, X25519 all-zero checks, parser strictness, AES-GCM sequence limits, key separation, capability authority, and test coverage. The remaining risks are mostly composition problems between TLS, the custom TCP layer, session pooling, buffers, and failure behavior.

The first issue is that malformed TLS record lengths can wedge the receive buffer. The TLS stream parser reads the record length from the five-byte header and waits until that many bytes are buffered. If a peer sends a record header with a length larger than the receive buffer can ever hold, the parser can keep waiting instead of failing the session. Production TLS needs to reject records above the TLS limit immediately, otherwise a single malicious header can stall the session.

The second issue is the custom TCP layer under TLS. The TCP feed path checks the destination IP and ports, but it does not fully validate the source IP against the expected server, does not verify the TCP checksum on received frames, and accepts some sequence and ACK behavior loosely. TLS record authentication protects encrypted data after keys exist, but the TCP layer can still be used for denial of service, handshake disruption, injected resets, or confusing pre-handshake bytes. The network path needs stricter packet validation before TLS trusts that bytes belong to the intended connection.

The third issue is write-sequence desynchronization on failed sends. The TLS write path clones the application traffic keys, encrypts a record, advances the write sequence during encryption, assigns the advanced keys back to the session, and then calls the TCP send path. If TCP send fails after the sequence has already advanced, the TLS nonce stream can move forward even though the record was not actually accepted for transmission. Skipping a sequence number is not as bad as reusing a nonce, but it can desynchronize accounting, confuse retries, and make record-limit enforcement harder.

The fourth issue is buffered plaintext after session failure. The read function drains the application buffer without checking whether the session is still Connected. If application bytes were already decrypted and buffered, then the session later moves to Closed or Error, a caller can still read whatever remains in the buffer. That may be acceptable under a deliberate stream-drain policy, but it needs to be explicit. A production TLS capability needs to decide whether close/error freezes reads, allows already-authenticated bytes to drain, or clears unread plaintext.

The fifth issue is silent hostname truncation. Session allocation copies the requested host into a fixed 253-byte array and silently truncates longer hostnames. The ClientHello SNI then uses the truncated hostname. Later, certificate and hostname validation will need to know whether the hostname was exact. A truncated authority string can cause policy, SNI, logging, and future certificate checks to disagree about what host the caller requested.

The sixth issue is transcript pollution from incomplete plaintext handshake parsing. The plaintext handshake handler computes the declared handshake length, clamps the end to the current record length, and updates the transcript with the bytes that are present. If the message is incomplete, the transcript can be updated with a partial handshake message before the parser has proven the full declared message exists. Transcript bytes are security-critical in TLS 1.3, so the stack must not hash partial or malformed handshake messages as if they were valid.

The seventh issue is that source and destination binding is not strong enough across the full path. The TLS session stores host, port, and server IP, and the ClientHello carries SNI, but the raw handle does not bind those fields to NetworkResolve, NetworkConnect, TCP peer validation, certificate identity, and eventual TlsSession capability metadata as one atomic authority object. Without that binding, the stack can grow features where DNS result, TCP peer, SNI, certificate identity, and capability metadata drift apart.

The eighth issue is that session-pool handles are reusable integers. A freed session slot can later be reused for a different connection, and the raw handle value can be the same. Without generation numbers or capability object ids, stale handles can accidentally refer to a newer session if a caller keeps an old handle. The capability work already says raw handles need to go away, but the stale-handle reuse risk should be named directly.

Together, these issues show that the TLS path needs to harden not only cryptography, but the edges around it. TLS security depends on exact record boundaries, strict transcript ownership, endpoint binding, correct sequence accounting, safe buffer lifetime, and non-reusable authority handles. The primitives are only one part of the security story.

### How the Persistance path uses these primitives
This path is how the kernel uses crypto to protect saved kernel state, when logs, snapshots, and records are written. The persistence path uses crypto to protect saved kernel state when Oreulius writes snapshots and log records. It is not using the TLS primitives for networking here; it is using the same crypto folder for storage integrity and snapshot sealing.

At the simplest level, persistence has log records. A log record has a header, a payload, and a CRC32 checksum. That CRC32 is useful for catching accidental corruption, like truncated or damaged data, but it is not cryptographic security. An attacker who can rewrite the record could also rewrite the CRC. So CRC32 is an integrity convenience, not a tamper-proof seal.

The stronger crypto path is the snapshot sealing path. When Oreulius writes a persistence snapshot, it derives two keys from a kernel persistence seal key:

| Derived value | How it is made | What it protects |
| --- | --- | --- |
| Encryption key | SHA-256 over persistence encryption label, slot id, and master seal key, then first 16 bytes are used | Encrypts the snapshot payload with AES-128-CTR |
| MAC key | SHA-256 over persistence MAC label, slot id, and master seal key | Authenticates the snapshot header and encrypted payload with HMAC-SHA256 |

The snapshot write flow is roughly:

| Step | What happens |
| --- | --- |
| Build header | Oreulius creates a snapshot header with magic, version, slot id, data length, offset, timestamp, flags, nonce, and empty MAC field. |
| Derive keys | It derives an AES key and HMAC key from the persistence seal key and slot id. |
| Encrypt payload | If the snapshot has data, AES-128-CTR encrypts the payload in place. |
| Authenticate snapshot | HMAC-SHA256 covers the header and encrypted payload. The code stores a truncated 16-byte MAC in the header. |
| Write sectors | The sealed snapshot image is written to disk sectors. |

On read, Oreulius reverses that process carefully. It reads the header, checks the magic/version/slot, reads the snapshot sectors, recomputes the HMAC over the header with the MAC field zeroed plus the stored payload, and compares that expected MAC with the stored MAC using constant-time comparison. Only after the MAC passes does it decrypt the payload with AES-128-CTR.

So the important rule is: authenticate before trusting or decrypting. The MAC tells Oreulius whether the snapshot still matches what the kernel wrote. AES-CTR gives confidentiality, but CTR mode by itself does not detect tampering, so the HMAC is what gives the snapshot its cryptographic integrity.

In capability terms, this path protects persisted authority and system state. If snapshots include capability state, service state, boot state, or security events, then persistence must prevent silent modification. The crypto here helps make saved state tamper-evident and optionally encrypted, so a restored snapshot is not just “bytes from disk,” but bytes that passed the kernel’s seal check.

#### Snapshot Sealing Flow
This part is how the persistance path turns an in memory snapshot into protected bytes before writing it to a disk, file fall back or an external snapshot backend. This means a snapshot can contain important kernel state. This state is important and necessary because it is what lets Oreulius recover the system without starting from nothing. It can preserve temporal history, filesystem state, service progress, offsets, timestamps, and authority-related data that the kernel may need after reboot, rollback, or crash recovery. Since that state can affect what the system trusts and what processes are allowed to do, it has to be protected before it is written outside memory.

The snapshot can carry temporal state for rollback and replay, VFS state for restoring files and filesystem metadata, service state for resuming kernel services, offsets for knowing where logs or streams should continue, timestamps for ordering recovery points, and authority-related data that may affect what processes or services are allowed to do.

| Snapshot data | What it means |
| --- | --- |
| Temporal state | Saved time/version state used for rollback, replay, and temporal recovery. |
| VFS state | Saved virtual filesystem state, such as files, directories, or filesystem metadata. |
| Service state | Saved state owned by kernel services that need to survive recovery. |
| Offsets | Position markers showing where logs, snapshots, or replay streams should resume. |
| Timestamps | Time markers used to order snapshots, events, or recovery points. |
| Authority-related data | Capability, policy, or security state that may affect what a process or service is allowed to do. |

The sealing flow is meant to make that saved state private and tamper-evident. Private means the payload is encrypted. Tamper-evident means the kernel can detect if someone changed the saved bytes before restoring them.

The current sealing flow works like this:

| Step | What happens |
| --- | --- |
| Build snapshot header | Oreulius creates a header with magic, version, slot id, data length, last offset, timestamp, flags, nonce, and an empty MAC field. |
| Derive seal keys | The kernel derives an AES encryption key and an HMAC key from the persistence seal key and snapshot slot id. |
| Choose nonce | The persistence path takes the next snapshot nonce for AES-CTR encryption. |
| Copy payload | The in-memory snapshot bytes are copied after the header into a scratch image. |
| Encrypt payload | AES-128-CTR encrypts the payload in place using the derived encryption key and nonce. |
| Authenticate sealed image | HMAC-SHA256 authenticates the header and encrypted payload. The MAC field is zeroed while computing the MAC. |
| Store MAC | The first 16 bytes of the HMAC are written into the header. |
| Write backend | The sealed image is written to disk sectors, the VFS snapshot file, or an external backend. |

The important security order is encryption first, then MAC over the encrypted form. On read, Oreulius does the opposite in terms of trust: it verifies the MAC before decrypting. That means modified snapshot bytes are rejected before the kernel uses plaintext.

The flow is also slot-aware. The slot id is included in key derivation and in the authenticated header, so the generic snapshot, temporal snapshot, and VFS snapshot do not all collapse into the same sealed object. Each slot gets its own derived sealing material.

In order to achieve full maturity, Oreulius should  treat snapshot sealing as a storage capability boundary. A caller with write snapshot authority should be able to ask the persistence service to seal state, but should not be able to choose raw encryption keys, reset nonces, skip the MAC, or write unsealed production snapshots. The persistence service should own the seal key, nonce, encryption, MAC, backend choice, and recovery policy internally.

#### Persistence Seal Key
The seal key is the root secret that the kernel uses to protect the snapshots at rest. It is not however, the AES key in a direct sense, nor is it the HMAC key in a direct sense either. What it is, is the master secret that the path uses to derive smaller purpose specific keys. 

This serves as yet another delegation point in the kernel to prevent authority leakage when transferring authority and capability in the security system of the kernel, but on the encryption side. It s not delegation in the capability-object sense yet, but it is authority separation through key derivation.

Oreulius derives smaller purpose-specific keys from it, such as one key for encryption and another key for authentication. This keeps the root secret from being used everywhere directly, and limits how much authority each derived key has. It acts as the master authority for the persistence path.

The persistence path derives narrower keys from the seal key. That would be an AES key for snapshot confidentiality and an HMAC key for snapshot integrity. That separation prevents one broad secret from being reused for every job and makes the design closer to least authority, even before persistence sealing becomes a full capability boundary.

The seal key lives in the security module as a 32-byte value. There is a default development key built into the kernel, and the comments already say production deployments should replace it through attested provisioning. That distinction matters: the default key is acceptable for local bring-up, but it is not a production security boundary because anyone with the source can know it.

The flow looks like this:


| Piece of the flow | What it does |
| --- | --- |
| Persistence seal key | Root secret for protecting snapshots at rest. |
| Slot id | Separates generic, temporal, and VFS snapshot slots. |
| Encryption label | Keeps encryption-key derivation separate from MAC-key derivation. |
| MAC label | Keeps authentication-key derivation separate from encryption-key derivation. |
| Derived encryption key | AES-128 key used to encrypt snapshot payload bytes. |
| Derived MAC key | HMAC-SHA256 key used to authenticate the snapshot header and encrypted payload. |


When Oreulius seals a snapshot, it asks for the persistence seal key, mixes it with the snapshot slot id and an encryption label, then hashes that into an encryption key. It does the same with a MAC label to create a separate MAC key. This gives each snapshot slot its own derived sealing material, and it keeps encryption and authentication separated.

The important security idea is that the seal key is the authority to protect and recover persisted state. If an attacker gets it, they may be able to decrypt snapshots or forge valid snapshot MACs. If the key is weak or left at the development default, snapshot sealing becomes much weaker. So the mature design should treat this key like a kernel root secret: provision it from a trusted source, never expose it to normal callers, never persist it in plaintext, and audit whether the system is using a real provisioned key or the development fallback.

In capability terms, callers should never receive the seal key. They should only receive limited persistence rights, such as write snapshot or read snapshot. The persistence service should own the seal key internally and use it only to seal or unseal snapshots after checking the caller’s authority.

The persistence seal is in a good prototype stage, but it is not production mature yet. It already separates the root seal key from the actual AES and HMAC keys, which is good because the broad authority is not reused directly everywhere. But the big issue is that the current root seal key still has a built-in development default, fine for testing, not fine for production. To mature it, Oreulius needs a real device-specific seal key, HKDF-based key derivation, stronger nonce and rollback protection, key zeroization, capability-gated seal and unseal operations, and end-to-end tamper and recovery tests.


#### Snapshot Key Derivation

Snapshot key derivation is the step where Oreulius turns the broad persistence seal key into the actual keys used for one snapshot slot. The seal key is the root authority, but the persistence path does not use it directly as the encryption key or the MAC key. Instead, it derives narrower keys from it so each job has its own scoped material.

In the current code, the function derives two keys:

| Derived key | How it is made | What it is used for |
| --- | --- | --- |
| Encryption key | SHA-256 over the persistence encryption label, slot id, and seal key, then the first 16 bytes are used | AES-128-CTR encryption of the snapshot payload |
| MAC key | SHA-256 over the persistence MAC label, slot id, and seal key | HMAC-SHA256 authentication of the snapshot header and encrypted payload |

The slot id matters because Oreulius has different snapshot slots, such as generic, temporal, and VFS snapshots. Including the slot id means those slots do not all derive the same encryption and MAC keys. A sealed VFS snapshot and a sealed temporal snapshot should not collapse into the same cryptographic context.

The labels matter because encryption and authentication are different jobs. The encryption label creates key material for confidentiality. The MAC label creates key material for integrity. That separation is important because reusing one key for multiple cryptographic purposes is a common way to weaken a design.

There is another maturity detail around seal key generation. Right now, the
section talks about the seal key as the root secret, but future snapshots should
also record which generation of that seal key protected them. That matters once
Oreulius supports key rotation. If the kernel replaces the old persistence seal
key with a new one, recovery needs to know whether an older snapshot was sealed
under generation one, generation two, or something later. Without that metadata,
the kernel may not know which key to try, whether the snapshot should be
migrated, or whether it should be rejected as stale.

The derivation context should also include snapshot purpose, not only slot id.
Slot id separates generic, temporal, and VFS snapshots mechanically, but purpose
labels make the meaning clearer and safer. A temporal snapshot, a VFS snapshot,
and a future capability-state snapshot should each derive keys in a context that
says what kind of state is being protected. That makes the derivation easier to
audit and prevents future snapshot classes from accidentally sharing a key
context because the slot behavior became confusing later.

The current design has the right idea: root seal key first, then separate derived keys for smaller purposes. But it is not fully mature yet because the derivation is custom SHA-256 label mixing. For production, it should become HKDF-SHA256 with clear labels, snapshot version, slot id, snapshot purpose, backend context, seal key generation, and strict length rules. That would make the persistence key schedule easier to review, test, and compare against standard KDF expectations.

The mature version should be documented like a small persistence key schedule,
similar to how TLS has a key schedule. The seal key would be the root secret,
HKDF would be the derivation mechanism, and each output would have a named
purpose: snapshot encryption key, snapshot MAC key, and later maybe migration or
recovery keys. That turns key derivation from a helper function into a clear
security design that explains exactly why each key exists and what authority it
carries.

#### AES-CTR Snapshot Encryption
This type of encryption, is the confidentiality part of the persistance seal, it keeps the snapshot payload bytes private after they are written outside of the kerne memory. If for example, the snapshot contains any of these:

1. temporal state
2. vfs state
3. service state
4. authority related data

Then the AES-CTR will stop someone from simply reading those bytes from disk or snapshot file. What CTR stands for is Counter mode. This mode does not cause AES to encrypt the snapshot payload directly like a fixed block, instead it uses the derived encryption key known as the snapshot nonce and the counter to create a stream of pseudorandom bytes. The stream of pseudorandom bytes is then XORed with the snapshot payload,which is then ciphertexted. 

In order to decrypt all of that, the kernel runs the same operation again with the same key and the nonce, for the XOR to turn the ciphertext back into plain text. 

Heres the compoenets of the encryption and decryption process in terms of how the AES-CTR works:

| Piece | What it does |
| --- | --- |
| Derived encryption key | AES-128 key derived from the persistence seal key. |
| Snapshot nonce | Per-snapshot value used to make the AES-CTR stream unique. |
| Counter | Advances across blocks so each part of the payload gets a different stream block. |
| Plaintext payload | The in-memory snapshot bytes before sealing. |
| Ciphertext payload | The encrypted snapshot bytes written to storage. |

It follows an important rule that the same encryption key and nonce must never be reused for two different snapshot payloads. IF they ever are repeated, then an attacker could compare the cuiphertexts and learn relationships between the underlying plaintexts. Therfore the persistance path must keep a snapshot nonce counter and update when it observes any recovered snapshots. 

AES-CTR does not authenticate data. It only hides it. If someone flips a bit in AES-CTR ciphertext, that bit flips in the decrypted plaintext too. That is why Oreulius pairs AES-CTR with HMAC-SHA256. The HMAC is what detects tampering. So the mature rule is: AES-CTR provides confidentiality, HMAC provides integrity, and the snapshot must pass HMAC verification before the kernel decrypts or restores it.

For AES-CTR snapshot encryption, the crypto operation itself should not become a capability. AES-CTR is just the mechanism that encrypts bytes. The capability should be around the persistence operation that uses it.

So the mature model should look like this:

| Thing | Should it be a capability? | Why |
| --- | --- | --- |
| AES-CTR primitive | No | It is a low-level encryption mechanism, not user-facing authority. |
| Derived encryption key | No, not directly exposed | It should stay internal to the persistence service. |
| Snapshot nonce | No, not directly exposed | Callers should not control or reset nonce state. |
| Seal snapshot operation | Yes | This is authority to write protected persisted state. |
| Unseal snapshot operation | Yes | This is authority to recover protected persisted state. |
| Persistence snapshot object | Yes | It represents access to a specific persisted state object or slot. |

Right now, this is only partially capability-based. The persistence service has local StoreCapability rights, such as write snapshot and read snapshot. That is a good start, but it is not fully integrated into the broader Oreulius capability system yet. It does not fully model owner process, provenance, delegation, revocation, lifetime, slot scope, backend scope, or audit labels the way a mature kernel capability should.

In order to make this fully production ready there is much work ahead to do, 

Such as; 


To keep AES-CTR as an internal detail of the persistence service, not something normal callers can control directly. A caller should need write snapshot authority before the kernel encrypts and seals snapshot state, and read snapshot authority before the kernel authenticates, decrypts, and restores that state. Callers should not be able to choose encryption keys, nonces, counters, or raw AES-CTR parameters, because those pieces control the safety of the sealed snapshot format.

The snapshot authority should also be scoped more tightly. A capability should say which snapshot slot it applies to, such as generic, temporal, VFS, or a future capability-state snapshot, and which backend it applies to, such as disk, file fallback, or an external backend. Oreulius should also audit seal, unseal, failed MAC, failed nonce, rollback, and backend fallback events. The larger maturity step is to promote StoreCapability into the global capability manager and add tests proving callers cannot bypass snapshot rights or trigger raw encryption and decryption paths directly.

AES-CTR itself should never become fully capability based, because it is only the low-level encryption primitive, but the snapshot sealing flow around it should become fully capability based. In the mature design, callers would not hold AES keys, choose nonces, reset counters, or call raw encryption directly. Instead, they would hold scoped persistence capabilities that authorize specific actions, such as sealing a temporal snapshot, unsealing a VFS snapshot, or recovering a snapshot from a specific backend. So the primitive stays internal, while the authority to use it becomes fully controlled by the capability system.


#### HMAC-SHA256 Snapshot Authentication
This part of the persistance path is how the integrity of the snapshot sealing is maintained. AES-CTR hides the snapshotpayload, ut it does not prove the bytes were not changed. HMAC-SHA256 is what lets Oreulius detect tampering before it trusts or restores a snapshot.

In the current and basic implementation of the persistence path, the kernel derives a MAC key from the persistence seal key. That MAC key is separate from the AES encryption key. When a snapshot is written, the kernel builds the snapshot header, encrypts the payload, then computes HMAC-SHA256 over the header and encrypted payload. The MAC field inside the header is zeroed while the MAC is computed, then the first 16 bytes of the HMAC are stored back into the header.

The authenticated data includes the important metadata and the ciphertext:

| Authenticated piece | Why it matters |
| --- | --- |
| Magic | Confirms the bytes are meant to be an Oreulius snapshot. |
| Version | Binds the snapshot format version into the MAC. |
| Slot id | Prevents one slot’s sealed snapshot from being silently treated as another slot. |
| Data length | Prevents length tampering. |
| Last offset | Protects the recovery position or log progress marker. |
| Timestamp | Protects the snapshot’s recorded time marker. |
| Flags | Protects whether the snapshot claims to be sealed or encrypted. |
| Nonce | Protects the AES-CTR nonce used for encryption. |
| Ciphertext payload | Protects the encrypted snapshot body from modification. |

On read, Oreulius recomputes the expected HMAC using the same MAC key, the same header with the MAC field zeroed, and the stored ciphertext. It then compares the expected MAC with the stored MAC using constant-time comparison. If the values do not match, the read path returns an integrity error and does not accept the snapshot as trusted state.

This is why the order matters: verify the HMAC before decrypting or restoring. If someone changes the ciphertext, the header, the nonce, the flags, the slot id, or the length, the HMAC should fail before any plaintext is used. That makes HMAC-SHA256 the gate between untrusted storage bytes and trusted recovered kernel state.

The current design is simply a scaffold with a good shape, but there are maturity points. The stored MAC is truncated to 16 bytes, so the security target for that truncation should be documented. The read path should fail closed for every malformed or missing MAC case. The same authentication policy should apply across disk, file fallback, and external backends. And audit should record failed MAC checks, because a failed MAC is not just a parse error, it may be evidence of tampering or rollback.

#### Snapshot Nonce Construction
When the kernel needs to keep the AES-CTR encyption from reusing the same keystream, it uses a construction of the snapshot nonces to do so. In CTR mode, the derived encryption key and nonce are used to generate a stream of bytes that gets XORed with the snapshot payload. If Oreulius ever reused the same key and nonce for two different snapshots, the encrypted snapshots could leak information about the original plaintexts. So the nonce is not a small detail, it is central to snapshot confidentiality.

Currently, a global next snapshot nonce counter. When it writes a sealed snapshot, it takes the current nonce, uses it for AES-CTR encryption, then advances the counter. The nonce is also stored in the snapshot header, and because the header is covered by HMAC-SHA256, an attacker cannot change the nonce without breaking the MAC.

The current nonce flow looks like this:

| Step | What happens |
| --- | --- |
| Seed nonce state | At startup, Oreulius mixes the in-memory nonce state with platform timing or entropy-like values. |
| Choose nonce | Snapshot write takes the current nonce value. |
| Encrypt payload | AES-CTR uses the derived encryption key and snapshot nonce to encrypt the payload. |
| Authenticate nonce | The nonce is stored in the snapshot header, and the header is authenticated by HMAC-SHA256. |
| Advance nonce | The next snapshot nonce moves forward for the next write. |
| Observe recovered nonce | During recovery, Oreulius observes the nonce from a valid snapshot and advances local nonce state past it. |

That recovery step matters. If the kernel reads a valid snapshot with nonce 20, it should not later write a new snapshot with nonce 20 again under the same key. So the read path updates the in-memory next nonce to be higher than the observed value.

The maturity issue is that this is still mostly an in-memory monotonic counter with startup mixing. That is better than a constant nonce, but it is not the same as durable rollback-resistant nonce management. If an attacker can roll the disk back to an older valid snapshot, or if the system loses nonce state across reboot, Oreulius may not have a perfect guarantee that a key and nonce pair will never repeat.

For production maturity, nonce state should be backed by something harder to roll back: a durable counter, a hardware monotonic counter, a trusted boot measurement, or a seal-key generation that changes when rollback is detected. The system should also fail closed if nonce freshness cannot be trusted. In short: AES-CTR snapshot encryption is only as safe as its key and nonce uniqueness.

#### Rollback Protection For Persisted State
This is how the persisted state stops an old but valid snapshot from eing restored as if it were the newest trusted state. It's different from tamper protection as HMAC-SHA256 can prove that a snapshot was sealed by Oreulius and was not modified. It however, cannot prove that the snapshot is the latest one.

That matters because an attacker may not need to forge a snapshot. If they can copy an older valid sealed snapshot back onto disk, the MAC can still verify. The bytes are real, the encryption is real, and the authentication tag is real, but the state may be stale. That stale state could bring back old policy, old service state, old filesystem contents, old temporal history, or old capability decisions.

The difference is:

| Protection type | What it catches | What it does not catch |
| --- | --- | --- |
| Tamper protection | Modified snapshot bytes, changed header fields, changed ciphertext, wrong MAC | An older valid snapshot copied back into place |
| Rollback protection | Older snapshot generation, stale state, replayed valid snapshot | Byte-level corruption by itself |
| Encryption | Someone reading snapshot contents from storage | Old encrypted snapshots being replayed |
| CRC32 | Accidental corruption | Malicious replay or recomputed malicious changes |

A mature persistence path needs a way to know freshness. That usually means binding each snapshot to a monotonic generation, boot counter, trusted rollback index, or previous-snapshot chain. Then recovery can ask: “Is this snapshot valid?” and also “Is this snapshot newer than or equal to the newest state I am allowed to trust?”

This gap matters particularly because persisted state may include authority-related data. If a capability was revoked, a policy was tightened, or a service moved forward, restoring an older valid snapshot could accidentally bring back authority that should no longer exist. So rollback protection is not just storage hygiene. It is part of preserving the security model across reboot and recovery.

The mature design needs to authenticate freshness metadata along with the snapshot. That means fields like generation, previous snapshot identity, boot epoch, rollback index, or seal key generation should be inside the HMAC-protected header. The kernel should reject snapshots that are valid but older than the last trusted generation, and it should audit that rejection because rollback attempts are security-relevant events.

#### Persistence Store Capabilities
The authority checks around the persistance service are done by storing persistant capabilities in and around those authority checks. They decide who is allowed to append logs, read logs, write snapshots, and read snapshots. This is separate from the crypto itself. AES-CTR and HMAC-SHA256 protect the bytes, but the capability layer decides who is allowed to ask the kernel to seal or unseal those bytes in the first place.

Persistence has a local StoreCapability type. It carries a capability id and a set of StoreRights. Those rights include append log, read log, write snapshot, and read snapshot. Before the persistence service appends a record, reads records, writes a snapshot, or reads a snapshot, it checks whether the passed capability has the required right.

The current rights are:

| Store right | What it allows |
| --- | --- |
| Append log | Add a new record to the persistence log. |
| Read log | Read records from the persistence log. |
| Write snapshot | Save snapshot state into the persistence system. |
| Read snapshot | Read recovered snapshot state from the persistence system. |

That is a good start because persistence is not fully ambient. A caller needs a capability-shaped object with the right bit set before the service performs the operation. But it is still local to the persistence service. It is not yet a full Oreulius capability with owner process binding, provenance, delegation, revocation, lifetime, slot scope, backend scope, or audit labels.

A mature version should make persistence authority first-class in the global capability manager. That means a process would not just pass a local StoreCapability. It would hold a real persistence capability that says what it can do, which snapshot slot it applies to, which backend it can touch, whether it can seal or unseal, how long the authority lasts, and whether it can delegate a reduced version to another process.

There are also many more rights that should be required, those planned rights being:

| Mature persistence right needed | What it should allow |
| --- | --- |
| PERSIST_APPEND_LOG | Append a new authenticated record to the persistence log. |
| PERSIST_READ_LOG | Read persistence log records. |
| PERSIST_WRITE_SNAPSHOT | Write snapshot state into an approved snapshot slot. |
| PERSIST_READ_SNAPSHOT | Read snapshot state after successful authentication and recovery. |
| PERSIST_SEAL | Encrypt and authenticate a snapshot before it leaves memory. |
| PERSIST_UNSEAL | Verify, decrypt, and load a sealed snapshot after recovery checks pass. |
| PERSIST_RECOVER | Run snapshot recovery during boot, crash recovery, or service restart. |
| PERSIST_MIGRATE | Migrate legacy or older snapshot formats into the current sealed format. |
| PERSIST_ROTATE_KEY | Rotate the persistence seal key and re-seal snapshots under the new key. |
| PERSIST_AUDIT | Emit or read persistence security audit events without reading snapshot plaintext. |
| PERSIST_DELEGATE | Delegate reduced persistence authority to another process or service. |
| PERSIST_INTROSPECT | Read safe metadata such as snapshot slot, backend, version, generation, size, and last error. |
| PERSIST_BIND_SLOT | Bind authority to a specific snapshot slot, such as generic, temporal, VFS, or capability-state. |
| PERSIST_BIND_BACKEND | Bind authority to a specific backend, such as disk, file fallback, or external backend. |
| PERSIST_ROLLBACK_CONTROL | Accept, reject, or advance trusted rollback generation state. |

The modular rules should work as follows;

 >Callers should not own the persistence seal key, AES key, HMAC key, nonce, or raw encryption function. They should own narrowly scoped authority. For example, one service might be allowed to write temporal snapshots but not read them. Another might be allowed to append audit log records but not overwrite snapshots. A recovery component might be allowed to unseal a VFS snapshot during boot, but not access generic service state.

So the capability layer should wrap the crypto. The persistence service keeps the keys and crypto internals private. Callers only get rights to operations like append, read, seal, unseal, recover, migrate, or audit. That is how persistence becomes aligned with Oreulius’s broader least-authority model.

#### Checking the Persistance path for security vulnerabilities still within the code not addressed previously. 

This second pass looked over the persistence path as a whole, not just the AES-CTR and HMAC pieces. The important thing it found is that the remaining persistence risk is mostly around who can reach the sealing key, which storage backend is allowed to participate, whether durable writes actually succeeded, and whether recovered state came through the sealed persistence path at all. In other words, the primitive shape is good, but the system boundary around the primitives still has loose spots.

| Area reviewed | What the code currently does | Security problem | Maturity direction |
| --- | --- | --- | --- |
| Seal key exposure | security::persistence_seal_key returns a copy of the root seal key, and set_persistence_seal_key can replace it. | The root key is not only used internally by persistence. Any kernel code that can call the public function can copy or replace the key, which makes the seal key an ambient root secret instead of a protected authority. | Hide the root seal key behind sealed operations, remove general key export, and gate key replacement behind production provisioning authority. |
| External snapshot backend | The external backend receives and returns raw Snapshot objects. | Disk and file backends seal snapshots inside the persistence service, but the external backend can bypass that sealing path unless every backend reimplements the same policy correctly. | Make the persistence service seal before calling external write, and authenticate after external read before trusting the returned bytes. |
| Durable write result handling | Generic write_snapshot ignores the durable write result, and temporal persistence ignores write_temporal_snapshot failure. | A caller can be told that a snapshot write succeeded even though durable persistence failed. The in-memory snapshot and recovered durable state can silently diverge. | Treat durable write failure as a real failure for production snapshots, audit it, and return it to the caller. |
| VFS persistence route | VFS recovery uses a flat filesystem snapshot path, while the sealed write_vfs_snapshot and read_vfs_snapshot APIs appear unused in the reviewed call graph. | VFS state can bypass the sealed persistence snapshot path, even though VFS state may contain filesystem metadata and authority-related state. | Route VFS recovery through sealed persistence snapshots or make the flat VFS snapshot format cryptographically sealed and policy-gated. |
| Backend fallback | Read fallback can accept file-backed data after disk read or integrity failure, and write fallback can move to file storage after primary failure. | A corrupted or attacked primary backend can cause recovery to trust a weaker or older fallback backend unless fallback is itself authenticated, freshness-checked, and policy-approved. | Distinguish unavailable backend from failed integrity, and do not fallback after integrity failure unless a signed recovery policy allows it. |
| File snapshot length parsing | File-backed snapshots accept the needed header and payload bytes but do not require the file to end exactly at the authenticated payload. | Trailing data can ride alongside a valid snapshot without being authenticated. It may not affect current parsing, but it weakens format strictness and can hide confusing state. | Require exact file length for file snapshots, or explicitly authenticate and define all padding and trailing bytes. |
| Snapshot flags | V2 reads require the sealed flag, but the encrypted flag is optional if the MAC verifies. | A production sealed snapshot can be accepted as authenticated but unencrypted if a valid writer creates that format. That blurs the difference between sealed, authenticated-only, and encrypted-at-rest snapshots. | Define allowed flag combinations and reject authenticated-only snapshots in production unless an explicit migration policy allows them. |
| StoreCapability construction | StoreCapability has a public constructor, StoreRights::all exists, and many internal callers mint all-rights capabilities directly. | Persistence authority is easy for kernel code to fabricate locally. The cap_id is not validated by a global capability manager, so it is not a strong authority object yet. | Move persistence capabilities into the global capability manager, with owner binding, revocation, delegation, slot scope, backend scope, and audit labels. |
| Backend registration | register_snapshot_backend can replace the external backend without a persistence capability check. | A malicious or mistaken kernel component can change where persistence writes and reads snapshots, which changes the trust boundary for recovered state. | Gate backend registration and clearing behind PERSIST_BIND_BACKEND or an equivalent privileged kernel authority. |
| Debug crypto tracing | trace_snapshot_crypto prints operation labels, slot ids, pointer addresses, lengths, and heap or JIT range membership for early snapshot crypto operations. | Serial debug output can leak memory layout and persistence activity. That is useful in bring-up, but it is not safe as default production telemetry. | Compile-gate or policy-gate persistence crypto tracing, remove raw addresses from production logs, and audit only safe metadata. |
| Recovery error handling | recover_snapshots_from_durable ignores individual read errors and only records that recovery was attempted. | A MAC failure, malformed header, backend error, or rollback suspicion can be lost as a silent empty or skipped recovery path. | Preserve and audit recovery outcomes per slot and backend, and fail closed when production recovery state cannot be trusted. |
| Log read bounds | AppendLog::read slices from records[from_offset..] without checking that from_offset is in range. | A caller-controlled offset can panic the kernel instead of returning a clean persistence error. | Validate log offsets and record lengths before slicing, and return InvalidRecord or range errors instead of panicking. |
| Snapshot stale tails | Snapshot::write and read paths update data_len but do not clear old data beyond the new length. | Old plaintext snapshot bytes can remain in memory after a shorter write or read. That is not immediately exposed through data_len, but it increases the blast radius of later bugs or memory disclosure. | Clear unused snapshot tails and scratch buffers after write, read, failed recovery, and failed seal operations. |
| Untracked file fallback writes | File-backed snapshot fallback uses write_path_untracked. | This avoids recursion, but it also means the fallback snapshot write bypasses normal VFS tracking, journaling, and audit expectations. | Treat fallback snapshot writes as special persistence operations with explicit audit records and recovery policy. |

The most serious new finding is the seal-key exposure. The README already says the development seal key needs replacement, but the code review adds a sharper point: the root persistence seal key is returned as a copy by a public security function, and it can be replaced through another public function. That means the root key is not yet encapsulated as an internal persistence authority. In a mature design, normal kernel callers would never receive the seal key. They would ask the persistence service to seal, unseal, rotate, or migrate state, and the service would use the key internally only after checking capability authority.

The second serious finding is the external backend boundary. Disk and file snapshot paths build a v2 header, derive keys, encrypt with AES-CTR, compute HMAC-SHA256, and verify the MAC before decrypting. The external backend path does not wrap the backend in that same sealing envelope. It passes a raw Snapshot to the backend and trusts a raw Snapshot coming back. That means the security of external persistence depends on the backend implementation instead of the persistence service enforcing one invariant. The mature model needs the persistence service to own the seal format no matter where the bytes are stored.

The third serious finding is silent durability failure. The generic snapshot write updates the in-memory snapshot and ignores the durable write result. The temporal snapshot persistence caller also ignores the result of write_temporal_snapshot. That makes the API look successful even when the durable state was not written. For a security boundary, that matters because recovery after reboot may not match the state the kernel thought it had saved. Production persistence needs to return durable write failure, audit it, and decide whether to halt, retry, fallback, or mark the snapshot as not durable.

The fourth serious finding is that VFS state appears to have a separate flat persistence route. The persistence service has write_vfs_snapshot and read_vfs_snapshot, but the reviewed call graph did not show VFS using those sealed APIs. Instead, VFS writes and recovers its own flat snapshot through filesystem storage. Since VFS state can contain files, metadata, paths, and possibly authority-relevant state, that route needs the same cryptographic protection as temporal snapshots. Either VFS needs to use the sealed persistence service, or the flat VFS snapshot format needs its own authenticated and encrypted seal with the same policy.

The fifth serious finding is backend fallback after integrity problems. Fallback is useful for reliability, but it can become dangerous if an attacker can corrupt the primary backend and force recovery from an older or weaker fallback. The code needs to distinguish backend unavailable from integrity failed. If a disk snapshot is present but fails MAC verification, recovery should treat that as a security event, not simply keep searching for something else to trust. Fallback after integrity failure needs a signed recovery policy, freshness checks, and audit records.

These findings do not replace the earlier persistence maturity list. They sharpen it. The previous list already covers default keys, HKDF, nonce reuse, truncated MACs, v1 CRC snapshots, rollback protection, store-local capabilities, backend policy, zeroization, and test coverage. This pass adds the deeper system-level point: persistence trust depends on key encapsulation, backend enforcement, durable write truth, sealed VFS recovery, strict parser behavior, safe fallback policy, and non-ambient authority. Without those, the encryption and MAC can be correct while the recovered kernel state still comes from the wrong path.



### How the OTA path uses these primitives
The OTA path uses crypto to protect update decisions. It does this by
hashing update data with SHA-256, comparing it to expected vs actual hashes with
ct_eq, then builds a canonical OTA manifest message, and verifies the detached
Ed25519 signature for that message. The key point of all of that is so that the kernel can verify both content identity and publisher authority. The bytes must match the expected
hash, and the manifest must be signed by the configured trusted key.

The OTA path uses the crypto folder to decide whether an update image is the image Oreulius expected and whether the update metadata came from a trusted signing key. It is not trying to encrypt the update. The main job here is integrity and publisher authority: the bytes must match the expected hash, and the manifest should be signed by the trusted OTA key.

The flow is built around A/B update slots. Oreulius has slot A, slot B, and an active pointer that says which slot is currently active. When an update is applied, the new image is written into the inactive slot. The kernel computes SHA-256 over that image and writes the expected hash into the OTA manifest. Later, when the update is committed, Oreulius reads the pending slot back, hashes it again, and compares the actual hash against the manifest hash.

| OTA piece | What it does |
| --- | --- |
| Slot A / Slot B | Hold the two possible update images. One is active, the other can be staged. |
| Active pointer | Records which slot should boot or be treated as active. |
| Manifest | Stores the expected SHA-256 hash of the pending image. |
| Version | Stores the update version string used in the signed manifest message. |
| Manifest signature | Ed25519 signature proving the manifest hash and version were approved by the trusted key. |
| Persistence record | Records OTA lifecycle events such as apply, commit, rollback, and verify. |

The apply phase is the staging phase. Oreulius reads the update image from a VFS path, computes SHA-256 over the bytes, writes the image into the inactive slot, writes the hash into the manifest, stores the version, and records an OTA apply event in persistence. At this point, the update is staged, but it is not trusted as active just because it was copied.

The commit phase is the trust decision. Oreulius reads the manifest hash, builds the canonical signed OTA manifest message from the hash and version, and verifies the detached Ed25519 signature if the trusted public key and signature are present. Then it reads the pending slot image, computes SHA-256 again, and compares the actual image hash to the expected manifest hash using constant-time comparison. If the hash does not match, the commit stops and records a verify event. If it matches, Oreulius switches the active pointer to the pending slot.

| Crypto primitive | How OTA uses it |
| --- | --- |
| SHA-256 | Creates the image identity hash. |
| Constant-time equality | Compares expected and actual image hashes without early-exit comparison. |
| Ed25519 | Verifies the detached manifest signature. |
| Canonical message formatting | Makes the signed hash and version serialize the same way every time. |
| Persistence log | Records OTA lifecycle events for audit and recovery. |

The important design detail is that SHA-256 answers “are these the same bytes?” while Ed25519 answers “did the trusted signer approve this manifest?” Those are different questions. A hash alone can catch accidental or malicious image changes, but it does not prove who approved the image. The signature binds publisher authority to the manifest hash and version.

Right now, this is a good prototype OTA integrity path, but it is not a full production update system yet. The comments in the code already say actual device reboot, flash-sector writing, EEPROM state, and hardware reset are out of scope for this profile. The mature version should make unsigned manifests a policy decision, protect rollback state, bind OTA authority into the capability model, and make update activation atomic enough that a crash cannot leave the system between trusted states.

#### Deeper dive into the CT_EQ
ct_eq means constant-time equality.

It is a comparison helper used when comparing security-sensitive values, such as hashes, MACs, tags, or signature-related bytes. Instead of stopping as soon as it finds the first different byte, it checks every byte and only decides equal or not equal at the end.

That matters because normal comparisons can leak timing information. For example, if a comparison stops at byte 2, it may run slightly faster than one that stops at byte 30. An attacker observing timing might learn how much of a secret value matched.

ct_eq is used when comparing:

| Compared value | Why constant-time helps |
| --- | --- |
| Expected image hash | The SHA-256 hash stored in the manifest. |
| Actual image hash | The SHA-256 hash computed from the pending slot image. |

So in OTA, ct_eq helps make the integrity decision cleaner: compute the expected hash, compute the actual hash, compare them without early-exit behavior, and only activate the update if they match.

#### OTA A/B Slot Model
The OTA A/B slot model is the update layout that lets Oreulius stage a new image without immediately replacing the currently active one. Instead of having one update image location, the system has two slots: slot A and slot B. One slot is active, and the other slot is inactive. The inactive slot is where a new update can be copied, hashed, verified, and prepared before the system switches over to it.

The current OTA code uses these paths:

| OTA path | What it stores |
| --- | --- |
| /ota/slot_a | Update image for slot A. |
| /ota/slot_b | Update image for slot B. |
| /ota/active | The active slot marker, either a or b. |
| /ota/manifest | The expected SHA-256 hash of the pending image. |
| /ota/manifest.sig | Detached Ed25519 signature for the manifest message. |
| /ota/manifest.pub | Trusted Ed25519 public key for OTA verification. |
| /ota/version | Version string for the staged update. |
| /ota/rollback_needed | Sentinel used when crash rollback should be considered. |

The main idea is separation. If slot A is active, then slot B is the update target. If slot B is active, then slot A is the update target. That means an update can be staged into the inactive slot while the current active slot remains available. If the update fails verification, the active slot does not need to change.

The flow looks like this:

| Step | What happens |
| --- | --- |
| Check active slot | Oreulius reads the active marker to see whether A or B is active. |
| Choose inactive slot | The other slot becomes the staging target. |
| Apply update | The update image is copied into the inactive slot. |
| Hash staged image | SHA-256 is computed over the staged image bytes. |
| Store manifest | The expected hash is written to the manifest. |
| Commit update | Oreulius re-hashes the pending slot and compares it to the manifest hash. |
| Switch active slot | If verification passes, the active marker changes to the pending slot. |
| Rollback if needed | Oreulius can switch back to the other slot if rollback is requested. |

The crypto part of this model is that the inactive slot is not trusted just because bytes were written there. It becomes eligible for activation only after its SHA-256 hash matches the manifest, and the manifest should be approved by the Ed25519 signature policy. The slot model gives the kernel a safe place to stage bytes. The crypto decides whether those bytes are allowed to become active.

The A/B slot model is at a good starting point, but the current kernel profile does not yet perform a real hardware reboot, flash-sector swap, bootloader handoff, or device-level rollback index update. The code manages the slot files and active pointer inside the kernel’s profile, which is useful for development and testing. A production version needs crash-safe slot switching, rollback-resistant active state, signed version policy, and capability-gated authority for who can apply, commit, or rollback OTA state.

The next important goal for the AB slot, is to make the A/B slot model capability based, Oreulius is going to need to stop treating the slot paths as the main authority boundary. The paths can still exist as storage locations, but permission should come from an OTA slot capability, not from being able to reach /ota/slot_a or /ota/slot_b. That capability should identify the slot, the allowed operation, the current slot state, the owning process, and the policy context.

A staged update, after the dev passes, will begin with a capability that allows writing only to the inactive slot. For example, if slot A is active, the updater might receive authority to write slot B, but not activate it. After the image is written, a separate verification authority should allow the kernel to hash the slot, check the signed manifest, and mark the slot as verified. Only after that should a separate activation capability allow switching the active pointer.

Rollback should also be capability-gated. A process should not be able to flip back to the other slot blindly. It should need rollback authority, and the kernel should verify that the fallback slot is still valid before switching. That rollback capability should be scoped to a known fallback slot, version, boot attempt, and rollback policy, not just “switch to the other slot.”

The mature authority chain will look like this:

| Phase | Required capability |
| --- | --- |
| Stage update image | OTA_SLOT_WRITE for the inactive target slot |
| Hash staged image | OTA_SLOT_VERIFY for that slot |
| Verify signed manifest | OTA_SLOT_VERIFY plus trusted manifest policy |
| Mark slot verified | OTA_SLOT_VERIFY for that slot state transition |
| Activate slot | OTA_SLOT_ACTIVATE for the verified target slot |
| Roll back slot | OTA_SLOT_ROLLBACK for a validated fallback slot |
| Inspect status | OTA_SLOT_INTROSPECT |
| Read or emit audit events | OTA_SLOT_AUDIT |

The key design rule is that no one capability should imply the whole update lifecycle. Write authority should not imply commit authority. Verify authority should not imply rollback authority. Audit authority should not expose image contents or allow state changes. Activation should only work on a slot that is already verified, signed, and policy-approved.

So the capability-based model after dev cycles will become more than just “protect slot A and slot B.” It is about protecting each state transition in the OTA lifecycle. 

The kernel should ask: 

_**who is allowed to stage this image**_

_**who is allowed to verify it**_

_**who is allowed to activate it**_
 
_**who is allowed to roll it back**_

_**what exact slot and version does that authority apply to?**_

These questions are what will bring the A/B slot model into Oreulius’s least-authority system.

#### OTA Apply Flow
OTA apply is the staging step. It copies an update image into the inactive slot and records the hash that later commit verification will use. This step does not make the update active. It only creates a pending candidate.

The current apply command takes a source VFS path and an optional version string. If the version is not provided, the code uses unknown. Then it reads the active slot marker, chooses the other slot as the target, reads the source image
from VFS, hashes the image with SHA-256, writes the image into the inactive slot, writes the expected hash into the OTA manifest, stores the version, and records an OTA apply event in persistence.

| Apply step | What happens |
| --- | --- |
| Read source path | Oreulius reads the update image from the provided VFS path. |
| Choose inactive slot | The target is the opposite of the current active slot. |
| Hash image | SHA-256 creates the staged image identity. |
| Write inactive slot | The image bytes are copied into slot A or slot B. |
| Write manifest | The expected image hash is stored for later commit verification. |
| Store version | The version string is stored beside the manifest. |
| Record event | The persistence log records an OTA apply lifecycle event. |

The important security point is that apply is not trust. A staged image is just a candidate. It should not become active until the commit path re-hashes the slot, checks the manifest, verifies the signature policy, and switches the active pointer only after those checks pass.

In the capability model, apply should require staging authority for a specific inactive slot. A process with OTA_SLOT_WRITE for slot B should be able to stage bytes into slot B while slot A is active, but that should not grant authority to activate slot B. Staging, verifying, and activating are separate powers.

The current design has the right basic shape, but it still needs maturity work, it needs to apply flow to behave like a transaction, not just a sequence of loose file writes. That means Oreulius should clearly know whether an update is staged, failed, or completed. If the image gets written into the inactive slot but the manifest write fails afterward, the system should not be left with confusing half-applied state. The slot, manifest, version, and apply status should move together so the kernel can tell whether the staged update is valid or should be discarded.

Before choosing where to stage the image, Oreulius should also validate the active slot marker. Right now, if the active marker is missing or malformed, the code can fall back to slot A behavior. In a production update path, that should be treated as a recovery problem, because picking the wrong inactive slot could overwrite the wrong update target. The version string also needs to be real in production. Defaulting to unknown is fine for testing, but mature rollback and downgrade policy needs a clear version or generation to compare.

For large images, the apply flow should stream data instead of loading the whole update image into memory at once. That is safer for memory pressure and closer to how real update systems handle firmware images. After writing the image into the inactive slot, Oreulius should hash the written slot again, not just the source buffer, to prove that storage actually contains the bytes it thinks it staged. 

Finally, staging should be capability-gated. A caller should need OTA_SLOT_WRITE for that exact target slot before it can write update bytes there. That keeps apply authority separate from verify, activate, or rollback authority. 


#### OTA Manifest Hashing
OTA manifest hashing is how Oreulius gives a staged update image a stable identity. The update image itself can be large, but the manifest stores a 32-byte SHA-256 hash of that image. Later, the commit path can read the pending slot, hash the bytes again, and compare the new hash to the manifest hash. If the values match, the slot contains the image the manifest expected. If they do not match, the update is rejected.

The apply path creates the manifest hash. It reads the source image from VFS, computes SHA-256 over the image bytes, writes the image into the inactive slot, and stores the hash as 64 hex characters in the OTA manifest file. The version string is stored beside the manifest and is later used in the signed manifest message.

| Manifest piece | What it does |
| --- | --- |
| Image bytes | The staged update image that will be copied into the inactive slot. |
| SHA-256 hash | The stable identity of those image bytes. |
| Manifest file | Stores the expected image hash as 64 hex characters. |
| Version file | Stores the staged update version used by signature verification. |
| Pending slot | Holds the staged image that should match the manifest hash. |

The commit path uses the manifest hash as the expected value. It reads the manifest, reads the pending slot image, computes SHA-256 over the pending slot bytes, and compares the actual hash to the expected manifest hash using constant-time comparison. If the hash comparison fails, the slot is not activated. This is the core integrity check: the update does not become active unless the staged slot still matches the expected digest.

The boot verification path also uses the manifest hash. It reads the active slot image, hashes it, and compares that hash to the stored manifest hash. In the current code, this is a software sanity check rather than a full bootloader-grade verified boot system. If the active slot does not match the manifest, Oreulius records a verification event, but the current profile does not yet halt the boot like a production verified-boot chain would.

The important maturity point is that a manifest hash should not float by itself. A hash only says “these bytes match,” but it does not say which slot the bytes belong to, which version they represent, whether they were signed for this device, or whether they are allowed by rollback policy. For production, the manifest hash should be bound to the target slot, version, signature, image boundary, update state, and policy mode.


For production maturity, the manifest hash is going to need to be a-part of one authenticated OTA metadata record instead of sitting beside separate files for version, signature, target slot, and slot state. Those pieces all describe the same update candidate, so they should move together and be verified together. If the manifest is malformed, too short, too long, or has trailing data, Oreulius should reject it instead of trying to interpret it loosely. The same applies to the version: if the version cannot be written or read correctly, the manifest should be treated as incomplete, not silently replaced with unknown.

After apply writes the image into the inactive slot, Oreulius should hash the written slot again to prove storage actually contains the bytes the manifest describes. Commit verification and boot verification should also hash the exact same byte range, so the kernel does not trust one interpretation of the image during commit and a different interpretation during boot. Finally, manifest hash verification should be capability-gated: a caller should need OTA_SLOT_VERIFY authority for the target slot before it can ask the kernel to treat that slot as a verified update candidate.

#### OTA Manifest Signature Verification
OTA manifest signature verification is how Oreulius checks publisher authority for an update. SHA-256 can prove that the image bytes match a manifest hash, but it cannot prove who approved that hash. Ed25519 signature verification fills that gap. It lets the kernel ask whether the trusted OTA signing key approved the manifest message for this update.

In the current code, Oreulius builds a canonical OTA manifest message from the image hash and version string. That message is deterministic, meaning the same hash and version always produce the same byte string. The detached Ed25519 signature is stored separately from the manifest, and the trusted public key is read from the OTA public key path. If the signature verifies against the canonical message, Oreulius treats the manifest as signed.

| Signature piece | What it does |
| --- | --- |
| Image hash | Identifies the update image bytes. |
| Version | Names the update version being approved. |
| Canonical manifest message | Stable byte string built from the hash and version. |
| Trusted OTA public key | The key allowed to approve OTA manifests. |
| Detached signature | Ed25519 signature over the canonical manifest message. |
| Verification result | Tells the OTA path whether the manifest is verified, unsigned, or invalid. |

The current verification helper has three important outcomes. If both the public key and signature are present, it verifies the Ed25519 signature. If one is present without the other, it returns an error because that is an inconsistent trust state. If both are missing, it reports the manifest as unsigned. That unsigned state is useful for development, but it should not be accepted in a production update policy.

| Result | Meaning |
| --- | --- |
| Verified | The trusted public key verified the detached signature for the manifest message. |
| Unsigned | No trusted public key and no signature were present. |
| Error | The key/signature state was inconsistent, malformed, unreadable, or the signature failed. |

The current design has the right shape because it separates image identity from publisher authority. The image hash says what bytes are being installed. The signature says who approved those bytes. A mature OTA flow needs both: the pending slot must match the expected hash, and the signed manifest must prove that the trusted update authority approved that hash and version.

The gap that currently exists is that the signed message is still too small for a production OTA policy. Right now it binds the hash and version, but it does not bind target slot, image type, target device, rollback generation, policy mode, or key identity. That means the signature approves a hash/version pair, but not the full meaning of the update inside the A/B slot system.

To address this gap, the kernel is going to be developed to reject unsigned OTA manifests instead of only warning about them. An unsigned update can be useful during development, but production needs a clear rule: the manifest must be approved by the trusted OTA signing key before the update can become active. The public key and signature files should also be parsed strictly, with exact expected lengths and no trailing data, so malformed or ambiguous key material cannot slip through the verification path.

The signature path should is going to need to produce clearer security outcomes. Missing files, malformed hex, read failures, and invalid signatures will no longer all collapse into the same kind of result. Instead, they will become distinct audit events so the system can tell the difference between “no production key was configured,” “someone supplied broken key material,” and “a real signature check failed.” The signed manifest message also will eventually bind more update context, such as target slot, image type, target device, rollback generation, policy mode, and key identity. That way, the signature approves the full meaning of the update, not just a hash and version string.

The trusted OTA public key should be protected from ordinary VFS modification, because if an attacker can replace the trusted key, they can define their own update authority. Afterwards, the test coverage will include valid signatures, missing keys, missing signatures, malformed keys, malformed signatures, wrong keys, wrong domains, and production rejection of unsigned manifests. That proves the signature path is enforcing publisher authority instead of only checking the happy path.

#### OTA Canonical Signed Message
The OTA canonical signed message is the exact byte string that the trusted OTA signing key signs. This matters because signatures do not sign ideas, they sign bytes. If two machines build the message differently, the same update can fail verification even when the hash and version are correct. Oreulius avoids that by building the signed message in one fixed format.

The current message format is text-based and deterministic. It starts with a domain line, then writes the image hash as lowercase hex, then writes the version string, and ends each line with a newline.

| Message field | What it means |
| --- | --- |
| oreulius-ota-manifest:v1 | Domain and format version for OTA manifest signatures. |
| hash | SHA-256 identity of the update image. |
| version | Version string attached to the staged update. |
| Newline separators | Keep the byte format stable and easy to parse. |

The current signed message looks like this:

```text
oreulius-ota-manifest:v1
hash=<64 lowercase hex characters>
version=<version string>
```

This format has a few strengths. The domain line keeps OTA signatures separate from other signed objects, such as fleet attestations. The hash is encoded as
lowercase hex, which makes the message readable and stable across platforms. The format also has a test that checks the exact output string for a known hash and version, so accidental formatting changes are easier to catch.

The signed message is used during manifest verification. Oreulius reads the expected image hash from the manifest, reads the version string, builds this canonical message, and verifies the detached Ed25519 signature over those exact bytes. If the signature verifies, the trusted update key approved that hash and version pair.

The current format is a good starting point, but it is still too small for the mature OTA policy. It binds the image hash and version, but not the full update decision. The mature format needs to bind the target slot, image type, target device, rollback generation, policy mode, trusted key identity, and exact image byte-range rules. That way, the signature approves the full meaning of the update, not only a hash and version.

The version field also needs stricter handling. Right now, the version string is copied into the signed message directly, and the commit path can fall back to unknown if the version file is missing. For production, the version needs a strict format, and missing or malformed versions need to fail the manifest verification path. That makes downgrade and rollback policy easier to enforce.

The mature OTA canonical message is going to act like a compact update contract. It will say which image bytes are approved, which slot they are meant for, which device or product they target, which rollback generation they belong to, which policy mode accepted them, and which signing key approved them. That makes the signed message useful not only for cryptographic verification, but also for capability and policy enforcement.

#### OTA Commit Flow
OTA commit is the point where a staged update becomes the selected update slot. Apply only copies bytes into the inactive slot. Commit is where Oreulius checks whether those bytes match the manifest, whether the manifest signature policy passes, and whether the active pointer can move to the new slot.

The current commit path starts by choosing the inactive slot as the target. It reads the expected image hash from the manifest, reads the version string, and builds the canonical OTA manifest message. Then it verifies the detached Ed25519 signature for that message. If the signature is invalid or the key and signature state is inconsistent, commit stops. If both key and signature are missing, the current code treats the manifest as unsigned and continues with a warning.

After signature handling, Oreulius reads the pending slot image and hashes it with SHA-256. It compares that actual hash with the manifest hash using ct_eq. If the hashes do not match, the slot is rejected and a verify event is recorded in persistence. If the hashes match, Oreulius writes the active slot marker to the target slot, writes a rollback sentinel, records an OTA commit event, and prints that the update will take effect on reboot.

| Commit step | What happens |
| --- | --- |
| Choose target slot | The target is the inactive slot, based on the current active marker. |
| Read manifest | Oreulius loads the expected SHA-256 hash. |
| Read version | The version is loaded and used in the signed manifest message. |
| Verify signature | Ed25519 checks whether the trusted OTA key approved the manifest message. |
| Read pending image | The inactive slot image is loaded for verification. |
| Hash pending image | SHA-256 creates the actual hash of the staged slot. |
| Compare hashes | ct_eq compares the actual hash with the expected manifest hash. |
| Switch active slot | The active marker is updated if verification passes. |
| Write rollback sentinel | A sentinel is written so boot-time crash rollback can revert if needed. |
| Record event | The persistence log records the commit lifecycle event. |

The important security idea is that commit turns a staged candidate into a selected boot candidate. That means commit needs to be stricter than apply. It is not enough that bytes exist in the inactive slot. Those bytes need to match the manifest, the manifest needs to satisfy signature policy, and the target slot needs to be the slot the metadata intended.

In the capability model, commit needs activation authority, not just staging authority. A process with OTA_SLOT_WRITE can stage bytes, but it does not get to switch the active pointer. OTA_SLOT_ACTIVATE needs to be separate and only valid for a verified, signed, policy-approved target slot.

The commit flow needs to become stricter because this is the point where a staged update becomes the selected boot candidate. In production mode, unsigned manifests need to fail instead of only producing a warning, and the version needs to be real instead of falling back to unknown. The manifest hash, version, target slot, signature, and slot state need to move together as one authenticated OTA metadata record, so commit verifies one complete update decision instead of several loose files.

The active slot switch also needs to become transactional and crash-safe. Oreulius needs to record commit intent before changing the active pointer, then record commit completion after the active pointer and rollback sentinel are safely written. The rollback sentinel write also needs to be checked, because commit should not be considered complete if the system cannot mark the new slot for crash rollback. Before switching, the kernel also needs to re-check that the target slot is still the intended inactive slot and verify the target slot hash using the same byte range that boot verification will use.

Switching the active marker needs OTA_SLOT_ACTIVATE authority for the verified target slot. Staging or verifying an update should not be enough to activate it. Activation is its own authority because it changes which image the kernel will trust next.

#### OTA Constant-Time Hash Comparison
OTA constant-time hash comparison is the final equality check between the hash Oreulius expected and the hash it actually computed from a slot image. In the commit path, Oreulius hashes the pending slot and compares that value to the manifest hash. In the boot verification path, it hashes the active slot and compares that value to the same expected manifest hash.

The helper used for this is ct_eq. It first checks that the two byte slices have the same length. If the lengths match, it walks every byte, XORs each pair, accumulates the differences, and only decides equal or not equal at the end. That avoids the usual early-exit behavior where a comparison stops as soon as the first different byte is found.

| OTA comparison point | What is compared | What happens on mismatch |
| --- | --- | --- |
| Commit verification | Pending slot SHA-256 hash against manifest SHA-256 hash | Commit stops and the slot is not activated. |
| Boot verification | Active slot SHA-256 hash against manifest SHA-256 hash | Oreulius records a verification event and reports an integrity mismatch. |

The security reason is simple: hash comparison is part of the trust decision. If the actual slot hash does not match the expected manifest hash, the image is not the image the manifest described. Constant-time comparison keeps the equality check from revealing which byte first differed. For SHA-256 hashes this is a narrow protection, but it is still the correct habit because the same helper is also used around MACs, tags, and other security-sensitive values.

For future dev cycles, the OTA hash comparison path needs to stay strict about where trust begins. Every security-sensitive OTA comparison needs to keep using ct_eq instead of normal equality, and the expected and actual hashes need to remain fixed-length values before comparison. But the comparison helper only protects the equality check itself. Oreulius also needs to reject malformed manifest hashes before comparison, so bad manifest data does not reach the trust decision at all.

Hash mismatch behavior also needs to become more production-aware. During commit, a mismatch already stops activation, and that needs to remain a fatal OTA verification failure. During boot verification, a mismatch currently behaves more like a warning and audit event. In production verified-boot mode, that needs to become fatal too, because an active slot that no longer matches the trusted manifest should not continue as trusted code.

The audit and logging behavior also needs tightening. Hash mismatches should be recorded as security-relevant OTA verification failures, but detailed expected and actual hash output should be controlled by development or debug policy. That keeps debugging useful without always exposing trust metadata in production logs.

The test coverage needs to prove the full comparison boundary. Tests need to confirm ct_eq is used in both commit verification and boot verification, and that it behaves correctly for equal hashes, different hashes, and length mismatch cases. Tests also need to prove malformed manifest data fails before comparison, and that production boot behavior rejects or halts on active-slot hash mismatch instead of only logging it.

#### OTA Rollback Flow

Rollback is the safety path for the A/B OTA model. If the newly committed slot turns out to be bad, Oreulius needs a way to move back to the other slot instead of staying pinned to code that cannot boot cleanly. In the current implementation, rollback is mostly controlled by the active slot pointer. Slot A and slot B both exist as stored images, and rollback changes which one the kernel treats as active.

There are two rollback paths in the code right now:

| Rollback path | What triggers it | What it does |
| --- | --- | --- |
| Manual rollback | The ota-rollback command is called. | Reads the current active slot, chooses the other slot, writes that slot into the active pointer, and records a rollback event. |
| Crash rollback | init_slots sees both a rollback sentinel and a recorded crash count during boot. | Treats the current active slot as bad, switches to the other slot, removes the rollback sentinel, and records a rollback event. |

The commit path is what sets up the automatic rollback path. After the pending slot passes the manifest hash check and the active pointer is moved to the new slot, Oreulius writes a rollback sentinel at /ota/rollback_needed. That sentinel means the new slot is still in a probation period. If the next boot crashes and the crash log reports that crash, init_slots sees the sentinel and moves the active pointer back to the other slot. If the system boots cleanly while the sentinel is present, init_slots removes the sentinel, which means the new slot survived its first boot window.

The manual rollback command is simpler. It reads the active slot, picks the opposite slot, writes that as the new active slot, and records an OTA rollback event with a placeholder hash. This is useful as a recovery command, but it is not yet a full trust decision. It does not verify that the fallback slot still matches a signed manifest, it does not bind the rollback to a specific version or rollback generation, and it does not prove that the fallback slot is actually safe before switching to it.

The security issue is that rollback is also authority. Moving the active pointer decides which stored image the kernel will trust on the next boot. In a mature capability model, rollback is not just a convenience command. It becomes a controlled operation that requires OTA_SLOT_ROLLBACK authority for the slot being recovered to, and it needs to be separate from OTA_SLOT_WRITE and OTA_SLOT_ACTIVATE. A process that can write an inactive slot does not automatically get to roll the machine back, and a process that can request rollback does not automatically get raw access to slot contents.

The rollback flow needs to mature from a simple “switch to the other slot” mechanism into a verified recovery decision. Before Oreulius switches active slots, it needs to verify that the fallback slot is still valid by checking that slot’s own image hash, signature, version, and slot identity. That also means OTA metadata needs to become per-slot instead of relying on one global manifest, because slot A and slot B each need their own trusted record.

The rollback sentinel also needs to become a real structured record. Instead of storing only a simple marker, it needs to bind the committed slot, fallback slot, version, boot attempt, rollback generation, and expected image hash. Commit needs to verify that this sentinel was written successfully before treating the update as complete. After a clean boot or after rollback, sentinel cleanup also needs to be checked so stale rollback state does not survive silently.

The active slot marker needs stronger handling too. A malformed active marker cannot silently default to slot A, because that turns corrupted state into a trust decision. Oreulius needs to treat malformed active state as a recovery error, store active and rollback state in authenticated or rollback-resistant metadata, and make active-pointer writes atomic so a crash during rollback cannot leave the system between slot A and slot B.

The boot-confirmation model also needs to become explicit. A newly committed slot needs a real success checkpoint before it is considered accepted. Without that, “no crash seen yet” is too weak. Oreulius also needs boot attempt counters, failed-slot tracking, and rollback generations so it does not bounce between slots forever during repeated failures.

Rollback also needs to become capability-gated. Manual rollback and crash-triggered rollback decisions need OTA_SLOT_ROLLBACK authority, separate from OTA_SLOT_WRITE and OTA_SLOT_ACTIVATE. A caller that can stage bytes into an inactive slot should not automatically be able to roll the machine backward, and a caller that can activate a verified slot should not automatically control recovery policy.

Finally, the audit and test story needs to be stronger. Rollback events need to record the real slot, version, image hash, rollback reason, and decision source instead of a dummy zero hash. Verified-boot failures need to become fatal in production mode instead of only logging a mismatch. The test suite needs coverage for manual rollback, crash rollback, missing sentinel, malformed sentinel, stale sentinel, invalid fallback slot, malformed active marker, failed sentinel write, failed sentinel cleanup, rollback ping-pong prevention, per-slot metadata validation, atomic active-pointer writes, and architecture-specific crash rollback behavior such as the current aarch64 gap.

#### OTA Persistence Records

OTA persistence records are the way the update path leaves behind a durable trail of what happened. When Oreulius applies an update, verifies a slot, commits a slot, or rolls back to a fallback slot, the OTA service calls record_ota_event. That helper builds a RecordType::OtaUpdate log record and appends it through the temporal persistence service.

The current record is intentionally small. It stores the OTA phase, the slot, and one 32-byte hash. The phase says what kind of lifecycle event happened. The slot says whether the event belongs to slot A or slot B. The hash is usually the image hash involved in the decision, but rollback currently uses a placeholder zero hash in some paths, which means the record does not fully explain what image was recovered to.

| Field | Current meaning |
| --- | --- |
| Phase | Apply, Commit, Rollback, or Verify. |
| Slot | Slot A or slot B, encoded as a small numeric value. |
| Hash | The SHA-256 image hash involved in the event, or a placeholder value for some rollback records. |

These records are useful because OTA is not only about copying bytes. It is a trust transition. The kernel needs to know when an image was staged, when it was checked, when it became active, and when the system moved away from it. That history matters for debugging, rollback policy, fleet attestation, and later security review. A signed image can still be the wrong image for a device, an old image, or a bad recovery target, so the record trail needs to explain the decision that was made, not only the final slot state.

The current implementation is a good prototype, but it is not yet a full production audit record. The OTA code creates a StoreCapability with broad rights inside record_ota_event, appends the record, and ignores append failure. That means the caller does not bring explicit OTA audit authority, and the update operation can continue even if the audit record was not stored. For a mature capability model, OTA logging needs to become part of the authority path. Staging, committing, verifying, and rolling back need to emit records through a capability that is scoped to OTA audit authority, slot identity, version, and policy mode.

The mature record also needs more context. It needs to include the version, signed manifest identity, target slot, previous active slot, key identity, rollback generation, boot attempt, decision reason, and policy mode where those fields matter. A failed signature, malformed manifest, hash mismatch, unsigned manifest rejection, rollback decision, failed sentinel write, or failed active-pointer update should all create records with distinct meanings. That turns persistence records into a security timeline instead of a short lifecycle counter.

The current design has the right basic shape, but the persistence record needs to carry more of the trust decision. Future dev cycles need to store the version, manifest identity, key identity, policy mode, rollback generation, previous active slot, and target slot in the OTA record when those fields affect the decision. Commit and rollback records especially need both sides of the transition, because the important security question is not only which slot became active, but which slot the kernel moved away from and why.

Rollback records also need to stop using placeholder hashes. When Oreulius rolls back, the record needs to carry the real fallback slot hash and the rollback reason, so later recovery, fleet attestation, or incident review can tell which image was trusted. Successful lifecycle events also need to be separated from failed trust decisions. A normal apply or commit is not the same kind of event as a bad signature, hash mismatch, malformed metadata, stale rollback sentinel, downgrade rejection, failed sentinel write, or failed active-pointer update.

The authority side needs to mature too. OTA audit records need to be written through OTA_AUDIT or slot-scoped OTA_SLOT_AUDIT authority instead of being appended through an internally created broad store capability. In production mode, audit append failure needs to become security-relevant, because an update path that cannot record its own trust decision is missing part of the accountability model. The record format also needs to stay stable enough that recovery code, fleet attestation, and post-incident tooling can read the same event meaning later.

The test work needs to prove that record behavior is not accidental. Apply, verify, commit, rollback, and failure paths all need tests showing that the expected OTA persistence records are emitted, that the right fields are present, and that audit append failure follows production OTA policy.

#### OTA Trusted Key Provisioning

OTA trusted key provisioning is how Oreulius decides which publisher is allowed to authorize an update. The OTA image hash proves what bytes were staged, but the trusted key decides who is allowed to bless those bytes. In the current code, ota-trust-key imports an Ed25519 public key from a VFS path and stores it at /ota/manifest.pub. Later, commit and boot verification read that public key, read the detached signature from /ota/manifest.sig, rebuild the canonical OTA manifest message, and call Ed25519 verification.

| File | Current role |
| --- | --- |
| /ota/manifest.pub | Trusted Ed25519 public key used to verify OTA manifest signatures. |
| /ota/manifest.sig | Detached Ed25519 signature over the canonical OTA manifest message. |
| /ota/manifest | Expected SHA-256 hash for the staged or active image. |
| /ota/version | Version string included in the signed message. |

The import path is useful for bring-up because it lets a developer load a key from the shell and test signed update behavior quickly. The helper reads a small hex file, parses 32 bytes for the public key, normalizes it back into lowercase hex, and writes it into the OTA key path. Signature import follows the same pattern with a 64-byte Ed25519 signature. That gives the current OTA path a simple detached-signature model: key file, signature file, and signed message are separate pieces.

The security problem is that a trusted key is not just data. It is update authority. If ordinary VFS writes can replace /ota/manifest.pub, then an attacker with filesystem write access can install their own OTA public key and make their own update look trusted. In that case Ed25519 still works cryptographically, but it no longer proves publisher authority, because the trust root was replaced first.

The mature design needs to treat OTA public keys as protected authority objects. The production key needs to come from a measured, signed, hardware-backed, or otherwise privileged provisioning path. Key import needs explicit OTA_IMPORT_KEY authority, and key replacement needs a policy that says who can rotate a key, which old key can authorize the new key, what key identity is being installed, and whether the system is in development, recovery, or production mode.

The current parser also needs stricter production behavior. The helper currently parses the required number of hex bytes and ignores extra trailing bytes after that parse boundary. For production key and signature files, exact length needs to matter. A malformed key, trailing data, wrong key size, missing key, missing signature, wrong key identity, or invalid signature should produce distinct audit outcomes so operators can tell the difference between a missing setup step and a real trust failure.

The current design has the right basic shape, but the trust root needs to mature before this becomes a production OTA authority path. The OTA key needs protected storage, explicit import authority, exact key and signature format checks, key identity binding inside the signed manifest policy, key rotation rules, audit records for every key import and verification failure, and tests proving that ordinary filesystem writes cannot replace the trusted publisher key.

#### OTA Version And Rollback Policy

OTA version and rollback policy is how Oreulius decides whether an update is allowed, not just whether it is correctly signed. A valid signature proves that a trusted key approved a manifest message. It does not automatically prove that the image is newer, safe for this device, or allowed under the current recovery policy. That is why version state and rollback state need to be part of the trust decision.

In the current code, ota-apply accepts an optional version string. If the caller does not provide one, the version becomes unknown. The version is written to /ota/version and is included in the canonical OTA manifest message alongside the image hash. That means the Ed25519 signature can bind the hash and version together, which is the right starting shape.

| Policy input | Current behavior |
| --- | --- |
| Version string | Optional during ota-apply, defaults to unknown when missing. |
| Version storage | Written to /ota/version, truncated to the stored byte limit. |
| Signed message | Includes the image hash and version string. |
| Monotonic version check | Not enforced yet. |
| Rollback permission | Not tied to a signed rollback generation or policy mode yet. |
| Crash rollback | Uses /ota/rollback_needed plus crash count to move back to the other slot. |

The weak point is that the current version is mostly descriptive. Oreulius records it and signs it, but it does not yet compare the pending version against the last accepted version or a rollback-resistant generation counter. That means an older but validly signed image can still look cryptographically correct. The signature proves the old image was once approved, but it does not prove that the old image is still allowed today.

Rollback policy needs to make that distinction explicit. There are legitimate reasons to roll back, such as a bad update, failed boot, recovery mode, or operator-approved downgrade. But rollback must be controlled. A rollback path needs to know the active version, the fallback version, the rollback generation, the boot attempt count, and the policy mode that allows the move. Without that, rollback can become a way to replay an older vulnerable image.

The current crash rollback path is useful but coarse. Commit writes a rollback sentinel, and init_slots can switch back to the other slot if a crash is detected on the next boot. That catches boot-loop cases, but it does not yet prove that the fallback image is still allowed, that the fallback version is not revoked, or that the rollback is happening under an explicit recovery policy. It also does not yet bind the sentinel to a specific committed slot, fallback slot, version, or boot attempt.

The mature version policy needs rollback-resistant state. Oreulius needs to store the last accepted version, update generation, or rollback index somewhere ordinary VFS writes cannot rewrite. Commit then checks the pending version against that state before activation. Recovery rollback can still be allowed, but it needs a signed or policy-approved exception that is recorded clearly, so an intentional rollback is different from an attacker replaying old signed metadata.

The version and rollback policy needs to become a real production gate. Version strings need a canonical format, missing versions need to fail in production, accepted versions need monotonic tracking, rollback needs explicit policy authority, and every downgrade or recovery rollback needs a durable audit record explaining why it was allowed.

#### OTA Capability Authority Model

The OTA capability authority model is where the update path becomes part of Oreulius's broader security design instead of staying as a set of powerful shell commands. Applying an update, verifying it, committing it, rolling back from it, importing a trusted key, writing audit records, and inspecting OTA state are different kinds of authority. They need to be represented as separate rights so one operation does not accidentally grant another.

In the mature model, OTA_SLOT_WRITE lets a caller stage bytes into an allowed inactive slot, but it does not let that caller activate the slot. OTA_SLOT_VERIFY lets a caller ask the kernel to check hash, signature, version, and policy, but it does not imply commit or rollback authority. OTA_SLOT_ACTIVATE only works after the slot is verified, signed, version-allowed, and rollback-safe. OTA_SLOT_ROLLBACK only works after the fallback slot is verified and the rollback policy allows the move. OTA_IMPORT_KEY controls trusted key provisioning and rotation. OTA_AUDIT controls writing OTA persistence records. OTA_INTROSPECT allows reading OTA state without mutating it.

These rights also need scope. A capability should not simply mean "can do OTA." It needs to be tied to the owner process, slot identity, slot state, version, image hash, key identity, policy mode, and sometimes boot attempt or rollback generation. That is how Oreulius prevents a process with authority over one staged slot from using the same authority to mutate a different slot, import a new signing key, or roll the system back to an old image.

Delegation is the part that needs special care. It is not enough to define OTA rights once. Oreulius also needs to control who can hand those rights to another process, how those rights can be narrowed, and when they can be revoked. A parent service might delegate OTA_INTROSPECT to a status tool, but not OTA_SLOT_ACTIVATE. A recovery service might receive OTA_SLOT_ROLLBACK for one slot and one version, but not a general rollback power. Delegation needs attenuation, audit, and revocation so authority can move through the system without becoming broader than intended.

The mature authority path also needs denial and use records. Successful OTA capability use, rejected capability use, delegation, attenuation, and revocation should all become visible security events. That matters because OTA authority changes what code the machine will boot. The audit trail needs to show not only that an update happened, but which capability allowed it, who held that capability, what scope it had, and whether any denied operation tried to cross the boundary.

The test work needs to prove the rights are actually separate. Tests need to show that write authority cannot activate, verify authority cannot rollback, audit authority cannot import keys, introspection cannot mutate state, and rollback authority cannot choose an unverified fallback. Tests also need to cover delegated and attenuated capabilities, including revocation after delegation and attempts to use a capability outside its slot, version, key, or policy scope.

#### OTA Failure Behavior

OTA failure behavior is about what Oreulius does when an update path cannot prove trust. Some failures mean the update should stop immediately. Some failures mean the system should keep running but record a security event. Some failures are still treated too softly today, mostly because the current OTA path is a prototype and not a full production verified-boot system yet.

The current apply path mostly fails closed for basic storage problems. If the caller does not provide an image path, if the source file cannot be read, if the source is empty, if writing the inactive slot fails, or if writing the manifest hash fails, apply stops. That is the right direction because a partially staged update should not become a commit candidate. The weaker parts are that the version can default to unknown, version write failure is ignored inside write_manifest, and the written inactive slot is not re-read after apply to prove storage matches the bytes that were hashed.

The commit path is stricter than apply in some places. It stops when the manifest is missing, when signature verification returns an error, when the pending slot is empty, when the slot cannot be read, when the image hash does not match, or when the active pointer cannot be written. That means obvious trust failures stop activation. But unsigned manifests still continue with only a warning, the version can still fall back to unknown, rollback sentinel write failure is ignored, and audit append failure is ignored. In production, those are not just minor errors. They affect whether the update decision can be trusted and explained later.

| Failure point | Current behavior | Mature behavior |
| --- | --- | --- |
| Missing source image | Apply stops. | Keep fail-closed behavior and audit the rejected apply. |
| Empty source image | Apply stops. | Keep fail-closed behavior and audit the rejected apply. |
| Slot write failure | Apply stops. | Mark the staged slot failed or quarantined. |
| Version missing | Defaults to unknown. | Reject in production unless recovery policy allows it. |
| Version write failure | Ignored inside manifest write. | Treat as manifest metadata failure. |
| Missing manifest at commit | Commit stops. | Keep fail-closed behavior and audit the missing manifest. |
| Unsigned manifest | Commit continues with a warning. | Reject in production unless a signed policy allows unsigned mode. |
| Signature verification failure | Commit stops. | Keep fail-closed behavior and audit the exact trust failure. |
| Hash mismatch at commit | Commit stops and records a verify event. | Keep fail-closed behavior, avoid exposing sensitive hash detail in production logs, and mark the slot failed. |
| Active pointer write failure | Commit stops. | Keep fail-closed behavior and preserve transaction recovery state. |
| Rollback sentinel write failure | Currently ignored. | Treat as commit failure or incomplete commit state. |
| Boot hash mismatch | Logged and recorded, but not fatal. | Fatal in production verified-boot mode. |
| Rollback target invalid | Not fully checked before switching. | Reject rollback unless fallback hash, signature, version, and policy pass. |

Boot verification is currently the softest part of the OTA trust path. If there is no manifest, it skips the check. If the active slot is empty, it skips the check. If the active image hash does not match the manifest, it logs the mismatch and records a verify event, but it does not halt or force recovery. That can be acceptable for a software-level sanity check during bring-up, but it is not production verified boot. In production mode, an active image that fails verification cannot remain trusted code.

Rollback failure behavior also needs to become more explicit. Manual rollback currently switches to the other slot and records a rollback event with a dummy hash. Crash rollback can switch to the other slot if the rollback sentinel exists and crash_count is nonzero, but it does not verify the fallback slot first, and some sentinel cleanup failures are ignored. The mature path needs to distinguish failed rollback decision, failed rollback execution, failed fallback verification, failed sentinel cleanup, and rollback policy denial.

Key and signature failures also need sharper reporting. The detached signature helper treats unreadable or malformed public key and signature files as absent in some cases, which can turn a malformed trust artifact into an unsigned state. For production, missing key, malformed key, missing signature, malformed signature, wrong key, wrong key identity, and invalid signature need distinct failure outcomes. That makes the trust decision auditable and avoids hiding a malformed key as if the system was simply unsigned.

The mature failure model needs a clear rule: production OTA failures fail closed unless a signed development or recovery policy says otherwise. Every failure needs a structured outcome, a safe audit record, and a defined state transition. A bad apply should leave the inactive slot failed or quarantined. A bad verify should not activate the slot. A bad commit should leave enough transaction state for recovery. A bad boot verification should trigger recovery or halt under production policy. A bad rollback should not silently switch to an unverified fallback.

The failure taxonomy also needs to become stable. Today many paths return by printing a string and stopping, but production OTA needs machine-readable failure classes such as storage failure, malformed metadata, policy denial, authority denial, signature failure, hash failure, rollback failure, verified-boot failure, and audit failure. Those classes need to drive state transitions, audit records, and recovery behavior. This matters because a read failure, a bad signature, and a rollback-policy denial are not the same security event, even if all three stop an update.

The state machine needs to be protected against races and partial transitions. Apply, commit, rollback, trusted-key import, and boot verification should not be able to interleave in a way that changes the manifest, key, active slot, or staged image between validation and use. The mature path needs locking or transaction ownership around OTA state, plus re-checks before activation, so a slot that was verified is still the same slot that becomes active.

Resource and cleanup failures need their own policy too. Large images can exhaust memory because the current path reads whole images into buffers. Failed apply or failed commit can leave stale slot bytes, stale manifests, stale signatures, or stale versions behind. The mature path needs bounded streaming, cleanup or quarantine of failed slots, retry limits, safe recovery after interrupted cleanup, and clear rules for when old metadata is ignored, preserved for audit, or deleted.

The test work needs to exercise all of those boundaries. Tests need to cover missing images, empty images, partial reads, partial writes, version write failure, missing manifest, malformed manifest, unsigned production policy, missing and malformed keys, invalid signatures, hash mismatch, active pointer write failure, rollback sentinel write failure, boot hash mismatch, invalid fallback slot, stale rollback sentinel, audit append failure, concurrent OTA operations, stale metadata after failure, resource exhaustion, failed cleanup, and recovery after interrupted transactions.

#### OTA Test Coverage

OTA test coverage is the proof that the update path behaves the same way the design says it behaves. Right now, the codebase has useful crypto-level tests: Ed25519 has RFC-style verification tests, AES-GCM has known-answer tests, SHA and HKDF have primitive coverage, and signing_formats.rs has a stable test for the canonical OTA manifest message. That proves pieces of the cryptography work, but it does not yet prove the composed OTA flow is production safe.

| Current test area | What it proves | What it does not prove |
| --- | --- | --- |
| Ed25519 primitive tests | Signature verification accepts valid vectors and rejects tampered messages. | OTA key provisioning, key identity, manifest policy, or production unsigned behavior. |
| SHA and hash helper tests | Hash primitives behave correctly. | The staged slot, manifest hash, commit hash, and boot hash all cover the same bytes. |
| Canonical OTA message test | The current hash-plus-version message format is stable. | The manifest includes every policy field needed for production OTA. |
| Constant-time comparison usage | The helper exists and is used in commit and boot checks. | Every OTA security comparison is tested through the full flow. |
| Persistence primitive tests | The persistence layer has its own behavior. | OTA apply, verify, commit, rollback, and failure records are emitted correctly. |

The missing layer is service-level OTA testing. The update manager needs tests that drive the actual apply, commit, rollback, trust-key import, signature import, and boot verification paths with controlled VFS state. A mature test suite should not only call crypto helpers directly. It should stage a fake image, write a manifest, import a key, import a signature, commit the slot, verify active state, record persistence events, and then run the same path with broken inputs to prove it fails closed.

The happy path needs coverage first. Tests need to prove a valid signed update can be applied to the inactive slot, hashed, written, verified, committed, and later checked during boot. They also need to prove that the slot chosen for apply is really the inactive slot, that commit activates only the verified target, that the rollback sentinel is written during commit, and that the expected OTA persistence records are emitted.

The negative tests are just as important. OTA needs tests for missing image, empty image, unreadable source, partial read, partial write, stale manifest, malformed manifest, wrong hash, missing version, invalid version format, missing key, malformed key, missing signature, malformed signature, wrong key, wrong key identity, invalid signature, unsigned manifest in production mode, and old signed version replay. Each of those cases needs to leave the system in a known state instead of half-staged, half-committed, or silently trusted.

Rollback and recovery need their own test group. Tests need to cover manual rollback, crash-triggered rollback, missing rollback sentinel, malformed sentinel, stale sentinel, failed sentinel write, failed sentinel cleanup, invalid fallback slot, fallback hash mismatch, fallback signature failure, rollback ping-pong prevention, aarch64 crash-signal behavior, and recovery after interrupted commit or rollback. The test should prove rollback does not become "switch to the other slot" unless the fallback slot and policy are valid.

Capability tests are also required once OTA rights exist. The suite needs to prove OTA_SLOT_WRITE cannot activate a slot, OTA_SLOT_VERIFY cannot roll back, OTA_SLOT_ACTIVATE cannot bypass signature or version policy, OTA_SLOT_ROLLBACK cannot choose an unverified fallback, OTA_IMPORT_KEY cannot be exercised by audit-only authority, OTA_INTROSPECT cannot mutate state, and delegated OTA capabilities cannot gain rights or escape their slot, version, key, or policy scope.

The failure behavior tests need to check production policy directly. Boot hash mismatch needs to be fatal in production verified-boot mode. Unsigned manifests need to be fatal in production unless a signed policy allows them. Audit append failure needs to follow production OTA policy. Concurrent apply, commit, rollback, key import, and boot verification attempts need to be rejected or serialized so the manifest, key, active slot, and staged image cannot change between validation and use.

The mature test suite should also include fuzzing and property-style checks around parsing and state transitions. Manifest parsing, key hex parsing, signature hex parsing, version parsing, active slot markers, and rollback sentinel data should be tested with malformed, truncated, oversized, and trailing-data inputs. State-machine tests should prove every path either reaches a valid state or a named failed state, with no ambiguous middle state.

The OTA service also needs to become easier to test. Right now the public OTA entry points are shell-style commands that print messages and return nothing. That is fine for an operator console, but tests need an internal API that returns structured results. Apply, commit, rollback, trust-key import, signature import, and boot verification should report outcomes like applied, committed, rejected unsigned manifest, hash mismatch, rollback denied, malformed metadata, or audit append failed. The shell layer can still turn those outcomes into text, but the test layer needs values it can assert on directly.

The test harness needs controllable dependencies. OTA currently reaches directly into VFS, persistence, crash_log, serial output, and crypto helpers. A mature test setup needs fake VFS state, fake persistence log capture, fake crash counts, fake policy mode, deterministic key and signature fixtures, and a way to force storage and audit failures. That is what makes it possible to test interrupted commits, failed cleanup, stale metadata, failed audit append, and rollback recovery without relying on global kernel state.

Boot-cycle tests need to be deterministic too. The suite should model first boot after commit, clean boot sentinel cleanup, crash boot rollback, malformed rollback sentinel, failed sentinel cleanup, aarch64 crash-count behavior, and production verified-boot halt behavior. That gives the rollback and verified-boot path the same level of attention as apply and commit, instead of treating boot behavior as something that only gets inspected manually.

Output and audit behavior also need test coverage. OTA prints security-relevant messages and writes persistence records, so tests need to prove production mode does not leak sensitive expected and actual hash detail, that debug-only output is gated by policy, and that audit records carry the correct failure class and slot metadata. The goal is not just that the update fails, but that it fails in a way operators and recovery code can trust.

Parser boundary tests need to be exact. Manifest, public key, signature, version, active marker, and rollback sentinel inputs should all reject bad lengths, trailing data, oversized files, truncated content, invalid UTF-8 where text is required, and non-canonical version formats. The current helpers are useful for bring-up, but production tests need to prove that malformed metadata cannot be silently accepted as a valid prefix.

To operate on those enhancemnets where required, we are going to need to add a small test/fuzz command set so the update path can be xercised from the kernel shell or a test harness.

| Command to develop | Purpose |
| --- | --- |
| ota-selftest | Runs the normal OTA service test suite: apply, commit, verify, rollback, key import, signature import, and persistence records. |
| ota-fuzz-manifest | Feeds malformed, truncated, oversized, trailing-data, and invalid-hex manifest inputs into the parser. |
| ota-fuzz-key | Fuzzes trusted public key parsing, including wrong length, trailing bytes, invalid hex, and malformed key data. |
| ota-fuzz-signature | Fuzzes detached signature parsing and signature mismatch behavior. |
| ota-fuzz-version | Fuzzes version strings, including empty, too long, invalid UTF-8, non-canonical, downgrade, and repeated versions. |
| ota-fuzz-slot-state | Fuzzes active slot markers, rollback sentinels, slot metadata, and staged/verified/committed state transitions. |
| ota-crash-test | Simulates crash-after-commit, crash-before-sentinel, crash-after-sentinel, and crash-during-rollback cases. |
| ota-rollback-test | Tests manual rollback, crash rollback, invalid fallback, stale sentinel, rollback ping-pong, and fallback verification. |
| ota-policy-test | Tests production, development, and recovery policy behavior for unsigned manifests, rollback, downgrade, and recovery keys. |
| ota-cap-test | Tests OTA capability boundaries: write without activate, verify without rollback, audit without key import, introspect without mutation. |
| ota-audit-test | Verifies expected audit/persistence records for success and failure paths. |
| ota-status --json or ota-status --machine | Emits machine-readable OTA state for automated tests and tooling. |

The most valuable first command would be ota-selftest, because it can become the umbrella command. Then fuzzing commands can either run standalone or be grouped under ota-selftest --fuzz.

To make it easy to use it in the basic sense, we need to keep the self test command simple, and the status command simple as well. 

```text
ota-selftest
ota-selftest --fuzz
ota-selftest --policy
ota-selftest --rollback
ota-selftest --capabilities
ota-status --machine
```
They should return structured counts: cases run, rejected as expected, accepted as expected, unexpected accepts, unexpected rejects, and crashes/panics. That makes them useful for regression testing instead of just manual inspection.

#### Checking the OTA for security vilnerabilities still within the code not addressed previously. 

This second pass looked over the OTA service as a whole, not just the cryptographic primitives. The important thing it found is that most of the remaining OTA risk is not that SHA-256, Ed25519, or ct_eq are the wrong primitives. The risk is that the code has to prove it is checking the right state, at the right time, for the right slot, with the right metadata, under the right authority. In the current implementation, several of those boundaries are still loose.

| Area reviewed | What the code currently does | Security problem | Maturity direction |
| --- | --- | --- | --- |
| Boot ordering | On x86_64, OTA slot init and verified boot run before VFS recovery. | The kernel can verify default or missing OTA state, then recover a different persisted OTA state afterward. That means the verified boot check can be checking the wrong state. | Recover durable VFS state first, then initialize OTA state, then verify the active slot before trusting it. |
| Architecture coverage | x86_64 calls OTA init and verified boot, while the reviewed aarch64 shared runtime does not wire OTA init or verified boot into the same path, and the x86 path recovers VFS without the same OTA enforcement. | OTA security behavior changes by architecture. One build may enforce some OTA checks while another may skip them completely. | Put OTA recovery and verification behind one shared boot contract that every supported architecture calls in the same order. |
| Crash rollback signal | init_slots checks crash_count and the rollback sentinel. The crash count is a current-boot in-memory counter, and aarch64 currently forces it to zero. | A real reboot clears the in-memory crash count, so automatic rollback may not know that the previous boot failed. On aarch64, crash-triggered rollback is disabled by construction. | Store a durable boot-attempt record, boot-success marker, and previous-boot failure signal that survive reboot. |
| Active and pending metadata | The manifest hash, signature, public key, and version are global files under /ota. | Applying a new update can overwrite the manifest used by boot verification for the currently active slot. After apply but before commit, boot verification can compare the active slot against pending-slot metadata. | Store metadata per slot, and bind each manifest to slot, version, key identity, policy mode, and lifecycle state. |
| Signature file parsing | The signing helpers parse the required prefix and accept extra trailing bytes. Oversized files can be truncated before parsing. | A malformed key or signature file can still be accepted if the valid prefix is present. That weakens manifest strictness and makes audit outcomes less trustworthy. | Require exact file lengths for public keys, signatures, and manifest hashes, with no trailing data and no truncation. |
| Malformed key downgrade | verify_detached_ed25519 treats public key read errors and signature read errors as missing files. If both fail, the result can become unsigned. | A malformed trusted key plus malformed or missing signature can collapse into the unsigned path, and the current commit path still permits unsigned manifests. | Separate missing, malformed, unreadable, wrong length, and invalid signature states, and make malformed trust material fatal. |
| Source path authority | ota-apply, ota-trust-key, and ota-set-signature import bytes from arbitrary VFS paths supplied by the caller. | Without source policy, a caller with command access can stage images or trust material from paths that were not meant to feed OTA, including metadata paths or other protected VFS state. | Require source-object authority and restrict OTA image, public key, and signature imports to approved update package paths. |
| Image size handling | ota-apply, ota-commit, and verify_boot_image allocate a Vec based on VFS path_size and then read the whole file. | A very large VFS file or corrupted size can cause memory exhaustion before any cryptographic verification happens. | Add hard OTA image size limits, stream hashing, bounded reads, and explicit resource-failure audit events. |
| Rollback sentinel | The rollback sentinel is a plain VFS file at /ota/rollback_needed. | Anyone who can modify that path can force rollback behavior, suppress rollback behavior, or create confusing recovery state. | Bind the sentinel to authenticated rollback metadata and protect it through OTA rollback authority. |
| Verified boot boundary | verify_boot_image is a software sanity check that runs after the kernel is already executing. It also logs mismatch without halting. | This cannot be treated as production verified boot. It can detect some corruption, but it cannot prevent a bad image from running first. | Move the enforceable measurement into the bootloader or early root-of-trust path, and make production mismatch fatal. |
| Status and logging output | ota-status prints manifest and signature status, and commit mismatch prints expected and actual hashes. | Debug output can leak update metadata or help an attacker understand which image and manifest state the kernel expects. | Gate OTA introspection behind OTA status authority and make production logs structured, minimal, and policy-controlled. |
| Time-of-check to time-of-use | OTA reads active markers, manifests, versions, signatures, and slot bytes through separate VFS calls. | A concurrent or privileged writer can change OTA state between checks unless the whole operation is locked and transactional. | Add an OTA transaction lock and commit over one authenticated metadata snapshot instead of many independent VFS reads. |

The most serious new finding is the boot-order issue. In the x86_64 runtime, the kernel initializes persistence, calls crash_log on_boot, initializes OTA slots, runs verify_boot_image, and only then calls VFS recovery. That ordering means OTA verification is not necessarily looking at the durable /ota state that will exist after recovery. In a mature OTA path, persistence recovery has to happen before OTA trust decisions. The kernel needs to restore the active marker, slot metadata, manifest, signature, rollback sentinel, and version first. Then OTA can decide whether the active slot is valid, whether rollback is needed, and whether the system can continue booting.

The second serious finding is that crash rollback is not yet a durable previous-boot decision. The current init_slots path looks for a rollback sentinel and then checks crash_count. That sounds right at a high level, but crash_count is the number of panics recorded since the current boot. After a real reboot, that counter starts over. The rollback decision needs a persistent boot attempt model instead. Commit will write a probation record for the newly activated slot. Early boot will read that record, increment or bind a boot attempt number, and only clear it after the system reaches a known-good point. If the next boot fails before that success marker is written, the next startup has durable evidence that the new slot failed.

The third serious finding is the global metadata model. Right now, /ota/manifest and /ota/version describe whichever image was most recently staged, not necessarily the image currently active. That creates a dangerous active-versus-pending confusion. If slot A is active and slot B is staged, the global manifest describes B. If the system reboots before commit, boot verification can try to verify A using B’s hash. The mature model needs slot A metadata and slot B metadata separately, plus a small authenticated record saying which slot is active, which slot is staged, which version belongs to each, and which signature/key identity approved each slot.

The fourth serious finding is parser strictness around trusted keys and signatures. The helper read_hex_file reads only up to a maximum, parse_hex_bytes accepts the first required bytes, and verify_detached_ed25519 turns read failures into missing values. That means malformed files are not cleanly separated from missing files. In the worst case, malformed trust material can fall into the unsigned-manifest path, and the commit path currently allows unsigned manifests with only a warning. Production OTA needs exact-size parsing, fatal malformed key material, fatal malformed signatures, and no fallback from malformed trust state to unsigned trust state.

The fifth serious finding is resource exhaustion. ota-apply, ota-commit, and verify_boot_image all allocate memory for the full image based on VFS path_size. That is fine for a prototype, but it is not safe for a kernel update path. A corrupted VFS entry, malicious source path, or unexpectedly large image can force a large allocation before the OTA policy has finished deciding whether the bytes are trusted. The mature path needs maximum image sizes, streaming SHA-256, bounded reads, and tests that prove huge files fail cleanly without starving the kernel.

These findings do not replace the earlier OTA maturity list. They sharpen it. The previous list already says OTA needs signed manifests, rollback protection, slot capabilities, stricter tests, and better persistence records. This pass adds the deeper system-level point: OTA trust depends on boot order, durable recovery state, exact metadata binding, architecture parity, and parser failure semantics. Without those, the crypto can be correct while the OTA security decision still protects the wrong thing.


### How the Fleet Attestation path uses these primitives

The fleet attestation path uses the crypto folder to describe the current runtime state in a way that another operator, peer, or later audit pass can reason about. It is not encrypting fleet data here. Its main job is measurement and evidence: collect important runtime facts, hash them into a compact measurement, optionally verify a detached signature over the canonical attestation message, and store the result in persistence.

The current implementation builds a FleetAttestationBundle. That bundle contains the boot session, crash count, boot tick, active OTA slot hash, scheduler context-switch count, and the SHA-256 measurement over those values. The active slot hash is read from the OTA manifest path, /ota/manifest. If the manifest cannot be read, the code uses an all-zero slot hash, which represents unknown state rather than a verified active image.

The measurement input is small and fixed in shape:

| Measurement field | What it means |
| --- | --- |
| Boot tick | A runtime timing value for when the bundle was built. |
| Crash count | Number of crashes recorded for the current boot path where available. |
| Boot session | Current boot session number where crash logging is available. |
| Active slot hash | The OTA manifest hash that is meant to represent the active slot image. |
| Scheduler switches | Total scheduler context switches seen by the slice scheduler. |

Those fields are serialized into a 56-byte input buffer and passed through SHA-256. The result is the 32-byte fleet measurement. That measurement is useful because it gives the fleet path one compact digest for the runtime facts it collected. It does not prove the facts are complete or trusted by itself, but it gives the rest of the attestation flow a stable value to record, print, export, and sign.

The attestation pieces in the current path are:

| Fleet attestation piece | What it does |
| --- | --- |
| SHA-256 measurement | Compresses boot tick, crash count, boot session, active slot hash, and scheduler switches into one measurement hash. |
| Canonical signed message | Turns the bundle fields into a stable text message with a fleet-attestation domain label. |
| Ed25519 verification | Verifies a detached signature over the exported canonical message when a trusted fleet public key and signature are present. |
| Persistence record | Stores boot session, crash count, boot tick, and measurement as an AttestationRecord. |
| Fleet export files | Writes the canonical message to /fleet/attest.msg and a human summary to /fleet/attest.txt. |
| CapNet attest frame | Can send an attest frame to a registered peer, though the detached signature remains local in this phase. |

The canonical message matters because a signature should be over exact bytes, not over a vague idea of the bundle. The signing helper builds a stable message with the domain oreulius-fleet-attestation:v1, then writes boot_session, crash_count, boot_tick, measurement, active_slot_hash, and sched_switches in a predictable order. That means the verifier and signer can agree on exactly what was signed.

The current signature verification path is detached. The trusted fleet key lives at /fleet/attest.pub, the detached signature lives at /fleet/attest.sig, and the signed message lives at /fleet/attest.msg. The fleet-attest-export command writes the current message and summary, then reports whether the exported message is unsigned, verified, or invalid. The fleet-attest-verify command checks the exported bundle signature directly. This makes the fleet attestation path closer to the OTA manifest pattern: deterministic message first, detached Ed25519 verification second.

The persistence path records a smaller attestation record than the full signed message. It stores boot session, crash count, boot tick, and the measurement hash as an AttestationRecord. That is useful for local history, audit, and later diagnostics, but it does not currently store the full active slot hash, scheduler switch count, key identity, signature status, peer identity, or policy decision in the persistence record. So the current record is a useful measurement event, not yet a complete remote-attestation evidence bundle.

The CapNet route is also still early. fleet-attest can send a CapNet Attest frame to a peer, but the code message says the signed bundle remains local/exported and the CapNet frame does not carry the detached signature in this phase. That means the remote peer may see that an attestation event was sent, but the full signed proof is not yet traveling as one authenticated attestation package.

In maturity terms, the current Fleet Attestation path has the right skeleton. It measures runtime facts with SHA-256, has a canonical signed-message format, uses Ed25519 detached-signature verification, records a persistence event, and can emit diagnostic output. The missing maturity is around authority and completeness: the active slot hash must be tied to the actual verified active slot, the all-zero unknown state needs strict policy, aarch64 should not silently report zero crash and boot-session values as if they are equivalent evidence, the signed bundle should travel with the CapNet attestation frame, and fleet key provisioning needs the same seriousness as OTA key provisioning.

Fleet attestation still needs a stronger maturity pass around identity, freshness, and authority. The active slot hash needs to come from verified OTA active-slot metadata, not just from the global manifest file, because the manifest may describe staged or stale update state instead of the image actually being trusted. If the active slot hash is missing or all zeros, that needs to be treated as an explicit unknown attestation state, not as normal healthy evidence.

The attestation evidence also needs to carry more context. It should include key identity, signature status, policy mode, active slot id, OTA version, peer identity, and enough persistence metadata to reconstruct what was measured and why the kernel considered it acceptable. Right now the persistence record stores the basic measurement event, but a mature record needs to explain the full trust decision, not only the hash.

For remote proof, the signed canonical bundle needs to travel with the CapNet attestation flow, or the frame needs to carry a hash and signature over that bundle. It also needs freshness, such as a nonce, challenge, verifier id, timestamp window, or request id, so an old signed attestation cannot be replayed as if it were current. The signed message should bind the destination verifier or peer identity when it is being used as remote evidence.

The fleet attestation commands also need capability gating. Attestation generation, trusted key import, signature import, diagnostics, and peer transmission should each require explicit fleet rights. The fleet files under /fleet, including attest.msg, attest.txt, attest.pub, and attest.sig, need protection from ordinary VFS modification. Finally, the test plan needs to cover stable canonical messages, bad signatures, missing keys, malformed keys, trailing key data, wrong active slot hashes, unknown slot hashes, replayed attestations, and remote transmission behavior.

#### Fleet Attestation Bundle Flow
The fleet attestation bundle starts in the current fleet service by collecting a small set of runtime facts about the kernel, turning those facts into one SHA-256 measurement, and then exporting that measurement as a canonical attestation message. The important point is that the measurement is not just a random hash. It is meant to be a compact statement about the device state at the moment attestation was built.

| Bundle field | Where it comes from today | What it means |
| --- | --- | --- |
| Boot session | Crash log state where available | Identifies the current boot lifetime. |
| Crash count | Crash log state where available | Shows whether the device has recorded crashes before this attestation. |
| Boot tick | Platform tick source | Gives a local time-like value for when the bundle was created. |
| Active slot hash | OTA manifest hash file | Connects the attestation to the software image the device believes is active. |
| Scheduler switches | Scheduler snapshot overview | Adds a small amount of live runtime state to the measurement. |
| Measurement | SHA-256 over the selected fields | Produces the fixed-size evidence value that can be signed, exported, recorded, or sent to a peer. |

The current implementation builds the measurement by serializing boot tick, crash count, boot session, active slot hash, and scheduler switch count into a fixed byte layout, then hashing those bytes with SHA-256. That gives the fleet path a stable internal measurement format, which is the right basic direction. After that, Oreulius can build a canonical signed message from the bundle, write the canonical message to the fleet export path, write a readable text summary, and verify a detached Ed25519 signature over the exported message when a public key and signature are present.

The main weakness is that the bundle is only as strong as the facts it is allowed to trust. Right now the active slot hash is read from the OTA manifest path directly, not from a fully verified active-slot metadata record. If that manifest is missing or too short, the code falls back to an all-zero hash. If the manifest contains malformed hex, invalid nibbles are converted into zero instead of making the evidence invalid. That makes unknown or malformed OTA state look too much like ordinary measured state, which is not mature enough for fleet trust.

The bundle also needs stronger context around what the measurement means. On aarch64, crash count and boot session are currently filled as zero because that crash source is not wired in there yet. That is different from a real zero-crash, real boot-session value, so the mature bundle needs to record whether each field is measured, unavailable, unknown, or policy-rejected. The same applies to active slot identity, OTA version, key identity, signature status, policy mode, architecture, peer identity, and freshness data. Without that context, two bundles can have the same shape while carrying very different trust meaning.

The fleet attestation bundle needs stricter handling around the OTA manifest it uses as evidence. Malformed manifest hex cannot be silently converted into zero bytes, because that turns bad evidence into something that looks measured. The active slot hash also needs to come from verified OTA active-slot metadata, not only from the global manifest file, so fleet attestation is tied to the software image the kernel actually trusts as active.

The bundle also needs to make unknown state explicit. Unknown, unavailable, and rejected fields need to be represented differently from valid measured values. That matters for cases like all-zero measurements, missing OTA data, architecture-specific unavailable crash state, or fields that policy refused to trust. The bundle also needs freshness data, such as a nonce, challenge, verifier identity, request id, or bounded timestamp data, so an old attestation cannot be replayed as if it were current proof.

The mature bundle needs more context around the measurement. It needs to include the active slot id, OTA version, key identity, signature status, policy mode, architecture, and peer identity where fleet policy depends on those facts. It also needs to classify fields clearly, so stable identity evidence, freshness evidence, and diagnostic-only runtime values are not confused with each other.

Persistence needs to record enough of the bundle to reconstruct what was measured and what trust decision was made, not only the final measurement hash. That includes the signature decision, such as unsigned, verified, invalid signature, missing key, missing signature, or malformed input. If persistence append fails during production attestation, that needs to be treated as security-relevant instead of being ignored.

The export and remote paths also need hardening. Fleet export files need protection so ordinary VFS writes cannot replace the canonical message, public key, signature, or text summary. Trusted key and detached signature files need exact-length parsing with no trailing data. Production policy needs to define what happens to unsigned bundles, especially whether they are rejected, marked diagnostic-only, or blocked from remote transmission. The remote CapNet attestation flow also needs to carry the canonical attestation message and detached signature, or a signed hash of them, instead of only sending a control frame while the signed bundle stays local.

The whole path needs capability checks and test coverage. Building, exporting, signing, verifying, recording, and transmitting fleet attestation evidence need explicit capability rights. Tests need to cover missing manifests, short manifests, malformed manifest hex, all-zero unknown measurements, architecture-specific unavailable fields, stale signatures, stale exported messages, replayed bundles, exact-length key and signature parsing, unsigned production policy, and remote attestation transmission behavior.

#### Fleet Measurement Inputs
Fleet attestation starts by deciding what facts are allowed to become measurement input. In the current implementation, build_current_bundle, gathers five inputs: boot tick, crash count, boot session, active slot hash, and scheduler switch count. Those values are then serialized into a fixed 56-byte buffer and hashed into the final fleet measurement.

| Input | Current source | Current role in the bundle |
| --- | --- | --- |
| Boot tick | RDTSC on x86/x86_64, platform ticks on aarch64 | Gives the bundle a local runtime time marker. |
| Crash count | Crash log on non-aarch64, zero on aarch64 | Shows how many crashes the current crash log knows about. |
| Boot session | Crash log on non-aarch64, zero on aarch64 | Identifies the current boot session where the crash log supports it. |
| Active slot hash | /ota/manifest parsed as 64 hex bytes | Connects the bundle to the OTA image hash the system currently reports. |
| Scheduler switches | Scheduler snapshot total switch count | Adds live kernel scheduling state to the measured runtime picture. |

The strongest input is meant to be the active slot hash, because that is the part that connects fleet attestation to the software image the device is claiming to run. The weaker inputs are boot tick and scheduler switch count, because they are live runtime values. They can help distinguish one bundle from another, but they do not prove software identity by themselves. Crash count and boot session sit in the middle: they are useful health and recovery signals, but their meaning depends on whether the architecture actually has a working crash log source.

The current code has a clean prototype shape, but the input model is not mature yet. The active slot hash is read directly from the OTA manifest file, not from a verified active-slot metadata record. If the manifest is missing or too short, the input becomes an all-zero hash. If the manifest contains invalid hex characters, those bad nibbles can become zero. On aarch64, crash count and boot session are also zeroed because that crash source is not wired in. Those are all different situations, but today they can collapse into ordinary-looking numeric fields.

The mature model needs each input to carry both its value and its meaning. A measured value, an unavailable value, an unknown value, and a rejected value are not the same thing. Fleet evidence also needs to label which inputs are identity evidence, which inputs are freshness evidence, and which inputs are diagnostic runtime evidence. That keeps the verifier from treating a scheduler switch counter or boot tick as if it proves the same kind of trust as a verified OTA image hash.

For this to become production-ready, the active slot hash needs to come from verified OTA active-slot metadata instead of only /ota/manifest. The measurement also needs to reject malformed manifest hex instead of converting invalid characters into zero nibbles. Missing, unavailable, unknown, and rejected inputs need to be represented as different states in the signed evidence, because a missing source and a valid zero value do not mean the same thing.

The bundle needs more identity context beside the active slot hash. That means adding active slot id, OTA version, policy mode, key identity, and signature status, then labeling each input by what kind of evidence it is. The active slot hash and OTA version are identity evidence, freshness values are used to prevent replay, and fields like scheduler switches are mostly diagnostic runtime evidence. Keeping those categories separate prevents a verifier from treating live runtime counters as if they prove the same thing as verified software identity.

The measurement inputs also need to be captured as one consistent snapshot. Today the bundle reads OTA state, crash state, boot tick, and scheduler state through separate calls. A mature fleet path needs a defined consistency rule, source generation numbers, or retry behavior so the final measurement cannot describe a mixed state that never existed at one point in time.

The input format needs schema versioning. Future fleet bundles are going to add fields and refine meanings, so the signed evidence needs a measurement schema id and version. Verifiers need to reject unknown or deprecated schemas instead of guessing how to interpret them. Numeric inputs also need wraparound and reset rules for boot tick, crash count, boot session, and scheduler switch count, especially across architectures and reboot boundaries.

Finally, each input source needs health and exposure policy. OTA metadata, crash log, scheduler snapshot, timer source, and architecture support need to report whether they are healthy, unavailable, estimated, or diagnostic-only. Remote attestation also needs to decide which raw values are safe to expose, which ones belong only in local diagnostics, and which ones need to be redacted, minimized, or hashed. The test suite needs to cover input changes, missing manifests, malformed manifests, unavailable crash sources, stale OTA metadata, source failures, schema mismatches, counter wraparound, and architecture-specific input behavior.

#### SHA-256 Fleet Measurement Hash
The fleet measurement hash is the compact fingerprint of the attestation bundle inputs. In the current code, build_measurement_hash creates a 56-byte binary input buffer, writes each measurement field into a fixed offset, and then passes that buffer into the kernel's SHA-256 implementation. The result is a 32-byte measurement value.

| Byte range | Field | Encoding |
| --- | --- | --- |
| 0..8 | Boot tick | u64 little-endian |
| 8..12 | Crash count | u32 little-endian |
| 12..16 | Boot session | u32 little-endian |
| 16..48 | Active slot hash | 32 raw bytes |
| 48..56 | Scheduler switches | u64 little-endian |

This is a good prototype shape because it avoids string parsing in the measurement itself. The hash input is fixed-size, the field order is deterministic, and the output is always the same size. That makes the measurement easy to store, print, sign, and compare. SHA-256 is being used here as a compression point: it turns several pieces of kernel state into one value that can represent the state in logs, signatures, CapNet policy, and future fleet verification.

The code then carries that 32-byte measurement into the canonical fleet attestation message. That message also includes the visible field values, such as boot session, crash count, boot tick, active slot hash, and scheduler switch count. This is important because the verifier should not only see the final hash, it should also understand what was hashed. The measurement is the compact fingerprint, while the canonical message is the explainable evidence wrapper around that fingerprint.

The current model still needs a stronger measurement domain. Right now the 56-byte buffer is just raw fields in a known order. A mature fleet measurement needs an explicit domain label and schema version inside the hash input, not only in the outer signed message. That prevents the same byte layout from being confused with another measurement type later. It also lets future versions add fields without making old verifiers guess what a measurement means.

The hash also needs stronger test discipline. The SHA-256 primitive has a standard structure, but the fleet measurement layout needs its own test vectors. Those tests need to prove that changing any input changes the measurement, that byte order is stable, that field boundaries are fixed, and that the same inputs produce the same measurement across supported architectures. Tests also need to cover schema-version mismatch, unknown schemas, unavailable input states, and malformed active slot evidence.

The hash needs to become part of a governed attestation format, not just a helper output. The measurement hash needs to be domain-separated, schema-versioned, tied to verified input sources, stored with enough context to reconstruct the decision, and compared in ways that preserve the full 32-byte value. Anywhere the fleet path maps this measurement into a smaller field, such as older u64-style CapNet measurement slots, that mapping needs an explicit truncation or compatibility policy so the system does not accidentally weaken the meaning of the full SHA-256 measurement.

The comparison rules need to be just as explicit as the hash construction. A fleet SHA-256 measurement is a 32-byte value, so production comparison needs to compare the whole 32 bytes and reject length mismatches. If Oreulius keeps a smaller compatibility measurement for older CapNet or capability paths, that smaller value needs a different name, a clear derivation rule, and a policy that says it is not equivalent to the full fleet measurement.

The hash input also needs to stop treating default values as self-explanatory. A real zero boot tick, an unavailable boot tick, and a rejected boot tick need to hash differently. The same applies to crash count, boot session, scheduler switches, and an all-zero active slot hash. The mature format needs state tags inside the hashed input so the verifier can tell the difference between a measured value and a placeholder value.

The test plan needs fixed golden vectors for the fleet measurement layout itself. That means known input bytes for the full measurement buffer and the exact SHA-256 output expected from those bytes. Those tests catch accidental changes to field order, byte order, field size, or schema layout. The underlying SHA-256 primitive also needs reference-vector coverage because fleet attestation turns that primitive into a trust anchor. Empty input, abc, long messages, multi-block messages, and incremental update behavior all need to match known SHA-256 outputs.

The measurement also needs a lifecycle. A hash created by fleet-attest should have a creation point, a freshness window, a replacement rule, and an expiry rule. Old measurements may remain useful for local audit, but they should not automatically remain valid remote proof. That lifecycle needs to be represented in the signed evidence and in persistence so verifiers can tell whether they are looking at current proof, stale proof, or historical audit state.

#### Canonical Fleet Attestation Message
The canonical fleet attestation message is the exact byte string that gets signed or verified for fleet evidence. The measurement hash is the compact fingerprint, but the canonical message is the readable proof format around it. It gives the verifier the measurement plus the field values that explain how that measurement was built.

| Message field | Current meaning |
| --- | --- |
| oreulius-fleet-attestation:v1 | Domain string for this signed message format. |
| boot_session | Boot session value from the crash log where available. |
| crash_count | Crash count value from the crash log where available. |
| boot_tick | Local tick value when the bundle was created. |
| measurement | 32-byte SHA-256 fleet measurement, written as lowercase hex. |
| active_slot_hash | OTA slot hash that the bundle used as software identity evidence. |
| sched_switches | Scheduler switch count when the bundle was created. |

The current builder is build_fleet_attestation_signed_message in signing_formats.rs. It writes a fixed header, then appends decimal fields and lowercase hex fields in a stable order, ending with a newline. The fleet service calls this through canonical_message_for_bundle, writes the result to /fleet/attest.msg, writes a human-readable summary to /fleet/attest.txt, and then verifies the detached Ed25519 signature against the exact exported message bytes.

This is the right basic model because signatures need exact bytes. If two systems serialize the same evidence in different ways, the signature becomes ambiguous and hard to verify. A canonical message removes that ambiguity by making one field order, one spelling, one newline style, and one hex format. The existing helper test already checks that the message stays stable for a known input, which is a good start.

The current message is still too small for production fleet trust. It does not include active slot id, OTA version, key identity, signature status, policy mode, architecture, source-health state, freshness data, peer identity, or verifier challenge. That means the signed message can prove the current fields, but it cannot fully explain the policy decision around those fields. It also means a remote verifier may not know whether it is seeing current proof, stale proof, diagnostic-only proof, development proof, or production proof.

The canonical message also needs a stronger relationship to export and transmission. Today /fleet/attest.msg is an ordinary exported file, and fleet-attest can send a CapNet Attest frame while the signed bundle remains local. A mature flow needs the canonical message, or a signed hash of it, to travel with the remote attestation event. Verification also needs to know whether it is checking the latest generated message or an older exported artifact.

Production maturity means the canonical message becomes a governed evidence contract. It needs explicit schema versioning, a freshness field, source-state tags, signature policy, key identity, and peer binding where remote proof is involved. It also needs tests that prove field order is stable, unknown fields are rejected or versioned, stale exported messages are detected, and signatures fail if any field changes by even one byte.

#### Fleet Detached Signature Verification
Fleet detached signature verification is the part that checks whether the exported canonical fleet message was approved by a trusted Ed25519 key. The message itself lives at /fleet/attest.msg, the trusted public key lives at /fleet/attest.pub, and the detached signature lives at /fleet/attest.sig. The verifier reads the message bytes, reads the key and signature as hex, and then calls Ed25519 verification over the exact message bytes.

| Verification state | Current meaning |
| --- | --- |
| Verified | A trusted public key and detached signature are present, and Ed25519 verification succeeds. |
| Unsigned | Both trusted public key and detached signature are absent or fail to load as usable hex. |
| Missing signature | A trusted public key is present, but the detached signature is absent or not usable. |
| Missing key | A detached signature is present, but the trusted public key is absent or not usable. |
| Invalid signature | A public key and signature are present, but the signature does not verify the message. |

The current model is useful for development because it separates the canonical message from the signature. That lets the kernel export the evidence first, then verify a detached signature over that evidence. It also keeps the signing key out of the fleet service, which is the right direction. Fleet only needs the trusted verification key and the detached signature, not the private signing key.

The weak part is that malformed trust material can collapse into the same broad states as missing trust material. The helper reads public keys and signatures as hex, but if parsing fails, the verifier treats that side as absent. That means a malformed public key can look like no key, and a malformed signature can look like no signature. For production policy, those need to be different outcomes because missing, malformed, unsigned, and invalid are different security events.

The key and signature files also need stricter file rules. A production verifier needs exact public key and signature lengths, no trailing data, no oversized files, no alternate whitespace forms, and no partial-prefix parsing. The trusted key file also needs to be protected from ordinary VFS writes, because changing /fleet/attest.pub changes the root of trust for fleet evidence.

Signature verification also needs to connect back to semantic verification. Ed25519 can prove that some exact bytes were signed, but it does not prove that those bytes are a valid fleet attestation under the current policy. After the signature succeeds, the kernel still needs to parse the canonical message, reject malformed or stale evidence, recompute the measurement from the visible fields, and check freshness, schema version, key identity, policy mode, and peer binding.

Production maturity means the detached signature path needs a richer result model and stronger audit behavior. Verified, unsigned, missing key, missing signature, malformed key, malformed signature, invalid signature, stale signature, wrong key generation, revoked key, and wrong policy mode need separate outcomes. Those outcomes need to be recorded in persistence and audit logs so fleet operators can tell whether the device had valid proof, no proof, broken proof, or proof under the wrong trust root.

The exported message read path also needs stricter behavior. Today the shared small-file reader caps the message buffer size and reads what fits, which is useful for avoiding unbounded allocation, but production verification needs to reject oversized canonical messages instead of verifying a truncated prefix. The verifier also needs to bind the message size to the active fleet schema so a larger or differently shaped future message cannot be silently cut down to something that still verifies under an older interpretation.

The Ed25519 core has several important checks already, including canonical scalar rejection, point decompression failure handling, small-order public key and R rejection, and constant-time comparison of the final encoded points. For production fleet trust, that still needs a broader assurance suite. The tests need more RFC 8032 vectors, malformed public keys, malformed R values, non-canonical S values, small-order points, wrong-domain messages, randomized negative cases, and comparison against a known-good Ed25519 implementation during development.

#### Fleet Trusted Key Provisioning
Fleet trusted key provisioning is how Oreulius decides which Ed25519 public key is allowed to verify fleet attestation evidence. In the current code, the fleet-trust-key command takes a VFS source path, reads a 32-byte public key encoded as hex, normalizes it into lowercase hex, and writes it to /fleet/attest.pub. Later, fleet detached signature verification uses that file as the trusted public key for /fleet/attest.msg and /fleet/attest.sig.

| Provisioning part | Current behavior |
| --- | --- |
| Source path | Provided by the caller through fleet-trust-key. |
| Key format | 32-byte Ed25519 public key encoded as hex. |
| Destination | /fleet/attest.pub. |
| Validation | Checks that enough valid hex exists for a 32-byte key. |
| Trust result | The imported key becomes the verifier key for fleet evidence. |

This is useful for development because it gives the fleet path a simple way to test signed evidence without embedding a private key or hardcoding a verifier key in the service. It also keeps the private signing key outside the kernel, which is the right trust direction. The kernel only needs to know which public key it trusts, then it can verify detached signatures over exported fleet messages.

The maturity problem is that this is not yet real provisioning. A caller-chosen VFS path is not a root of trust by itself, and /fleet/attest.pub is just a file unless the VFS layer or capability system protects it. If ordinary code can replace that file, it can change which signer the fleet path trusts. That would let an attacker move the trust root instead of breaking Ed25519.

Production provisioning needs a protected trust path. The fleet public key needs to come from a measured boot path, signed provisioning package, hardware-backed store, factory provisioned slot, recovery authority, or another explicitly trusted source. The key also needs identity and lifecycle metadata, such as key id, generation, policy mode, issuer, activation time, expiry, revocation state, and whether it is a development key or a production key.

The import rules need to be stricter too. The key file needs exact length, no trailing data, no malformed hex, no prefix-only parsing, and no silent downgrade into missing-key behavior. Import should be capability-gated, source-path scoped, audited, and rejected if the source object is not authorized for fleet key provisioning. Replacing the trusted key should also be treated as a security event, not just a file write.

A mature design also needs key rotation and recovery. Fleet needs a way to move from one trusted verifier key to the next without accepting arbitrary key swaps. It also needs a way to revoke a compromised key, distinguish old signatures from new signatures, and explain which key generation verified each attestation. Without that lifecycle, the fleet path can verify a signature, but it cannot fully explain why that signer was trusted at that time.

The test plan needs to cover valid key import, malformed key import, short key files, oversized key files, trailing data, unauthorized source paths, unauthorized destination replacement, revoked keys, wrong-generation keys, development keys in production mode, and signature verification after key rotation. The goal is not only to prove Ed25519 works, but to prove the trusted key cannot be changed except through the intended authority path.

#### Fleet Attestation Persistence Records
Fleet attestation persistence records are the durable trail that says an attestation was produced. In the current code, fleet-attest builds the bundle, exports the canonical message, and then calls record_attestation. That helper creates an AttestationRecord and appends it to the persistence log.

| Persisted field | Current encoding |
| --- | --- |
| Boot session | 4 bytes, little-endian |
| Crash count | 4 bytes, little-endian |
| Boot tick | 8 bytes, little-endian |
| Measurement | 32 raw bytes |

The current payload is 48 bytes total. It is useful because it records the most compact identity of the attestation event: which boot session and crash count were observed, what local tick was used, and what 32-byte fleet measurement was produced. That is enough to know that an attestation happened, but not enough to reconstruct the full trust decision later.

The missing context is the important part. The record does not store the active slot hash, active slot id, OTA version, key identity, signature status, policy mode, freshness data, schema version, source-health state, peer identity, or whether the evidence was local-only, exported, verified, invalid, or transmitted. It also does not store why verification failed when it failed. Without those fields, persistence can remember a measurement hash, but it cannot explain whether that measurement was trusted, unsigned, stale, malformed, or tied to the right software image.

The write path also needs stronger authority and failure behavior. The current code creates a persistence capability with all store rights, even though fleet only needs append-log authority for this record. It then ignores the append result. In a production path, failed attestation persistence needs to be security-relevant, especially if the system is about to export or transmit evidence. A fleet attestation that cannot be recorded may need to fail closed, enter diagnostic-only mode, or clearly report that the audit trail is incomplete.

The mature record needs to become an evidence record, not just a hash record. It needs to bind the canonical message identity, measurement schema, source-health states, signature result, trusted key generation, freshness window, peer destination, and policy decision into one durable record. If the same attestation is later sent over CapNet, the persistence layer should be able to explain which message was sent, which key verified it, which peer received it, and whether the event was accepted or rejected by policy.

The test plan needs to prove that successful attestations, unsigned attestations, invalid signatures, missing keys, malformed keys, stale messages, unknown active slot state, failed persistence appends, and remote transmission attempts all produce the expected records or fail in the expected way. The goal is that fleet operators can reconstruct what happened from persistence without guessing from console output.

#### Fleet CapNet Attestation Transmission
Fleet CapNet attestation transmission is the path that tries to send fleet evidence to another peer. In the current code, fleet-attest first builds and exports the local fleet bundle. If the operator also provides a peer id, IP address, and port, the command sends a CapNet Attest control frame through net_reactor and the network stack.

| Step | Current behavior |
| --- | --- |
| Build bundle | Fleet creates the local measurement and canonical message. |
| Export evidence | The canonical message stays at /fleet/attest.msg and the summary stays at /fleet/attest.txt. |
| Parse destination | The command parses peer id, IPv4 address, and port from the shell arguments. |
| Send frame | CapNet sends an Attest control frame to the destination. |
| Payload | The current Attest frame carries no signed bundle, no detached signature, and no measurement payload. |

The important detail is that the current transmission is a signal, not a complete remote attestation proof. CapNet can send an Attest control frame, but the frame is built with an empty payload. The receive side also expects Hello, Attest, and Heartbeat control frames to have zero payload. That means the peer can observe that an attestation event was signaled, but it does not receive the canonical message, detached signature, trusted key identity, freshness data, or measurement evidence inside that frame.

This is still useful as a scaffold because it routes fleet attestation into the network authority path. It proves that fleet can build local evidence and trigger a peer-directed CapNet event. But it is not enough for production remote attestation because the remote peer cannot verify what was measured from the frame alone.

the path still needs an evidence-carrying protocol. CapNet either needs an Attest payload format that carries the signed canonical bundle, or it needs to carry a hash of the bundle plus the detached signature and enough metadata for the peer to fetch or validate the full evidence. That payload needs to be bound to peer id, destination, challenge, nonce, request id, schema version, key identity, policy mode, and freshness window. Otherwise an old local bundle could be replayed, forwarded to the wrong peer, or interpreted under the wrong policy.

Transmission also needs capability and policy gating. Local fleet attestation authority should not automatically imply remote transmission authority. A caller may be allowed to build local evidence, but not send it to a peer. The mature rights model needs to scope fleet transmission to peer id, destination, evidence type, policy mode, and possibly maximum disclosure level. Remote transmission also needs to fail closed when the bundle is unsigned, invalid, stale, missing required context, or not recorded in persistence.

Finally, the persistence and audit story needs to follow the network event. When fleet evidence is transmitted, the persistence record should identify the peer, destination, CapNet sequence, bundle identity, signature status, freshness state, and final send result. Tests need to cover signed transmission, unsigned transmission, invalid signature, stale evidence, wrong peer, missing bundle payload, replayed challenge, failed send, and policy-denied transmission.

#### Fleet Active Slot Hash Binding
Fleet active slot hash binding is the part that connects fleet attestation to the software image Oreulius claims to be running. The active slot hash is supposed to be the software identity input inside the fleet bundle. If this value is wrong, stale, or describing the wrong slot, the rest of the fleet evidence can look clean while pointing at the wrong image.

In the current Fleet code, the active slot hash is read from /ota/manifest. That file contains a 64-byte hex SHA-256 value. Fleet parses those bytes and places the resulting 32-byte hash into the attestation bundle. The problem is that /ota/manifest is not a complete verified active-slot record. In the OTA path, the manifest is written when an update is applied to the inactive slot, and later reused during commit and boot verification. That means the manifest can describe pending update state, active state, or stale state unless the surrounding OTA metadata proves which state it belongs to.

| Source | Current meaning |
| --- | --- |
| /ota/active | Indicates slot a or slot b, but malformed or missing state can fall back to slot a in some paths. |
| /ota/manifest | Stores the expected image hash, but not a full active-slot proof by itself. |
| /ota/version | Stores the update version, but is separate from the manifest hash. |
| /ota/manifest.sig | Detached signature for the manifest message, but not currently bound to every fleet field. |
| /ota/rollback_needed | Rollback sentinel, but separate from the active slot hash evidence. |

The binding needs to be stronger because fleet attestation is about trust, not just file contents. A mature fleet bundle needs to know which slot is active, which image hash belongs to that slot, which version was committed, which signature policy passed, which key verified it, and whether rollback state changes the trust meaning. Reading only /ota/manifest does not answer all of that.

The current design also has parsing differences that matter. OTA read_manifest rejects invalid hex by returning no manifest, while Fleet read_active_slot_hash converts invalid hex nibbles into zero. That means the OTA and Fleet paths can interpret the same malformed manifest differently. For production trust, both paths need one strict parser and one shared meaning for malformed, missing, stale, and verified OTA metadata.

The mature model needs verified active-slot metadata. That metadata should bind active slot id, image hash, version, signature status, key identity, policy mode, rollback generation, boot verification result, and commit state into one authenticated record. Fleet should read that verified record instead of reading scattered OTA files independently. If the active record is missing, stale, unsigned, malformed, rollback-tainted, or not verified, the fleet bundle needs to say that explicitly instead of presenting a normal-looking slot hash.

The test plan needs to cover staged manifest confusion, stale manifest reuse, malformed active slot marker, malformed manifest hex, wrong active slot hash, unsigned manifest policy, rollback sentinel interaction, active slot switch during measurement, and verified active-slot metadata. The goal is that fleet attestation can never claim a healthy software identity unless the OTA path has actually proved that identity.

#### Fleet Unknown Measurement State
Fleet unknown measurement state is how Oreulius needs to describe evidence that could not be measured or could not be trusted. In the current Fleet path, the clearest example is the active slot hash. If /ota/manifest cannot be read or is too short, Fleet returns a 32-byte all-zero hash and treats that as an honest unknown value.

That is a useful prototype signal, but it is not a mature attestation state. A 32-byte zero value is just bytes unless the evidence also says why those bytes are zero. It could mean the manifest was missing, the source was unavailable, the source was rejected by policy, the source was malformed, or a real measured field happened to contain zero. Those meanings have very different security implications.

| State | Meaning |
| --- | --- |
| Measured | The field was read from a trusted source and accepted by policy. |
| Unknown | The field could not be determined, such as a missing manifest. |
| Unavailable | The platform does not currently provide that source, such as aarch64 crash state in this code. |
| Rejected | The field existed, but policy refused to trust it. |
| Malformed | The field existed, but parsing failed or the format was invalid. |
| Stale | The field was valid at some earlier time, but no longer proves current state. |

The current code collapses too many of those cases into ordinary-looking values. Missing OTA manifest becomes an all-zero active slot hash. Malformed manifest hex can also become zero nibbles. On aarch64, crash count and boot session become zero because the crash source is not wired in there yet. Those are not the same as valid measured zero values, but the current bundle does not fully separate them.

The mature fleet bundle needs state tags beside every important input. The active slot hash needs to say measured, unknown, malformed, stale, or rejected. Crash count and boot session need to say measured or unavailable. Boot tick and scheduler switches need to say which source produced them and whether that source was healthy. These tags need to be inside the signed canonical message, inside the hashed measurement input where relevant, and inside persistence records.

Policy then needs to decide what unknown means. A development machine may allow unknown measurements as diagnostic-only evidence. A production device may reject them, block remote transmission, or allow them only under a signed recovery policy. The important part is that unknown state cannot look like healthy state.

The test plan needs to prove that all-zero active slot hash is not accepted as verified evidence, malformed manifest hex is rejected instead of zeroed, unavailable architecture fields are labeled unavailable, stale OTA state is labeled stale, and remote attestation policy handles unknown evidence exactly as configured.

#### Fleet Architecture-Specific Evidence
Fleet architecture-specific evidence is how Oreulius keeps one platform's measurement from being confused with another platform's measurement. The Fleet bundle is currently built on both non-aarch64 and aarch64 targets, but some inputs do not mean the same thing on each architecture.

In the current code, this happens inside the Fleet bundle builder. Non-aarch64 builds read the boot tick from the RDTSC path, crash count from the crash log, and boot session from the crash log. Aarch64 builds read the boot tick from platform ticks, but crash count and boot session are set to zero because that crash source is not wired in on that architecture yet. The measurement hash then packs those values into the same fixed input layout, so the final SHA-256 measurement does not explain whether a zero came from a real measured value or from an unavailable source.

| Evidence field | non-aarch64 path | aarch64 path |
| --- | --- | --- |
| Boot tick | Reads the x86 RDTSC path through rdtsc_begin. | Reads platform ticks through vfs_platform ticks. |
| Crash count | Reads the crash log crash_count value. | Uses zero because that crash source is not wired in. |
| Boot session | Reads the crash log boot_session value. | Uses zero because that crash source is not wired in. |
| Scheduler switches | Reads scheduler snapshot total switches. | Reads scheduler snapshot total switches. |
| Active slot hash | Reads the OTA manifest-derived hash. | Reads the OTA manifest-derived hash. |

The important point is that a zero value does not always mean the same thing. On x86 or x86_64, a crash count of zero can mean the crash log source reported no crashes. On aarch64 today, a crash count of zero means the fleet path does not have that crash source. Those two cases need different evidence labels. The same applies to boot session. A real measured zero and an unavailable zero cannot be treated as equal fleet proof.

The boot tick source also differs by architecture. The non-aarch64 path uses RDTSC, while aarch64 uses platform ticks. Both can be useful as local runtime markers, but they are not the same clock, not the same unit, and not necessarily comparable across machines. A mature bundle needs to say which timer source produced the value and whether that timer source is monotonic, resettable, estimated, or diagnostic-only.

Fleet diagnostics already hints at this difference by printing that the crash log is not available on aarch64. The attestation bundle needs the same honesty inside the signed evidence. If diagnostics says a source is unavailable, but the signed bundle only contains zero, a verifier has to guess what happened. Production evidence should not require guessing.

The current signed Fleet message also does not include an architecture id, build id, timer-source label, crash-source label, or source-health label. That means two machines on different architectures can produce messages with the same field names even though some fields were produced by different mechanisms. For local diagnostics this is understandable, but for fleet attestation it is too ambiguous. The verifier needs to know not only the values, but also which platform produced them and which sources were actually available.

The mature model needs architecture id, build id, evidence-source metadata, timer-source metadata, crash-source metadata, and architecture support status inside the canonical fleet message. It also needs policy that says whether a given architecture is production-ready for fleet attestation or only allowed to produce diagnostic evidence. Until aarch64 crash state is real, aarch64 fleet evidence should mark crash count and boot session as unavailable rather than measured.

The test plan needs architecture-specific cases. It should prove that x86_64, x86, and aarch64 produce evidence with the right source labels, that unavailable fields do not hash the same way as measured zero fields, that unsupported architecture evidence is rejected or marked diagnostic-only under production policy, and that verifiers do not compare timer values across architectures as if they used the same source.


#### Fleet Capability Authority Model
The Fleet attestation path is authority-bearing because it can describe the kernel to an outside verifier. It can build a measurement, export a canonical message, import a trusted verification key, import a detached signature, verify the exported bundle, record attestation evidence in persistence, print diagnostics, and send an attestation frame through CapNet. Those are not all the same permission. A mature capability model needs to split them apart so a caller that can inspect local evidence does not automatically gain the authority to change trusted keys or transmit evidence to a peer.

In the current code, Fleet is mostly exposed through shell command functions. The attest command builds the bundle, writes the canonical message and text summary, records an attestation record, verifies the local detached signature state, and can optionally send a CapNet Attest frame. The export command writes local files. The verify command checks the exported detached signature. The trust-key command imports a trusted Ed25519 public key. The set-signature command imports a detached signature. The diagnostics command prints crash state, OTA state, measurement state, signature state, scheduler state, persistence usage, and CapNet peer state. That is useful for alpha-stage development, but in production these commands need to become capability-checked operations.

| Fleet right | What it allows in the mature model |
| --- | --- |
| FLEET_ATTEST | Build a local Fleet attestation bundle from current kernel evidence. |
| FLEET_EXPORT | Write the canonical message and human summary into Fleet export files. |
| FLEET_VERIFY | Verify a detached Fleet signature against the exported canonical message. |
| FLEET_IMPORT_KEY | Install or rotate the trusted Fleet Ed25519 verification key. |
| FLEET_IMPORT_SIGNATURE | Import a detached Fleet signature for the current exported bundle. |
| FLEET_RECORD | Append Fleet attestation records into the persistence log. |
| FLEET_TRANSMIT | Send Fleet attestation evidence to a remote peer through CapNet. |
| FLEET_DIAG | Read local diagnostic state for operator debugging. |
| FLEET_INTROSPECT | Read higher-detail Fleet internals, source labels, policy state, and record history. |
| FLEET_AUDIT | Write or inspect Fleet audit events. |
| FLEET_DELEGATE | Delegate a narrower Fleet right to another process or service. |
| FLEET_REVOKE | Revoke a Fleet authority that was previously granted. |

The important separation is between local evidence, trusted-key authority, and remote disclosure authority. Building a measurement is not the same as approving it for a peer. Verifying a detached signature is not the same as importing a new trusted key. Reading diagnostics is not the same as exporting the signed canonical message. The mature design needs these rights to be independently grantable, auditable, and revocable.

Remote transmission needs the narrowest scope. FLEET_TRANSMIT needs to bind the peer id, destination address, destination port, evidence type, freshness requirements, and policy mode. Otherwise a caller with local attestation access could send evidence to a peer it was never allowed to talk to. CapNet transmission also needs to carry the signed bundle, or a hash and signature over it, so the remote side receives evidence instead of only a control frame.

Key authority needs even stricter handling. FLEET_IMPORT_KEY is root-like for Fleet attestation because changing the trusted key changes what signatures the kernel accepts. That right needs to be rare, logged, policy-bound, and separated from ordinary diagnostics or verification. FLEET_IMPORT_SIGNATURE is also sensitive because it can change the apparent approval state of the exported bundle, but it is still less powerful than changing the trusted public key itself.

Fleet persistence also needs a real right. The current record path creates a store capability internally with broad store rights, then appends the record. The mature version needs a Fleet-specific record authority that decides who can record attestation evidence and what failures mean. In production, failed persistence append cannot be treated as a harmless side effect if the verifier depends on the record later.

The capability object for Fleet needs enough metadata to explain the authority being exercised. It should identify the owner process, the right set, the allowed peer or peer group, the allowed evidence class, the policy mode, the key generation, the freshness rules, the expiry time, and an audit label. That makes Fleet authority understandable in logs and prevents a generic attestation permission from silently becoming key management, diagnostics, or remote disclosure authority.

The current design has the right basic shape, but it still needs maturity work. Fleet commands need to stop being raw shell operations and become wrappers around capability-checked service calls. Every build, export, verify, key import, signature import, record append, diagnostic read, and CapNet transmit operation needs an explicit right check. The tests need to prove that diagnostics authority cannot import keys, local attestation authority cannot transmit remotely, verification authority cannot overwrite trust material, and transmit authority cannot send evidence to an unauthorized peer.

#### Fleet Diagnostics Output
Fleet diagnostics are the human-readable side of Fleet attestation. The diagnostics command is meant to give an operator a compact view of what the kernel currently thinks about crash state, OTA state, attestation state, scheduler state, persistence, and CapNet peers. It is useful because it lets a developer or operator understand why a Fleet measurement looks the way it does.

In the current code, fleet diagnostics print directly to the console. On non-aarch64 targets, the command reads crash count, boot session, and the number of live crash-ring entries. On aarch64, it prints that the crash log is not available on that architecture. It then reads the active OTA marker, prints the sizes of slot A and slot B, builds a fresh Fleet bundle, prints the measurement hash and active slot hash, checks the exported detached signature state, prints scheduler process and context-switch counts, prints persistence log usage, and counts registered CapNet peers.

| Diagnostic area | What the current command shows |
| --- | --- |
| Crash log | Crash count, boot session, and live crash-ring entry count when available. |
| OTA state | Active slot marker and the sizes of slot A and slot B. |
| Attestation | Fresh measurement hash, active slot hash, and exported signature status. |
| Scheduler | Total processes, running processes, and context-switch count. |
| Persistence | Current persistence log usage and capacity. |
| CapNet | Number of registered peers. |

This output is powerful because it crosses several trust boundaries at once. It can reveal whether a device has crashed, which OTA slot is active, how much update data is present, whether the exported bundle verifies, how active the scheduler is, how full the persistence log is, and whether CapNet peers are registered. That is exactly the kind of information an operator needs during debugging, but it is also information that should be controlled in production.

The diagnostic output also needs to line up with the signed evidence model. If diagnostics say that aarch64 crash state is unavailable, the signed Fleet bundle needs to represent that same unavailable state instead of only showing zero. If diagnostics print an active slot marker, the attestation bundle needs to make clear whether the slot hash came from verified active-slot metadata or from a weaker manifest-derived path. Diagnostics should help explain the evidence, not create a second unofficial version of it.

The mature model needs separate local diagnostics from remote attestation evidence. Local diagnostics can be more detailed for a trusted operator console. Remote evidence should be narrower, policy-shaped, and signed. The kernel needs to decide which fields are safe to print locally, which fields are safe to export, and which fields are only available under stronger introspection authority. In production, FLEET_DIAG should allow ordinary diagnostic reading, while FLEET_INTROSPECT should cover deeper internal state.

The current design has the right basic shape, but it still needs maturity work. Fleet diagnostics need to be capability-gated, redacted by policy, and audited. Sensitive details such as crash state, active slot state, signature status, scheduler load, persistence usage, and peer counts need production disclosure rules. Diagnostic reads need denied-access audit events, and tests need to prove that unauthorized callers cannot read diagnostics, that redaction works under production policy, and that diagnostic-only information is not accidentally treated as signed Fleet evidence.

#### Fleet Failure Behavior
Fleet failure behavior is about what the kernel does when attestation evidence cannot be built, exported, verified, recorded, or transmitted cleanly. For Fleet, this matters because a partial failure can make the system look healthier than it is. A failed signature check, missing manifest, malformed hash, failed persistence append, or failed CapNet transmission should not all be treated the same way.

The current code has a mixed failure model. Export failure is treated as serious in the main attest command: if the canonical message or text summary cannot be written, the command prints an export failure and stops. Bad peer id, bad IP address, missing port, malformed port, and out-of-range port also stop transmission. CapNet transmission failure is printed, but the local attestation work has already happened by that point.

| Failure area | Current behavior |
| --- | --- |
| Missing OTA manifest | Active slot hash becomes all zero. |
| Malformed OTA manifest hex | Invalid hex nibbles become zero nibbles. |
| Export write failure | Main attest command stops before recording or transmitting. |
| Persistence append failure | Append result is ignored after the record is built. |
| Missing key and missing signature | Verification reports unsigned. |
| Missing key with signature present | Verification reports an error. |
| Key present with signature missing | Verification reports an error. |
| Invalid detached signature | Verification reports an error. |
| CapNet send failure | Error is printed after local bundle export and record work. |
| Diagnostics read failures | Some fields become unknown or zero-sized values. |

The biggest issue is that some security-relevant failures are converted into normal-looking evidence. A missing manifest becomes an all-zero slot hash. Malformed manifest hex can produce partly zeroed bytes instead of rejected evidence. A failed persistence append does not stop the command from printing that the attestation record was written. Missing key and missing signature become unsigned, which can be acceptable for development, but production policy needs to decide whether unsigned evidence is fatal.

Fleet also needs to distinguish local failure from remote failure. If local export fails, there is no canonical message to sign or verify. If signature verification fails, the evidence may still be useful for local debugging but it is not verified fleet proof. If CapNet transmission fails, the local evidence may be valid but the peer did not receive it. Those outcomes need different status codes, audit records, and policy decisions.

The mature model needs fail-closed behavior for production trust decisions. Malformed evidence should be rejected, not normalized. Unknown measurements should be labeled unknown, not treated as healthy zero values. Failed persistence append should be security-relevant when auditability is required. Unsigned evidence should be allowed only under explicit development or diagnostic policy. Remote transmission should not claim success unless the signed evidence, freshness data, peer binding, and send result all line up.

The current design has the right basic shape, but it still needs maturity work. Fleet needs a typed failure model that separates missing, malformed, unavailable, unsigned, invalid signature, stale, rejected, persistence failure, export failure, and transmission failure. Each one needs a policy result, an audit result, and tests. Production mode needs to reject malformed or unauthenticated evidence, while development mode can keep printing useful diagnostics without pretending the evidence is verified.

#### Fleet Test Coverage
Fleet test coverage needs to prove more than whether the individual primitives work. The Fleet path is a composition of measurement gathering, SHA-256 hashing, canonical message formatting, detached Ed25519 verification, VFS export files, persistence records, diagnostics, capability authority, and CapNet transmission. A bug in any one part can make the final attestation look stronger than it really is.

The current code has useful lower-level tests, but Fleet-specific coverage is still thin. The signing-format helper has a test proving the Fleet canonical message is stable for one fixed input. The Ed25519 verifier has a basic RFC vector and a tampered-message rejection test. The crypto folder has primitive tests for pieces such as AES-GCM, HKDF, X25519, and SHA-512. That is a good start, but it does not prove the Fleet service behaves safely when OTA metadata is missing, malformed, stale, unsigned, replaced, or changing while the bundle is being built.

| Coverage area | What needs to be proven |
| --- | --- |
| Measurement inputs | Every field changes the measurement in the expected way, and missing or malformed inputs are labeled instead of hidden. |
| Active slot binding | The active slot hash comes from verified OTA active-slot metadata, not stale staged metadata. |
| Canonical message | Field order, schema version, decimal encoding, hex encoding, and domain string stay stable and strict. |
| Signature verification | Valid signatures pass, wrong signatures fail, malformed keys fail, malformed signatures fail, and unsigned policy is explicit. |
| Export files | Exported message, summary, key, and signature files cannot be replaced or verified as stale evidence without detection. |
| Persistence records | Successful, failed, unsigned, invalid, stale, unknown, transmitted, and diagnostic-only attestations are recorded correctly. |
| CapNet transmission | Remote evidence includes the signed bundle or signed bundle identity, freshness data, peer binding, and final send result. |
| Capability checks | Each Fleet right is enforced independently and cannot imply stronger authority. |
| Diagnostics | Redaction, unauthorized access denial, architecture-specific unavailable fields, and diagnostic-only labels are tested. |
| Failure behavior | Missing, malformed, unavailable, unsigned, invalid, stale, rejected, export, persistence, and transmission failures are typed. |

The Fleet measurement tests need to start with deterministic builders. The test harness should be able to inject boot tick, crash count, boot session, active slot hash, scheduler switches, architecture label, source-health labels, and policy mode. Then each field can be changed one at a time to prove the measurement changes only in the expected way. Tests also need to prove that measured zero is not the same as unavailable zero, and that malformed manifest hex cannot become partly zeroed evidence.

The canonical message tests need to be stricter than the current stable-string test. They need to cover missing fields, duplicate fields, changed field order, non-canonical decimal encodings, uppercase hex, malformed hex, trailing bytes, CRLF variants, wrong domain strings, wrong schema versions, and future unknown fields. A valid signature over a malformed or semantically incomplete message should not become production trust.

Signature tests need to happen at two levels. The Ed25519 primitive needs broader RFC 8032 vectors, malformed public key cases, malformed R values, non-canonical S values, small-order public keys, small-order R values, wrong-domain messages, and comparison against a known-good implementation in test builds. The Fleet wrapper also needs policy tests proving missing key, missing signature, malformed key, malformed signature, invalid signature, unsigned development policy, and unsigned production policy all produce the right outcome.

The service-flow tests need to exercise the command behavior without relying on a human console. Fleet attest, export, verify, trust-key, set-signature, diagnostics, persistence record append, and CapNet transmit all need harnessable service calls with observable results. That would let the test suite prove export write failure stops the right work, persistence append failure is not silently treated as success, CapNet send failure stays distinct from local attestation success, and diagnostics redaction follows policy.

The capability tests need to prove rights separation. FLEET_DIAG cannot import keys. FLEET_ATTEST cannot transmit remotely. FLEET_VERIFY cannot overwrite trusted material. FLEET_RECORD cannot read diagnostics or send to peers. FLEET_TRANSMIT cannot send to the wrong peer, wrong destination, wrong policy mode, stale evidence, unsigned evidence, or evidence that lacks freshness. These tests are what turn Fleet from a command surface into an authority-controlled service.

The architecture and failure tests need to be part of the main matrix, not side notes. x86, x86_64, and aarch64 evidence need source labels. Aarch64 crash count and boot session need to be unavailable until a real crash source exists there. Timer values from RDTSC and platform ticks cannot be compared as if they were the same clock. Failure tests need to cover missing manifest, malformed manifest, stale manifest, unsigned manifest policy, invalid active slot marker, source changes during measurement, failed export, failed persistence append, invalid signature, stale signature, failed send, and replayed remote evidence.

The mature test plan also needs fuzzing and adversarial input coverage. Fleet canonical message parsing, hex parsing, detached signature file parsing, OTA manifest parsing, CapNet attestation payload parsing, and persistence record parsing should all be fuzzed with malformed, oversized, truncated, duplicated, and mixed-line-ending inputs. The goal is not only to avoid crashes. The goal is to prove malformed evidence never downgrades into unsigned, unknown, diagnostic-only, or healthy evidence without an explicit policy decision.

The current design has the right basic shape, but it still needs maturity work. Fleet needs unit tests for the small helpers, integration tests for the service flow, policy tests for production versus development behavior, capability tests for rights isolation, architecture tests for source labels, persistence tests for auditability, CapNet tests for remote proof, and fuzz tests for every parser that can influence attestation trust. Until that exists, Fleet attestation should be treated as implementation-started rather than production-proven.

#### Other Security vulnerabilities not previously covered in the Fleet attestation path 
This extra scrub pass looked for problems that sit between the sections above. The main Fleet path has already been reviewed for active-slot binding, unknown measurements, canonical messages, signatures, persistence, CapNet transmission, capabilities, diagnostics, architecture-specific evidence, failure behavior, and tests. The remaining security risks are mostly composition bugs: places where two individually understandable pieces can still combine into a weak attestation story.

The first issue is that the Fleet measurement hash is a raw SHA-256 over a fixed 56-byte buffer. The buffer layout is stable in the code, but the hash input does not carry its own domain string, schema version, field tags, source-health labels, architecture label, or policy mode. That means the 32-byte measurement only has meaning if the verifier already knows the exact layout and the exact interpretation of each field. A mature measurement should be self-framed before hashing, so the hash itself is tied to Fleet attestation and not just to a sequence of numbers and bytes.

The second issue is the exported evidence race. The Fleet command builds a fresh bundle and writes the canonical message into the Fleet export file, but verification later reads the message back from VFS. Because the exported files are mutable VFS state, there is a window where the message, signature, or key can change between export, verification, diagnostics, and transmission. The existing write path is useful for development, but production needs an atomic evidence object or a locked export generation so the thing printed, recorded, signed, verified, and transmitted is the same thing.

The third issue is peer and destination confusion in remote attestation. The command accepts a peer id, IP address, and port from the shell, then asks CapNet to send an Attest frame for that peer. The current CapNet Attest frame carries no signed Fleet evidence, and the reviewed path does not prove that the destination address and port are the authorized endpoint for that peer id. That creates a future risk where evidence intended for one peer could be sent to another network destination, or where a peer id is treated as enough authority without binding it to a verified remote endpoint.

The fourth issue is that the persistence record is too implicit even aside from missing fields. The code comment says the AttestationRecord payload is 40 bytes, but the code writes 48 bytes: boot session, crash count, boot tick, and the 32-byte measurement. The generic log header records the payload length, but the Fleet payload itself has no Fleet magic, Fleet record version, schema id, field tags, final policy decision, or status code. That makes future replay and incident review fragile, because a reader has to know the exact old layout instead of decoding a self-describing Fleet attestation record.

The fifth issue is unthrottled attestation pressure. The attest command can build, export, record, and optionally transmit evidence each time it is invoked. The persistence log is finite, and CapNet transmission can be requested repeatedly. Without capability gating, rate limits, quotas, or backpressure policy, Fleet attestation can become a log-filling and network-spam surface. Even if the evidence is not trusted yet, a noisy caller can consume audit capacity, create misleading record volume, or pressure the network path.

The sixth issue is measurement width mismatch between Fleet and CapNet token structures. Fleet measurements are SHA-256 values, so they are 32 bytes. CapNet capability tokens currently have a measurement_hash field that is only 64 bits. That may be fine for a separate token-local fingerprint, but it is dangerous if future code tries to bind Fleet attestation into CapNet by truncating the Fleet measurement into that field. A production Fleet-to-CapNet binding needs either a full-width measurement field, an explicit signed evidence reference, or a collision-resistant object identity that does not silently reduce the Fleet measurement.

The seventh issue is that public helper shape can hide evidence quality. The build_measurement helper returns only a 32-byte measurement. It does not return whether the active slot hash was verified, unknown, malformed, stale, unavailable, or rejected. Any future caller that consumes only that hash can accidentally treat weak evidence as healthy evidence. The mature interface needs to return a structured evidence object, not just the digest, whenever the caller will make a trust decision.

These findings all point at one larger rule: Fleet attestation needs to move from loose files and raw hashes into typed evidence objects. A typed object can carry the measurement, source states, schema, signature status, policy result, key identity, peer binding, persistence identity, freshness data, and audit outcome together. That is what prevents a valid-looking hash from becoming stronger than the evidence that produced it.

## The Four Main Security Boundaries
There are four main security boundaries. These act as places where trust changes form. The network turns remote traffic into a local secure channel. Storage turns live kernel authority into durable bytes and later back into live state. Update turns external image bytes into code or system state the kernel may boot or activate. Attestation turns internal state into a claim that another machine, operator, or policy engine may trust.

Each of those boundaries also decides what happens when something goes wrong. A bad TLS record must not become plaintext. A tampered snapshot must not become restored authority. A forged update must not become the active slot. A stale attestation must not become current proof. That is why these four areas need the strongest crypto governance, the clearest capability rules, and the most adversarial tests.

They also connect to each other. OTA state is measured by Fleet. Persistence can store OTA and Fleet records. TLS or CapNet can carry attestation evidence. Capabilities decide who may connect, seal, update, attest, delegate, or inspect. So the crypto folder is not just a pile of primitives. It is the shared trust layer that these four boundaries use to make the rest of the kernel believable.

**Network boundary:** The network boundary is where untrusted remote bytes enter the kernel. In this review, that mostly means the TLS path and the TCP path underneath it. X25519, HKDF-SHA256, transcript hashing, Finished verification, and AES-128-GCM are supposed to turn an untrusted connection into a verified encrypted channel. This boundary is not mature until the kernel can prove the peer identity, bind the connection to NetworkResolve and NetworkConnect authority, reject malformed records, protect traffic keys, and issue a real TlsSession capability only after the handshake is trusted.

**Storage boundary:** The storage boundary is where trusted in-memory kernel state becomes bytes at rest. Persistence snapshots can contain temporal state, VFS state, service state, offsets, timestamps, and potentially authority-related data. AES-CTR and HMAC-SHA256 are used here to seal and authenticate snapshots, but the security boundary is larger than encryption. It also needs nonce freshness, seal-key lifecycle, rollback resistance, backend policy, snapshot capability rights, and fail-closed recovery behavior.

**Update boundary:** The update boundary is where new code or system images try to become trusted runtime state. In this review, that means the OTA path. SHA-256 binds image bytes to a manifest, Ed25519 verifies that the manifest was authorized, and the A/B slot model decides what can become active. This boundary is not mature until apply, verify, commit, rollback, trusted-key provisioning, version policy, active-slot metadata, and rollback sentinels are all authenticated, crash-safe, capability-gated, and audited.

**Attestation boundary:** The attestation boundary is where the kernel explains its state to another party. In this review, that means the Fleet path. SHA-256 creates the measurement, canonical signed messages describe the evidence, Ed25519 verifies detached signatures, persistence records keep the history, and CapNet is intended to carry evidence remotely. This boundary is not mature until evidence is typed, fresh, source-labeled, signed, peer-bound, capability-gated, recorded, and protected against replay or stale export confusion.

### The Sub-Boundaries outside of the four main security boundaries

#### Key Ownership Boundary

The key ownership boundary is where Oreulius decides which part of the kernel is allowed to create, hold, use, rotate, or destroy secret material. Right now, key ownership is started but not fully centralized. TLS owns private X25519 material and traffic keys inside TlsSession. Persistence owns the seal key through the security module and derives snapshot encryption and MAC keys from it. OTA and Fleet trust Ed25519 public keys stored in VFS files. CapNet has its own peer/session key material. These are all real trust points, but they are not yet governed by one kernel-wide key lifecycle model.

The mature version needs each key to have a clear owner, purpose, lifetime, rotation path, revocation path, and audit story. The persistence seal key cannot stay as a built-in development default for production. OTA and Fleet trusted public keys need protected provisioning instead of ordinary file replacement. TLS session keys need to be owned only by the verified session object and destroyed when the session closes or errors. The important rule is that raw key material must not become ambient authority. The service that owns the key should expose only the operation the caller is allowed to perform.

#### Nonce And Counter Boundary

The nonce and counter boundary is where the kernel prevents accidental reuse of cryptographic streams. This matters because AES-GCM and AES-CTR are both dangerous if the same key and nonce stream is reused. TLS builds record nonces by XORing a traffic IV with the read or write sequence number. Persistence uses AES-CTR with a snapshot nonce and updates an in-memory next snapshot nonce after writes and recovery. CapNet has replay nonces for peer control traffic. These pieces show the right direction, but nonce safety is not yet fully durable or globally enforced.

The main risk is that a counter can reset, wrap, or advance at the wrong time. In TLS, write sequence state currently advances when the record is encrypted, before the TCP send path proves the record was accepted. In persistence, the snapshot nonce is monotonic in memory, but it is not backed by a durable monotonic counter or hardware-backed freshness source. In Fleet and OTA, freshness is still mostly metadata-level, not a hard replay proof. The mature rule is simple: every nonce and counter must have a single owner, a no-reuse proof, a wrap limit, and tests that cover zero, one, high values, failed operations, reboot, recovery, and rollback.

#### Capability Delegation Boundary

The capability delegation boundary is where raw cryptographic power becomes a narrow operation right. Oreulius already has the right idea in its broader authority model, but several crypto paths still create or use authority internally instead of receiving a scoped capability from the global capability manager. Persistence has StoreCapability with append, read-log, write-snapshot, and read-snapshot rights, but services often create broad internal StoreCapability values for themselves. TLS has session handles and state, but the TlsSession itself is not yet a first-class capability object with separate connect, read, write, close, inspect, and delegate rights. OTA and Fleet commands are still largely command-accessible surfaces rather than strict capability-gated trust operations.

The mature version needs capability rights to wrap the trust-changing operation, not just the surrounding command. TLS_READ should not imply TLS_WRITE. OTA_SLOT_WRITE should not imply OTA_SLOT_ACTIVATE. FLEET_ATTEST should not imply FLEET_TRANSMIT. SNAPSHOT_SEAL should not imply SNAPSHOT_UNSEAL. Capability checks also need owner process, target object, target slot, target backend, expiry, generation, and audit label. That is what keeps crypto from becoming a universal tool that any kernel path can invoke without proving authority.

#### Signature Trust Boundary

The signature trust boundary is where Oreulius decides whether an external approval is real authority. OTA uses Ed25519 detached signatures over a canonical manifest message. Fleet uses Ed25519 detached signatures over a canonical attestation message. The Ed25519 primitive itself has important validation work, including canonical scalar checks and small-order checks, but the trust boundary is larger than the primitive. A valid signature only means something if the signed message contains the right context.

The current OTA signed message binds the image hash and version, but it does not yet bind the target slot, image class, target device, rollback generation, policy mode, key identity, or active slot state. The current Fleet signed message binds the measurement and a few inputs, but it still needs freshness, peer identity, verifier challenge, source-health labels, architecture identity, policy mode, and key identity where those affect trust. The mature rule is that signatures must be domain-separated, context-rich, policy-aware, and tied to the exact object that will be trusted. A signature over a hash is not enough if the same hash can be reused in the wrong slot, wrong device, wrong policy, or wrong time window.

#### Metadata Binding Boundary

The metadata binding boundary is where Oreulius prevents attackers from mixing individually valid pieces into a false whole. This shows up everywhere. OTA currently stores image bytes, manifest hash, version, signature, active slot marker, and rollback sentinel as related but separate pieces. Fleet reads the OTA manifest hash as an input, but that is not the same thing as reading verified active-slot metadata. Persistence seals a header and payload together, but backend identity, key generation, and snapshot purpose still need stronger framing. TLS stores host, port, server IP, SNI, negotiated keys, and session state, but those need to become one authority object.

The mature version needs authenticated metadata records that bind the pieces together before trust is granted. OTA needs one authenticated update record containing target slot, image hash, version, signature status, key identity, slot state, rollback generation, and policy mode. Persistence needs snapshot records that bind slot, backend, version, nonce, timestamp, seal key generation, purpose, and last offset. Fleet needs evidence records that bind measurement, sources, source health, policy decision, signature status, peer identity, and freshness. TLS needs session metadata that binds DNS resolution, TCP endpoint, SNI, certificate identity, negotiated TLS version, cipher suite, and session capability generation.

#### Recovery And Rollback Boundary

The recovery and rollback boundary is where old state tries to become current state again. This is one of the most important boundaries because HMACs and signatures can prove that something was once valid, but not that it is still the newest allowed state. Persistence snapshots can be authentic and still stale. OTA rollback can be useful and still dangerous if it switches to an old or unverified slot. Fleet evidence can be correctly signed and still replayed from an earlier system state. TLS sessions can have valid handles and still refer to stale or closed session objects if generation tracking is missing.

The mature model needs anti-rollback state for every trust path that accepts durable or remote evidence. Persistence needs durable monotonic snapshot generation and nonce freshness. OTA needs rollback-resistant active-slot metadata, signed version policy, commit intent and completion records, and verified rollback sentinels. Fleet needs freshness data and explicit stale evidence handling. TLS needs generation-bound session capabilities so a closed or reused slot cannot be mistaken for the original verified session. Recovery must be fail-closed in production: if the kernel cannot prove the restored state is current enough and context-correct, it should not silently accept it as trusted authority.

#### Audit And Evidence Boundary

The audit and evidence boundary is where Oreulius records what trust decision happened and why. Current logging exists, but it is still too thin for production security review. OTA records phase, slot, and hash. Fleet records boot session, crash count, boot tick, and measurement. Persistence records are append-only with CRC32 for accidental corruption, and snapshot sealing has crypto protection for snapshot payloads. These are useful starting points, but they do not yet capture enough context to reconstruct a security decision after the fact.

The mature audit model needs records that are self-describing, versioned, policy-aware, and tied to the caller authority. OTA audit needs version, key identity, policy mode, signature status, previous slot, target slot, rollback reason, and failure class. Fleet audit needs source health, freshness state, signature state, peer binding, transmission result, and whether the evidence was local, exported, or remote. Persistence audit needs seal, unseal, failed MAC, failed nonce, rollback rejection, backend fallback, and seal key generation. Audit append failure itself also has to become security-relevant in production, because a trust decision that cannot be recorded may not be acceptable.

#### Public API Boundary

The public API boundary is where the kernel decides which crypto functions are safe for broad callers and which ones must stay behind services. The crypto folder currently exports useful primitives such as SHA-256, HMAC-SHA256, HKDF, AES-CTR, AES-GCM, X25519, Ed25519, and signing helpers. That is convenient for development, but primitive access is not the same as safe authority. If any caller can choose keys, nonces, signatures, or metadata formats directly, then the caller can accidentally bypass the higher-level security rules.

The mature API shape should make the safe path easier than the raw path. Most kernel code should ask for operations like open TLS session, seal snapshot, verify OTA manifest, build Fleet evidence, or verify signed attestation. Raw AES-CTR, raw AES-GCM, raw key derivation, and raw signing-format helpers should either stay internal to trusted modules or be clearly marked as low-level primitives with strict caller rules. This boundary matters because many security failures come from using a correct primitive in the wrong mode, with the wrong nonce, wrong context, or wrong policy.

#### Secret Material Boundary

The secret material boundary is where the kernel prevents secrets from leaking after they have done their job. TLS stores private X25519 keys, handshake secrets, master secrets, traffic secrets, traffic keys, and IVs inside TlsSession. Persistence derives AES and MAC keys from the seal key. AES-CTR wipes expanded round keys after use, but not every secret-bearing buffer in the larger paths has a complete zeroization story. Debug traces also currently print pointer and nonce information for snapshot crypto, which is useful during bring-up but needs production policy.

The mature version needs explicit cleanup for private keys, shared secrets, derived traffic secrets, snapshot encryption keys, MAC keys, imported signing material, and temporary buffers. Session close and error paths should wipe TLS secrets. Snapshot seal and unseal paths should wipe derived keys after use. Imported key handling should avoid leaving stale copies in VFS scratch buffers or command buffers where possible. Secret material must not be cloneable, exportable, logged, or readable through diagnostic paths unless a specific capability and policy allows it.

#### Canonical Encoding Boundary

The canonical encoding boundary is where Oreulius makes sure that signed and hashed data has exactly one byte representation. The signing helpers already build simple canonical messages for OTA manifests and Fleet attestations, with domain strings and stable decimal and hex formatting. That is a good starting point. The weakness is that the format is still too small and mostly writer-side. There is not yet a strict parser that rejects duplicate fields, trailing data, unknown fields, wrong line endings, oversized messages, or semantically inconsistent values.

The mature version needs canonical schemas, not just canonical writers. OTA needs a manifest format where image hash, version, target slot, key identity, rollback generation, and policy mode have one legal encoding. Fleet needs a signed evidence format where measurement, source labels, source health, freshness, peer identity, architecture, and policy decision have one legal encoding. Persistence records need magic, version, schema id, field layout, and migration rules. Canonical encoding is what stops two byte strings from meaning the same thing, and it is also what stops one byte string from being interpreted two different ways by different parts of the kernel.

#### Failure Behavior Boundary

The failure behavior boundary is where Oreulius decides whether a trust failure stops the operation, becomes diagnostic-only, or is allowed during development. Right now, behavior varies by path. TLS rejects bad Finished data and bad GCM tags, but some malformed or unexpected records are ignored rather than becoming hard errors. OTA treats some unsigned states as warnings and verified-boot mismatches as logged failures rather than fatal production blockers. Fleet can report unsigned, invalid, unknown, or export failures, but those states are not yet tied to a production policy engine. Persistence rejects failed MAC checks, but durable write failures and backend fallbacks still need stronger policy treatment.

The mature model needs a clear failure table for each boundary. In production, bad TLS authentication should fail the session, tampered snapshots should not restore authority, unsigned OTA manifests should not commit, stale Fleet evidence should not verify as current proof, and audit failures should not be silently ignored when auditability is required. Development mode can remain more permissive, but the code needs an explicit policy switch so warnings do not accidentally become production behavior.

#### Test And Verification Boundary

The test and verification boundary is where the kernel proves that the design actually holds. The primitives already have some direct tests and vectors, including AES-GCM, HKDF, SHA-512, Ed25519, X25519, and canonical signing messages. CapNet also has fuzzing and formal self-check style obligations. The missing piece is composed security testing across the actual trust paths. Primitive tests do not prove TLS handshake correctness, OTA commit safety, persistence rollback resistance, or Fleet evidence freshness.

The mature test model needs end-to-end tests for each boundary and adversarial tests for each sub-boundary. TLS needs transcript, key schedule, record tamper, nonce, sequence, certificate, and session capability tests. Persistence needs snapshot seal and unseal tests for tampered headers, ciphertext, MACs, flags, nonce rollback, backend fallback, and recovery. OTA needs tests for apply, manifest, signature, commit, rollback, version policy, trusted key provisioning, active-slot metadata, crash recovery, and capability rights. Fleet needs tests for measurement inputs, canonical messages, detached signatures, stale exports, CapNet transmission, source-health labels, architecture differences, diagnostics, and failure classes. Fuzzing should cover parsers, hex input, signed messages, persistence records, TLS records, OTA manifests, and Fleet evidence.


## SHA-256 — FIPS 180-4

SHA-256 is the main public hash primitive in the crypto folder. It turns arbitrary bytes into a fixed 32-byte digest. In Oreulius, that digest becomes a stable identity for data that may later be verified, compared, signed, recorded, or measured. The OTA path uses SHA-256 to identify image bytes. Fleet uses SHA-256 to build measurement hashes. TLS uses SHA-256 for the handshake transcript and HKDF labels. Persistence uses SHA-256 as part of its current snapshot key derivation.

The implementation is a direct streaming SHA-256 construction. The Sha256 state keeps eight 32-bit chaining words, a 64-byte buffer, a buffer length, and a total byte count. Update accepts input in pieces, fills the current block, compresses full 64-byte blocks, and stores any remaining tail for later. Finalize applies the standard SHA-256 padding rule: append 0x80, zero padding, and the original message length in bits as a big-endian 64-bit value. The result is written as eight big-endian 32-bit words.

This is important because SHA-256 is not authority by itself. It proves identity of bytes, not permission to trust those bytes. A hash of an OTA image only matters if it is bound to a signed manifest, target slot, version, and policy. A Fleet measurement only matters if it is bound to source labels, freshness, signature state, and peer policy. SHA-256 gives Oreulius stable names for data, but the surrounding protocol decides whether those names become trusted.

## AES-128 — Over GF(2^8)

AES is the block cipher used when the kernel needs symmetric encryption. The README used to spell out the whole field math here; the practical point is that the code implements the AES state, key schedule, and round transformations directly.

The AES core expands a 16-byte key into the AES-128 round key schedule, then encrypts one 16-byte block through the normal AES round structure. The implementation has the pieces you would expect: SubBytes through the AES S-box, ShiftRows, MixColumns over GF(2^8), AddRoundKey, and the final round without MixColumns. That block primitive is then reused by higher-level modes, especially AES-GCM for TLS and AES-CTR for persistence snapshots.

AES as a block cipher does not decide how data is protected. The mode around it does. In TLS, AES is used through AES-128-GCM, which gives both encryption and authentication. In persistence, AES is used through CTR mode, which gives confidentiality but depends on HMAC-SHA256 for integrity. That distinction matters: AES alone is not a storage seal, not a TLS record layer, and not a capability. It is the block transformation underneath those higher-level security paths.

The current software AES path is useful for portability and kernel bring-up, but production maturity still needs attention around timing behavior and hardware acceleration. The S-box is table-based, which can be a cache-timing concern on some targets. A mature kernel profile needs either hardware AES where available or a software fallback with a clear side-channel policy.

## HMAC-SHA256 — RFC 2104

HMAC-SHA256 combines SHA-256 with a secret key so the kernel can authenticate data instead of only hashing it. It is used when the kernel needs a keyed integrity check.

The implementation follows the standard HMAC shape. If the key is longer than the SHA-256 block size, it is first hashed down to 32 bytes. The key is then placed into a 64-byte block and mixed with the inner pad and outer pad. The inner hash processes the padded key and message, then the outer hash processes the outer pad and the inner digest. The result is a 32-byte MAC.

The folder exposes both one-shot HMAC and a streaming HmacSha256 type. The streaming type is useful when a caller wants to authenticate data in pieces without building one large buffer first. There is also a truncated 16-byte output path, currently used by the persistence snapshot MAC format. That is convenient for compact records, but it is also a security design choice that needs to stay documented and tested.

In Oreulius authority terms, HMAC proves possession of a secret. A plain SHA-256 hash can be recomputed by anyone who has the bytes. An HMAC can only be recomputed by someone with the key. That is why HMAC is used for TLS Finished verification and persistence snapshot authentication. It lets the kernel reject data that does not come from the expected secret context.

## AES-128-GCM — NIST SP 800-38D

AES-GCM is the authenticated-encryption mode used when the kernel needs both confidentiality and integrity. It encrypts the data and attaches a tag that the receiver must verify before releasing plaintext.

The AES-GCM implementation combines AES-CTR encryption with GHASH authentication. For encryption, the code expands the AES key, derives the hash subkey by encrypting the zero block, builds the initial counter block from the 12-byte IV, encrypts plaintext with counter blocks starting at counter value two, and then computes the authentication tag over the associated data and ciphertext. The tag is then mixed with the encrypted initial counter block.

The decrypt path checks the tag before decrypting. It recomputes GHASH over the associated data and ciphertext, mixes it with the initial counter block, and compares the result with ct_eq. Only if the tag matches does it produce plaintext. That ordering is the important safety property: tampered TLS records do not become plaintext.

In the TLS path, AES-128-GCM protects records after traffic keys and IVs are derived. The associated data is the TLS record header, and the nonce comes from the traffic IV combined with the record sequence number. The security of this path depends on never reusing the same key and nonce pair. That is why the TLS sequence counter and record-limit rules are part of the crypto maturity work, not just networking details.

## GHASH over GF(2^128)

GHASH is the authentication part of AES-GCM. It combines the ciphertext and associated data into the tag that proves the data was not modified in transit.

The GHASH implementation works over 128-bit blocks in GF(2^128). It keeps a running 16-byte accumulator, XORs each padded block into that accumulator, and multiplies by the AES-derived hash subkey. It processes associated data first, then ciphertext, then a final length block containing the bit lengths of both inputs. That final length block prevents different splits of associated data and ciphertext from authenticating as the same stream.

GHASH does not encrypt anything. Its job is integrity inside AES-GCM. If a TLS record header, ciphertext byte, tag, or length changes, GHASH helps make the authentication tag fail. That failure has to be treated as a record-layer security failure, not as ordinary malformed input.

The current GHASH implementation is clear and compact, but production maturity needs side-channel review. GF(2^128) multiplication can leak information if the implementation branches or accesses memory based on secret-dependent values. In this code, the multiplication loop checks bits of its input, so the larger AES-GCM path needs a target-specific timing review before it becomes a hardened production primitive.

## HKDF-SHA256 — RFC 5869

HKDF expands a shared secret into keyed material the kernel can use for later crypto operations. It is the key-derivation step that turns one secret into several usable secrets.

The HKDF implementation has extract, expand, and a TLS-style expand-label helper. Extract uses HMAC-SHA256 to mix salt and input key material into a clean pseudorandom key. Expand uses repeated HMAC blocks to generate the requested output length. The TLS expand-label helper builds the TLS 1.3 label format with the tls13 prefix, a label, an output length, and optional context, then feeds that into expand.

TLS uses HKDF heavily. X25519 gives the handshake one shared secret, but TLS needs separate secrets for client handshake traffic, server handshake traffic, Finished keys, client application traffic, server application traffic, AES keys, and IVs. HKDF labels keep those outputs separated. A value derived with the key label is not the same thing as a value derived with the iv label, even when both come from the same traffic secret.

The current HKDF is useful and already has an RFC 5869 vector, but there are maturity caveats. The expand path truncates info to 255 bytes, and the TLS expand-label helper truncates labels and contexts to local fixed limits. That is fine for the current TLS labels, but production code needs explicit length rejection instead of silent truncation. Key schedules should fail when context is too long, because silent truncation can turn two different contexts into the same derived output.

## X25519 — Montgomery Ladder on Curve25519

X25519 is the key-exchange primitive the kernel uses when two sides need to derive the same shared secret. It is written in the Montgomery ladder form so the scalar multiplication stays structured and predictable.

The current x25519_montgomery module delegates the actual X25519 operation to x25519-dalek. It exposes three small entry points: a raw X25519 operation, public key generation from a private scalar using the base point, and shared-secret generation using the local private scalar and the peer public value. TLS uses this during the ClientHello and ServerHello exchange.

In the TLS path, Oreulius creates a private X25519 value, derives the public key, sends the public key in the ClientHello key share, then combines the private key with the server key share from ServerHello. The result is the shared secret that feeds the TLS HKDF key schedule. The shared secret is never supposed to be sent over the network or exposed to callers.

X25519 does not authenticate the server by itself. It only creates a shared secret with whoever supplied the peer key share. The server identity proof still has to come from the certificate and CertificateVerify path. The mature TLS path also needs all-zero shared secret rejection, stronger random private key generation, key-share group validation, and secret cleanup after the key schedule has consumed the shared secret.

## Ed25519 — Twisted Edwards Curve

Ed25519 is the signature scheme used when the kernel needs to verify that data came from the right key holder. The module implements the curve operations and the signature verification path directly.

The verifier decompresses the public key point, decompresses the signature R value, checks that the scalar S is canonical, rejects small-order public keys and R values, hashes R, the public key, and the message with SHA-512, and then checks the Ed25519 verification equation after multiplying both sides by the cofactor. The final point comparison uses ct_eq over compressed encodings.

Oreulius uses Ed25519 as the approval primitive for signed authority-bearing objects. OTA uses it to verify manifest approval. Fleet uses it to verify detached attestation signatures. The important thing is that Ed25519 verifies a message, not a policy. The signed message must already contain the context that makes the approval meaningful: domain, schema, hash, version, slot, peer, policy mode, key identity, freshness, or whatever the path needs.

The current verifier has good structural checks for a prototype, but production assurance needs more vectors and negative tests. It needs broader RFC 8032 coverage, malformed public key tests, malformed R tests, non-canonical scalar tests, small-order edge cases, wrong-domain tests, wrong-message tests, and comparisons against a known-good implementation during test builds.

## Merkle-Damgård Domain Separation

This section explains how the kernel keeps hash inputs separated when it needs distinct hashes for different object types. The point is to avoid treating two different structures as the same just because their byte layout looks similar.

The domain-separated hash helper prefixes the hash input with a fixed marker, the domain length, the domain bytes, and the payload length before hashing the payload. Leaf and node helpers build on that by tagging leaves with zero and internal nodes with one, then hashing through the same domain-separated path. This gives Oreulius a simple way to say that a leaf hash, node hash, signed payload hash, and future tree hash are not interchangeable just because they all end as 32-byte SHA-256 digests.

This matters anywhere hashes become authority. A digest used as an OTA image identity should not be confused with a Fleet measurement, a tree node, a transcript value, or a persistence payload identity. Domain separation gives each hash a purpose label before the bytes are compressed. That makes cross-protocol confusion harder.

The current helper is a good base, but the maturity rule is that every authority-bearing hash needs an explicit domain, schema version, and field framing. A bare SHA-256 digest is fine for local byte identity, but once the digest enters signing, attestation, capability records, or persistence recovery, it needs context around it.

## Constant-Time Equality

We already discussed constant-time equality earlier in the README when reviewing the OTA and Fleet paths. This section is the deeper technical dive into what that helper is doing and why it matters. The helper compares two byte slices without stopping at the first mismatch. Instead of returning as soon as one byte differs, it walks the whole input and accumulates every byte difference into one value. If that final accumulated value is zero, the inputs are equal. If it is nonzero, at least one byte differed.

That shape matters because ordinary equality can leak where a mismatch happened. If comparison stops early, an attacker who can measure timing may learn whether the first byte matched, then the second byte, then the third byte, and so on. Constant-time equality avoids that class of leak by doing the same kind of work for every byte in equal-length inputs. It does still reject different lengths immediately, so callers need to keep security-sensitive values at fixed lengths before comparing them.

Oreulius uses this helper where equality itself is part of a trust decision. AES-GCM uses it to compare authentication tags before releasing plaintext. The Ed25519 path uses it for field and point comparisons. OTA uses it when comparing expected and actual image hashes. Persistence uses it when checking snapshot MACs. Fleet needs it anywhere a measurement, signature result, or evidence identity comparison becomes security-relevant.

The maturity rule is that constant-time equality is only one piece of the boundary. It prevents byte-position timing leaks in fixed-length comparisons, but it does not prove the compared values are fresh, correctly framed, signed, or authorized. A hash comparison can be constant-time and still be the wrong hash for the wrong slot. A tag comparison can be constant-time and still be unsafe if the nonce was reused. So this helper is necessary, but the surrounding metadata, nonce, capability, and failure policy still carry the real authority model.

## Signing Formats

The signing formats file covers the small canonical message helpers the kernel uses when it needs to verify signed data loaded from storage. It is used by the OTA path for signed update manifests and by the Fleet path for signed attestation evidence. The purpose is to turn security-relevant fields into one deterministic byte string before Ed25519 verification.

The current file is small, but it sits on an important authority boundary. It does not implement Ed25519 itself. Instead, it prepares the exact message bytes that Ed25519 will verify, loads public keys and detached signatures from VFS-backed files, parses those files from hex, and returns whether the signed object is unsigned, verified, or invalid. That makes it the bridge between raw signature verification and the higher-level OTA and Fleet policy paths.

The current status is prototype-complete for simple signed artifacts. It can build an OTA manifest message from an image hash and version string. It can build a Fleet attestation message from boot session, crash count, boot tick, measurement hash, active slot hash, and scheduler switch count. It can import a hex public key or signature from one VFS path and normalize it into another VFS path. It can also verify a detached Ed25519 signature over caller-provided message bytes. That is enough to prove the basic shape of signed OTA and signed Fleet evidence.

The limitation is that the helper currently treats storage files as the trust interface. Public keys, signatures, and exported messages live in ordinary paths such as OTA manifest key files or Fleet attestation files. That is convenient for alpha development, but mature trust material needs stronger ownership than ordinary VFS replacement. The signing layer needs to become part of a protected evidence object model, where the message, signature, key identity, policy mode, generation, and audit record are bound together.

There is also a parser strictness problem. The hex parser requires at least the needed number of hex characters, but it does not require the file to contain exactly that amount and nothing else. The small-file helper reads only up to a maximum size, which means an oversized signed message can be truncated before verification unless the caller checks the size first. The detached verification helper also collapses key-read and signature-read failures into missing values. That makes it harder to distinguish a truly unsigned artifact from malformed or unreadable trust material.

For production maturity, the signing formats layer needs strict modes. Trusted public keys and signatures need exact length checks. Oversized canonical messages need to be rejected before verification. Malformed files need to be a different result from missing files. Signed messages need schema-aware parsers, not only writers. Verification needs to prove that the signed bytes are not just valid Ed25519 input, but also valid OTA manifest evidence or valid Fleet attestation evidence under the active policy.

### Detached Signature Pattern

The detached signature pattern keeps the signed message, public key, and signature as separate inputs. The helper loads the public key and signature from VFS-backed hex files, parses them into fixed-size byte arrays, and then verifies the provided message with Ed25519. If both the public key and signature are missing, the result is treated as unsigned. If one exists without the other, the result is an error. If both exist, the signature must verify against the exact message bytes.

That three-way behavior is important because it prevents a partial trust state from looking clean. A trusted public key without a signature is not a valid signed object. A detached signature without a trusted key is not a valid signed object either. Removing only one file should not downgrade a failed signed state into a harmless unsigned state.

The limitation is that this pattern is still storage-file based. The trusted key, signature, and exported message can be replaced through ordinary VFS paths unless a higher-level capability and storage policy protects them. The mature design needs these detached-signature pieces to be treated as one evidence object with a generation, key identity, policy mode, and audit trail.

### Canonical Message Formats

The canonical message builders are writer-side helpers. They do not parse or validate a full signed object yet. Their job is to take fields already chosen by the caller and serialize them in a stable order. The OTA message starts with an Oreulius OTA manifest domain string, then writes the image hash as lowercase hex and the version as text. The Fleet message starts with an Oreulius Fleet attestation domain string, then writes boot session, crash count, boot tick, measurement, active slot hash, and scheduler switches in a stable text format.

The reason this is text-line encoded is that it avoids struct padding and endianness confusion. Decimal values are written as plain decimal ASCII. Hashes are written as lowercase hex. Fields are written in one order. The same inputs produce the same byte string each time, which is required for signing and verification to agree.

The maturity gap is that stable writing is not the same thing as complete canonical verification. A production verifier needs to parse the message, reject duplicate fields, reject missing fields, reject unknown fields under strict schema, reject non-canonical numbers, reject malformed hex, reject trailing data, and recompute any embedded measurement or hash relationship. Without that, the kernel can verify a signature over bytes but still not fully understand whether those bytes represent valid authority.

The OTA message also needs more context before it is production-ready. The signed message needs to include target slot, image type, target device, rollback generation, policy mode, key identity, and slot state where those fields affect update authority. The Fleet message needs source-health labels, architecture identity, peer identity, freshness, verifier challenge, policy mode, and key identity where those fields affect attestation authority. These fields are what keep a valid signature from being replayed into the wrong context.

## Public API Summary

The public API groups the hash, MAC, encryption, key-exchange, and signature helpers into one module so kernel callers do not need to know where each primitive lives.

In the current code, the crypto module is both a namespace and a convenience layer. It publicly exposes the primitive modules themselves, and it also re-exports the main helpers that the rest of the kernel is expected to call directly. That means callers can reach SHA-256, SHA-512, HMAC-SHA256, HKDF-SHA256, AES-128 block encryption, AES-CTR, AES-128-GCM, X25519, Ed25519 verification, domain-separated hashing, constant-time equality, and signing-format helpers from the same crypto entry point.

That shape is useful during alpha because the kernel can wire TLS, persistence, OTA, and Fleet attestation without every caller knowing the internal file layout. The network path can ask for X25519, HKDF, transcript hashing, and AES-GCM. The persistence path can ask for AES-CTR, HMAC, SHA-256, and constant-time comparison. The OTA and Fleet paths can ask for canonical signed-message builders, detached Ed25519 verification, hash comparison, and domain-separated measurement helpers. The public API is therefore acting as the shared toolbox for every place where bytes become trust.

The important maturity issue is that this public surface is still too raw. Many helpers expose primitives directly instead of exposing policy-safe operations. A caller can request AES-CTR with a chosen nonce, call HKDF with caller-chosen labels, parse public keys from ordinary VFS files, or verify an Ed25519 signature without the API itself knowing which capability, slot, backend, peer, key generation, or policy mode is involved. That is acceptable for a prototype review surface, but it is not the final authority boundary.

The mature version needs a narrower safe API above the raw primitives. TLS callers need session-bound operations such as connect, read, write, close, and introspect instead of direct access to traffic keys and sequence counters. Persistence callers need seal and unseal operations scoped by snapshot slot and backend instead of direct control over encryption keys, MAC keys, and nonces. OTA callers need apply, verify, commit, rollback, and audit operations scoped by slot capability instead of loose file reads and standalone signature checks. Fleet callers need build, sign, verify, export, transmit, and record operations scoped by attestation capability instead of directly assembling evidence from mutable files.

The raw primitive functions can still exist, but they need to be treated as internal building blocks. Production code needs capability-aware wrappers that own key lifecycle, nonce construction, metadata binding, strict parsing, audit outcomes, and failure behavior. The public API should make the safe path easy and the dangerous path hard to reach, because cryptographic correctness in Oreulius is not only about whether a primitive computes the right bytes. It is about whether those bytes are tied to the right authority at the right boundary.

---

## Security Guarantees and Design Constraints

This section keeps the crypto rules blunt: what is protected, what is limited, and what callers still need to handle themselves.

The crypto folder gives Oreulius the raw ability to hash data, authenticate data, encrypt data, derive keys, exchange secrets, verify signatures, and compare security values without obvious timing leaks. Those are real building blocks, but they are not full security boundaries by themselves. A primitive can be correct and still be used in the wrong place, with the wrong key, with the wrong nonce, or without the right authority check.

The guarantee at this layer is mostly mathematical and byte-level. SHA-256 and SHA-512 produce stable digests. HMAC-SHA256 proves that someone with the right key authenticated the same bytes. HKDF-SHA256 turns one secret into purpose-specific derived keys. AES-CTR encrypts a byte stream when its key and nonce are unique. AES-GCM encrypts and authenticates records when its key, IV, associated data, and sequence rules are correct. X25519 produces a shared secret with a peer public key. Ed25519 verifies that a signature matches a message and public key. Constant-time equality compares fixed-size security values without leaking which byte differed first.

The constraint is that the primitives do not automatically know the kernel policy around them. They do not know who owns the key, whether the caller had authority, whether the nonce was already used, whether a version is stale, whether a slot is active, whether a peer identity is trusted, or whether a failure should be fatal. Those rules belong to the TLS, persistence, OTA, Fleet, capability, and audit layers that call into this folder.

### Constraint Table

The constraint section used to be a table, but the real point is that each primitive comes with a small set of explicit limits rather than pretending everything is unlimited.

| Primitive | What it protects | What callers still have to handle |
| --- | --- | --- |
| SHA-256 and SHA-512 | Stable byte identity and transcript or measurement hashing | Domain separation, field framing, freshness, and whether the measured bytes are the right bytes |
| HMAC-SHA256 | Keyed integrity over a message | Key ownership, key rotation, key erasure, and exact message framing |
| HKDF-SHA256 | Purpose-specific key derivation from a shared or root secret | Salt choice, label choice, context binding, output limits, and key schedule documentation |
| AES-CTR | Confidentiality for snapshot-like byte streams | Nonce uniqueness, counter wrap prevention, authentication, rollback protection, and caller authority |
| AES-128-GCM | Confidentiality and integrity for records | Unique IVs, sequence limits, associated data correctness, record-size limits, and fail-closed behavior |
| GHASH | Authentication tag construction inside AES-GCM | Constant-time backend choice, correct AAD framing, and never using it as a standalone MAC |
| X25519 | Shared-secret agreement with a peer public key | Peer authentication, all-zero shared-secret rejection, private-key generation, and secret cleanup |
| Ed25519 | Signature verification over exact message bytes | Trusted key provisioning, key purpose, key identity, canonical message parsing, and policy enforcement |
| Constant-time equality | Fixed-length comparison without early byte mismatch leaks | Fixed input lengths, correct value selection, and surrounding freshness or authority checks |
| Signing formats | Stable signed message construction for OTA and Fleet evidence | Strict parsing, complete metadata binding, protected trust files, and capability-gated import or verification |

### Primitive Composition in the Kernel

The kernel composes primitives in simple chains, such as hash plus key plus tag, so each higher-level operation has a clear crypto basis.

TLS is the clearest network example. X25519 gives the handshake a shared secret, HKDF-SHA256 expands that secret into traffic keys, SHA-256 binds the handshake transcript, HMAC-SHA256 supports Finished verification, and AES-128-GCM protects records after the keys are installed. The composition only becomes secure when the TLS state machine also verifies the peer, tracks sequence numbers, separates read and write keys, and refuses bad records before plaintext reaches the rest of the kernel.

Persistence composes primitives differently. A seal key becomes purpose-specific snapshot keys through derivation. AES-CTR provides encryption for snapshot bytes, HMAC-SHA256 authenticates the sealed data, SHA-256 can identify payloads, and constant-time equality checks MACs or hashes. That composition only becomes mature when the persistence layer owns nonce construction, rollback protection, snapshot metadata, key generations, and store capabilities.

OTA uses signatures and hashes as the update trust path. SHA-256 identifies the image, signing formats build the canonical message, Ed25519 verifies the detached signature, and constant-time equality compares expected and actual image hashes. That composition only becomes safe when the manifest binds the target slot, version, rollback generation, key identity, policy mode, and commit state into one authenticated update record.

Fleet attestation uses a similar pattern for evidence. SHA-256 builds measurement identity, signing formats create the canonical attestation message, Ed25519 verifies detached evidence, and persistence records make the result auditable later. That composition only becomes meaningful when the evidence is fresh, peer-bound, architecture-labeled, policy-labeled, and protected from ordinary VFS replacement.

So the design rule is simple: primitives compute, but paths decide. Crypto gives the kernel trustworthy operations over bytes. The surrounding path decides what those bytes mean, who was allowed to produce them, whether they are current, and what happens when verification fails.

### Known Limitations

The current implementation is still intentionally alpha-level. It has real primitives, but it does not yet have the full governance layer that production crypto needs. The main limitation is not just missing algorithms. It is missing ownership, lifecycle, and misuse resistance around the algorithms that already exist.

AES is currently implemented in software. That keeps the code portable, but table-based AES can have timing and cache-side-channel concerns on real hardware. A mature build needs hardware AES where available, a reviewed constant-time fallback where hardware support is not available, and a clear policy for which backend is allowed in production.

AES-GCM and AES-CTR depend on nonce and counter discipline. The primitive functions can perform encryption, but the production guarantee depends on callers never reusing nonces and never allowing counters to wrap. That means TLS, persistence, and any future encrypted channel need hard record limits, sequence limits, and key rotation rules above the primitive.

HKDF is useful only when labels and context are precise. The current helpers support key expansion, but production paths need documented key schedules. TLS, persistence, OTA, Fleet, and future capability sealing should each describe which secret is being derived, which label is used, what context is bound, and when old keys are erased.

Ed25519 currently provides verification, not kernel-side signing. That is the right shape for OTA and Fleet today because the kernel mostly needs to verify external authority. The limitation is that verification still needs protected key provisioning, key identity, key purpose, revocation, and strict canonical message parsing before signatures can carry production authority.

Constant-time equality is available, but it only solves one narrow problem. It helps fixed-size comparisons avoid leaking the first differing byte. It does not make the compared values fresh, correctly framed, authorized, or tied to the right policy. Every caller still needs to prove it is comparing the right value for the right object.

The signing-format helpers are useful, but still too file-oriented and parser-light. They need exact length checks, strict canonical parsers, structured error results, capability-gated imports, protected trust stores, and audit-aware verification outcomes before they can become the mature signed-object layer for OTA and Fleet.

The final limitation is test coverage. The folder has important test scaffolding and known-answer tests, but production maturity needs broader vectors, adversarial malformed-input tests, fuzzing, strict parser tests, misuse tests, cross-path tests, and architecture-specific tests. In this folder, correctness is not only whether the happy path works. It is whether malformed, stale, replayed, oversized, wrong-key, wrong-domain, wrong-slot, and unauthorized inputs fail in the right way.


## Mathematical derivation across all the code to make sure it is correct

### The plan for how we are going to derive 
We need to do this in the most mathematically honest way possible. That means we do not just say the code “implements AES” or “implements SHA-256” and move on. We check the constants, the state transitions, the padding rules, the field arithmetic, the byte order, the counter construction, the domain strings, and the way each primitive is composed into TLS, persistence, OTA, and Fleet attestation. The goal is to prove what the code actually does, not what we hope it does.

The right method is to move from the smallest pieces outward. First, verify the primitive math against the standard it claims to follow. Second, verify the code-level representation of that math, such as arrays, rotations, endianness, finite-field reduction, scalar clamping, and canonical encodings. Third, verify the Oreulius-specific composition rules, such as which bytes become associated data, which fields are signed, which nonces are built from counters, which keys are derived from which root secret, and which capability boundary owns the operation.

This section should not pretend that a derivation is complete just because a test vector passes. Test vectors prove important cases, but the derivation has to explain why the general algorithm is correct, where the implementation has limits, and what assumptions the caller must keep true. When a primitive depends on a caller-owned rule, such as nonce uniqueness or peer authentication, the derivation has to say that directly. That is what keeps the proof honest.

### Derivation and Correctness Check: AES Primitives And Oreulius-Specific Constants

The AES core in Oreulius is AES-128 encryption only. That means the block size is 16 bytes, the key size is 16 bytes, the number of rounds is 10, and the expanded key schedule is 16 times 11 bytes, or 176 bytes total. Those values match the AES-128 shape from FIPS 197: one initial AddRoundKey step, nine full rounds, and one final round.

The S-box table used by the code is the standard AES S-box. That table is the nonlinear substitution step used in both SubBytes and the key schedule SubWord step. The round constants are the AES-128 Rcon sequence: 01, 02, 04, 08, 10, 20, 40, 80, 1B, and 36. Those constants are exactly the ten key-schedule constants needed for ten AES-128 rounds.

The key expansion starts by copying the original 16-byte key into the first round-key slot. After that, every new word is derived from the word 16 bytes earlier and a temporary 4-byte word. At each 16-byte boundary, the temporary word is rotated left by one byte, each byte is passed through the AES S-box, and the first byte is XORed with the next Rcon value. The code then XORs that transformed word with the word from the previous round-key column. This is the AES-128 key schedule: RotWord, SubWord, Rcon, then chained XOR expansion.

The state layout is column-major, which matches AES. In that layout, bytes 0, 1, 2, and 3 are the first column, bytes 4, 5, 6, and 7 are the second column, and so on. The ShiftRows implementation confirms this layout. Row zero keeps positions 0, 4, 8, and 12 in place. Row one rotates positions 1, 5, 9, and 13 left by one. Row two rotates positions 2, 6, 10, and 14 left by two. Row three rotates positions 3, 7, 11, and 15 left by three. That is the AES ShiftRows transform expressed over the column-major byte array.

MixColumns is implemented with the standard AES optimized form. For each column, the code takes the four bytes, computes their XOR as a shared term, and uses multiplication by 2 in the AES byte field to build the transformed column. The helper for multiplication by 2 shifts left and conditionally XORs 1B when the high bit was set. That corresponds to reduction by the AES field polynomial after multiplying by x. So the MixColumns step is doing the normal AES linear column transform over GF(2^8).

The encryption path is the standard AES encryption schedule. It first applies round key zero. Rounds one through nine perform SubBytes, ShiftRows, MixColumns, and AddRoundKey. The final round performs SubBytes, ShiftRows, and AddRoundKey without MixColumns. That final omission is required by AES, so the code has the correct round shape rather than simply repeating the full round ten times.

Oreulius reuses this AES block primitive in two places. AES-CTR expands the key once, builds a 16-byte input block from a 64-bit nonce and a 64-bit counter in little-endian order, encrypts that block, and XORs the result with the data stream. AES-GCM also expands the key and uses AES block encryption to derive the GHASH subkey and record keystream blocks. So the AES primitive is the shared block-cipher core under both persistence encryption and TLS record protection.

The correctness conclusion is that the AES-128 primitive has the right mathematical structure for AES encryption: standard constants, standard key expansion, standard column-major state transforms, standard full rounds, and standard final round. The implementation still has production limitations. It is software AES using table lookups, so it needs hardware AES or a reviewed constant-time fallback for hardened builds. AES-CTR currently owns an Oreulius-specific nonce and counter encoding that must never repeat under the same key. AES-GCM and AES-CTR both rely on callers to enforce higher-level key, nonce, counter, and record limits. The AES core can be correct while the composed encryption path is unsafe if those surrounding rules are not enforced.

### Derivation and Correctness Check: AES-CTR Counter Mode

This check needs to prove how the 64-bit nonce and 64-bit counter are encoded into the AES input block, how the keystream is XORed with snapshot bytes, and where counter wrap becomes unsafe. The correctness argument is simple only if every nonce and counter pair is unique under the same key.

### Derivation and Correctness Check: AES-GCM Record Protection

This check needs to verify the GCM counter block construction, the starting counter value, the AES keystream use, the authentication tag construction, the associated-data binding, and the decrypt-before-release rule. It also needs to derive the exact record limits that prevent counter exhaustion.

### Derivation and Correctness Check: GHASH Over GF(2^128)

This check needs to verify the polynomial field representation, the reduction polynomial, block ordering, length-block encoding, AAD handling, ciphertext handling, and how GHASH combines with AES output to form the final GCM tag.

### Derivation and Correctness Check: SHA-256

This check needs to verify the initial hash constants, round constants, message schedule, compression function, padding rule, big-endian length encoding, streaming update behavior, and one-shot wrapper behavior. It also needs to address the current length-accounting limits.

### Derivation and Correctness Check: SHA-512

This check needs to verify the 64-bit SHA-512 constants, schedule expansion, compression rounds, padding rule, length encoding, streaming behavior, and the way SHA-512 supports Ed25519 verification.

### Derivation and Correctness Check: HMAC-SHA256

This check needs to derive the HMAC construction from key normalization, inner pad, outer pad, inner digest, and final digest. It also needs to verify streaming HMAC behavior, truncated output behavior, and the rule that HMAC security depends on secret key ownership.

### Derivation and Correctness Check: HKDF-SHA256

This check needs to verify extract, expand, block chaining, output length limits, info handling, and TLS-style expand-label formatting. It also needs to map Oreulius key schedules onto HKDF labels and contexts instead of treating derivation as generic byte expansion.

### Derivation and Correctness Check: X25519 Key Agreement

This check needs to verify scalar clamping, Montgomery ladder behavior, public-key derivation, shared-secret derivation, byte order, and all-zero shared-secret rejection. It also needs to separate the raw Diffie-Hellman result from authenticated peer identity.

### Derivation and Correctness Check: Ed25519 Verification

This check needs to verify point decompression, canonical encoding, scalar bounds, group equation checking, cofactor handling, SHA-512 message hashing, and final point comparison. It also needs to explain why verification alone is not the same thing as trusted authority unless the public key and message format are trusted.

### Derivation and Correctness Check: Constant-Time Equality

This check needs to verify that equal-length comparisons examine every byte and only decide after accumulating all differences. It also needs to state the limit clearly: different lengths return early, so callers must keep security-sensitive comparisons fixed-size.

### Derivation and Correctness Check: Merkle-Damgård Domain Separation

This check needs to verify the domain framing, payload framing, leaf hashing, node hashing, and collision-separation goal. It also needs to verify that long domains are not silently collapsed into the same effective domain in production paths.

### Derivation and Correctness Check: Signing Formats And Canonical Messages

This check needs to verify the exact bytes produced for OTA and Fleet signed messages, including field order, decimal encoding, lowercase hex encoding, newlines, domain headers, and required metadata. It also needs to verify strict parsing, not only strict writing.

### Derivation and Correctness Check: TLS Primitive Composition

This check needs to verify the full TLS chain from X25519 shared secret, through HKDF traffic keys, transcript hashing, Finished verification, read and write traffic separation, nonce construction, record sequence counters, and AES-GCM record protection.

### Derivation and Correctness Check: Persistence Primitive Composition

This check needs to verify how the seal key derives snapshot keys, how AES-CTR encrypts snapshot bytes, how HMAC-SHA256 authenticates sealed records, how nonces are constructed, and how rollback protection binds persisted state to a current generation.

### Derivation and Correctness Check: OTA Primitive Composition

This check needs to verify how the image hash, canonical manifest, detached Ed25519 signature, target slot, version, rollback state, commit state, and constant-time hash comparison combine into one update trust decision.

### Derivation and Correctness Check: Fleet Attestation Primitive Composition

This check needs to verify how measurement inputs become a SHA-256 measurement, how the canonical Fleet message is built, how detached Ed25519 verification proves evidence origin, how freshness is represented, and how the result is recorded or transmitted.

### Derivation and Correctness Check: Public API And Capability-Safe Wrappers

This check needs to verify that the public API exposes the right level of abstraction. Raw primitives can be mathematically correct while still being unsafe to call directly from policy code. The final derivation needs to show which operations remain raw internals and which operations become capability-aware wrappers.

### The results of the derived tests

We ran the derivation tests in a separate host-side crate located at `/cryptography-tests-backend`. This crate exists outside the kernel runtime so the cryptographic math can be tested directly, repeatedly, and without depending on boot flow, device state, scheduler behavior, or kernel shell execution.

The goal of these tests was not only to check that the functions return expected values. The goal was to verify that the mathematical shape of each primitive and composition path matches the derivation plan above. That means the tests check constants, byte order, field arithmetic, state layout, counter construction, canonical message bytes, key separation, authenticated metadata, rollback behavior, and capability-safe wrapper rules.

The first focused run executed 24 AES and AES-CTR derivation tests. That run completed with 22 passing tests, 0 failing tests, and 2 ignored future-direction tests. The ignored tests were intentionally marked as future work: one for hardware AES versus software AES side-channel backend policy, and one for older AES-CTR derivation placement that has since been superseded by the full CTR derivation test group.

The larger derivation suite then executed 73 tests across the full cryptographic composition surface. That run completed with 73 passing tests, 0 failing tests, and 73 total tests. This gives us a clean host-side correctness checkpoint for the current derivation work.

These results show that the AES-128 primitive matches the expected AES-128 structure. The tests verify the AES constants, S-box sample points, key expansion against the FIPS 197 Appendix A.1 vector, ShiftRows over the column-major state layout, MixColumns against the FIPS 197 example, finite-field multiplication by 2 using the AES reduction rule, and AES-128 block encryption against the FIPS 197 Appendix C.1 vector. This confirms that the AES core is not only shaped like AES-128, but also agrees with known standard reference material at the constant, schedule, transform, and block-encryption levels.

The AES-CTR derivation tests verify how Oreulius constructs the counter-mode input block. The nonce is encoded into bytes 0 through 7 in little-endian order, and the counter is encoded into bytes 8 through 15 in little-endian order. The tests also verify that the keystream block equals AES encryption of the nonce-counter block, that XOR is self-inverse, that encryption and decryption round-trip correctly, that partial final blocks only XOR the remaining bytes, and that empty input is a no-op.

The CTR tests also include negative-security behavior that must remain documented. The suite verifies that nonce reuse under the same key leaks the XOR of the plaintexts. It also verifies that counter wrap at `u64::MAX` repeats the keystream from block zero. These are not success properties of CTR as a safe protocol. They are explicit demonstrations of the caller-owned rules that must be enforced above the primitive: a nonce and counter stream must not repeat under the same key.

The SHA-256 and SHA-512 tests verify known digest behavior for empty input and `abc`. These are basic but important derivation anchors because they confirm that the one-shot hash wrappers match standard digest outputs for canonical test cases. SHA-512 is especially important because it supports the Ed25519 verification path, while SHA-256 supports domain-bound hashing, manifest hashes, measurement hashes, and other kernel trust material.

The HMAC-SHA256 tests verify consistency and truncated 16-byte output behavior. This matters because HMAC is used as a keyed authentication primitive and as the basis for HKDF. The derivation confirms that truncation is intentional and deterministic where used, but the security of HMAC still depends on correct ownership and protection of the secret key.

The HKDF-SHA256 test verifies repeatability of the extract-and-expand path. This confirms that the derivation process is deterministic for the same inputs. The broader composition tests then verify that HKDF labels separate purposes in TLS and persistence paths, which is more important than repeatability alone. The same root secret must not collapse into the same derived material for different roles.

The GHASH test verifies repeatability over GF(2^128). The AES-GCM test verifies an encryption and decryption round-trip. Together, these confirm that the current GHASH and AES-GCM composition can authenticate and recover data under the tested conditions. The deeper TLS record tests then extend that by verifying associated-data tamper rejection and nonce construction behavior.

The X25519 key agreement test verifies that both sides derive the same shared secret. The TLS composition tests also verify that the X25519 shared secret matches both TLS-side views. This confirms that the raw Diffie-Hellman agreement path is symmetric and usable as input to later HKDF derivation. It does not by itself prove peer identity. That remains a higher-level authentication and trust-anchor concern.

The signing-format tests verify exact canonical bytes for OTA manifest signed messages and Fleet attestation signed messages. These tests check lowercase fixed-width hex encoding, decimal encoding without padding, and exact byte layout. They also document current limits, including the current parser accepting trailing data, OTA version bytes currently being unescaped, and the current OTA message lacking target-slot metadata. The suite includes future-rule tests for stricter parser behavior so the intended hardening direction is recorded beside the current behavior.

The TLS primitive composition tests verify the chain from X25519 shared secret, through HKDF traffic-secret separation, transcript hashing, Finished verify-data construction, AES-GCM record protection, AAD tamper rejection, and TLS-style nonce construction where the sequence number is XORed into the last eight nonce bytes. These tests are important because they do not only check individual primitives. They check whether the primitives compose into a coherent record-protection path.

The persistence primitive composition tests verify that snapshot key derivation separates purpose labels and binds generation state. They also verify that AES-CTR snapshot encryption round-trips correctly, that HMAC detects ciphertext tampering, that HMAC detects metadata tampering, and that rollback generation prevents old records from being accepted under new keys. This directly supports the persistence-side rule that sealed state must be tied to both content and metadata, not only encrypted bytes.

The OTA primitive composition tests verify that image hashes bind manifest bytes, that the current canonical manifest has exact expected bytes, that constant-time hash decisions accept exact matches and reject tampered values, that mature metadata records bind target slot, that commit-state phase changes alter the digest, and that production policy rejects unsigned manifests. This connects cryptographic correctness to update safety. It shows that the update path must bind image data, metadata, activation authority, and signature policy into one trust decision.

The Fleet attestation primitive composition tests verify the current canonical Fleet message bytes, the measurement hash input layout, measurement changes when the active slot hash changes, freshness nonce changes in the mature bundle hash, unknown measurement state being distinct from a zero hash, peer identity changing the signed bundle, and the current Fleet message lacking freshness as a documented limit. This is important because attestation must not treat a stale or ambiguous measurement as equivalent to a fresh, identified, peer-bound statement.

The public API and capability-safe wrapper tests verify that raw primitives still compute without authority context, but higher-level wrapper rules must enforce capability boundaries. The tests show that TLS write without write authority is denied, TLS read and write rights do not cross directions, capability context is authenticated through AAD, OTA activation requires activation authority rather than only verification authority, snapshot seal and unseal rights are separate, and Fleet attestation and key-import rights are separate.

This is one of the most important results of the suite. It shows that mathematical primitive correctness is not enough for Oreulius. A raw AES-GCM call can be correct and still be the wrong API for kernel policy code. The capability-safe wrapper tests prove the intended direction: raw cryptographic primitives should remain lower-level building blocks, while kernel-facing operations should carry capability context, operation-specific authority, authenticated metadata, and separated rights.

The overall result is that the current derivation test suite validates the crypto folder at three levels.

First, it validates primitive math. AES, SHA, HMAC, HKDF, GHASH, AES-GCM, X25519, and signing helpers all have direct tests that check their local behavior.

Second, it validates composition. TLS, persistence, OTA, and Fleet attestation tests check that primitives are being connected with the correct labels, metadata, counters, hashes, signatures, and authentication rules.

Third, it validates architectural boundaries. The public API and capability-safe wrapper tests check that cryptographic operations are moving toward authority-aware kernel flows instead of remaining unrestricted utility functions.

These tests do not mean the crypto layer is finished. They mean the derivation work has produced a passing, reproducible correctness baseline for the parts currently implemented and modeled. The remaining work is mostly hardening and integration work: stricter parsing, nonce lifecycle enforcement, key ownership rules, constant-time backend policy, adversarial test expansion, public API narrowing, and deeper connection into boot, OTA, persistence, Fleet attestation, capability grants, temporal state, and policy contracts.

The honest conclusion is that the cryptographic folder has moved from being only a primitive collection toward being a mathematically reviewed trust layer in progress. The tests prove the current derivation assumptions for the covered code paths, document known limits where behavior is not yet final, and establish the next development boundary for making the crypto layer mature enough to sit underneath capability-based authority in Oreulius.

## Known Limitations in the Crypto Folder

### Issues in the TLS Path's crypto primitives operating in the network stack

1. **No Real Server Authentication**

Issue: The TLS path can complete a handshake without proving that the peer is the intended server. Finished verification proves the peer has the derived handshake secret, but without certificate and CertificateVerify validation, that peer may still be an attacker.

Required fixes:
- Validate the server certificate chain against trusted roots.
- Validate certificate time bounds and key usage.
- Validate the hostname against SAN DNS/IP entries.
- Fail the handshake if identity validation fails.

2. **Weak Randomness For TLS Private Keys**

Issue: TLS private keys and client random are derived from scheduler ticks and fixed constants. That is predictable and not suitable for cryptographic key generation.

Required fixes:
- Add or integrate a kernel CSPRNG.
- Seed it from real entropy sources.
- Use it for X25519 private keys, client random, nonces, and future secrets.
- Block or fail secure operations until the CSPRNG is initialized.

3. **X25519 All-Zero Shared Secret Not Checked**

Issue: The code derives keys from the X25519 output without rejecting an all-zero shared secret. Low-order or invalid peer public keys can produce this value.

Required fixes:
- After X25519, compare the shared secret against 32 zero bytes.
- Abort the handshake if it is all zero.
- Add test cases for low-order public keys.

4. **Permissive TLS Parsing**

Issue: ServerHello and encrypted handshake parsing accept incomplete or malformed structures too easily. Loose parsing can accidentally accept invalid handshakes.

Required fixes:
- Validate exact record lengths and handshake message lengths.
- Reject malformed, duplicate, missing, or unexpected extensions.
- Validate selected TLS version, cipher suite, group, and key share.
- Add negative parser tests.

5. **Certificate Validation Missing**

Issue: The Certificate message is treated as a state transition instead of a trust decision. The kernel does not verify that the certificate chains to a trusted authority.

Required fixes:
- Parse X.509 certificates.
- Build and verify certificate chains.
- Maintain a trusted root store or pinned certificate/key policy.
- Check signature algorithms, expiry, basic constraints, and key usage.

6. **Hostname Validation Missing**

Issue: Even if a certificate chain were valid, the code does not check that the certificate belongs to the requested host.

Required fixes:
- Compare the requested host against subjectAltName DNS/IP entries.
- Do not rely on Common Name except as a legacy fallback if explicitly desired.
- Reject wildcard misuse.
- Fail closed on malformed names.

7. **CertificateVerify Not Verified**

Issue: TLS 1.3 CertificateVerify is not checked. This message proves the server owns the private key corresponding to its certificate and binds that identity to the transcript.

Required fixes:
- Parse CertificateVerify.
- Verify the signature using the certificate public key.
- Use the TLS 1.3 signature context string and transcript hash.
- Reject unsupported signature algorithms.

8. **AES-GCM Sequence Overflow Not Handled**

Issue: TLS record nonces are derived from sequence numbers. If a sequence number overflows under the same key, nonce reuse can destroy AES-GCM security.

Required fixes:
- Detect write_seq and read_seq approaching overflow.
- Rekey before limits are reached, or close the session.
- Enforce TLS record usage limits.
- Add tests for sequence limit behavior.

9. **Table-Based AES Timing Risk**

Issue: Software AES uses lookup tables. On real hardware, table lookups may leak key-dependent information through cache timing.

Required fixes:
- Use AES-NI or platform hardware AES where available.
- Add a constant-time fallback for platforms without hardware AES.
- Avoid key-dependent memory access in software AES.
- Document platform guarantees.

10. **HKDF Info Truncation**

Issue: HKDF expand truncates info to 255 bytes instead of rejecting oversized input. Silent truncation can make two different contexts derive the same key.

Required fixes:
- Change HKDF APIs to return Result for invalid parameters.
- Reject oversized info instead of truncating.
- Enforce RFC 5869 output length limits.
- Add tests for invalid length handling.

11. **Incomplete Secret Zeroization**

Issue: Private keys, shared secrets, traffic keys, transcript-derived secrets, and plaintext scratch buffers remain in memory after use.

Required fixes:
- Add a zeroization utility that compiler optimizations cannot remove.
- Wipe private keys, shared secrets, traffic secrets, temporary buffers, and plaintext scratch space.
- Clear session structs on close/free.
- Avoid unnecessary cloning of key material.

12. **State Machine Accepts Messages Too Broadly**

Issue: Some handshake messages are accepted mainly because they arrive in the expected state, without full semantic validation.

Required fixes:
- Define strict expected message transitions.
- Validate each message body before advancing state.
- Reject extra, missing, reordered, or unexpected handshake messages.
- Add state machine tests for invalid flows.

13. **ServerHello Validation Incomplete**

Issue: ServerHello parsing extracts the peer key but does not fully validate negotiated parameters.

Required fixes:
- Verify TLS 1.3 selected version.
- Verify AES-128-GCM-SHA256 is the selected cipher suite.
- Verify X25519 is the selected group.
- Verify key_share length and extension structure exactly.
- Reject downgrade signals or inconsistent legacy fields.

14. **Malformed Or Duplicate Extensions Not Rejected**

Issue: TLS extensions are parsed in a simple loop without enforcing uniqueness or required-extension policy.

Required fixes:
- Track seen extensions.
- Reject duplicates where TLS forbids them.
- Reject required extensions that are missing.
- Reject extension lengths that do not match their internal structure.

15. **Long-Lived Session Secrets**

Issue: Session structs keep private keys and derived traffic secrets for the lifetime of the session and may leave them after free.

Required fixes:
- Zero secrets immediately when they are no longer needed.
- Separate handshake secrets from application secrets.
- Wipe handshake secrets after app keys are derived.
- Wipe all session memory when freeing a session.

16. **HelloRetryRequest Not Handled**

Issue: The current handshake assumes the first ServerHello contains an acceptable X25519 key share. TLS 1.3 also allows the server to send HelloRetryRequest, which asks the client to send a corrected second ClientHello.

Required fixes:
- Detect HelloRetryRequest by its special ServerHello random value.
- Rebuild ClientHello with the requested key share parameters.
- Insert the synthetic message_hash transcript entry required by TLS 1.3.
- Reject illegal second retry attempts.

17. **Transcript Message-Hash Handling Missing**

Issue: The transcript is currently treated as a straight SHA-256 stream over handshake messages. That works for the simple path, but TLS 1.3 has special transcript rules when HelloRetryRequest is used.

Required fixes:
- Implement TLS 1.3 transcript-hash rules exactly.
- Add transcript handling for HelloRetryRequest.
- Test normal and retry transcript paths.
- Compare transcript hashes against known TLS 1.3 traces.

18. **Handshake Fragmentation Not Fully Handled**

Issue: The current encrypted handshake path expects complete handshake messages to be available inside the current record buffer. Real TLS peers can split one handshake message across records or place multiple messages in one record.

Required fixes:
- Add handshake message reassembly.
- Track partial handshake headers and bodies.
- Process a message only after the full declared length is present.
- Reject oversized or incomplete handshake messages safely.

19. **Certificate Message Size Too Constrained**

Issue: The encrypted handshake scratch buffer is fixed at 8192 bytes. Real certificate chains can be larger than that, especially when intermediates are included.

Required fixes:
- Support larger certificate messages or streaming certificate parsing.
- Define a deliberate maximum certificate chain size.
- Fail cleanly when a certificate chain exceeds the limit.
- Avoid stack-heavy temporary buffers for large handshake data.

20. **Handshake Failures Do Not Always Fail Closed**

Issue: Some malformed or unexpected handshake data can return silently instead of moving the session into Error. That leaves the connection in an ambiguous state.

Required fixes:
- Convert silent parse failures into explicit handshake errors.
- Send fatal TLS alerts where appropriate.
- Close the session after fatal handshake errors.
- Add tests for malformed ServerHello and encrypted handshake inputs.

21. **Unexpected Handshake Messages Are Ignored**

Issue: Unexpected state and message combinations can fall through without error. TLS handshakes should reject messages that arrive out of order or in the wrong phase.

Required fixes:
- Treat unexpected handshake messages as fatal.
- Reject duplicate handshake messages.
- Reject messages that arrive too early or too late.
- Add negative tests for invalid state transitions.

22. **EncryptedExtensions Not Validated**

Issue: The current flow advances past EncryptedExtensions without validating its contents. TLS 1.3 uses this message for negotiated parameters that must be checked.

Required fixes:
- Parse EncryptedExtensions.
- Validate allowed extensions for this phase.
- Reject forbidden, malformed, or duplicate extensions.
- Check consistency with ClientHello and ServerHello.

23. **CertificateRequest Policy Missing**

Issue: The current client flow assumes the server will not request client authentication. If a CertificateRequest appears, the implementation needs an explicit policy.

Required fixes:
- Detect CertificateRequest.
- Either implement client certificate authentication or reject it cleanly.
- Document whether Oreulius supports server-auth only or mutual TLS.
- Add tests for CertificateRequest handling.

24. **Post-Handshake Message Policy Missing**

Issue: TLS 1.3 allows messages after the main handshake, such as NewSessionTicket and KeyUpdate. The current Connected state does not define a complete policy for these messages.

Required fixes:
- Decide whether to support or reject NewSessionTicket.
- Decide whether to support or reject post-handshake authentication.
- Route post-handshake messages separately from application data.
- Fail closed on unsupported post-handshake behavior.

25. **KeyUpdate Not Handled**

Issue: TLS 1.3 peers can request traffic key updates after the connection is established. The current flow does not process KeyUpdate.

Required fixes:
- Parse KeyUpdate messages.
- Derive next-generation application traffic secrets.
- Update read and write keys safely.
- Reject illegal or repeated KeyUpdate messages.

26. **Downgrade Protection Validation Missing**

Issue: ServerHello should be checked for TLS downgrade signals and selected-version consistency. Without this, protocol negotiation is not strict enough.

Required fixes:
- Validate that supported_versions selects TLS 1.3.
- Validate ServerHello random downgrade markers.
- Reject inconsistent legacy_version behavior.
- Reject any negotiated version outside Oreulius policy.

27. **Session Resumption And PSK Policy Missing**

Issue: The current handshake appears to support only fresh X25519 handshakes. TLS 1.3 also supports PSK and session resumption, which must be either implemented or explicitly rejected.

Required fixes:
- Explicitly reject PSK and resumption extensions if unsupported.
- Or implement PSK binder verification and the resumption key schedule.
- Document that only full fresh handshakes are supported if that is the intended policy.
- Add tests for unsupported PSK and resumption inputs.

28. **Handshake Test Matrix Missing**

Issue: The handshake needs specific positive and negative tests. General primitive tests do not prove the state machine handles real TLS flows safely.

Required fixes:
- Test a valid full handshake.
- Test malformed ServerHello, missing key_share, wrong cipher suite, and duplicate extensions.
- Test fragmented Certificate and encrypted handshake records.
- Test bad Finished, alert handling, and unexpected message order.

29. **Interoperability Trace Validation Missing**

Issue: TLS is exact at the byte level. A handshake can look structurally correct while still deriving different transcript hashes or secrets from real TLS 1.3 clients.

Required fixes:
- Capture known-good TLS 1.3 handshake traces.
- Compare ClientHello bytes against expected layouts.
- Compare transcript hashes and derived secrets where test vectors allow.
- Test against multiple real TLS 1.3 servers.

30. **TLS Sessions Are Raw Handles Instead Of Capabilities**

Issue: The current TLS session is represented as a raw integer handle from the TLS session pool. That handle identifies a slot, but it does not prove owner authority, rights, lifetime, provenance, or revocation status through the Oreulius capability manager.

Required fixes:
- Add a first-class TlsSession capability type.
- Store TLS sessions as kernel objects with stable object ids.
- Issue a TlsSession capability only after policy allows the connection and the handshake reaches a verified secure state.
- Replace direct raw-handle access with capability verification.

31. **Network Capability Types Are Missing**

Issue: The generic capability taxonomy does not yet model network authority. Without NetworkResolve, NetworkConnect, and TlsSession capability types, outbound network access still behaves partly like ambient authority.

Required fixes:
- Add NetworkResolve, NetworkConnect, and TlsSession capability types to the capability taxonomy.
- Define object ids for DNS authority, remote endpoints, and TLS session objects.
- Make network and TLS operations require these capability types.
- Add audit events for network capability creation, use, denial, delegation, and revocation.

32. **TLS Rights Are Not Defined In The Rights Bitset**

Issue: The proposed TLS authorities are not yet represented as concrete rights. Without explicit rights, the kernel cannot separate connect, handshake, read, write, close, introspection, rekeying, exporter use, delegation, CapNet binding, and audit access.

Required fixes:
- Add TLS_CONNECT, TLS_HANDSHAKE, TLS_READ, TLS_WRITE, TLS_CLOSE, TLS_INTROSPECT, TLS_REKEY, TLS_EXPORTER, TLS_DELEGATE, TLS_BIND_CAPNET, and TLS_AUDIT rights.
- Ensure TLS_CONNECT does not imply TLS_READ or TLS_WRITE.
- Require exact rights at every TLS operation boundary.
- Add tests proving rights attenuation prevents escalation.

33. **TLS Session Ownership Is Not Enforced By The Capability Manager**

Issue: Any code path that can obtain a TLS handle can try to access the TLS session. The session is not bound to an owner process through the global capability table.

Required fixes:
- Bind each TlsSession capability to the creating process.
- Verify owner process and capability token before read, write, close, introspect, rekey, or exporter operations.
- Reject use from other processes unless the capability was explicitly delegated.
- Log invalid owner attempts as capability violations.

34. **TLS Session State Is Not A Capability Gate**

Issue: The current code checks the handshake state internally, but the capability itself does not encode whether the session is usable. A mature TlsSession capability should only authorize data access after the session is connected and verified.

Required fixes:
- Add a session state field to the TLS capability metadata.
- Allow TLS_CONNECT and TLS_HANDSHAKE during setup.
- Grant TLS_READ and TLS_WRITE only after peer identity validation and Connected state.
- Revoke or downgrade rights when the session enters Closed or Error.

35. **Remote Identity Is Not Bound To The TLS Capability**

Issue: The proposed TlsSession capability needs to carry remote identity, but the current TLS stack does not bind the session to a verified hostname, certificate identity, pinned key, or CapNet peer identity.

Required fixes:
- Store the requested hostname, certificate identity, and validated peer key material in the TLS session metadata.
- Bind hostname validation results to the issued TlsSession capability.
- Reject capability issuance if server identity is unknown or unverified.
- Include remote identity in audit records and introspection output.

36. **Transport Binding Is Not Captured As Authority Metadata**

Issue: The TLS session currently knows host, port, and server IP internally, but this is not captured as capability authority metadata. A delegated capability should preserve what endpoint and protocol parameters it authorizes.

Required fixes:
- Store IP, port, scheme, TLS version, cipher suite, key exchange group, and ALPN if supported.
- Include those fields in the TlsSession capability object metadata.
- Reject use if the session metadata and actual TLS state disagree.
- Expose transport binding through TLS_INTROSPECT without exposing plaintext.

37. **TLS Capability Profiles Are Not Implemented**

Issue: The README defines profiles such as TLS connector, TLS data stream, TLS receive-only stream, TLS send-only stream, TLS monitor, TLS key manager, TLS protocol binder, and TLS delegator. The code does not yet create or enforce those attenuated profiles.

Required fixes:
- Add constructors for each TLS capability profile.
- Use rights attenuation when deriving narrower TLS capabilities.
- Prevent a profile from delegating rights it does not hold.
- Add tests for receive-only, send-only, monitor-only, and delegator behavior.

38. **TLS Delegation Is Not Integrated With The Capability Graph**

Issue: A TLS authority should be transferable only through explicit delegation, with provenance and no rights escalation. The current raw TLS handle does not participate in the capability graph.

Required fixes:
- Route TLS capability delegation through CapabilityManager transfer logic.
- Record TLS delegation edges in the capability graph.
- Enforce no rights escalation during TLS delegation.
- Prune delegated TLS authority when the parent TLS capability is revoked.

39. **TLS Revocation Is Not Capability-Aware**

Issue: Closing a TLS session releases the transport, but there is no capability-wide revocation model for all holders of delegated TLS authority.

Required fixes:
- Add revoke support for TlsSession capabilities.
- Close or quarantine the underlying TLS session when required by policy.
- Revoke all delegated child capabilities when the root TLS session authority is revoked.
- Emit audit records for TLS revocation and attempted post-revocation use.

40. **TLS Capability Lifetime Is Not Enforced**

Issue: The proposed capability includes expiry or lifetime, but current TLS sessions do not expire based on capability metadata. A long-lived TLS handle can remain usable until manually closed or errored.

Required fixes:
- Add not-before and expires-at fields for TlsSession capabilities.
- Reject reads, writes, rekeys, and exporters after expiry.
- Close or require reauthorization for expired sessions.
- Add tests for expired TLS capability use.

41. **TLS Audit Labels And Security Events Are Missing**

Issue: The TLS path reports errors locally, but it does not produce rich capability audit events that explain what authority was exercised, denied, delegated, revoked, or failed.

Required fixes:
- Add audit labels to TLS capability metadata.
- Log TLS connect attempts, handshake success, handshake failure, read, write, close, rekey, exporter use, delegation, and revocation.
- Include session object id, owner process, remote identity, and rights in audit context.
- Feed denied TLS capability use into the security violation path.

42. **Fetch Session Capabilities Are Service-Local Instead Of Kernel Capabilities**

Issue: The fetch service uses its own opaque Cap token for session authority. That is useful locally, but it is not a signed OreuliusCapability in the global capability manager and does not participate in provenance, delegation, or global revocation.

Required fixes:
- Back fetch session authority with a real ServicePointer or FetchSession capability.
- Bind HTTPS navigation to NetworkResolve, NetworkConnect, and TlsSession capabilities.
- Replace or wrap service-local Cap checks with capability-manager verification.
- Preserve fetch session policy while integrating with global audit and revocation.

43. **WASM TLS Host Calls Bypass Capability Checks**

Issue: WASM host calls can open and use TLS sessions through raw TLS handles. They do not currently require a process-owned NetworkConnect or TlsSession capability.

Required fixes:
- Add capability arguments to WASM TLS host calls.
- Verify NetworkConnect before tls_connect.
- Verify TLS_READ, TLS_WRITE, TLS_CLOSE, TLS_INTROSPECT, and TLS_HANDSHAKE for the matching operations.
- Reject raw TLS handle use without a valid capability.

44. **TLS Exporter Authority Is Not Separated**

Issue: TLS exporter material can bind other protocols or derive new secrets from the TLS channel. If added later without a dedicated right, ordinary read/write authority could accidentally become key-derivation authority.

Required fixes:
- Implement TLS exporter only behind TLS_EXPORTER.
- Bind exporter labels and contexts to policy.
- Audit every exporter call.
- Ensure TLS_READ and TLS_WRITE do not imply exporter access.

45. **TLS Rekey Authority Is Not Separated**

Issue: KeyUpdate and rekey behavior can affect traffic keys and record safety. The proposed TLS_REKEY right is not yet enforced because the current stack does not treat rekeying as a separate authority.

Required fixes:
- Require TLS_REKEY for locally triggered KeyUpdate.
- Validate peer-triggered KeyUpdate against session policy.
- Audit all rekey transitions.
- Prevent ordinary read/write holders from forcing key updates unless explicitly authorized.

46. **TLS CapNet Binding Is Not Implemented**

Issue: The proposed TLS_BIND_CAPNET right is meant to bridge TLS transport identity into CapNet peer/session authority. Today TLS and CapNet are separate paths, so a TLS handshake does not establish CapNet peer trust or remote capability lease authority.

Required fixes:
- Define how a verified TLS peer maps to a CapNet peer identity.
- Require TLS_BIND_CAPNET before binding TLS exporter material or peer identity into CapNet.
- Connect successful binding to CapNet peer session establishment.
- Reject CapNet token transport over TLS when the TLS peer identity is unverified.

47. **Network DNS Authority Is Not Capability-Scoped**

Issue: DNS resolution for HTTPS fetches happens before TLS connection setup, but the authority to resolve names is not modeled as a separate capability.

Required fixes:
- Require NetworkResolve for DNS resolution.
- Scope NetworkResolve by allowed suffix, exact host, or policy domain.
- Audit resolution attempts and failures.
- Ensure NetworkConnect can be bound to the resolved name and resulting IP.

48. **Network Connect Authority Is Not Endpoint-Scoped**

Issue: Outbound TLS connection authority should be limited by host, IP, port, and scheme. The current path can allocate TLS sessions based on host and port without a generic endpoint-scoped NetworkConnect capability.

Required fixes:
- Require NetworkConnect for outbound TCP/TLS connect attempts.
- Encode allowed host, IP range, port, and scheme in the capability object or policy.
- Reject connection attempts outside the capability scope.
- Add tests for host, port, and scheme mismatches.

49. **ClientHello Advertisement Is Not Capability-Scoped**

Issue: The ClientHello advertises TLS version, cipher suite, key share, SNI, and extensions without first proving that those choices are inside the caller's NetworkConnect authority.

Required fixes:
- Validate host, port, scheme, TLS version, cipher suite, key exchange group, and SNI against NetworkConnect before building ClientHello.
- Refuse to send ClientHello if the advertised parameters exceed the caller's authority.
- Record the advertised ClientHello parameters in TLS session metadata.
- Compare the server's selected parameters against both ClientHello and NetworkConnect policy.

50. **TLS Capability Metadata Is Not Persisted Or Restored Safely**

Issue: If TLS capability state or fetch session state is persisted later, it must not restore stale live TLS authority without a valid transport session and fresh keys.

Required fixes:
- Do not persist live TLS traffic secrets.
- Persist only safe metadata such as audit records or policy intent.
- Recreate TLS sessions through a fresh handshake after restore.
- Invalidate any restored TlsSession capability that lacks a live verified session object.

51. **TLS Capability Formal Tests Are Missing**

Issue: Turning TLS into a capability adds new proof obligations: no rights escalation, owner binding, delegation correctness, revocation correctness, and fail-closed behavior. These are not covered by primitive or handshake tests.

Required fixes:
- Add tests for each TLS right.
- Add tests for owner mismatch, invalid token, expired capability, revoked capability, and delegated child capabilities.
- Add tests proving TLS_CONNECT cannot read or write and TLS_READ cannot write.
- Add formal or self-check coverage for TLS capability graph invariants.

52. **TLS HKDF Key Schedule Test Vectors Are Missing**

Issue: The HKDF primitive has an RFC 5869 test vector, but the TLS 1.3 key schedule itself does not yet have dedicated tests proving that early secret, handshake secret, traffic secrets, Finished keys, application secrets, keys, and IVs match known TLS 1.3 vectors.

Required fixes:
- Add TLS 1.3 key schedule test vectors for the normal X25519 handshake path.
- Verify early secret, derived separators, handshake secret, client and server handshake traffic secrets, and Finished keys.
- Verify master secret, client and server application traffic secrets, application keys, and application IVs.
- Compare transcript-bound outputs against known-good TLS 1.3 traces.

53. **TLS AES-GCM Record-Layer Tamper Tests Are Missing**

Issue: AES-GCM has primitive-level vectors, but the TLS record layer still needs tests proving that tampered headers, ciphertext, tags, nonces, and inner content types are rejected before plaintext is accepted.

Required fixes:
- Add tests for tampered TLS record headers used as associated data.
- Add tests for tampered ciphertext and tampered authentication tags.
- Add tests for wrong read nonces and sequence mismatches.
- Add tests for unexpected or malformed inner content types.
- Verify that failed records do not advance read sequence state or release plaintext.

54. **TLS Record Fail-Closed Behavior Is Incomplete**

Issue: The TLS record layer must reject malformed lengths, bad authentication tags, wrong nonces, and unexpected inner content types without advancing state or releasing plaintext.

Required fixes:
- Treat malformed record lengths as fatal record errors.
- Reject bad tags without releasing plaintext.
- Reject unexpected inner content types for the current TLS state.
- Ensure failed records do not advance read sequence counters.
- Add tests for all record-layer failure paths.

55. **TLS Nonce Construction Tests Are Missing**

Issue: The TLS nonce path follows the TLS 1.3 shape, but the test list does not yet require direct verification of nonce construction from IVs and sequence counters. Without those tests, a counter encoding bug, wrong XOR position, or accidental counter reset could break AES-GCM safety without being caught.

Required fixes:
- Keep read and write sequence counters private to the TLS session.
- Reset sequence counters only when new traffic keys are installed.
- Add tests that verify nonce values for sequence zero, sequence one, and high sequence numbers.
- Add tests proving read and write nonce streams remain separate.
- Add tests proving handshake and application nonce streams remain separate.

56. **TLS Traffic Key Encapsulation Is Incomplete**

Issue: TLS traffic keys are still ordinary session fields instead of authority-protected session internals. A mature TLS capability model should prevent callers from reading, cloning, exporting, resetting, or misusing traffic keys outside the record layer.

Required fixes:
- Keep handshake traffic keys and application traffic keys clearly separated.
- Grant TLS_READ only for decrypting with the current read traffic key.
- Grant TLS_WRITE only for encrypting with the current write traffic key.
- Prevent callers from reading, exporting, cloning, or resetting traffic keys directly.
- Zero old traffic keys when new traffic keys replace them.
- Add tests proving read-only and write-only TLS capabilities cannot cross directions.

57. **Oversized TLS Record Lengths Can Wedge The Receive Buffer**

Issue: The TLS stream parser waits for the full record length declared in the header. If a peer declares a record length larger than the receive buffer or larger than the TLS record limit, the session can keep waiting for bytes that should never be accepted.

Required fixes:
- Reject TLS records whose declared length exceeds the TLS record limit.
- Reject TLS records whose declared length cannot fit in the receive buffer.
- Move the session to Error on impossible record lengths.
- Clear or resynchronize the receive buffer after fatal record length errors.
- Add tests for oversized record headers, impossible record lengths, and receive-buffer wedging.

58. **TCP Peer Validation Under TLS Is Too Weak**

Issue: The custom TCP layer under TLS checks ports and local destination IP, but it does not fully bind received frames to the expected server IP, does not verify TCP checksums, and accepts some loose sequence and ACK behavior. TLS authentication protects encrypted records, but weak TCP validation can still cause denial of service, injected resets, handshake disruption, or confusing pre-handshake input.

Required fixes:
- Verify source IP matches the expected TLS server IP.
- Verify received TCP checksums before accepting payload bytes.
- Validate ACK numbers and sequence windows more strictly.
- Treat unexpected RST, SYN, ACK, and payload behavior as connection errors.
- Add tests for spoofed source IP, bad checksum, wrong ACK, wrong sequence, injected RST, and injected pre-handshake payload.

59. **TLS Write Sequence Can Advance Before TCP Send Succeeds**

Issue: The TLS write path encrypts a record and advances the write sequence before proving the TCP send path accepted the record. If the send fails, the session can consume a TLS sequence number for a record that was not transmitted.

Required fixes:
- Advance the write sequence only after the record is accepted for transmission, or record the skipped sequence as a deliberate failed-send event.
- Keep pending encrypted records until TCP accepts them or the session fails.
- Define retry behavior for partially accepted records.
- Include failed-send sequence behavior in record-limit accounting.
- Add tests for send_data returning zero, partial send behavior, retry behavior, and sequence counter state after failure.

60. **Buffered Plaintext Can Be Read After Close Or Error**

Issue: The TLS read function drains the application buffer without checking that the session is still Connected. If bytes were already decrypted before the session entered Closed or Error, callers may still read buffered plaintext after the session is no longer trusted.

Required fixes:
- Define whether close/error allows draining already-authenticated plaintext or clears unread plaintext.
- Enforce that policy inside TLS read.
- Bind the policy to TLS_READ capability state.
- Clear buffered plaintext on fatal errors if production policy requires fail-closed behavior.
- Add tests for reads after close, reads after fatal error, buffered plaintext drain policy, and buffer clearing.

61. **TLS Hostname Is Silently Truncated**

Issue: Session allocation copies the requested host into a fixed 253-byte buffer and silently truncates longer hostnames. SNI, policy, logs, and future certificate validation can then refer to a different hostname than the caller supplied.

Required fixes:
- Reject hostnames that exceed the supported SNI or policy length.
- Record whether the host was exact and unmodified.
- Use the exact requested hostname for certificate validation and audit metadata.
- Fail connection setup when hostname encoding is invalid or too long.
- Add tests for overlong hostnames, boundary-length hostnames, malformed hostnames, and SNI/certificate identity mismatch.

62. **Plaintext Handshake Transcript Can Include Partial Messages**

Issue: The plaintext handshake handler clamps the declared handshake length to the current record length and updates the transcript with the bytes that are present. That can hash an incomplete handshake message before the parser has proven the full declared message exists.

Required fixes:
- Do not update the transcript until the complete declared handshake message is present.
- Reject plaintext handshake messages whose declared length exceeds the available record bytes unless reassembly is active.
- Add proper plaintext handshake reassembly for messages split across records.
- Treat truncated ServerHello and malformed plaintext handshake messages as fatal.
- Add tests for truncated ServerHello, overdeclared handshake length, partial plaintext handshake messages, and transcript pollution.

63. **TLS Endpoint Binding Is Not Atomic Across DNS, TCP, SNI, Certificate, And Capability Metadata**

Issue: TLS stores host, port, and server IP internally, and ClientHello carries SNI, but the path does not yet bind NetworkResolve, NetworkConnect, TCP peer validation, SNI, certificate identity, and TlsSession capability metadata into one authority object.

Required fixes:
- Bind DNS result, requested host, target IP, target port, SNI, certificate identity, and TLS capability metadata together.
- Reject handshakes when any endpoint identity field disagrees with policy.
- Preserve the endpoint binding through delegation and introspection.
- Audit endpoint binding at connect, handshake success, and capability issuance.
- Add tests for DNS/IP mismatch, SNI/hostname mismatch, certificate/hostname mismatch, and capability metadata mismatch.

64. **TLS Session Handles Can Be Reused Without Generation Protection**

Issue: TLS sessions are addressed by small integer handles into a reusable session pool. A freed slot can later hold a different connection with the same handle value, so stale handle use can accidentally target a newer session.

Required fixes:
- Add generation numbers or stable session object ids to TLS handles.
- Reject handles whose generation does not match the live session.
- Prefer capability object ids over raw slot indexes.
- Clear session memory and invalidate old handles on free.
- Add tests for stale handle reuse, free-and-reallocate behavior, generation mismatch, and post-free access.

### Issues in the Persistance path's crypto primitives

1. **Development Persistence Seal Key Is Still The Default**

Issue: The persistence seal key has a built-in development default. That is useful for bring-up, but it means snapshot encryption and authentication can be predictable if production boot does not replace it with a device-specific secret from a real root of trust.

Required fixes:
- Require production builds to provision a device-specific persistence seal key.
- Bind the seal key to measured boot, secure storage, TPM, enclave, or another hardware-backed source where available.
- Refuse sealed snapshot writes when the default development key is still active in production mode.
- Add boot-time audit output showing whether the persistence seal key was provisioned or left at development default.
- Add tests proving production policy rejects the default seal key.

2. **Snapshot Key Derivation Is Ad Hoc**

Issue: Snapshot encryption and MAC keys are derived with SHA-256 over labels, slot id, and the master seal key. The labels help separate purposes, but this is still a custom KDF shape instead of a standard HKDF-based derivation with explicit context and length rules.

Required fixes:
- Replace custom SHA-256 key derivation with HKDF-SHA256.
- Use separate labels for persistence encryption, persistence MAC, slot id, snapshot version, and backend context.
- Include snapshot purpose in the HKDF context, such as generic state, temporal state, VFS state, or future capability-state snapshots.
- Reject invalid derivation parameters instead of silently accepting ambiguous context.
- Add key-derivation test vectors for every snapshot slot and backend.
- Document the persistence key schedule beside the TLS key schedule.

3. **AES-CTR Nonce Reuse Would Break Snapshot Confidentiality**

Issue: Snapshot payloads use AES-128-CTR. CTR mode is safe only when the same key and nonce stream are never reused. The current nonce is monotonic in memory and is updated after recovery, but it is not backed by a durable monotonic counter or hardware nonce source.

Required fixes:
- Store the next snapshot nonce durably or bind it to a hardware monotonic counter where available.
- Detect nonce rollback across reboot, snapshot restore, or disk rollback.
- Refuse to write encrypted snapshots if nonce freshness cannot be guaranteed.
- Add tests proving recovery observes the highest valid snapshot nonce and advances the next write nonce past it.
- Add tests for reboot, recovery, corrupted snapshot, rollback, and high-counter behavior.
- Consider moving snapshot sealing to an AEAD mode with a larger nonce and stricter misuse resistance.

4. **AES-CTR Encryption Depends Entirely On HMAC For Integrity**

Issue: AES-CTR only encrypts bytes. It does not authenticate them. The current design correctly adds HMAC-SHA256 over the header and ciphertext, but any path that decrypts before checking the MAC, skips the MAC, or accepts an old snapshot format weakens the seal.

Required fixes:
- Keep authenticate-before-decrypt as a hard invariant for every snapshot backend.
- Reject encrypted v2 snapshots when the MAC is missing or malformed.
- Add tests proving tampered header fields, ciphertext, flags, nonce, slot id, and MAC are rejected before plaintext is used.
- Make the read path fail closed on any v2 seal inconsistency.
- Consider replacing AES-CTR plus HMAC with a single AEAD construction for simpler enforcement.

5. **Snapshot MAC Is Truncated To 16 Bytes**

Issue: The snapshot HMAC is truncated to 16 bytes. A 16-byte tag can be acceptable in some designs, but the truncation policy should be explicit, tested, and tied to a security target. Right now the README does not explain why 16 bytes is enough for persistence snapshots.

Required fixes:
- Document the reason for the 16-byte MAC length and the intended forgery resistance.
- Consider storing the full 32-byte HMAC-SHA256 output if space allows.
- Add tests that reject tags with wrong length, wrong bytes, and partial matches.
- Keep MAC comparison constant-time.
- Include MAC length in the snapshot format documentation.

6. **Legacy V1 Snapshots Are Only CRC-Protected**

Issue: The read path still accepts version 1 snapshots that use CRC32 instead of cryptographic sealing. CRC32 detects accidental corruption, but it is not a security boundary. If old snapshots can be loaded in a production security context, an attacker with disk write access could modify persisted state and recompute the CRC.

Required fixes:
- Treat v1 snapshots as migration-only data, not trusted production state.
- Reject v1 snapshots in production mode unless an explicit recovery policy allows them.
- Migrate v1 snapshots to v2 sealed snapshots immediately after successful recovery.
- Add audit events when a v1 snapshot is accepted or rejected.
- Add tests proving production policy does not silently trust CRC-only snapshots.

7. **Append Log Records Use CRC32 Instead Of Cryptographic Authentication**

Issue: Log records have CRC32 checksums for basic integrity. That catches accidental damage, but it does not prove the record was written by the kernel or that the log was not edited. Persistence logs may contain security-relevant events such as OTA updates, boot events, health snapshots, and attestation records.

Required fixes:
- Add cryptographic authentication for append log records.
- Chain log records with HMAC-SHA256 or a Merkle/log hash so deletion, reordering, and insertion are detectable.
- Bind record type, length, offset, and previous record hash into the authenticated data.
- Add tests for modified payloads, modified headers, reordered records, deleted records, and replayed records.
- Keep CRC32 only as a corruption check, not as the security proof.

8. **Rollback Protection Is Incomplete**

Issue: HMAC proves that a snapshot was sealed by the kernel key, but it does not by itself prove that the snapshot is the newest one. An attacker who can restore an older valid snapshot may roll the system back to older capability state, older policy, or older service state.

Required fixes:
- Bind snapshots to a monotonic generation, boot counter, or trusted rollback index.
- Store and verify the latest accepted snapshot generation in a rollback-resistant place.
- Reject sealed snapshots that are valid but older than the last trusted generation.
- Include generation and previous snapshot identity in the authenticated header.
- Add rollback tests using older valid snapshots.
- Add tests proving rollback cannot restore revoked capabilities, older policy, or stale authority state.

9. **Persistence Capabilities Are Store-Local**

Issue: StoreCapability checks rights such as append log, read log, write snapshot, and read snapshot, but this authority is local to the persistence service. It does not yet appear to be a first-class kernel capability with owner binding, provenance, delegation, lifetime, revocation, and audit integration.

Required fixes:
- Promote persistence store authority into the global capability manager.
- Bind each persistence capability to owner process, store object, slot, backend, rights, and lifetime.
- Separate rights for append log, read log, write snapshot, read snapshot, seal, unseal, recover, and migrate.
- Route persistence delegation and revocation through the capability graph.
- Add tests for owner mismatch, revoked capability use, delegated reduced rights, and raw capability-id guessing.

10. **Snapshot Backends Need Consistent Security Policy**

Issue: Snapshots can be written to disk, external backend, or file fallback. The crypto format is similar across paths, but policy must ensure every backend enforces the same seal, nonce, MAC, version, and failure behavior.

Required fixes:
- Define one shared snapshot validation routine for all durable backends.
- Require the same v2 seal checks for disk, external, and file-backed snapshots.
- Audit which backend was used for write, read, recovery, and fallback.
- Reject backend fallback when the fallback would weaken security policy.
- Add cross-backend tests for tampering, rollback, missing backend, corrupted header, and valid recovery.

11. **Snapshot Secrets And Plaintext Buffers Are Not Fully Zeroized**

Issue: Snapshot encryption keys, MAC keys, decrypted payloads, scratch images, and temporary buffers can remain in memory after use. For persistence, this matters because snapshots may contain capability state, service state, filesystem state, or security-relevant metadata.

Required fixes:
- Zero encryption keys, MAC keys, decrypted payload scratch space, and temporary snapshot images after use.
- Use a zeroization routine that compiler optimizations cannot remove.
- Clear failed-read buffers before returning errors.
- Avoid unnecessary copies of decrypted snapshot data.
- Add tests or debug self-checks showing scratch buffers are cleared after seal and unseal operations.

12. **Persistence Crypto Test Coverage Is Not Complete**

Issue: The persistence path uses several composed crypto operations, but primitive tests alone do not prove the storage format is safe. Snapshot sealing needs end-to-end tests that exercise encryption, MAC verification, nonce behavior, backend recovery, and failure handling together.

Required fixes:
- Add round-trip tests for sealed snapshot write and read.
- Add tamper tests for header, flags, slot id, nonce, ciphertext, MAC, and length fields.
- Add tests proving the snapshot MAC is computed with the header MAC field zeroed.
- Add nonce freshness tests across write, read, recovery, and reboot simulation.
- Add tests for v1 migration or v1 rejection policy.
- Add backend fallback tests proving security policy stays consistent.

13. **Snapshot Sealing Flow Is Not Yet A Full Authority Boundary**

Issue: Snapshot sealing protects in-memory kernel state before it leaves memory, but the flow is not yet treated as a complete authority boundary. A mature persistence path should ensure that temporal state, VFS state, service state, offsets, timestamps, and authority-related data are sealed only through the persistence service, never by callers choosing raw keys, resetting nonces, skipping authentication, or writing unsealed production snapshots.

Required fixes:
- Make snapshot sealing the only production path for writing recoverable kernel state.
- Prevent callers from choosing raw encryption keys, MAC keys, nonces, or seal flags.
- Require write snapshot authority before sealing and read snapshot authority before unsealing.
- Reject unsealed or partially sealed snapshots in production mode.
- Bind snapshot slot, backend, version, nonce, timestamp, and last offset into authenticated metadata.
- Add tests proving sealed snapshots are authenticated before restore and unsealed snapshots are rejected.

14. **Persistence Seal Key Lifecycle Is Incomplete**

Issue: The persistence seal key is treated as a single root secret, but the lifecycle around that secret is not fully defined. A mature design needs to handle key rotation, key versioning, anti-exfiltration, seal and unseal audit events, and recovery behavior when the production seal key is missing or unavailable.

Required fixes:
- Add seal key generation or version metadata to sealed snapshots.
- Define a safe key rotation path that can re-seal old snapshots under a new production key.
- Prevent the root seal key from being exported, logged, copied to callers, or exposed through debug paths.
- Audit seal, unseal, key provisioning, key rotation, and missing-key recovery events.
- Define boot and recovery behavior when the expected production seal key is unavailable.
- Add tests for key rotation, wrong key version, missing key, and attempted seal key export.

15. **Raw AES-CTR Snapshot Bypass Tests Are Missing**

Issue: AES-CTR should remain an internal persistence implementation detail, but the test plan does not explicitly prove that callers cannot trigger raw snapshot encryption or decryption outside authorized persistence paths. A mature capability model needs tests showing that snapshot sealing and unsealing happen only after the proper persistence authority is checked.

Required fixes:
- Add tests proving callers cannot trigger raw AES-CTR encryption outside write snapshot authority.
- Add tests proving callers cannot trigger raw AES-CTR decryption outside read snapshot authority.
- Add tests proving callers cannot supply their own AES key, nonce, counter, or seal flags.
- Add tests proving direct crypto helper access cannot bypass StoreCapability or future global persistence capabilities.
- Add tests for rejected attempts to seal or unseal the wrong snapshot slot or backend.

16. **Persistence Failure Audit Coverage Is Incomplete**

Issue: Persistence audit coverage should explain not only successful seal and unseal operations, but also security-relevant failures. Failed MAC checks, failed nonce freshness checks, rollback rejection, missing production seal keys, and backend fallback decisions are all events that should be visible to security review.

Required fixes:
- Audit failed MAC verification before any plaintext is released.
- Audit failed nonce freshness checks and nonce rollback detection.
- Audit rollback rejection for older but otherwise valid snapshots.
- Audit backend fallback decisions and whether fallback changed the storage path.
- Audit missing production seal key behavior during boot and recovery.
- Include snapshot slot, backend, version, nonce or generation metadata, and caller authority in audit records where safe.

17. **Mature Persistence Rights Are Not Fully Defined**

Issue: The current StoreCapability has basic local rights, but the mature persistence authority model needs a complete rights set. Without explicit rights, the kernel cannot cleanly separate append, read, seal, unseal, recover, migrate, key rotation, audit, introspection, delegation, slot binding, backend binding, and rollback control.

Required fixes:
- Define PERSIST_APPEND_LOG, PERSIST_READ_LOG, PERSIST_WRITE_SNAPSHOT, PERSIST_READ_SNAPSHOT, PERSIST_SEAL, PERSIST_UNSEAL, PERSIST_RECOVER, PERSIST_MIGRATE, PERSIST_ROTATE_KEY, PERSIST_AUDIT, PERSIST_DELEGATE, PERSIST_INTROSPECT, PERSIST_BIND_SLOT, PERSIST_BIND_BACKEND, and PERSIST_ROLLBACK_CONTROL.
- Ensure PERSIST_SEAL does not imply PERSIST_UNSEAL.
- Ensure PERSIST_AUDIT and PERSIST_INTROSPECT do not grant snapshot plaintext access.
- Ensure PERSIST_ROTATE_KEY does not imply read snapshot or write snapshot authority.
- Add tests for each persistence right individually.
- Add rights-separation tests for seal without unseal, unseal without seal, audit without read, introspect without plaintext, rotate key without snapshot read, and slot/backend mismatch rejection.

18. **Persistence Seal Key Is Not Fully Encapsulated**

Issue: The root persistence seal key can be returned as a copied byte array through security::persistence_seal_key, and it can be replaced through set_persistence_seal_key. That makes the root secret reachable as ambient kernel data instead of being locked behind sealed persistence operations.

Required fixes:
- Remove general-purpose seal key export from normal kernel callers.
- Keep the root seal key inside the security or persistence authority boundary.
- Replace direct key access with operations such as seal snapshot, unseal snapshot, rotate seal key, and migrate snapshot.
- Gate seal key provisioning and replacement behind production provisioning authority.
- Add tests proving callers cannot read, clone, log, or replace the seal key without the proper authority.

19. **External Snapshot Backends Can Bypass The Seal Format**

Issue: Disk and file snapshots are sealed by the persistence service, but the external snapshot backend receives and returns raw Snapshot objects. That means the external backend can bypass the built-in AES-CTR, HMAC, nonce, header, and validation rules unless the backend reimplements them perfectly.

Required fixes:
- Seal snapshot bytes inside the persistence service before calling an external backend write function.
- Authenticate and decrypt bytes inside the persistence service after an external backend read function.
- Treat external backends as storage transports, not trusted crypto implementers.
- Require external backend registration to declare security capabilities and policy mode.
- Add tests proving an external backend cannot return unauthenticated plaintext as trusted snapshot state.

20. **Durable Snapshot Write Failures Can Be Hidden**

Issue: The generic write_snapshot path updates the in-memory snapshot and ignores the result of the durable write. The temporal persistence caller also ignores write_temporal_snapshot failure. This can make the kernel believe a snapshot was saved even when durable storage failed.

Required fixes:
- Return durable write failure to callers in production snapshot paths.
- Distinguish in-memory snapshot update from durable snapshot commit.
- Audit durable write failure, backend fallback, and partial durable write behavior.
- Add retry, fallback, or quarantine policy when durable persistence fails.
- Add tests proving failed disk, external, and file snapshot writes do not look like successful durable commits.

21. **VFS State Can Bypass The Sealed Persistence Snapshot API**

Issue: The persistence service has write_vfs_snapshot and read_vfs_snapshot APIs, but the reviewed VFS path writes and recovers a flat filesystem snapshot through its own storage route. That can bypass the sealed persistence snapshot path for VFS state, even though VFS state may include metadata and authority-relevant information.

Required fixes:
- Route VFS persistent state through write_vfs_snapshot and read_vfs_snapshot, or seal the flat VFS snapshot format with the same policy.
- Require authentication before VFS recovered state is accepted.
- Encrypt VFS snapshot payloads when production persistence confidentiality is required.
- Bind VFS snapshot purpose, version, backend, and generation into authenticated metadata.
- Add tests proving tampered VFS snapshots, stale VFS snapshots, and unsealed VFS snapshots are rejected in production mode.

22. **Backend Fallback Can Weaken Recovery Policy**

Issue: Persistence fallback is useful for reliability, but recovery can become unsafe if a failed, corrupted, or attacked primary backend causes the kernel to trust an older or weaker fallback backend. The code needs to distinguish backend unavailable from integrity failure.

Required fixes:
- Treat MAC failure, malformed sealed headers, and rollback suspicion as security events, not ordinary backend misses.
- Forbid fallback after integrity failure unless a signed recovery policy explicitly allows it.
- Compare freshness metadata across disk, external, and file backends before choosing a recovered snapshot.
- Audit which backend was chosen and why other backends were rejected.
- Add tests for corrupted primary backend, stale fallback backend, valid newer disk snapshot, valid older file snapshot, and recovery-policy fallback.

23. **File Snapshot Length Is Not Strictly Authenticated**

Issue: File-backed snapshot recovery reads the available file bytes and verifies the header and payload length, but it does not require the file to end exactly at the authenticated snapshot payload. Trailing data can exist after an otherwise valid sealed snapshot.

Required fixes:
- Require exact file snapshot length, or define and authenticate any padding and trailer area.
- Reject trailing data in production file-backed snapshots unless the format explicitly allows it.
- Include file length or padded length in authenticated snapshot metadata.
- Add tests for valid snapshot plus trailing bytes, truncated file snapshots, padded file snapshots, and malformed file lengths.

24. **Snapshot Flag Policy Is Too Permissive**

Issue: V2 snapshot reads require the sealed flag, but the encrypted flag is optional if the MAC verifies. That means a valid authenticated-only snapshot can be accepted even when production policy expects encrypted-at-rest snapshots.

Required fixes:
- Define allowed V2 snapshot flag combinations.
- Require sealed and encrypted flags for production confidential snapshots.
- Reject authenticated-only snapshots unless a migration or recovery policy explicitly allows them.
- Bind the expected confidentiality policy into snapshot metadata or recovery policy.
- Add tests for sealed-only, encrypted-only, neither flag, unknown flag bits, and production encrypted-required mode.

25. **Store Capabilities Can Be Locally Fabricated**

Issue: StoreCapability has a public constructor, StoreRights::all exists, and many internal callers create all-rights persistence capabilities directly. The cap_id is not validated through the global capability manager, so the object is not yet a strong authority token.

Required fixes:
- Make persistence capabilities issued by the global capability manager instead of arbitrary constructors.
- Remove unrestricted StoreRights::all usage from normal service code.
- Bind capability id to owner, issuer, rights, slot, backend, lifetime, and revocation state.
- Audit all all-rights persistence capability use during migration.
- Add tests proving guessed cap_id values and locally fabricated StoreCapability objects are rejected.

26. **External Backend Registration Is Not Capability-Gated**

Issue: register_snapshot_backend and clear_snapshot_backend can change the external snapshot backend without a persistence capability check. That changes where snapshots are written and read, which changes the trust boundary for recovered state.

Required fixes:
- Require PERSIST_BIND_BACKEND or equivalent privileged authority before registering or clearing external snapshot backends.
- Bind backend registration to caller identity, backend identity, policy mode, and audit label.
- Prevent untrusted code from replacing a production backend with a weaker test backend.
- Audit backend registration, backend clearing, and backend replacement.
- Add tests for unauthorized backend registration, backend replacement during recovery, and backend clearing during snapshot write.

27. **Persistence Crypto Debug Tracing Leaks Runtime Metadata**

Issue: trace_snapshot_crypto prints operation labels, slot ids, pointer addresses, payload lengths, span lengths, and heap or JIT range membership. That is useful for bring-up, but production logs should not leak memory layout or crypto-operation metadata.

Required fixes:
- Compile-gate or policy-gate persistence crypto tracing.
- Remove raw pointer addresses from production serial output.
- Avoid printing heap and JIT range membership in production mode.
- Replace debug tracing with safe audit metadata such as operation type, slot, result, and failure class.
- Add tests or build checks proving persistence crypto tracing is disabled in production profiles.

28. **Persistence Recovery Errors Can Be Swallowed**

Issue: recover_snapshots_from_durable ignores individual read errors and only marks recovery as attempted. A MAC failure, malformed header, backend error, or rollback suspicion can be lost as an empty or skipped recovery path.

Required fixes:
- Track recovery outcome per snapshot slot and backend.
- Audit MAC failure, malformed header, missing backend, stale snapshot, rollback rejection, and successful recovery separately.
- Fail closed when production recovery state is present but cannot be authenticated.
- Expose safe recovery status through PERSIST_INTROSPECT without exposing plaintext.
- Add tests for disk MAC failure, file MAC failure, external backend failure, malformed headers, and partial recovery.

29. **Append Log Reads Can Panic On Out-Of-Range Offsets**

Issue: AppendLog::read slices records[from_offset..] without first checking that from_offset is within the log array. A caller-controlled offset can panic the kernel instead of returning a clean persistence error.

Required fixes:
- Validate from_offset before slicing the log record array.
- Return InvalidRecord or a dedicated range error for out-of-range reads.
- Clamp or reject max_records according to policy.
- Add tests for from_offset equal to capacity, greater than capacity, usize::MAX, and large max_records.
- Audit malformed log read requests when they come from untrusted callers.

30. **Snapshot Buffers Can Retain Stale Plaintext Tails**

Issue: Snapshot::write updates data_len but does not clear old bytes beyond the new length. Read and recovery paths also leave large snapshot and scratch buffers populated after use. Old plaintext can remain in memory after shorter writes or failed recovery.

Required fixes:
- Clear unused snapshot tail bytes after every shorter write.
- Clear output snapshot buffers before failed recovery returns.
- Clear global scratch image buffers after seal, unseal, and failed operations.
- Zero derived keys and plaintext staging areas with a compiler-resistant routine.
- Add tests or debug checks for stale tail clearing after shorter writes and failed reads.

31. **File Fallback Snapshot Writes Bypass Normal VFS Tracking**

Issue: File-backed fallback snapshot writes use write_path_untracked. That avoids recursive persistence through VFS, but it also bypasses normal VFS tracking, journaling, and audit expectations.

Required fixes:
- Treat file fallback snapshot writes as explicit persistence operations with their own audit records.
- Ensure write_path_untracked cannot be used by ordinary callers to bypass persistence policy.
- Bind fallback writes to backend policy, slot id, seal status, and failure reason.
- Verify file fallback snapshots after write when production recovery depends on them.
- Add tests for fallback write audit, fallback write failure, fallback tamper, and fallback recovery after primary backend failure.

### Issues in the OTA's path usage for these Crypto Primitives

1. **Unsigned OTA Manifests Are Still Policy-Permitted**

Issue: The OTA commit path can continue with a warning when the manifest is unsigned. That is useful during bring-up, but it is not production mature. A production update path should treat missing signatures as a policy failure unless the system is explicitly in a development or recovery mode.

Required fixes:
- Require a verified Ed25519 manifest signature in production mode.
- Treat unsigned manifests as fatal unless a signed policy explicitly allows them.
- Separate development, recovery, and production OTA verification policy.
- Add audit events for unsigned manifest acceptance and rejection.
- Add tests proving production mode rejects unsigned manifests.

2. **OTA Trusted Key Provisioning Is Not Fully Defined**

Issue: The OTA path reads the trusted public key from the VFS. That makes testing simple, but production maturity requires a clear trust root for the OTA signing key. If the trusted key can be replaced by ordinary filesystem writes, signature verification no longer proves publisher authority.

Required fixes:
- Provision the OTA public key through a measured, signed, or hardware-backed trust path.
- Protect the trusted OTA key from ordinary VFS modification.
- Require exact trusted public key length and reject trailing key file data.
- Define key replacement and key rotation policy.
- Define key revocation policy so removed or compromised signing keys cannot authorize future updates.
- Track OTA signing key identity and key version in trusted key metadata and signed manifest policy.
- Support a keyring or multi-key policy if Oreulius needs staged migrations between signing keys or publishers.
- Prevent rollback of trusted key state so an old revoked key cannot be restored as trusted authority.
- Separate development, recovery, and production signing keys with hard policy boundaries.
- Define emergency recovery key behavior, including when it is allowed and how it is audited.
- Define where the production trust root lives, such as measured boot state, firmware, hardware-backed storage, sealed persistence, or another protected authority path.
- Audit OTA key import, replacement, missing key, and mismatched key events.
- Audit OTA key use during successful and failed signature verification.
- Add tests proving an untrusted key cannot authorize an update.

3. **OTA Version Monotonicity Is Not Enforced**

Issue: The manifest includes a version string, but the commit path does not enforce that the pending version is newer than the active version. A validly signed older image could be replayed if rollback policy does not reject it.

Required fixes:
- Store the last accepted OTA version or generation in rollback-resistant state.
- Reject signed updates with older or repeated versions unless recovery policy allows them.
- Bind version monotonicity to the signed manifest message.
- Audit rejected downgrade attempts.
- Add tests for older signed versions, repeated versions, and allowed recovery rollback.

4. **OTA Rollback Protection Is Incomplete**

Issue: SHA-256 and Ed25519 can prove that an image matches a signed manifest, but they do not prove that the image is the newest allowed image. Without rollback protection, an attacker may replay an older valid image, manifest, and signature.

Required fixes:
- Bind OTA activation to a trusted rollback index, boot generation, or monotonic update counter.
- Reject old but valid signed OTA bundles outside explicit rollback mode.
- Record committed update generations in persistence or hardware-backed state.
- Ensure crash rollback cannot silently restore revoked or vulnerable images.
- Add rollback tests using older valid manifests and images.

5. **OTA Commit Is Not Fully Atomic**

Issue: The OTA path writes slot data, manifest data, version data, persistence records, and the active pointer through separate steps. A crash or power loss between those steps could leave the system in a partially updated state.

Required fixes:
- Define an atomic OTA transaction model for apply, verify, commit, and rollback.
- Write commit intent and completion records before and after active slot changes.
- Recover safely from crashes between manifest write, slot write, and active pointer update.
- Make active slot switching fail closed if the pending slot is not fully verified.
- Make active pointer writes atomic so a crash cannot leave /ota/active partially written or ambiguous.
- Re-check that the target slot is still the intended inactive slot immediately before switching the active marker.
- Verify the target slot hash after signature verification and before activation using the same byte range as boot verification.
- Verify the rollback sentinel is written successfully before treating commit as complete.
- Add crash-injection tests for every OTA transition point.

6. **OTA Authority Is Not Capability-Gated**

Issue: OTA commands can stage, verify, commit, and rollback update state, but those operations are not modeled as first-class capabilities. A mature kernel should separate who can stage an update, verify a manifest, activate a slot, rollback a slot, import a key, and inspect OTA state.

Required fixes:
- Add OTA capability rights such as OTA_STAGE, OTA_VERIFY, OTA_COMMIT, OTA_ROLLBACK, OTA_IMPORT_KEY, OTA_AUDIT, OTA_INTROSPECT, and OTA_DELEGATE.
- Require exact rights before applying, committing, rolling back, or changing trusted OTA key material.
- Bind OTA authority to owner process, slot, version, key identity, and policy mode.
- Route OTA delegation and revocation through the capability manager.
- Require delegated OTA capabilities to be attenuated so delegation can only remove rights or narrow scope, never add authority.
- Revoke delegated child OTA capabilities when the parent OTA capability is revoked.
- Audit OTA capability use, denial, delegation, attenuation, and revocation.
- Add tests proving staging authority does not imply commit authority and audit authority does not imply key import authority.

7. **OTA Hash And Signature Binding Needs Stronger Format Policy**

Issue: The OTA path builds a canonical signed message from hash and version, which is the right shape. The mature policy should also make sure the signed message includes every field that affects update meaning, such as slot purpose, image type, target device, policy mode, and rollback generation.

Required fixes:
- Extend the signed OTA manifest message with explicit domain, image type, target device, slot purpose, policy mode, and rollback generation where needed.
- Bind trusted key identity into the signed OTA manifest message where policy requires it.
- Reject manifests with missing required fields.
- Reject manifest files that are malformed, too short, too long, or contain trailing data.
- Restrict version strings to a safe canonical format before including them in the signed message.
- Keep canonical encoding stable across architectures and versions.
- Add test vectors for canonical OTA manifest messages.
- Add negative tests for field reordering, missing fields, malformed version, and wrong domain.

8. **OTA Image Hash Coverage Needs Clear Boundaries**

Issue: SHA-256 is computed over the staged image bytes, but the README should define exactly what counts as the image. Production OTA needs clear boundaries for headers, metadata, padding, signatures, and payload bytes so the signed hash cannot be interpreted differently by different boot stages.

Required fixes:
- Define the exact byte range covered by the OTA image hash.
- Decide whether image headers, metadata, padding, and bootloader fields are inside or outside the hash.
- Ensure commit verification and boot verification hash the same byte range.
- Treat boot hash mismatch as fatal in production verified-boot mode.
- Reject ambiguous or partially read image data.
- Add tests for truncated images, padded images, and metadata changes.

9. **OTA Persistence Events Are Not A Complete Security Audit Trail**

Issue: The OTA path records lifecycle events such as apply, commit, rollback, and verify, but production maturity needs a richer audit trail for security decisions. Signature failure, hash mismatch, unsigned manifest policy, downgrade rejection, rollback activation, and key changes should all be visible.

Required fixes:
- Audit signature verification success and failure.
- Audit hash mismatch with expected and actual hash metadata where safe.
- Gate detailed expected and actual hash printing behind development or debug policy.
- Audit unsigned manifest policy decisions.
- Audit missing files, malformed hex, read failures, and invalid signatures as distinct OTA trust outcomes.
- Audit downgrade rejection and rollback acceptance.
- Audit rollback decisions separately from rollback execution, including the reason rollback was chosen before the active pointer changes.
- Store version, manifest identity, key identity, policy mode, rollback generation, previous active slot, target slot, and decision reason in OTA audit records where safe.
- Replace rollback placeholder hashes with the real fallback slot hash and rollback reason.
- Treat OTA audit append failure as security-relevant during production OTA operations.
- Require OTA_AUDIT or slot-scoped OTA_SLOT_AUDIT authority before writing OTA audit records.
- Keep OTA persistence record formats stable enough for recovery, fleet attestation, and post-incident review.
- Audit trusted key provisioning and key rotation.
- Add tests proving failed OTA decisions create audit records.

10. **OTA Test Coverage Is Not Complete**

Issue: Primitive tests for SHA-256, Ed25519, and constant-time comparison do not prove the full OTA flow is safe. OTA needs composed tests that verify staging, manifest signing, hash comparison, commit, rollback, failure handling, and recovery behavior together.

Required fixes:
- Add tests for valid signed update apply and commit.
- Add tests for unsigned manifest rejection in production mode.
- Add tests for invalid signature, missing public key, missing signature, and mismatched key.
- Add tests for malformed public keys, malformed signatures, trailing key data, and trailing signature data.
- Add tests for revoked key, rotated key, wrong key identity, development key in production mode, old key replay, recovery key policy, and ordinary VFS replacement attempts.
- Add tests for hash mismatch, truncated slot image, wrong version, and wrong manifest domain.
- Add tests for equal hashes, different hashes, and hash length mismatch behavior.
- Add tests proving malformed manifest data fails before hash comparison.
- Add tests for production boot behavior when the active slot hash mismatches.
- Add rollback and crash-recovery tests for apply, commit, active pointer switch, and rollback sentinel behavior.
- Add tests for failed rollback sentinel cleanup, rollback ping-pong prevention, per-slot metadata validation, atomic active-pointer writes, and failed fallback-slot verification.
- Add tests proving apply, verify, commit, rollback, and failure paths emit the expected OTA persistence records.
- Add tests proving audit append failure is handled according to production OTA policy.
- Add tests proving ct_eq is used for security-sensitive OTA hash comparisons.
- Add ota-selftest as an umbrella command for apply, commit, verify, rollback, key import, signature import, persistence records, and failure-path checks.
- Add ota-selftest --fuzz or focused fuzz commands for manifest, key, signature, version, active slot marker, rollback sentinel, and slot-state parsing.
- Add ota-selftest --policy for production, development, and recovery policy checks around unsigned manifests, downgrade rejection, rollback, and recovery keys.
- Add ota-selftest --rollback for manual rollback, crash rollback, stale sentinel, invalid fallback, and interrupted rollback checks.
- Add ota-selftest --capabilities for OTA rights separation, delegated authority, revoked capability use, owner mismatch, and scope mismatch checks.
- Add ota-selftest --audit for expected persistence records, audit append failure behavior, and production-safe logging checks.
- Add ota-status --machine or an equivalent machine-readable status command for automated tests and tooling.
- Make test and fuzz commands report structured counts such as cases run, expected accepts, expected rejects, unexpected accepts, unexpected rejects, and crashes or panics.

11. **OTA Slot Metadata Is Not Bound Together**

Issue: The A/B slot model stores slot image, active pointer, manifest hash, version, signature, and rollback sentinel as separate pieces of state. The current model does not fully bind the manifest and version to a specific pending slot or track an explicit staged, verified, committed, or rollback state.

Required fixes:
- Bind target slot, image hash, version, signature, and slot state into one authenticated OTA metadata record.
- Store per-slot manifest metadata so slot A and slot B can each be verified against their own hash, version, signature, key identity, and slot identity.
- Track explicit slot states such as active, inactive, staged, verified, committed, failed, and rollback.
- Reject commit when manifest metadata does not match the pending slot.
- Reject stale or mismatched version and manifest files.
- Treat version write failure as manifest metadata failure.
- Add tests for mismatched manifest, wrong pending slot, stale version, and partial slot metadata.

12. **OTA Active Slot And Rollback Target Validation Is Incomplete**

Issue: The active slot marker can fall back to slot A when missing or malformed, and rollback switches to the other slot without proving the fallback slot is currently valid. A mature A/B model should validate active and rollback targets before trusting or switching them.

Required fixes:
- Treat malformed active slot markers as recovery errors instead of silently trusting slot A.
- Verify the rollback target hash and signature before switching active slots.
- Bind rollback sentinel data to committed slot, fallback slot, version, boot attempt, rollback generation, and expected image hash.
- Verify rollback sentinel cleanup succeeds after clean boot or completed rollback so stale rollback state cannot survive silently.
- Require an explicit successful boot checkpoint before accepting a newly committed slot as stable.
- Track failed slots, boot attempts, and rollback generations to prevent rollback ping-pong loops.
- Store active slot state in rollback-resistant or authenticated metadata.
- Add tests for malformed active marker, empty fallback slot, invalid fallback signature, and stale rollback sentinel.

13. **OTA Slot Capabilities Are Not Fully Defined For A/B Slots**

Issue: The OTA capability model needs slot-scoped rights, not only broad update rights. A mature A/B update path should distinguish authority to write an inactive slot, verify a staged slot, activate a verified slot, roll back to a validated fallback slot, inspect slot metadata, and audit slot lifecycle events.

Required fixes:
- Define OTA_SLOT_READ, OTA_SLOT_WRITE, OTA_SLOT_VERIFY, OTA_SLOT_ACTIVATE, OTA_SLOT_ROLLBACK, OTA_SLOT_AUDIT, and OTA_SLOT_INTROSPECT.
- Scope each OTA slot capability to slot id, slot state, version, image hash, key identity, boot attempt, and policy mode where needed.
- Ensure OTA_SLOT_WRITE does not imply OTA_SLOT_ACTIVATE.
- Ensure OTA_SLOT_VERIFY does not imply OTA_SLOT_ROLLBACK.
- Allow OTA_SLOT_ACTIVATE only for a verified, signed, policy-approved target slot.
- Allow OTA_SLOT_ROLLBACK only after validating the fallback slot hash, signature, and rollback policy.
- Add tests for write-without-activate, verify-without-rollback, activate-unverified-slot, rollback-invalid-fallback, delegated OTA use, revoked OTA capability use, rights escalation attempts, owner mismatch, scope mismatch, and introspect-without-mutate behavior.

14. **OTA Apply Storage Verification Is Incomplete**

Issue: The OTA apply path reads the whole source image into memory, hashes that source buffer, and then writes the buffer into the inactive slot. It does not immediately prove that the inactive slot now contains the exact bytes that were hashed. A mature apply flow should handle large images in bounded chunks and verify the stored slot after write.

Required fixes:
- Stream large update images in bounded chunks instead of reading the whole image into memory.
- Hash the source image while streaming it into the inactive slot.
- Re-read or re-hash the written inactive slot after write to prove storage matches the expected hash.
- Treat partial writes or post-write hash mismatch as failed apply state.
- Clear or quarantine the inactive slot when apply fails after partial write.
- Add tests for large images, partial reads, partial writes, storage mismatch, and interrupted apply.

15. **OTA Failure Behavior Is Not Fully Defined**

Issue: OTA failure paths currently mix printed errors, early returns, warnings, ignored write or cleanup failures, and non-fatal boot verification mismatches. That is useful during bring-up, but production OTA needs a stable failure model where each failure has a machine-readable class, a safe audit record, a defined state transition, and a clear fail-closed or recovery-policy outcome.

Required fixes:
- Define stable OTA failure classes such as storage failure, malformed metadata, policy denial, authority denial, signature failure, hash failure, rollback failure, verified-boot failure, and audit failure.
- Map each failure class to a defined state transition, such as failed apply, failed verify, failed commit, failed rollback, quarantined slot, recovery required, or production halt.
- Treat production OTA failures as fail-closed unless a signed development or recovery policy explicitly allows softer behavior.
- Add OTA transaction ownership or locking so apply, commit, rollback, trusted-key import, and boot verification cannot interleave across the same metadata and slot state.
- Re-check manifest, key, slot, version, and image hash state immediately before activation to avoid stale validation.
- Add cleanup and quarantine policy for stale slot bytes, stale manifests, stale signatures, stale versions, and failed rollback sentinels.
- Add retry limits and recovery behavior for interrupted cleanup, interrupted commit, failed audit append, and failed active-pointer writes.
- Add tests for missing images, empty images, malformed metadata, partial reads, partial writes, version write failure, unsigned production policy, invalid signatures, hash mismatch, active pointer write failure, rollback sentinel write failure, boot hash mismatch, invalid fallback slot, stale metadata after failure, concurrent OTA operations, resource exhaustion, failed cleanup, and recovery after interrupted transactions.

16. **OTA Boot Verification Runs Before Durable VFS Recovery**

Issue: On the reviewed x86_64 boot path, OTA slot initialization and verify_boot_image run before VFS recovery restores persisted filesystem state. That means the kernel can verify default, missing, or stale OTA state, then recover a different /ota state afterward. In that order, the verified boot check can protect the wrong state.

Required fixes:
- Recover durable VFS state before making OTA trust decisions.
- Run OTA slot initialization only after the active marker, manifest metadata, signatures, rollback sentinel, and slot files have been recovered.
- Run verify_boot_image after recovery and before recovered OTA state is treated as trusted.
- Treat failed recovery of production OTA metadata as a security-relevant boot failure.
- Add boot-order tests proving recovered /ota state is the state that OTA verification checks.

17. **OTA Boot Enforcement Is Inconsistent Across Architectures**

Issue: The reviewed x86_64 path wires in OTA slot initialization and verified boot, but the reviewed aarch64 shared runtime does not call the same OTA init or verification path, and the x86 runtime recovery path does not show the same OTA enforcement. That makes OTA security architecture-dependent.

Required fixes:
- Define one shared OTA boot contract for every supported architecture.
- Require every architecture to call VFS recovery, OTA init, rollback decision, and boot image verification in the same security order.
- Make missing OTA boot enforcement a build-time or boot-time error in production profiles.
- Add architecture parity tests for x86_64, x86, and aarch64 OTA startup behavior.
- Document which architectures are development-only until OTA boot enforcement is wired in.

18. **Crash Rollback Does Not Yet Have A Durable Previous-Boot Signal**

Issue: init_slots checks crash_count with the rollback sentinel, but crash_count is a current-boot in-memory panic counter. After a real reboot, that counter starts over. This means crash-triggered rollback may not actually know that the previous boot failed. On aarch64, the current code forces crash_count to zero.

Required fixes:
- Add a durable boot-attempt record that is written before booting a newly committed slot.
- Add a durable boot-success marker that is written only after the new slot reaches a known-good point.
- Treat an uncleared boot-attempt record as evidence that the previous boot failed or did not complete.
- Bind boot attempt, committed slot, fallback slot, rollback generation, and expected image hash into the rollback decision.
- Add tests for real reboot rollback, missing boot-success marker, stale boot-attempt record, and aarch64 crash rollback behavior.

19. **Global OTA Metadata Can Confuse Active And Pending Slots**

Issue: The current OTA path stores manifest hash, signature, public key, and version as global /ota files. Applying a new update overwrites the metadata that boot verification may use for the currently active slot. If the system reboots after apply but before commit, the active slot can be compared against pending-slot metadata.

Required fixes:
- Store manifest, version, signature status, key identity, policy mode, and slot state per slot.
- Keep active-slot metadata separate from pending-slot metadata.
- Bind each manifest to the slot it describes.
- Reject boot verification when global metadata does not identify the active slot.
- Add tests for apply-without-commit followed by reboot, rollback after failed commit, and stale global manifest data.

20. **Malformed OTA Trust Material Can Downgrade Into The Unsigned Path**

Issue: The detached-signature helper treats public key read errors and signature read errors as missing values. If both trust files are malformed or unreadable, the result can become unsigned instead of malformed. Since the current commit path still permits unsigned manifests with a warning, malformed trust material can accidentally become a weaker trust state.

Required fixes:
- Separate missing public key, malformed public key, unreadable public key, missing signature, malformed signature, unreadable signature, invalid signature, and unsigned policy states.
- Treat malformed trusted key material as fatal in production.
- Treat malformed signatures as fatal instead of falling back to unsigned behavior.
- Prevent malformed key and malformed signature pairs from producing DetachedSignatureStatus::Unsigned.
- Add tests for malformed key plus missing signature, malformed key plus malformed signature, missing key plus malformed signature, and unreadable trust files.

21. **OTA Hex Metadata Parsing Accepts Prefixes And Trailing Data**

Issue: The current hex parsing helpers accept the required leading hex bytes and do not require the file to end exactly there. Oversized files can also be truncated before parsing. That means a file with a valid prefix and trailing garbage can still become accepted trust metadata.

Required fixes:
- Require exact byte lengths for manifest hashes, Ed25519 public keys, and Ed25519 signatures.
- Reject trailing bytes, leading whitespace, embedded whitespace, and oversized files in production OTA metadata.
- Reject truncated reads instead of parsing the prefix that was available.
- Make import_hex_file normalize only after exact validation succeeds.
- Add tests for valid prefix plus trailing data, oversized key files, oversized signature files, whitespace variants, and truncated metadata.

22. **OTA Source Paths Are Not Policy-Scoped**

Issue: ota-apply, ota-trust-key, and ota-set-signature import bytes from caller-supplied VFS paths. Without source-path policy, OTA can consume images, keys, or signatures from paths that were not meant to feed the update system, including metadata paths, active slot paths, temporary files, or other protected VFS state.

Required fixes:
- Require source-object authority before OTA imports image, key, or signature bytes.
- Restrict OTA image imports to approved update package locations.
- Restrict trusted key and signature imports to approved provisioning paths.
- Reject imports from /ota metadata files, active slot files, or other protected kernel state unless an explicit recovery policy allows it.
- Add tests for staging from active slot, staging from manifest path, importing key from untrusted VFS path, and importing signature from protected metadata.

23. **OTA Image And Slot Reads Can Exhaust Kernel Memory**

Issue: ota-apply, ota-commit, and verify_boot_image allocate a buffer based on VFS path_size and then read the whole image or slot into memory. A malicious, corrupted, or unexpectedly large VFS object can force large allocation before the update is trusted.

Required fixes:
- Add a hard maximum OTA image size.
- Add a hard maximum slot image size.
- Stream image hashing and slot verification in bounded chunks.
- Treat oversized files as policy failures before allocation.
- Add tests for huge image paths, corrupted path_size values, oversized slot files, and memory-pressure failure behavior.

24. **OTA Rollback Sentinel Is Plain VFS State**

Issue: The rollback sentinel is a plain file at /ota/rollback_needed. If a caller or corrupted recovery path can create, delete, or alter that file without OTA authority, it can force rollback, suppress rollback, or leave confusing recovery state.

Required fixes:
- Store rollback sentinel state inside authenticated OTA metadata.
- Bind sentinel state to committed slot, fallback slot, version, boot attempt, rollback generation, and expected image hash.
- Require OTA_SLOT_ROLLBACK or an internal boot-recovery authority before changing sentinel state.
- Treat sentinel cleanup failure as a security-relevant recovery failure.
- Add tests for forged sentinel, deleted sentinel, stale sentinel, malformed sentinel, and unauthorized sentinel writes.

25. **Verified Boot Is Still A Software Sanity Check**

Issue: verify_boot_image runs after the kernel is already executing and currently logs mismatch without halting. That can catch some corruption, but it cannot stop a bad image from running before the check. It is not yet production verified boot.

Required fixes:
- Move production image measurement and enforcement into the bootloader or an earlier root-of-trust path.
- Make production active-slot hash mismatch fatal.
- Ensure bootloader verification and kernel verification use the same canonical image byte range.
- Record verified-boot failure in audit state before halting or entering recovery when possible.
- Add tests or boot traces proving a bad active slot cannot reach normal runtime in production mode.

26. **OTA Status And Debug Output Leak Trust Metadata**

Issue: ota-status prints manifest hash and signature status, and commit mismatch prints expected and actual hashes. This is useful during development, but production status and logs should not freely expose trust metadata to any caller with shell access.

Required fixes:
- Gate OTA status behind OTA_INTROSPECT or slot-scoped OTA_SLOT_INTROSPECT authority.
- Gate detailed expected and actual hash output behind development or debug policy.
- Make production OTA status output minimal and machine-readable.
- Audit denied status and introspection attempts.
- Add tests proving unauthorized callers cannot read manifest hashes, signature status, key identity, or detailed mismatch metadata.

27. **OTA VFS Reads Have Time-Of-Check To Time-Of-Use Risk**

Issue: OTA reads the active marker, manifest, version, signature, public key, and slot bytes through separate VFS operations. If OTA state can change between those operations, the kernel can verify one set of bytes and activate or report on another set.

Required fixes:
- Add an OTA transaction lock covering apply, commit, rollback, key import, signature import, status, and boot verification.
- Read OTA metadata into one authenticated snapshot before making a trust decision.
- Re-check active slot, pending slot, manifest identity, signature identity, key identity, and image hash immediately before activation.
- Reject commit if any OTA input changed between verification and activation.
- Add tests for concurrent apply and commit, key replacement during commit, signature replacement during verify, active marker changes during rollback, and manifest changes during boot verification.

### Issues in the Fleet Attestations usage for these crypto primitives

1. **Fleet Active Slot Hash Is Not Bound To Verified OTA State**

Issue: The fleet measurement reads the active slot hash from the global OTA manifest file. That file may not prove which slot is actually active, whether the active slot was verified, or whether the manifest describes staged state instead of trusted active state. It also does not bind rollback state, boot verification result, or commit state into the fleet evidence.

Required fixes:
- Read active slot hash from verified OTA active-slot metadata.
- Bind active slot id, OTA version, image hash, signature status, key identity, policy mode, rollback generation, boot verification result, and commit state into fleet attestation evidence.
- Use one strict OTA metadata parser for both OTA and Fleet so malformed manifest hex has one shared meaning.
- Reject or mark attestation as unknown when active-slot metadata is missing, stale, unsigned, malformed, rollback-tainted, unverified, or mismatched.
- Add tests for staged manifest confusion, wrong active slot hash, stale manifest data, malformed active marker, malformed manifest hex, unsigned manifest policy, rollback sentinel interaction, active slot switch during measurement, and verified active-slot metadata.

2. **All-Zero Unknown Measurements Are Not A Strong Attestation State**

Issue: If the OTA manifest cannot be read, the fleet path uses an all-zero active slot hash. That is honest as an unknown value, but it should not be treated as normal healthy evidence. Malformed OTA manifest hex is also too weak today because invalid nibbles can become zero bytes instead of making the attestation evidence invalid. More broadly, the bundle does not yet distinguish measured, unknown, unavailable, rejected, malformed, and stale inputs as separate evidence states.

Required fixes:
- Represent unknown slot hash as an explicit attestation state.
- Add explicit state tags for measured, unknown, unavailable, rejected, malformed, and stale inputs.
- Treat malformed OTA manifest hex as invalid evidence instead of converting bad characters into zero nibbles.
- Bind state tags into the signed canonical message, hashed measurement input where relevant, and persistence records.
- Mark architecture-missing fields such as aarch64 crash count and boot session as unavailable, not as valid zero values.
- Require policy to decide whether unknown measurements are allowed, warning-only, diagnostic-only, fatal, or allowed only under signed recovery policy.
- Block or downgrade remote transmission when evidence is unknown, unavailable, rejected, malformed, or stale according to production policy.
- Audit unknown measurement generation and transmission.
- Add tests proving all-zero slot hash, malformed manifest hex, unavailable architecture fields, stale OTA state, and rejected inputs are not accepted as normal verified evidence.

3. **Fleet Attestation Evidence Is Missing Important Context**

Issue: The current bundle signs boot session, crash count, boot tick, measurement, active slot hash, and scheduler switches. It does not yet include key identity, signature status, policy mode, active slot id, OTA version, peer identity, architecture, or evidence freshness. It also does not classify fields by meaning, so stable identity evidence, freshness evidence, and diagnostic runtime evidence can look equally authoritative.

Required fixes:
- Add key identity and signing policy mode to the attestation evidence.
- Add active slot id and OTA version to the evidence.
- Add peer identity or verifier identity when the bundle is intended for remote proof.
- Add architecture and evidence-source metadata for fields that differ across platforms.
- Classify bundle fields as identity evidence, freshness evidence, or diagnostic evidence.
- Define production policy for unsigned local bundles, including whether unsigned evidence can be exported, recorded, printed, or used only as diagnostic state.
- Add tests proving missing required evidence fields are rejected.

4. **Fleet Attestation Persistence Records Are Too Small**

Issue: The AttestationRecord stores boot session, crash count, boot tick, and measurement hash. It does not store enough information to reconstruct the full attestation decision later. It also uses a broad persistence capability in the current fleet path, even though attestation recording only needs append-log authority. The persistence log has CRC32 integrity for accidental corruption, but fleet attestation evidence still needs authenticated and rollback-resistant record handling for production trust.

Required fixes:
- Store active slot hash, active slot id, OTA version, key identity, signature status, policy mode, peer identity, and freshness metadata where safe.
- Store canonical message identity, measurement schema version, source-health states, trusted key generation, and final policy decision.
- Store whether the measurement was local-only, exported, or transmitted to a peer.
- Store peer destination details when evidence is transmitted remotely.
- Store whether signature verification was unsigned, verified, malformed, or invalid.
- Add monotonic record sequence, boot generation, and anti-rollback metadata for fleet attestation records.
- Protect fleet attestation records with authenticated storage, not only CRC32.
- Define retention, rollover, and log-full behavior for attestation evidence.
- Use append-log-only persistence authority instead of StoreRights::all.
- Treat failed persistence append as security-relevant and define whether it fails closed, enters diagnostic-only mode, or blocks remote transmission.
- Add tests proving persistence records explain successful attestations, failed records, unsigned records, invalid-signature records, unknown-slot records, stale-message records, remote-transmission records, log-full behavior, record tampering, and rollback attempts.

5. **Remote CapNet Attestation Does Not Carry The Signed Bundle**

Issue: fleet-attest can send a CapNet Attest frame, but the code says the signed bundle remains local and the CapNet frame does not carry the detached signature in this phase. The current CapNet Attest frame is built with an empty payload, and the receive path expects Attest control frames to have zero payload. That means remote attestation transmission is not yet a complete signed proof.

Required fixes:
- Carry the signed canonical bundle inside the CapNet attestation flow, or carry the bundle hash and detached signature.
- Define an evidence-carrying Attest payload format, or define a separate signed-evidence fetch and verification path.
- Bind transmitted evidence to target peer id, network destination, challenge, nonce, request id, schema version, key identity, policy mode, and freshness window.
- Scope FLEET_TRANSMIT authority by peer id, destination, evidence type, policy mode, and disclosure level.
- Reject remote attestation transmission when the bundle is unsigned, invalid, stale, missing required context, or not recorded in persistence.
- Audit transmitted attestation sequence, peer id, destination, CapNet sequence, bundle identity, bundle hash, signature status, freshness state, and final send result.
- Add tests for remote transmission with signed bundle, unsigned bundle, invalid signature, stale evidence, wrong peer, missing payload, replayed challenge, failed send, policy denial, and missing signature.

6. **Fleet Attestation Lacks Freshness Protection**

Issue: The signed canonical fleet message does not include a verifier challenge, nonce, request id, peer id, or expiration window. A stale signed attestation can be replayed as if it were fresh.

Required fixes:
- Add verifier challenge, nonce, request id, timestamp window, or peer-bound freshness token to the signed message.
- Reject old signed attestations outside the allowed freshness window.
- Bind freshness metadata to the verifier or destination peer when used remotely.
- Store freshness metadata in persistence for audit and replay investigation.
- Add replay tests proving an old signed /fleet/attest.msg cannot be reused as current evidence.

7. **Fleet Trusted Key Provisioning Is Not Fully Defined**

Issue: The trusted fleet public key is imported from a VFS path into /fleet/attest.pub. That is useful for testing, but production attestation needs a protected trust root, source-path policy, and key lifecycle. Replacing the trusted key changes who can authorize fleet evidence, so it has to be treated as a security decision instead of an ordinary file update.

Required fixes:
- Provision trusted fleet keys through a measured, signed, or hardware-backed path.
- Protect /fleet/attest.pub from ordinary VFS modification.
- Require source-object authority before importing a fleet trusted key.
- Restrict trusted key import to approved provisioning paths.
- Track fleet key identity, generation, issuer, policy mode, activation time, expiry time, development or production status, and revocation state.
- Define fleet key rotation and emergency recovery key behavior.
- Audit trusted key import, replacement, denial, rotation, recovery, and revocation.
- Record which trusted key generation verified each fleet attestation.
- Add tests proving untrusted, revoked, expired, wrong-generation, wrong-issuer, unauthorized-source, and development keys cannot authorize production evidence.
- Add tests for signature verification before and after key rotation.

8. **Fleet Signature Parsing Can Inherit OTA-Style Strictness Problems**

Issue: Fleet uses the same detached-signature helpers as OTA. The helpers accept valid prefixes with trailing data, and malformed key or signature reads can collapse into missing values. That can make malformed trust material look unsigned instead of malformed.

Required fixes:
- Require exact fleet public key and signature file lengths.
- Reject trailing data, oversized files, whitespace variants, and malformed hex.
- Separate missing key, malformed key, missing signature, malformed signature, invalid signature, and unsigned policy states.
- Prevent malformed key and malformed signature pairs from downgrading into unsigned state.
- Add tests for malformed fleet key, malformed fleet signature, trailing data, wrong key, wrong domain, and unsigned production policy.

9. **Fleet Export Files Are Ordinary VFS State**

Issue: The canonical message, human summary, trusted public key, and detached signature are stored as files under /fleet. If ordinary VFS writes can modify those files, exported evidence and trusted verification state are not protected. Verification also needs to know whether /fleet/attest.msg belongs to the latest built bundle or whether it is an older exported artifact being checked later.

Required fixes:
- Protect /fleet/attest.msg, /fleet/attest.txt, /fleet/attest.pub, and /fleet/attest.sig with fleet authority or signed storage policy.
- Bind exported message files to the measurement and signature status that produced them.
- Reject verification if exported files changed after measurement without a new attestation operation.
- Mark stale exported messages explicitly when verifying an older /fleet/attest.msg outside the current bundle build flow.
- Audit fleet export writes and trusted key or signature replacement.
- Add tests for ordinary VFS replacement of fleet message, signature, public key, summary files, and stale exported message verification.

10. **Fleet Commands Are Not Capability-Gated**

Issue: Fleet attestation, export, verification, trusted key import, detached signature import, persistence recording, diagnostics, and peer transmission are command-accessible operations. The current command surface is useful for alpha development, but it does not yet enforce separate authority for local evidence, trusted-key control, persistence writes, diagnostics, or remote disclosure.

Required fixes:
- Define FLEET_ATTEST for building local Fleet attestation bundles.
- Define FLEET_EXPORT for writing canonical messages and human summaries.
- Define FLEET_VERIFY for verifying detached Fleet signatures.
- Define FLEET_IMPORT_KEY for installing, rotating, or replacing trusted Fleet verification keys.
- Define FLEET_IMPORT_SIGNATURE for importing detached Fleet signatures.
- Define FLEET_RECORD for appending Fleet attestation records into persistence.
- Define FLEET_TRANSMIT for sending Fleet evidence through CapNet.
- Define FLEET_DIAG for reading local Fleet diagnostic state.
- Define FLEET_INTROSPECT for reading higher-detail Fleet internals, source labels, policy state, and record history.
- Define FLEET_AUDIT for writing or inspecting Fleet audit events.
- Define FLEET_DELEGATE and FLEET_REVOKE for controlled delegation and revocation of Fleet authority.
- Require exact rights before building, exporting, verifying, transmitting, recording, diagnosing, importing keys, importing signatures, or modifying fleet attestation state.
- Scope FLEET_TRANSMIT by peer id, destination address, destination port, evidence type, freshness requirements, and policy mode.
- Scope FLEET_IMPORT_KEY by provisioning source, key generation, issuer, policy mode, activation time, expiry time, and revocation state.
- Scope FLEET_IMPORT_SIGNATURE to the current exported bundle, expected key generation, and policy mode.
- Add Fleet capability metadata for owner process, right set, allowed peer or peer group, allowed evidence class, policy mode, key generation, freshness rules, expiry time, and audit label.
- Replace broad internally-created persistence authority with Fleet-specific record authority for attestation records.
- Audit fleet capability use, denial, delegation, revocation, key import, signature import, diagnostic access, persistence append, and remote transmission.
- Add tests proving diagnostics authority does not imply key import, local attestation authority does not imply remote transmission, verification authority cannot overwrite trusted material, record authority cannot transmit, and transmit authority cannot send evidence to an unauthorized peer.

11. **Fleet Diagnostics Output Exposes Sensitive System State**

Issue: fleet-diag prints crash state, OTA state, measurement hash, slot hash, signed bundle status, scheduler state, persistence log usage, and CapNet peer count. That is valuable for operators, but it should not be exposed without authority in production.

Required fixes:
- Gate fleet diagnostics behind FLEET_DIAG or FLEET_INTROSPECT authority.
- Define production disclosure policy for crash state, OTA active slot state, slot sizes, measurement hash, active slot hash, signature status, scheduler counts, persistence usage, and CapNet peer counts.
- Redact or minimize sensitive fields in production diagnostics according to that policy.
- Separate local debug output from remote operator evidence.
- Keep diagnostic output aligned with signed Fleet evidence, especially for unavailable architecture fields and weak active-slot hash sources.
- Mark diagnostic-only fields so they are not accidentally treated as signed Fleet evidence.
- Separate ordinary diagnostics from deeper Fleet introspection state.
- Audit diagnostic access and denied diagnostic attempts.
- Audit redacted diagnostic reads and full introspection reads separately.
- Add tests proving unauthorized callers cannot read fleet diagnostics state.
- Add tests proving production redaction works and diagnostic-only output does not become remote attestation evidence.

12. **Architecture-Specific Evidence Is Not Normalized**

Issue: Fleet evidence is built through architecture-specific branches, but the signed message does not yet carry enough metadata to explain those branches. Non-aarch64 uses the RDTSC boot tick and crash-log crash state, while aarch64 uses platform ticks and zeroes crash count and boot session because that crash source is unavailable. That makes the bundle shape match, but the evidence meaning is not the same across architectures.

Required fixes:
- Add architecture id and build id to the canonical fleet attestation message.
- Add evidence-source metadata for boot session, crash count, boot tick, scheduler fields, and active slot hash.
- Add source-health metadata so each field can say measured, unavailable, estimated, diagnostic-only, stale, or rejected.
- Add timer-source metadata so RDTSC values and platform tick values are not treated as directly comparable.
- Add crash-source metadata so measured zero crash state is distinct from unavailable crash state.
- Mark unavailable architecture-specific fields as unavailable, not as equivalent zero values.
- Carry architecture and source labels into the hashed measurement input, signed canonical message, and fleet persistence record.
- Define architecture support status, such as production-ready, diagnostic-only, unsupported, or rejected.
- Define architecture parity requirements for production fleet attestation.
- Make diagnostics and signed evidence agree when a source is unavailable.
- Add x86, x86_64, and aarch64 evidence tests proving source labels are correct.
- Add tests proving unavailable fields do not hash the same way as measured zero fields.
- Add tests proving unsupported architecture evidence is rejected or marked diagnostic-only under production policy.
- Add tests proving verifiers do not compare timer values across architectures as if they came from the same clock.
- Audit architecture-specific attestation limitations.

13. **Fleet Attestation Test Coverage Is Not Complete**

Issue: The current helper tests prove one canonical Fleet message string is stable, and the lower crypto primitives have some direct tests. That does not prove the full Fleet attestation flow is safe across measurement gathering, active-slot binding, canonical parsing, signature policy, export files, persistence records, CapNet transmission, capability enforcement, diagnostics, architecture-specific evidence, failure behavior, or malformed input handling.

Required fixes:
- Add deterministic Fleet bundle builders for test injection of boot tick, crash count, boot session, active slot hash, scheduler switches, architecture label, source-health labels, and policy mode.
- Add tests proving every measurement input changes the SHA-256 measurement in the expected way.
- Add tests proving measured zero, unavailable zero, unknown zero, and rejected zero do not become the same attestation state.
- Add tests for active slot hash binding to verified OTA active-slot metadata.
- Add tests for missing OTA metadata, stale OTA metadata, staged manifest confusion, malformed active slot marker, malformed manifest hex, unsigned manifest policy, rollback-tainted metadata, and active slot changes during measurement.
- Add strict canonical message tests for stable field order, schema version, domain string, decimal encoding, hex encoding, missing fields, duplicate fields, unknown fields, uppercase hex, malformed hex, CRLF variants, trailing data, and wrong schema.
- Add semantic verification tests proving the parsed fields recompute to the signed measurement.
- Add Ed25519 primitive tests using broader RFC 8032 vectors and negative cases for malformed public keys, malformed R values, non-canonical S values, small-order public keys, small-order R values, wrong domains, and wrong messages.
- Add Fleet wrapper tests for valid signature, wrong signature, wrong key, missing key, missing signature, malformed key, malformed signature, unreadable key, unreadable signature, unsigned development policy, and unsigned production policy.
- Add export-file tests proving ordinary VFS replacement of the message, summary, trusted key, and signature files is rejected or detected.
- Add stale export tests proving an old /fleet/attest.msg cannot be verified as current evidence without policy.
- Add persistence tests for successful attestations, failed attestations, unsigned records, invalid-signature records, unknown-slot records, stale-message records, remote-transmission records, log-full behavior, record tampering, failed append, and rollback attempts.
- Add CapNet transmission tests for signed evidence, unsigned evidence, invalid signatures, stale evidence, wrong peer, wrong destination, missing payload, replayed challenge, failed send, policy denial, and missing freshness.
- Add capability tests proving FLEET_DIAG cannot import keys, FLEET_ATTEST cannot transmit remotely, FLEET_VERIFY cannot overwrite trust material, FLEET_RECORD cannot transmit, and FLEET_TRANSMIT cannot send to an unauthorized peer.
- Add diagnostics tests for unauthorized access, production redaction, diagnostic-only labels, source unavailability, and local diagnostics not becoming remote attestation evidence.
- Add architecture tests for x86, x86_64, and aarch64 source labels, timer-source labels, crash-source availability, unsupported architecture policy, and unavailable fields not hashing like measured zero fields.
- Add failure-behavior tests for missing, malformed, unavailable, unsigned, invalid, stale, rejected, export failure, persistence failure, diagnostics read failure, and transmission failure states.
- Add parser fuzzing for Fleet canonical messages, hex trust files, detached signature files, OTA manifest input, CapNet attestation payloads, and persistence attestation records.
- Add oversized, truncated, duplicate-field, mixed-line-ending, malformed, and random-input fuzz cases.
- Add test commands or CI targets for Fleet unit tests, Fleet integration tests, Fleet policy tests, Fleet parser fuzzing, and Fleet cross-architecture evidence tests.

14. **Fleet Measurement Inputs Are Not Captured As One Consistent Snapshot**

Issue: The fleet bundle reads OTA state, crash state, boot tick, and scheduler state through separate calls. If those values change while the bundle is being built, the final measurement can describe a mixed state that never existed as one real kernel moment.

Required fixes:
- Add a fleet measurement snapshot operation that gathers all required inputs under a defined consistency rule.
- Lock or version OTA metadata while active slot hash, active slot id, version, and signature state are read.
- Record source generation numbers or read timestamps for crash log, scheduler, timer, and OTA inputs.
- Reject or retry bundle creation when any input source changes during measurement.
- Add tests for OTA changes during measurement, scheduler changes during measurement, crash-log changes during measurement, and retry behavior.

15. **Fleet Measurement Schema Versioning Is Not Defined**

Issue: The current measurement layout is fixed in code, but the evidence does not carry a full schema identity for verifiers. Future bundles may add fields, remove fields, or change field meaning, and old verifiers need a clear way to reject unknown layouts instead of misreading them.

Required fixes:
- Add a measurement schema id and version to the signed fleet evidence.
- Bind the schema name or domain into the canonical message and persisted attestation record.
- Define verifier behavior for unknown, deprecated, development-only, and production schemas.
- Keep old schema parsing tests so future changes do not silently change the meaning of existing evidence.
- Add tests for schema-version mismatch, unknown schema rejection, and backward-compatible schema handling.

16. **Fleet Input Counters Do Not Have Wraparound Or Reset Policy**

Issue: Boot tick, crash count, boot session, and scheduler switch count are numeric inputs, but the current model does not define what happens when they wrap, reset, become unavailable, or come from different platform timer sources.

Required fixes:
- Define wraparound behavior for boot tick, crash count, boot session, and scheduler switch counters.
- Record whether each counter is monotonic, resettable, unavailable, estimated, or diagnostic-only.
- Bind timer source and counter source metadata into the evidence where policy needs it.
- Reject impossible counter movement when comparing current evidence against prior fleet evidence.
- Add tests for counter wraparound, counter reset, unavailable counters, and architecture-specific timer behavior.

17. **Fleet Measurement Inputs Need Source Health And Exposure Policy**

Issue: The bundle includes values from OTA metadata, crash logging, scheduler state, and timer state, but it does not record whether each source was healthy. It also does not define which raw inputs are safe to expose to remote peers and which should be redacted, minimized, or hashed.

Required fixes:
- Add source-health status for OTA metadata, crash log, scheduler snapshot, timer source, and architecture support.
- Bind source-health status into the signed evidence.
- Define which fields are safe for local diagnostics, local audit, and remote fleet attestation.
- Redact, minimize, or hash privacy-sensitive runtime details before remote transmission.
- Add tests for source failure, partial source availability, source-health reporting, and remote redaction policy.

18. **Fleet Canonical Message Verification Is Not Semantic Verification**

Issue: The current detached signature path verifies Ed25519 over the exported canonical message bytes, but it does not yet define a strict parser for the canonical message or re-check that the visible fields recompute to the embedded measurement. A valid signature over malformed, stale, duplicate-field, or policy-incomplete evidence is still not enough for production fleet trust.

Required fixes:
- Add a strict canonical fleet message parser for the signed evidence format.
- Reject missing fields, duplicate fields, unknown fields for the active schema, non-canonical decimal encodings, uppercase or malformed hex, CRLF variants, and trailing data.
- Recompute the SHA-256 measurement from the parsed fields and require it to match the signed measurement field.
- Bind parser behavior to schema version and production policy.
- Add tests for duplicate fields, missing fields, changed field order, wrong measurement recomputation, non-canonical numbers, malformed hex, trailing bytes, stale signed evidence, and valid signed evidence.

19. **Fleet Signature Verification Can Truncate Oversized Messages**

Issue: The exported message verifier reads /fleet/attest.msg through a bounded small-file helper. That avoids unbounded allocation, but the mature behavior needs to reject oversized canonical messages instead of reading and verifying only the prefix that fits.

Required fixes:
- Define exact or schema-bounded canonical fleet message sizes.
- Reject oversized /fleet/attest.msg files before Ed25519 verification.
- Reject truncated reads and partial canonical messages.
- Bind message size policy to fleet schema version.
- Add tests for oversized signed messages, prefix-valid messages with trailing data, truncated reads, and schema-specific message length limits.

20. **Fleet Ed25519 Verification Needs Broader Production Assurance**

Issue: The Ed25519 verifier already rejects decompression failures, non-canonical S values, and small-order public key or R values, and it uses constant-time comparison for the final encoded point check. The current tests, however, only cover one RFC vector and one tampered message case, which is not enough for a production fleet trust anchor.

Required fixes:
- Add more RFC 8032 Ed25519 verification vectors.
- Add negative tests for malformed public keys, malformed R values, non-canonical S values, small-order public keys, small-order R values, wrong domains, and wrong messages.
- Add randomized negative tests during development.
- Compare verification results against a known-good Ed25519 implementation during test builds.
- Add tests proving malformed signatures do not collapse into unsigned policy states at the fleet wrapper layer.

21. **Fleet Failure Behavior Is Not Fully Typed**

Issue: Fleet failure paths currently mix hard stops, printed warnings, ignored persistence failures, unsigned states, invalid signature errors, unknown measurements, and transmission failures. That is useful during bring-up, but production Fleet attestation needs each failure to have a clear machine-readable class, policy outcome, audit record, and fail-closed or diagnostic-only decision.

Required fixes:
- Define Fleet failure classes for missing evidence, malformed evidence, unavailable evidence, unsigned evidence, invalid signature, stale evidence, rejected evidence, export failure, persistence append failure, diagnostics read failure, and remote transmission failure.
- Treat malformed evidence as rejected instead of normalizing it into zero values or unsigned states.
- Treat failed persistence append as security-relevant when attestation auditability is required.
- Define production policy for unsigned evidence, including whether it can be printed, exported, recorded, or transmitted.
- Keep local failure, verification failure, persistence failure, and remote transmission failure as separate outcomes.
- Block remote transmission when evidence is unsigned, invalid, stale, malformed, missing required context, or not recorded when policy requires a record.
- Record a safe audit event for each failure class before returning or entering diagnostic-only mode.
- Add tests for missing manifest, malformed manifest hex, export write failure, failed persistence append, missing key, missing signature, malformed key, malformed signature, invalid signature, stale exported message, CapNet send failure, and production unsigned policy.

22. **Fleet Measurement Hash Is Not Self-Framed**

Issue: The Fleet measurement is currently SHA-256 over a fixed 56-byte buffer. The input does not carry a Fleet domain string, schema version, field tags, source-health labels, architecture label, or policy mode. That makes the digest depend on out-of-band knowledge of the layout and can make future schema changes or cross-protocol reuse easier to mishandle.

Required fixes:
- Add a Fleet measurement domain string before hashing.
- Add measurement schema version and field tags into the hashed input.
- Include source-health labels where they affect trust decisions.
- Include architecture label and policy mode where verifiers need them.
- Reject measurement verification when the schema or domain is unknown.
- Add tests proving old and new schemas do not collide in interpretation.
- Add tests proving the same raw values under different source-health labels produce different measurement evidence.

23. **Fleet Export Verification Has Mutable VFS Race Risk**

Issue: Fleet builds a bundle, writes the canonical message into /fleet/attest.msg, and later verifies by reading that file back from VFS. Because /fleet files are mutable, the message, signature, summary, or trusted key can change between export, verification, diagnostics, persistence recording, and transmission.

Required fixes:
- Treat a built Fleet bundle as an immutable evidence object until the operation completes.
- Add an export generation id or evidence object id to bind message, summary, signature status, persistence record, and transmission result together.
- Lock or version /fleet export files while verification and transmission are using them.
- Reject verification if /fleet/attest.msg, /fleet/attest.sig, or /fleet/attest.pub changes after the bundle was built.
- Record the export generation id in persistence and audit records.
- Add tests for replacing the message, signature, public key, and summary between export and verify.
- Add tests for replacing export files between verify and CapNet transmission.

24. **Fleet Peer Identity Is Not Bound To Network Destination**

Issue: Remote Fleet attestation accepts a peer id, IP address, and port from the command surface, but the reviewed path does not prove that the destination address and port are the authorized endpoint for that peer id. The current CapNet Attest frame also carries no signed Fleet evidence, which makes peer identity, destination, and evidence binding incomplete.

Required fixes:
- Bind peer id to an authorized destination address and port before transmission.
- Validate the requested destination against the CapNet peer table or peer policy.
- Include peer identity and destination binding in the signed Fleet evidence or signed transmission envelope.
- Reject transmission when peer id and destination do not match policy.
- Audit peer id, destination, bundle identity, freshness data, and send result together.
- Add tests for wrong destination, wrong port, stale peer binding, unknown peer, and peer id mismatch.

25. **Fleet Attestation Records Are Not Self-Describing**

Issue: The Fleet AttestationRecord payload is an implicit byte layout. The source comment says 40 bytes, while the code writes 48 bytes. The payload does not include a Fleet record magic, Fleet record version, schema id, field tags, signature status, source-health state, policy decision, or peer binding. Future recovery and incident review can misread old records unless the reader already knows the exact layout.

Required fixes:
- Fix the documented AttestationRecord payload length.
- Add Fleet record magic and Fleet record version.
- Add schema id, field tags, source-health state, signature status, and policy decision.
- Add peer binding and transmission status when evidence is sent remotely.
- Add parser tests for current records, future-version records, malformed records, short records, long records, and unknown schema ids.
- Add migration rules for older Fleet attestation records.

26. **Fleet Attestation Can Create Log And Network Pressure**

Issue: Fleet attestation can be invoked repeatedly to build, export, record, and optionally transmit evidence. The persistence log is finite, and CapNet transmission is externally visible. Without rate limits, quotas, or capability-scoped backpressure, Fleet can become a log-filling and network-spam surface.

Required fixes:
- Add rate limits or quotas for Fleet attest, export, diagnostics, and remote transmit operations.
- Scope quotas by owner process, capability, peer, and policy mode.
- Define log-full behavior for Fleet attestation records.
- Prevent low-authority callers from exhausting Fleet audit capacity.
- Add backpressure for repeated CapNet attestation sends.
- Audit denied or throttled Fleet operations.
- Add tests for repeated attestation, log saturation, repeated failed sends, quota exhaustion, and recovery after throttling.

27. **Fleet-To-CapNet Measurement Binding Can Lose Security Width**

Issue: Fleet measurements are 32-byte SHA-256 values, but CapNet capability tokens currently expose a 64-bit measurement_hash field. If future code binds Fleet attestation into CapNet by truncating the Fleet measurement into that field, it would reduce the collision resistance of the binding and make the token relationship weaker than the Fleet evidence.

Required fixes:
- Do not truncate Fleet SHA-256 measurements into the 64-bit CapNet token measurement field for production trust.
- Add a full-width Fleet measurement reference to CapNet evidence binding, or carry the signed Fleet bundle itself.
- Define whether CapNet measurement_hash is only a local fingerprint or a trust-bearing attestation binding.
- Bind CapNet tokens to Fleet evidence through a signed bundle hash, full-width digest, or verified evidence object id.
- Add tests proving truncated Fleet measurements are not accepted as full Fleet proof.
- Add tests for CapNet token binding to the signed Fleet bundle or full-width measurement identity.

28. **Fleet Public Measurement Helper Loses Evidence Quality**

Issue: The public Fleet measurement helper returns only a 32-byte digest. It does not return whether inputs were verified, unknown, malformed, stale, unavailable, rejected, unsigned, or diagnostic-only. A future caller could consume the digest alone and treat weak evidence as healthy evidence.

Required fixes:
- Replace trust-bearing uses of raw build_measurement output with a structured Fleet evidence object.
- Include measurement digest, source states, schema id, signature status, policy result, and freshness state in that object.
- Mark raw digest-only access as diagnostic or internal-only unless paired with evidence metadata.
- Add tests proving callers cannot use a raw Fleet hash as verified Fleet attestation.
- Audit every caller that consumes Fleet measurement bytes directly.

### Issues across all the security boundaries

1. **Network Boundary Trust Is Not Yet Atomic**

Issue: The network boundary turns remote traffic into local trusted plaintext, but the current TLS route does not yet bind DNS resolution, TCP peer validation, SNI, certificate identity, negotiated TLS parameters, traffic keys, and TlsSession capability metadata into one indivisible authority object. Pieces of the route exist, but the trust decision is still spread across separate structures and checks.

Required fixes:
- Bind NetworkResolve, NetworkConnect, TCP endpoint, SNI, certificate identity, TLS version, cipher suite, and TlsSession generation into one session authority record.
- Issue TLS_READ, TLS_WRITE, TLS_CLOSE, TLS_INTROSPECT, and TLS_DELEGATE only after the handshake reaches a fully verified Connected state.
- Reject plaintext release if any endpoint, transcript, certificate, record, nonce, or state-machine check fails.
- Add audit records for resolve, connect, ClientHello advertisement, peer identity verification, session capability issuance, record failure, close, and error.
- Add tests for DNS/IP mismatch, SNI mismatch, certificate mismatch, TCP spoofing, stale session handles, and capability bypass.

2. **Storage Boundary Trust Is Not Yet Fully Sealed**

Issue: The storage boundary turns live kernel state into durable bytes and later back into live authority. Persistence already has sealed snapshot support with AES-CTR and HMAC-SHA256, but the boundary still depends on a development seal key, in-memory nonce freshness, backend-specific fallback behavior, store-local capabilities, and partial audit records.

Required fixes:
- Replace the development persistence seal key with device-specific attested provisioning for production.
- Use a documented HKDF-based persistence key schedule with seal key generation, snapshot purpose, slot id, backend, version, and nonce context.
- Back snapshot nonce freshness with durable monotonic state or hardware-backed freshness where available.
- Require scoped snapshot capabilities for seal, unseal, backend selection, recovery, and audit.
- Treat unsealed, stale, rollbacked, or backend-weakened snapshot recovery as a production trust failure.
- Add end-to-end tests for sealed write, sealed read, tamper rejection, nonce rollback, backend fallback, seal key rotation, and recovery failure.

3. **Update Boundary Trust Is Not Yet Crash-Safe Or Rollback-Resistant**

Issue: The update boundary turns external image bytes into code or system state the kernel may activate. OTA has an A/B slot model, SHA-256 image hashing, Ed25519 manifest verification, and rollback support, but the current implementation still separates image, manifest, version, signature, active marker, and rollback sentinel into mutable pieces that are not one authenticated transaction.

Required fixes:
- Bind image hash, version, target slot, active slot state, signature status, key identity, rollback generation, and policy mode into one authenticated OTA metadata record.
- Make apply, verify, commit, and rollback transactional with staged, failed, completed, commit-intent, and commit-complete states.
- Store active slot and rollback state in rollback-resistant or authenticated metadata.
- Reject unsigned manifests, unknown versions, malformed slot metadata, stale rollback sentinels, and downgrade attempts in production mode.
- Require OTA_SLOT_WRITE, OTA_SLOT_VERIFY, OTA_SLOT_ACTIVATE, OTA_SLOT_ROLLBACK, OTA_KEY_IMPORT, and OTA_AUDIT rights for the matching operations.
- Add tests for crash during apply, crash during commit, stale metadata, wrong slot, wrong signature, rollback attack, downgrade attack, and active marker corruption.

4. **Attestation Boundary Trust Is Not Yet Complete Evidence**

Issue: The attestation boundary turns internal kernel state into claims another machine, operator, or policy engine may trust. Fleet currently builds a SHA-256 measurement and can verify detached Ed25519 signatures over exported canonical messages, but the evidence does not yet carry enough typed context, freshness, source-health state, peer binding, or persistence metadata to be full production proof.

Required fixes:
- Represent Fleet evidence as a structured object with schema version, measurement, source labels, source-health states, freshness, key identity, policy mode, signature status, and peer binding.
- Bind active slot hash to verified OTA active-slot metadata, not only to the global manifest file.
- Add verifier challenge, nonce, request id, peer id, destination, bounded timestamp, or equivalent freshness to signed evidence.
- Carry the signed bundle, full-width bundle hash, or verified evidence object id through CapNet attestation transmission.
- Require FLEET_ATTEST, FLEET_VERIFY, FLEET_KEY_IMPORT, FLEET_SIGNATURE_IMPORT, FLEET_RECORD, FLEET_TRANSMIT, and FLEET_DIAG rights where appropriate.
- Add tests for stale evidence, replayed evidence, malformed evidence, missing sources, unknown measurements, wrong peer, wrong destination, and unsigned production policy.

5. **Key Ownership Is Fragmented Across Services**

Issue: TLS session secrets, persistence seal keys, OTA trusted keys, Fleet trusted keys, and CapNet peer/session keys are owned by separate paths with separate lifecycle behavior. There is not yet a kernel-wide key ownership model that defines who can create, rotate, revoke, delegate, seal, inspect, or erase each key class.

Required fixes:
- Define key classes for TLS session keys, persistence seal keys, OTA trust keys, Fleet trust keys, CapNet peer keys, and future loader or policy keys.
- Assign an owner service, allowed operations, lifetime, rotation rule, revocation rule, and audit rule to each key class.
- Prevent ordinary VFS writes from replacing trust roots such as OTA and Fleet public keys.
- Add key generation, import, rotation, revocation, and destruction events to audit.
- Add tests proving one key class cannot be used in another domain.

6. **Nonce And Counter Guarantees Are Not Global Or Durable Enough**

Issue: TLS, persistence, CapNet, OTA, and Fleet all depend on counters, nonces, sequence numbers, or freshness values, but those guarantees are implemented locally. Some are in memory only, some are tied to mutable metadata, and some freshness fields are still missing.

Required fixes:
- Define a nonce and counter ownership table for TLS record sequence numbers, persistence snapshot nonces, CapNet replay nonces, OTA rollback generations, and Fleet freshness values.
- Enforce wrap limits, reset rules, failed-operation behavior, and reboot behavior for every counter.
- Back storage and update freshness with durable monotonic state or rollback-resistant metadata.
- Add tests for counter zero, counter one, high values, wraparound, reboot, rollback, failed writes, failed decrypts, and stale evidence replay.

7. **Capability Enforcement Is Not Consistent At Trust Boundaries**

Issue: The codebase has a capability authority model, but several crypto-backed trust operations still use raw handles, locally fabricated capabilities, or command-accessible surfaces. That lets a caller reach sensitive operations before the operation is represented as a global kernel capability.

Required fixes:
- Promote TLS session authority, persistence store authority, OTA slot authority, and Fleet attestation authority into the global capability manager.
- Require exact operation rights instead of broad service-local rights.
- Bind every capability to owner process, target object, rights, expiry, generation, audit label, and delegation policy.
- Reject raw handles or direct command paths when a matching capability is missing.
- Add tests for owner mismatch, right mismatch, stale generation, revoked capability, overbroad delegation, and raw-handle bypass.

8. **Signed Messages Do Not Yet Carry Enough Authority Context**

Issue: OTA and Fleet both use Ed25519 detached signatures over canonical messages, but the signed messages do not yet carry every field needed to make the signature a complete authority decision. A valid signature over too little context can be replayed into the wrong slot, wrong peer, wrong policy, wrong key generation, or wrong time window.

Required fixes:
- Add target slot, image type, device identity, rollback generation, policy mode, key identity, and slot state to OTA signed messages.
- Add peer identity, verifier challenge, freshness, architecture, source-health labels, policy mode, and key identity to Fleet signed messages.
- Add strict schema versioning and domain strings for every signed format.
- Reject signatures over unknown, deprecated, incomplete, duplicate-field, or trailing-data messages.
- Add tests for wrong domain, wrong slot, wrong peer, stale challenge, missing field, duplicate field, malformed field, and unknown schema.

9. **Metadata Binding Is Still Too Spread Out**

Issue: The main security paths often store trust-related fields separately. OTA separates active slot, manifest, signature, version, and rollback sentinel. Fleet separates exported message, signature, public key, summary, persistence record, and transmission. TLS separates endpoint metadata from capability metadata. Persistence separates backend behavior from a full authenticated policy record.

Required fixes:
- Create authenticated metadata records for TLS sessions, persistence snapshots, OTA updates, and Fleet evidence.
- Include schema version, object id, owner, key identity, policy mode, source state, and operation result where relevant.
- Keep related fields together through apply, verify, commit, recover, attest, transmit, and audit.
- Reject operations when related metadata pieces disagree or come from different generations.
- Add tests for metadata mix-and-match, stale metadata, missing metadata, malformed metadata, wrong generation, and partial update.

10. **Recovery And Rollback Policy Is Not Centralized**

Issue: Persistence recovery, OTA rollback, Fleet stale evidence handling, and TLS session reuse each have their own local behavior. There is not yet one clear production rule for when old state can become current authority again.

Required fixes:
- Define a kernel-wide recovery policy for trusted durable state, update state, network session state, and attestation evidence.
- Require freshness, generation, or rollback-resistant proof before accepting recovered authority.
- Treat unknown recovery state as diagnostic-only or rejected under production policy.
- Bind recovery decisions to audit records and capability authority.
- Add tests for stale snapshot restore, stale OTA rollback, stale Fleet evidence, stale TLS handle reuse, and partial recovery failure.

11. **Audit Records Are Too Thin For Boundary-Level Forensics**

Issue: Current audit and persistence records often record only a phase, hash, measurement, or small payload. That is not enough to reconstruct which authority was exercised, which policy was applied, which key was trusted, which peer or slot was involved, or why a trust decision failed.

Required fixes:
- Add self-describing audit records with magic, version, schema id, event type, caller authority, policy mode, key identity, object identity, and result.
- Record both successful trust transitions and failed trust decisions.
- Treat audit append failure as security-relevant when auditability is required.
- Add migration rules for old audit record formats.
- Add parser and replay tests for current, malformed, short, long, future-version, and unknown-schema audit records.

12. **Raw Crypto APIs Are Too Easy To Use Outside Their Safe Context**

Issue: The crypto module exposes raw primitives and helpers that are useful during development, but safe production use depends on higher-level context. AES-CTR, AES-GCM, HKDF, X25519, Ed25519, HMAC, and signing helpers can all be correct primitives while still being misused by a caller that supplies the wrong nonce, wrong key, wrong label, wrong message, or wrong policy.

Required fixes:
- Separate low-level primitive APIs from high-level authority APIs.
- Prefer service-level operations such as open verified TLS session, seal snapshot, verify OTA update, and build signed Fleet evidence.
- Restrict raw encryption, decryption, key derivation, and signing helper access to trusted modules or explicitly marked internal APIs.
- Add misuse tests proving callers cannot choose production keys, nonces, counters, labels, or signed-message layouts directly.
- Document which APIs are safe for broad kernel callers and which are primitive-only.

13. **Secret Material Cleanup Is Not Systematic**

Issue: TLS private keys, shared secrets, handshake secrets, traffic secrets, persistence derived keys, imported signing buffers, and plaintext snapshot buffers do not yet have a complete zeroization and lifetime policy. Some local wiping exists, but it is not enforced across all error, close, recovery, and failure paths.

Required fixes:
- Add explicit cleanup for TLS private keys, shared secrets, handshake secrets, traffic secrets, application keys, and IV material on close and error.
- Wipe persistence encryption keys, MAC keys, decrypted payload buffers, and scratch buffers after use.
- Avoid leaving imported key and signature material in command buffers or VFS scratch buffers where possible.
- Disable or redact secret-adjacent debug traces in production.
- Add tests or debug assertions proving secret-bearing state is cleared after close, error, recovery failure, and key rotation.

14. **Canonical Encoding Is Writer-Side But Not Fully Parser-Enforced**

Issue: OTA and Fleet have canonical message builders, but production trust also needs strict readers. Without strict parsing, a signed message can be stable when produced by Oreulius but still ambiguous, oversized, malformed, duplicated, or policy-incomplete when imported or verified.

Required fixes:
- Add strict parsers for OTA manifests, Fleet evidence, trust key files, signature files, persistence records, and future signed authority records.
- Reject trailing data, duplicate fields, missing fields, unknown fields under strict schema, mixed line endings, non-canonical numbers, malformed hex, and oversized messages.
- Recompute semantic fields from parsed data before accepting signatures or measurements.
- Bind parser behavior to schema version and policy mode.
- Add parser fuzzing for signed messages, hex files, metadata records, TLS records, OTA manifests, Fleet evidence, and persistence records.

15. **Failure Behavior Is Not Yet One Production Policy**

Issue: Different paths currently mix warnings, ignored errors, diagnostic-only output, hard failures, unsigned states, and logged-but-accepted failures. That is useful in alpha, but production needs a single policy model for when a boundary fails open, fails closed, or becomes diagnostic-only.

Required fixes:
- Define production and development policy modes for TLS, persistence, OTA, Fleet, and CapNet-related evidence.
- Create machine-readable failure classes for missing, malformed, stale, unsigned, invalid, unavailable, rejected, rollbacked, and audit-failed states.
- Make production trust decisions fail closed when required evidence is missing or invalid.
- Keep diagnostic-only results separate from authority-bearing results.
- Add tests proving development warnings do not silently become production acceptance.

16. **Cross-Boundary Test Coverage Is Not Yet Complete**

Issue: Primitive tests exist, and several modules have local tests or self-checks, but the actual security boundary behavior depends on composition. The current test surface does not yet prove that network, storage, update, and attestation boundaries hold together under adversarial input, rollback, stale metadata, capability misuse, and failure.

Required fixes:
- Add end-to-end boundary tests for TLS, persistence, OTA, and Fleet.
- Add cross-boundary tests where OTA feeds Fleet, Fleet transmits over CapNet, persistence records OTA and Fleet events, and TLS or fetch consumes network capability authority.
- Add fuzzing for TLS records, OTA metadata, Fleet canonical messages, persistence records, hex trust files, and CapNet attestation payloads.
- Add negative tests for stale evidence, wrong key, wrong peer, wrong slot, wrong backend, wrong owner, wrong capability, wrong generation, and wrong policy mode.
- Add CI commands for primitive tests, composed boundary tests, parser fuzzing, cross-architecture evidence tests, and production-policy tests.

17. **Development Defaults Can Accidentally Look Like Production Trust**

Issue: Several paths have development-friendly behavior, such as default persistence seal keys, unsigned OTA and Fleet states, diagnostic output, software verified-boot stubs, mutable VFS trust files, and architecture placeholders. These are acceptable for alpha development, but they must not be mistaken for production security boundaries.

Required fixes:
- Add an explicit development versus production security mode.
- Block default seal keys, unsigned manifests, unsigned attestations, mutable trust roots, and software-only boot trust in production mode.
- Label diagnostic-only evidence clearly so it cannot become authority.
- Add startup checks that refuse production mode when required roots of trust are missing.
- Add tests proving every development-only path is rejected or downgraded to diagnostic-only under production policy.

18. **Mutable VFS Trust Material Creates Cross-Boundary Race Risk**

Issue: OTA trust keys, OTA signatures, Fleet trust keys, Fleet signatures, Fleet exported messages, OTA active markers, OTA manifests, rollback sentinels, and file-backed snapshots are all represented through VFS paths in the current prototype. That makes them easy to inspect and change during development, but it also creates race and replacement risk for production trust material.

Required fixes:
- Move trust-bearing files behind capability-gated storage APIs or sealed metadata records.
- Add generation ids, object ids, or immutable evidence handles for trust material.
- Lock or version trust material during verify, commit, attest, transmit, and recovery operations.
- Reject operations if files change between read, verify, use, and audit.
- Add tests for VFS replacement of trust keys, signatures, manifests, active markers, rollback sentinels, exported evidence, and snapshot files.

19. **Architecture Parity Is Not Yet A Security Requirement**

Issue: Some security evidence behaves differently across x86, x86_64, and aarch64. Fleet crash count and boot session are unavailable on aarch64, TLS network receive is disabled in some target paths, persistence nonce seeding uses different sources, and verified boot or rollback behavior may differ by target. Without explicit labels, verifiers may compare evidence from different architectures as if it came from the same source model.

Required fixes:
- Add architecture id, build id, source availability, timer source, crash source, and feature support labels to trust-bearing evidence.
- Define production parity requirements for TLS, persistence, OTA, and Fleet on each supported architecture.
- Mark unavailable architecture-specific evidence as unavailable, not as measured zero.
- Reject or downgrade evidence from unsupported or incomplete architecture paths under production policy.
- Add cross-architecture tests for x86, x86_64, and aarch64 evidence labels and failure behavior.

20. **Boundary Operations Need Resource And Abuse Controls**

Issue: Trust-boundary operations can consume memory, log capacity, network bandwidth, crypto time, or durable storage. OTA can read whole images into memory. Fleet can repeatedly append records and transmit attestations. TLS can buffer malformed records. Persistence can attempt backend fallbacks and large snapshot writes. Without quotas and backpressure, security services can become denial-of-service surfaces.

Required fixes:
- Add per-capability quotas for OTA apply, Fleet attest, Fleet transmit, TLS session allocation, snapshot writes, and audit records.
- Stream large inputs instead of requiring full in-memory buffers where possible.
- Define log-full, snapshot-full, session-full, and network-send-failure behavior.
- Audit throttled or denied boundary operations.
- Add tests for oversized records, repeated attestations, repeated OTA apply, log saturation, session pool exhaustion, snapshot storage exhaustion, and malformed network input pressure.


### Issues in the primitives 

1. **SHA-256 Length Accounting Uses Saturating Arithmetic**

Issue: The SHA-256 implementation tracks total input length with a 64-bit counter and uses saturating arithmetic when adding new input and when converting bytes to bits during finalization. That prevents integer overflow panics, but it also means extremely large inputs can silently saturate instead of being rejected. A production hash API should not silently hash a message with the wrong encoded length.

Required fixes:
- Replace saturating length accounting with checked length accounting.
- Return an error when the message length exceeds the SHA-256 maximum representable length.
- Add tests for normal length handling, boundary lengths, and overflow rejection.
- Add streaming tests proving one-shot and chunked hashing produce identical digests.
- Add more FIPS 180-4 SHA-256 known-answer vectors.

2. **SHA-256 Internal Buffers Are Not Explicitly Cleared**

Issue: Sha256 stores partial input blocks, schedule words, and internal state during hashing. SHA-256 is not normally secret by itself, but Oreulius uses SHA-256 inside HMAC, HKDF, persistence key derivation, signatures, and measurement paths. When hash state handles secret-adjacent material, stale buffers should not remain longer than needed.

Required fixes:
- Add explicit zeroization for temporary schedule words and partial block buffers where secret-adjacent use matters.
- Consider separate public-hash and secret-adjacent hash wrappers if zeroization cost matters.
- Wipe HMAC inner hashes and derived temporary digest material after use where possible.
- Add debug assertions or tests that secret-bearing wrapper state is cleared after finalize.

3. **HMAC-SHA256 Key Material Is Not Fully Zeroized**

Issue: HMAC builds a 64-byte normalized key block, inner pad, outer pad, and inner digest. Those values are derived from secret keys. The one-shot and streaming paths do not fully wipe every temporary key-derived buffer after use.

Required fixes:
- Wipe normalized key blocks, inner pads, outer pads, and inner digests after HMAC finalization.
- Add a drop or explicit finalize behavior for HmacSha256 that clears opad and inner state.
- Keep truncated-HMAC use documented and scoped to formats that intentionally accept a 16-byte tag.
- Add tests for HMAC RFC 4231 vectors, long keys, empty keys, streaming updates, and truncated output.

4. **AES Software Core Has Table-Based Timing Risk**

Issue: AES uses an S-box table for SubBytes and key schedule operations. That is straightforward and portable, but table lookups can leak timing information through cache behavior on some targets. This is especially important because AES-GCM and AES-CTR protect sensitive TLS and persistence data.

Required fixes:
- Prefer hardware AES instructions on targets that provide them.
- Add a constant-time software fallback or document target-specific side-channel assumptions.
- Gate production use on a selected AES backend policy.
- Add known-answer tests for AES-128 block encryption and key expansion.
- Add side-channel review notes for each supported architecture.

5. **AES-CTR Allows Counter Wrap Without A Hard Error**

Issue: The AES-CTR helper builds blocks from a 64-bit nonce and a 64-bit counter. The counter uses wrapping addition. If a caller ever encrypts enough data under one nonce to wrap the counter, the keystream would repeat. That is catastrophic for CTR mode.

Required fixes:
- Reject encryption when the data length would exceed the available counter space for one nonce.
- Return a Result from AES-CTR instead of silently continuing.
- Keep nonce and counter ownership outside raw callers in production paths.
- Add tests for counter zero, counter one, high counter limits, and wrap rejection.
- Add misuse tests proving snapshot callers cannot reset counters or choose raw nonce streams.

6. **AES-CTR Debug Tracing Leaks Runtime Metadata**

Issue: The AES-CTR helper prints debug traces containing call count, buffer pointer, length, and nonce. That is useful while debugging persistence, but it leaks runtime metadata and nonce values into logs. In production, cryptographic helpers should not emit secret-adjacent operational details by default.

Required fixes:
- Disable AES-CTR crypto tracing in production builds.
- Redact pointers and nonce values unless a privileged diagnostics policy allows them.
- Move crypto tracing behind a compile-time feature or runtime security policy.
- Add tests or build checks proving production mode does not emit crypto debug traces.

7. **AES-GCM Does Not Validate Output Buffer Length**

Issue: AES-GCM encryption and decryption write into caller-provided output slices, but the primitive assumes the output is large enough for the plaintext or ciphertext length. If a caller passes a short buffer, the primitive can panic or corrupt the operation contract. A production primitive should make buffer length part of its checked API.

Required fixes:
- Return an error when the output buffer is shorter than the input length.
- Add explicit length checks before writing encryption or decryption output.
- Add tests for exact-sized buffers, oversized buffers, short buffers, empty messages, and partial-block messages.
- Keep record-layer callers responsible for maximum record size before calling AES-GCM.

8. **AES-GCM Counter Exhaustion Is Not Enforced**

Issue: AES-GCM uses a 32-bit counter field when building counter blocks from a 96-bit IV. The implementation starts data encryption at counter value two and wraps on overflow. A production AEAD must refuse inputs that would exhaust the counter space under one IV.

Required fixes:
- Reject plaintext or ciphertext lengths that would require counter wrap.
- Return an error instead of wrapping the GCM counter.
- Add AEAD-level limits for maximum bytes per nonce.
- Add tests for maximum safe blocks, one-block-over limit rejection, and empty messages.
- Ensure TLS record limits stay below primitive-level limits.

9. **AES-GCM Round Keys And Hash Subkeys Are Not Cleared**

Issue: AES-GCM expands the AES key and derives the GHASH subkey, then leaves those temporary values in local memory until overwritten. Those are secret-derived values. The AES-CTR path wipes its expanded round keys, but the AES-GCM path does not do the same.

Required fixes:
- Wipe AES-GCM round keys, GHASH subkey, counter blocks, expected tags, and temporary keystream blocks after use where possible.
- Add a small internal cleanup helper for AES-derived temporary state.
- Add tests or debug assertions for cleanup in development builds if practical.
- Document which temporary values are secret-derived and require wiping.

10. **GHASH Multiplication Is Not Constant-Time Enough For Production Assurance**

Issue: GHASH multiplication branches on input bits while processing GF(2^128) multiplication. GHASH input includes ciphertext and associated data, while the hash key is derived from AES encryption of zero under the record key. The current implementation is clear, but it needs a side-channel review before being treated as hardened.

Required fixes:
- Replace GHASH multiplication with a constant-time implementation or hardware-assisted carryless multiplication where available.
- Document side-channel assumptions for software GHASH on each supported architecture.
- Add GHASH known-answer vectors independent of AES-GCM.
- Add AES-GCM tests with associated data, multi-block ciphertext, partial blocks, and tampered length blocks.

11. **HKDF Silently Truncates Info, Labels, And Context**

Issue: HKDF expand truncates info to 255 bytes. The TLS expand-label helper also truncates labels and context to local fixed limits. Silent truncation is dangerous because two distinct inputs can become the same derivation context after truncation.

Required fixes:
- Return an error when info, label, or context exceeds the supported size.
- Make HKDF and TLS expand-label APIs fallible for production use.
- Add tests proving oversized info, labels, and contexts are rejected.
- Add TLS 1.3 HKDF expand-label vectors and key schedule vectors.
- Document exact length limits for each derivation helper.

12. **HKDF Expand Does Not Enforce The RFC Output Block Limit**

Issue: HKDF expand uses an 8-bit block counter and wraps it with wrapping addition. RFC 5869 limits output to 255 hash-length blocks. The current const-generic API can request outputs beyond that bound without a hard rejection.

Required fixes:
- Reject output lengths greater than 255 times the SHA-256 output length.
- Make over-limit derivation a compile-time or runtime error.
- Add tests for zero-length output, one block, multiple blocks, maximum allowed output, and over-limit rejection.
- Avoid exposing raw unlimited HKDF expansion to high-level callers.

13. **X25519 Does Not Enforce All-Zero Shared Secret Rejection**

Issue: The X25519 helper returns the raw shared secret. It does not reject the all-zero output that can result from small-order or invalid peer inputs. That check may be done by callers, but a production key-agreement wrapper should make the safe behavior hard to skip.

Required fixes:
- Add a checked X25519 shared-secret helper that rejects all-zero output.
- Prefer the checked helper in TLS and any future key-agreement path.
- Add tests for valid vectors and known low-order peer inputs.
- Document that the raw X25519 helper is primitive-only and not a complete authenticated key exchange.

14. **X25519 Raw Primitive Does Not Own Randomness Or Secret Cleanup**

Issue: X25519 itself only performs scalar multiplication. The primitive does not generate private keys, validate caller randomness quality, or zero the private scalar and shared secret after use. That is acceptable for a primitive, but dangerous if high-level callers treat it as a complete session setup API.

Required fixes:
- Add a high-level X25519 session helper that takes randomness from an approved CSPRNG.
- Keep private scalar and shared secret cleanup in the high-level helper.
- Mark raw X25519 helpers as low-level primitive APIs.
- Add tests proving high-level key agreement rejects bad peer shares and clears temporary secret material.

15. **Ed25519 Needs Broader Verification Assurance**

Issue: The Ed25519 verifier has useful structural checks: public key decompression, R decompression, canonical S rejection, small-order public key rejection, small-order R rejection, cofactor handling, and constant-time final comparison. The current tests, however, are narrow and do not prove the full range of RFC 8032 and adversarial edge cases.

Required fixes:
- Add more RFC 8032 Ed25519 verification vectors.
- Add negative tests for malformed public keys, malformed R values, non-canonical S values, small-order public keys, small-order R values, wrong messages, and wrong domains.
- Compare verification behavior against a known-good Ed25519 implementation in test builds.
- Add tests for empty message, large message, boundary-sized message, and random tamper cases.

16. **Ed25519 Scalar Multiplication Is Variable-Time**

Issue: The Ed25519 verifier uses scalar multiplication that branches on scalar bits. For public verification, this is usually less dangerous than private-key signing, because the signature scalar and hash are public inputs. Still, production maturity needs the timing model written down clearly, especially because this code runs inside a kernel.

Required fixes:
- Document that this verifier is for public signature verification only and does not implement secret signing.
- Keep private signing out of this module unless a constant-time scalar multiplication implementation is added.
- Review variable-time behavior for denial-of-service and timing amplification risks.
- Add performance and worst-case input tests for malformed points and large verification batches.

17. **Domain-Separated Hashing Silently Truncates Long Domains**

Issue: The domain-separated hash helper stores the domain length in one byte and silently truncates domains longer than 255 bytes. Silent truncation can collapse two different domains into the same effective hash domain.

Required fixes:
- Reject domains longer than the supported length instead of truncating them.
- Add schema version or domain version fields for authority-bearing hashes.
- Add tests for normal domains, maximum-length domains, over-limit rejection, and domain collision resistance by construction.
- Document which domains are used by each kernel path.

18. **Domain-Separated Hashing Is Not Used Everywhere Authority Hashes Appear**

Issue: The helper exists, but several authority-bearing hashes still use bare SHA-256 over fixed buffers or raw bytes. Bare hashes are fine for local byte identity, but signed, persisted, attested, or capability-bearing hashes need explicit domain and field framing.

Required fixes:
- Audit every use of raw SHA-256 in TLS, OTA, persistence, Fleet, signing formats, and capability records.
- Move authority-bearing hashes to domain-separated or schema-framed hashing.
- Add domain strings for OTA image identity, Fleet measurement identity, persistence payload identity, TLS transcript-adjacent helper hashes, and future capability hashes.
- Add tests proving the same raw bytes under different domains produce different digests.

19. **Constant-Time Equality Rejects Length Mismatch Early**

Issue: The constant-time equality helper compares equal-length buffers without early exit, but it immediately rejects length mismatches. That is acceptable when lengths are public and fixed, such as AES-GCM tags or SHA-256 hashes. It is not enough if a caller compares variable-length secret-bearing values and treats length as sensitive.

Required fixes:
- Document that constant-time equality is safe only for fixed-length security values.
- Add typed wrappers for common fixed-size comparisons such as 16-byte tags, 32-byte hashes, and 64-byte signatures.
- Audit callers to ensure security-sensitive comparisons are fixed length before calling.
- Add tests for equal values, unequal values, and length mismatch behavior.

20. **Signing Format Helpers Accept Prefixes And Trailing Data**

Issue: Hex parsing accepts any input that has at least the required number of hex characters. It parses the prefix and ignores trailing bytes. That can make malformed trust files look valid, and it weakens strict signed-artifact handling for OTA and Fleet.

Required fixes:
- Require exact hex length for public key and signature files.
- Reject trailing data, whitespace variants, malformed hex, and truncated files unless a documented parser mode allows them.
- Add strict import and strict read helpers for production trust material.
- Add tests for exact files, short files, long files, malformed files, trailing data, and newline variants.

21. **Small VFS File Reads Can Verify Truncated Messages**

Issue: The small-file helper reads up to a maximum length by allocating only the smaller of file size and max length. If a file is larger than the maximum, the helper reads and returns a prefix instead of rejecting the oversized file. That is unsafe for signed messages because a prefix can be valid while trailing data changes the intended object.

Required fixes:
- Reject files larger than the maximum before reading them.
- Use exact or schema-bounded sizes for canonical signed messages.
- Add tests for oversized signed messages, valid prefixes with trailing data, and truncated reads.
- Keep imported trust material and signed evidence behind strict parser helpers.

22. **Primitive APIs Do Not Consistently Return Errors**

Issue: Some primitive APIs return bare outputs or unit errors, while others cannot report misuse at all. AES-CTR cannot report counter exhaustion or short buffers. HKDF cannot report oversized context. AES-GCM encrypt returns a tag directly and assumes valid buffer sizing. Production maturity needs primitive misuse to become explicit errors.

Required fixes:
- Make misuse-prone primitive APIs fallible where length, counter, context, or buffer constraints matter.
- Keep one-shot convenience wrappers only for inputs that are guaranteed safe by type.
- Define shared CryptoError variants for invalid length, output too small, counter exhausted, context too long, invalid nonce, invalid tag, and unsupported mode.
- Add tests proving misuse returns errors instead of panicking, truncating, wrapping, or silently accepting.

23. **Primitive Test Coverage Is Not Production Complete**

Issue: The folder has useful primitive tests, but coverage is uneven. AES-GCM has a couple of NIST vectors. HKDF has one RFC 5869 case. Ed25519 has a valid vector and a tampered message. X25519 has an RFC vector. SHA-256, HMAC, GHASH, AES block encryption, AES-CTR, domain separation, strict parsing, and error behavior need broader direct coverage.

Required fixes:
- Add FIPS 180-4 SHA-256 vectors and chunked streaming tests.
- Add RFC 4231 HMAC-SHA256 vectors, including long key and truncated output cases.
- Add FIPS 197 AES-128 block vectors and AES-CTR vectors.
- Add NIST AES-GCM vectors covering AAD, multi-block messages, partial blocks, and tampering.
- Add GHASH standalone vectors.
- Add RFC 5869 HKDF cases and TLS 1.3 expand-label vectors.
- Add RFC 7748 X25519 low-order and all-zero rejection tests.
- Add RFC 8032 Ed25519 vectors and adversarial signature tests.
- Add parser, fuzz, and misuse tests for signing helpers and domain-separated hashing.


### Issues in the Signing Format

1. **Hex Trust Files Are Not Strictly Parsed**

Issue: The signing format parser accepts files that contain at least the required number of hex characters, then ignores whatever comes after that prefix. This means a public key or signature file can contain valid-looking leading bytes plus trailing junk and still be accepted. For production trust material, a file needs to be exactly the expected shape.

Required fixes:
- Require exact hex length for public keys, signatures, and imported trust files.
- Reject trailing bytes, malformed characters, partial pairs, unexpected whitespace, and mixed parser modes.
- Add a separate relaxed parser only if development tooling truly needs one.
- Add tests for exact hex, short hex, long hex, invalid hex, odd-length hex, trailing bytes, and newline variants.

2. **Small VFS Reads Can Truncate Signed Evidence**

Issue: The small-file reader checks the file size, but it allocates only up to the caller-provided maximum and then reads that prefix. Oversized files are not rejected before reading. For signed messages, this is dangerous because a valid signed prefix can be accepted while trailing bytes change the real object on disk.

Required fixes:
- Reject files larger than the allowed maximum before reading.
- Use exact-size reads for public keys and signatures.
- Use schema-bounded reads for canonical messages and exported evidence.
- Add tests proving oversized public keys, signatures, canonical messages, and attestation exports are rejected instead of truncated.

3. **Read Failures Collapse Into Missing Trust Material**

Issue: Detached signature verification treats public key read failures and signature read failures as missing files. If both reads fail, the result can become unsigned. That hides the difference between a clean unsigned artifact, a malformed public key, a malformed signature, a VFS read failure, and a permission problem.

Required fixes:
- Return distinct states for missing, unreadable, malformed, wrong length, invalid signature, unsigned, and verified.
- Make malformed trust material fatal under production policy.
- Make unreadable trust material auditable instead of silently treating it as absent.
- Add tests for missing key, missing signature, malformed key, malformed signature, unreadable key, unreadable signature, wrong key, wrong signature, unsigned development policy, and unsigned production policy.

4. **Unsigned Is A Verification Result, Not A Policy Decision**

Issue: The helper can return unsigned, but the helper does not know whether unsigned artifacts are allowed. That decision is left to OTA or Fleet callers. In production, unsigned evidence cannot be treated as a neutral result unless the active policy explicitly allows it.

Required fixes:
- Separate signature parsing from policy enforcement.
- Add production policy gates that reject unsigned OTA manifests and unsigned Fleet evidence unless explicitly configured otherwise.
- Include policy mode in audit records and signed evidence where relevant.
- Add tests proving unsigned artifacts are accepted only in development policy and rejected in production policy.

5. **Detached Signature Pieces Are Not Bound Into One Evidence Object**

Issue: The public key, signature, and message are read or provided as separate pieces. The helper verifies that the signature matches the message, but it does not bind those pieces into one protected evidence object with an identity, generation, policy mode, or audit trail. That makes replacement and confusion attacks easier around mutable VFS paths.

Required fixes:
- Introduce a signed evidence object that carries message hash, signature hash, key identity, schema version, policy mode, and generation id.
- Lock or version the message, public key, and signature while verification is happening.
- Reject verification if any piece changes between read, verify, use, and audit.
- Add tests for key replacement, signature replacement, message replacement, stale signature reuse, and generation mismatch.

6. **Trusted Key Identity Is Not Modeled**

Issue: Ed25519 verification proves that a signature matches one public key, but the signing format helper does not report which trusted key was used or what that key is authorized to sign. OTA keys, Fleet keys, recovery keys, development keys, and production keys need separate identities and purposes.

Required fixes:
- Add key identity, key purpose, key generation, and trust root metadata to verified signature results.
- Separate OTA signing keys from Fleet attestation keys unless an explicit policy grants both purposes.
- Record key identity in OTA, Fleet, persistence, and audit records.
- Add tests for wrong-purpose keys, stale key generations, revoked keys, and multiple trusted keys.

7. **Canonical OTA Messages Do Not Bind Enough Authority Context**

Issue: The OTA signed message currently binds the image hash and version string. That proves a key signed those two fields, but it does not fully bind the update authority. The signed object also needs the target slot, image type, target device, rollback generation, policy mode, key identity, and slot state where those fields affect whether the update is safe to apply.

Required fixes:
- Extend OTA canonical messages to include target slot, image type, target device, rollback generation, policy mode, key identity, and slot state.
- Make apply, verify, commit, rollback, and boot verification use the same canonical byte range and same metadata record.
- Reject manifests missing required authority fields under production policy.
- Add tests for wrong slot, wrong device, stale rollback generation, wrong policy mode, wrong key identity, and mismatched slot state.

8. **Canonical Fleet Messages Do Not Carry Enough Attestation Context**

Issue: The Fleet signed message currently binds a small set of measurement fields. It does not fully bind freshness, peer identity, verifier challenge, architecture source labels, policy mode, key identity, or source-health states. Without those fields, a valid signature can describe evidence that is incomplete, stale, or not tied to the verifier that requested it.

Required fixes:
- Add nonce or challenge data, verifier identity, peer identity, bounded timestamp data where available, policy mode, key identity, architecture id, and source-health labels.
- Represent unavailable, unknown, rejected, and measured-zero states separately in the signed message.
- Carry enough metadata to distinguish local diagnostics evidence from remote Fleet attestation evidence.
- Add tests for replayed evidence, wrong peer, missing challenge, stale exported message, unknown measurements, unavailable architecture fields, and wrong policy mode.

9. **Canonical Writers Do Not Have Strict Parsers**

Issue: The signing format helpers can write canonical OTA and Fleet messages, but there is no matching strict parser that reads those messages back and proves they are canonical. A verifier can check Ed25519 over bytes without proving the bytes represent a valid schema.

Required fixes:
- Add strict parsers for every canonical signing format.
- Reject duplicate fields, missing fields, unknown fields, non-canonical numbers, malformed hex, invalid field order, and trailing data.
- Rebuild the canonical message from parsed fields and require byte-for-byte equality.
- Add parser round-trip tests and adversarial parser tests for OTA and Fleet messages.

10. **Text Fields Are Not Sanitized Against Canonical Injection**

Issue: The OTA version string is inserted directly into the canonical message. If a caller provides newline characters or field-like text, the signed message can become harder to parse and reason about. Even if the current verifier signs exact bytes, production canonical formats need field values that cannot inject new fields or ambiguous layout.

Required fixes:
- Define allowed character sets and maximum lengths for text fields such as version, policy mode, key identity, peer identity, and device identity.
- Reject newline, carriage return, separator, and control characters in canonical text fields.
- Prefer length-prefixed or typed field encoding if the text format becomes too fragile.
- Add tests for newline injection, duplicate-field injection, very long text fields, empty required fields, and non-canonical text encoding.

11. **Detached Verification Has A TOCTOU Window**

Issue: The helper reads public key and signature files separately, and callers often read or build the signed message outside the helper. If ordinary VFS paths can change during verification, the kernel can verify one set of bytes and later act on another set.

Required fixes:
- Add stable file generations, immutable handles, or locked reads for trust material.
- Read message, key, and signature under one verification transaction where possible.
- Include verified object ids or generations in audit records.
- Add tests where key, signature, manifest, attestation message, or exported evidence changes between read and use.

12. **Import Helpers Can Rewrite Trust Material Without Authority Context**

Issue: The import helper normalizes a hex file and writes it to a destination path. The helper itself does not know whether the caller has authority to import an OTA key, Fleet key, signature, or other trust artifact. It also writes through ordinary VFS paths instead of a protected trust-store object.

Required fixes:
- Gate key and signature import behind capability rights.
- Separate import rights by purpose, such as OTA key import, OTA signature import, Fleet key import, and Fleet signature import.
- Make trust-material writes atomic and auditable.
- Add tests proving ordinary callers cannot overwrite trusted keys or signatures.

13. **Error Reporting Is Too Thin For Security Audits**

Issue: The signing format helper returns short static string errors. That is useful while developing, but it is not enough for production audit trails. The kernel needs to know whether a failure was missing material, malformed material, wrong key, wrong domain, stale evidence, policy rejection, VFS failure, or invalid signature.

Required fixes:
- Replace plain string errors with structured signing error variants.
- Preserve enough detail for audit without leaking secret material.
- Map signing errors into OTA, Fleet, and boundary-level audit outcomes.
- Add tests proving each failure mode produces the expected structured result.

14. **Signing Format Helpers Are Exposed Too Broadly**

Issue: The crypto public API re-exports signing helpers directly. That makes it easy for callers to parse trust files, import keys, or verify detached signatures without going through OTA or Fleet policy. In the mature design, most callers should not touch raw signing-format helpers.

Required fixes:
- Move raw signing-format helpers behind internal or restricted APIs where possible.
- Expose policy-safe OTA and Fleet verification operations instead of raw file-based verification.
- Keep development tooling separate from production trust paths.
- Add code review checks or tests proving production callers use policy wrappers.

15. **Signing Format Tests Are Too Narrow**

Issue: The current tests prove that the OTA and Fleet message builders produce stable strings for simple inputs. They do not test strict parsing, malformed input, import behavior, detached verification state transitions, policy modes, oversized files, or adversarial canonical messages.

Required fixes:
- Add tests for all parser failure modes and detached-signature state transitions.
- Add tests for OTA canonical context, Fleet canonical context, text-field validation, and wrong-domain signatures.
- Add tests for import normalization, exact length enforcement, oversized file rejection, and VFS read failure behavior.
- Add fuzz tests for canonical message parsers and hex parsers.


## Known issues in the Security Guarantees and Design Constraints

1. **Guarantees Are Still Mostly Descriptive**

Issue: The README describes what each primitive can guarantee when used correctly, but the current code does not yet enforce all of those conditions at the API boundary. For example, AES-GCM only gives record confidentiality and integrity if nonces are unique, record sizes stay within limits, and associated data is correct. Those rules are currently spread across callers instead of being enforced by one typed operation.

Required fixes:
- Turn each security guarantee into an enforceable API contract.
- Add checked wrappers for TLS records, persistence snapshots, OTA manifests, and Fleet evidence.
- Make unsafe or raw primitive calls internal where possible.
- Add tests proving invalid preconditions fail before cryptographic work is accepted.

2. **Primitive Constraints Are Not Expressed In Types**

Issue: Many constraints are described in prose but not represented in Rust types. Keys, IVs, nonces, hashes, tags, signatures, public keys, and canonical messages are often passed as raw byte arrays or slices. That makes it easier to accidentally pass the right number of bytes with the wrong meaning.

Required fixes:
- Add typed wrappers for AES keys, GCM IVs, CTR nonces, SHA-256 hashes, GCM tags, Ed25519 public keys, Ed25519 signatures, X25519 public keys, and derived secrets.
- Separate read keys from write keys and handshake keys from application keys.
- Separate OTA image hashes from Fleet measurement hashes and persistence payload hashes.
- Add compile-time or constructor checks for fixed-size security values.

3. **Nonce And Counter Rules Are Caller-Owned**

Issue: AES-CTR and AES-GCM safety depends on never reusing a nonce under the same key and never wrapping counters. The primitive layer can perform encryption, but it does not own durable nonce state, sequence limits, or key rotation. That makes nonce safety a path-level responsibility that can be missed.

Required fixes:
- Move nonce construction into path-owned state machines for TLS and persistence.
- Enforce hard limits before counter wrap is possible.
- Reset counters only when new traffic keys or snapshot keys are installed.
- Add tests for nonce uniqueness, sequence zero, sequence one, high sequence values, and counter-limit rejection.

4. **Key Lifecycle Is Not A First-Class Guarantee**

Issue: The guarantees section talks about keys as if the right key already exists, but production maturity needs the lifecycle around that key. The current primitives do not fully own key generation, key purpose, key storage, key rotation, key revocation, key erasure, or compromise recovery.

Required fixes:
- Define key ownership for TLS, persistence, OTA, Fleet, and future capability sealing.
- Add key generation and key purpose metadata where keys become authority.
- Add key rotation and revocation paths for long-lived trust roots.
- Zero key-derived temporary material after use where practical.
- Add tests for stale keys, wrong-purpose keys, revoked keys, and key-generation mismatch.

5. **Capability Authority Is Not Part Of The Crypto Contract Yet**

Issue: The current primitives can be called without knowing whether the caller has authority to use the result. A caller can hash, encrypt, verify, import, or compare security data without the crypto API itself knowing whether the operation is allowed for that process, slot, peer, backend, or evidence object.

Required fixes:
- Put capability-aware wrappers above raw crypto operations.
- Require TLS, persistence, OTA, and Fleet rights before trust-bearing operations.
- Scope authority by session, slot, backend, key purpose, peer, or evidence object.
- Add tests proving callers cannot bypass path-level rights by calling lower-level crypto helpers directly.

6. **Composition Rules Are Not Centralized**

Issue: TLS, persistence, OTA, and Fleet each compose primitives differently, but the rules for those compositions are mostly documented rather than enforced in shared policy objects. That leaves room for paths to drift and use the same primitive with different framing, different failure behavior, or different metadata binding.

Required fixes:
- Define explicit composition objects for TLS records, sealed snapshots, signed OTA manifests, and signed Fleet bundles.
- Keep key derivation, metadata binding, nonce construction, and failure behavior inside those objects.
- Document each composition as a small protocol with inputs, outputs, state transitions, and failure rules.
- Add integration tests for each full composition, not only each primitive.

7. **Associated Metadata Is Not Always Bound To The Protected Bytes**

Issue: The guarantee of an encrypted record, signed manifest, sealed snapshot, or attestation bundle depends on the metadata being protected with the data. Some paths still keep key identity, version, slot state, policy mode, backend, peer identity, or audit status outside the exact authenticated object.

Required fixes:
- Bind metadata into AES-GCM associated data, HMAC input, signed canonical messages, or sealed snapshot records as appropriate.
- Keep data and metadata in one authenticated record where the policy depends on both.
- Reject objects whose metadata is missing, stale, malformed, or inconsistent with the protected bytes.
- Add tests for swapped metadata, stale metadata, missing metadata, and valid data under wrong context.

8. **Failure Behavior Is Not Uniform Across Boundaries**

Issue: Some paths fail closed, some warn and continue, some return unsigned, and some log a mismatch without stopping the operation. The guarantee section needs one production policy for what happens when cryptographic trust fails.

Required fixes:
- Define production failure policy for bad tags, bad MACs, bad signatures, malformed keys, stale rollback state, unknown measurements, and unavailable trust roots.
- Separate development warnings from production failures.
- Make failure outcomes auditable with structured reasons.
- Add tests proving production mode rejects trust failures consistently.

9. **Audit Evidence Does Not Yet Prove The Guarantee Was Exercised**

Issue: A successful crypto operation is not enough for later review. The kernel needs records that explain which operation happened, which key or capability was used, which object was protected, which policy accepted it, and what failure or success state resulted. Current audit and persistence records are not yet complete enough across every boundary.

Required fixes:
- Add structured audit events for TLS trust decisions, snapshot seal and unseal, OTA apply and commit, rollback, Fleet bundle creation, signature verification, and trust-material import.
- Include object id, key identity, capability id, policy mode, generation, and result where relevant.
- Treat audit append failure as security-relevant in production paths.
- Add tests proving security operations emit the expected audit records.

10. **Development Defaults Can Look Like Security Guarantees**

Issue: Some current behavior is useful for alpha development, such as unsigned OTA manifests, mutable VFS trust files, unknown measurements, fallback slot behavior, and diagnostic exports. Those defaults can be mistaken for mature security behavior if they are not clearly separated from production policy.

Required fixes:
- Add explicit development, test, and production policy modes.
- Reject development-only trust behavior in production mode.
- Label unsigned, unknown, unavailable, fallback, and diagnostic-only states clearly.
- Add tests proving production mode cannot silently use development defaults.

11. **Strict Parsing Is Not A Global Constraint Yet**

Issue: Security guarantees depend on exact byte interpretation. The code still has places where parsers accept prefixes, truncate oversized files, treat malformed data as missing, or allow text fields that can become ambiguous. That weakens signatures, hashes, and attestation evidence because the kernel may verify bytes without fully understanding the object.

Required fixes:
- Add strict parsers for canonical signing formats, trusted key files, signatures, manifests, snapshot metadata, rollback sentinels, and Fleet evidence.
- Reject trailing data, duplicate fields, missing fields, malformed numbers, malformed hex, and non-canonical encodings.
- Rebuild canonical messages from parsed fields and require byte-for-byte equality.
- Add fuzz tests and malformed-input tests for every trust-bearing parser.

12. **Test Coverage Does Not Yet Match The Claimed Guarantees**

Issue: The README describes the desired guarantee model, but the tests are not broad enough to prove it. The folder needs more than happy-path primitive vectors. It needs misuse tests, path-level tests, parser tests, capability tests, replay tests, rollback tests, and architecture-specific behavior tests.

Required fixes:
- Add known-answer vectors for every primitive and mode.
- Add malformed-input tests for every parser and trust file.
- Add misuse tests for nonce reuse, counter wrap, wrong key, wrong domain, wrong slot, wrong peer, and wrong policy mode.
- Add integration tests for TLS, persistence, OTA, and Fleet compositions.
- Add fuzzing targets for canonical messages, hex parsing, record parsing, manifest parsing, snapshot metadata, and attestation bundles.
