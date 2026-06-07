# Oreulius Fetch Service

The fetch service is the kernel's headless internet layer. It is not a browser, and it is not trying to become one. Its job is to let the kernel own the trusted parts of fetching remote content: sessions, request authority, URL parsing, origin checks, HTTP transport, TLS state, cookies, cache records, downloads, storage, temporal restore, and audit history.

This matters because the internet is a major trust boundary. A full browser stack would bring HTML parsing, CSS layout, JavaScript execution, rendering, fonts, media policy, and user interaction into the trusted core. Oreulius avoids that. The kernel fetch service handles the network and policy-sensitive state, then gives structured events to a renderer or client that can decide how to display the result.

The practical model is simple: the kernel may fetch bytes, classify them, remember security-relevant state, and produce events. It should not execute page code, lay out pages, draw web content, or pretend that internet content is trusted just because the connection succeeded.

## What the fetch service is responsible for

The fetch service is responsible for the kernel-owned parts of HTTP and fetch state. It opens sessions, checks capabilities, dispatches requests, talks to the transport layer, parses HTTP responses, emits fetch events, stores cookies, uses a small response cache, coordinates downloads, maintains per-session storage, and snapshots selected state for temporal restore.

**Responsibility**

**Session ownership:** Tracks one fetch session per caller context and binds it to a session capability.

**Request dispatch:** Accepts structured fetch requests and turns successful navigation requests into request ids and event streams.

**Policy checks:** Blocks unsupported schemes, mixed-content patterns, origin violations, oversized body declarations, and redirect behavior where policy says to stop.

**Transport:** Connects over HTTP or HTTPS through the network reactor and TLS layer.

**HTTP parsing:** Builds HTTP/1.1 requests, parses status lines, headers, redirects, content length, content type, and chunked transfer encoding.

**Event delivery:** Queues headers, body chunks, TLS state, redirects, policy blocks, download offers, completion, and errors for clients to poll.

**Cookies and cache:** Maintains bounded cookie and cache state without heap allocation.

**Downloads and storage:** Tracks download jobs and gives each session a VFS-backed storage area under the browser storage root.

**Temporal state:** Snapshots sessions, navigation history, cookies, and download jobs so selected fetch state can survive lifecycle events.

**Audit history:** Records security-relevant fetch events into a small kernel-owned audit ring.

## What the fetch service is not responsible for

The fetch service deliberately does not include a full browser. That is the main design choice. The kernel should not be parsing and executing the web platform inside the trusted core.

**Out of kernel**

**HTML parsing:** The kernel fetch service relays bytes and MIME information, but does not build a DOM.

**CSS parsing and layout:** Layout belongs in a userspace renderer or future GUI client, not in the kernel service.

**JavaScript execution:** Remote script execution is outside this kernel layer.

**Rendering:** The fetch service does not draw web pages. It emits events.

**Fonts and media pipelines:** The service may fetch bytes for those resources, but does not rasterize fonts or decode media as part of the trusted fetch layer.

**Page scripting policy:** The kernel can enforce coarse fetch policy, but page-level script semantics belong above this service.

## Current request flow

A normal fetch starts with a client opening a session. The service gives the caller a session id and a capability token. Later requests must present both. A navigation request is then parsed, checked, assigned a request id, and executed through the fetch pipeline. Results are not returned as one giant response. They are pushed into the session event queue as structured events.

The current flow is:

1. A caller opens a fetch session.
2. The service creates a session entry and session capability.
3. The service registers origin policy and storage for that session.
4. The caller sends a navigation request with a URL, method, body, and redirect policy.
5. The service validates the session capability.
6. The URL is parsed into a fixed-size URL structure.
7. Scheme and origin policy are checked.
8. A request id is allocated.
9. GET requests check the response cache first.
10. Cache misses enter the fetch pipeline.
11. The transport connects over HTTP or HTTPS.
12. TLS state is emitted as an event.
13. An HTTP/1.1 request is built and sent.
14. The response status and headers are parsed.
15. Redirects return a redirect outcome to the service.
16. Non-redirect responses emit headers and stream body chunks.
17. Completion or error events are queued.
18. The client polls pending events from the session.

That flow gives the kernel a controlled way to interact with the internet without giving the caller raw socket ownership as the main browser API.

## Public service protocol

The protocol file is the client-facing language for this subsystem. It defines fetch requests, fetch responses, fetch events, policy block reasons, TLS state, response headers, request ids, download ids, and error types. The important part is that fetch clients do not call transport internals directly. They send service requests and receive structured service responses.

**Request family**

**Open session:** Creates a new fetch context for one process and returns session authority.

**Close session:** Closes the session and purges related state.

**Navigate:** Starts a URL fetch and queues events for headers, body, redirect, completion, or failure.

**Subscribe and unsubscribe:** Marks whether the session wants event delivery.

**Abort request:** Records an abort request for an in-flight fetch.

**Accept or reject download:** Lets the owning session decide whether an offered download should be written.

**Poll events:** Drains pending events from the session queue.

The response model is also bounded. A successful session open returns a session id and capability. A successful navigation returns a request id. Event polling returns up to eight events at a time. Errors are typed so callers can distinguish invalid sessions, invalid capabilities, unsupported schemes, invalid URLs, invalid downloads, and quota failures.

## Module map

The fetch service is split into small modules because the internet path crosses several different boundaries. Network transport, HTTP parsing, policy, storage, cookies, cache, downloads, sessions, and audit each need their own owner.

**Module**

**mod.rs:** Public module boundary, exports, init, tick, and service dispatch.

**service.rs:** Global fetch service singleton, request dispatcher, session lifecycle, navigation flow, cache lookup, event enqueueing, and cleanup.

**protocol.rs:** Fixed-size request, response, event, error, header, download, and TLS-state types.

**types.rs:** Core data types such as URL, origin, scheme, method, session id, request id, download id, status code, MIME type, and capability token.

**transport.rs:** HTTP and HTTPS transport wrapper over the network reactor and TLS session pool.

**fetch.rs:** High-level fetch pipeline for DNS, connect, TLS, HTTP request building, response parsing, redirect return, and body streaming.

**headers.rs:** HTTP header helpers for status lines, header parsing, content length, content type, location, and chunked transfer decoding.

**policy.rs:** Stateless checks for scheme, mixed content, redirects, declared body size, download prompt threshold, TLS failure, and host denylist.

**origin.rs:** Same-origin and same-site classification, per-session origin policy, allowlist behavior, and origin table.

**cookie_jar.rs:** Fixed-size cookie storage with Secure, HttpOnly, SameSite, domain, path, and expiry fields.

**cache.rs:** Fixed-size response cache with URL digests, ETag, Last-Modified, max-age, and a bounded body pool.

**content_filter.rs:** MIME classification, attachment handling, filename extraction, and basic signature sniffing.

**downloads.rs:** Bounded download job table with pending, active, complete, rejected, and error states.

**storage.rs:** Per-session VFS-backed key/value storage under the browser storage root.

**temporal.rs:** Snapshot and restore logic for session identity, navigation history, cookies, and download jobs.

**audit.rs:** Fixed-size audit log for important fetch service events.

## Session model

The session model is the authority container for the fetch service. A session belongs to a process id, carries a session capability, stores navigation history, stores a policy profile, tracks subscription state, and owns an event queue. Most service operations require the caller to present the correct session id and capability.

**Session field**

**Session id:** The handle used to identify one fetch session.

**Process id:** The process identity recorded when the session is opened.

**Capability:** The token required for session operations.

**Policy profile:** Per-session policy settings such as mixed-content behavior, redirect limit, body-size limit, and denylist entries.

**Navigation history:** A fixed-depth ring of recent URLs.

**Event queue:** A fixed-size queue of pending fetch events.

**Request counter:** Allocates request ids inside the session.

The model is useful because it avoids global ambient fetch authority. A client has to operate through its session. When the session closes, the service purges origin policy, cookies, cache entries, downloads, and storage registration for that session.

The maturity gap is that OpenSession currently receives the process id as request data. Production maturity should bind session identity to the real IPC caller instead of trusting the client to describe itself correctly.

## Transport and HTTP model

The transport layer chooses between plaintext HTTP and HTTPS. For HTTPS, it allocates a TLS session through the network TLS module and drives the handshake until completion or failure. For HTTP, it opens a TCP connection through the network reactor. The fetch layer then builds a compact HTTP/1.1 request, sends it, reads until the response header boundary, parses headers, and streams body chunks.

**Transport path**

**DNS:** Hostnames are resolved through the network reactor.

**HTTP:** Uses a TCP connection to the target port.

**HTTPS:** Uses the TLS session pool and emits a TLS state event.

**Request building:** Sends method, path, host header, connection close, accept, and optional content length.

**Response parsing:** Parses the status line, response headers, content length, content type, redirect location, and chunked transfer mode.

**Body streaming:** Emits body chunks in bounded chunks rather than allocating a full response body.

This is the right shape for an in-kernel fetch service because it keeps buffering bounded. The fetch layer uses stack buffers and caller-provided event arrays rather than heap allocation. The tradeoff is that the current implementation is still a simple HTTP/1.1 client. It does not implement the full browser network stack, HTTP/2, HTTP/3, connection pooling, certificate policy reporting, advanced cache revalidation flow, or full content security policy.

## Origin and policy model

The origin model gives each session a top origin and optional allowlist rules. Navigation and subresource decisions can be classified as same origin, same site, cross origin, or opaque. The current same-site logic is intentionally simple: it approximates registrable domain by comparing the last hostname labels rather than using the full public suffix list.

**Policy area**

**Scheme policy:** Only HTTP and HTTPS are fetchable.

**Mixed content:** Plain HTTP subresources on HTTPS pages can be blocked.

**Redirect policy:** Redirect count is bounded, non-HTTP schemes are blocked, and HTTPS-to-HTTP downgrade is blocked.

**Origin policy:** Sessions can enforce same-origin or allowlisted cross-origin behavior.

**Body-size policy:** Declared body size can be rejected when it exceeds limits.

**Download policy:** Large or attachment-like responses can become download offers.

**Denylist policy:** Compact host denylist entries can block specific hosts.

The important point is that the fetch service is not just a socket wrapper. It is where the kernel starts deciding which remote content is allowed to enter a session. That said, this is still a scaffold. Full browser-grade origin and web security policy is much deeper than the current fixed-array policy model.

## Cookie, cache, and storage model

Cookies, cache, and storage are where fetch state becomes persistent or semi-persistent. Those states are security-sensitive because they can affect future requests, session identity, user tracking, authentication behavior, and replay.

Cookies are stored in a fixed-size cookie jar. Each cookie records name, value, domain, path, session, Secure, HttpOnly, SameSite, expiry, and active state. Cache entries store URL digest, status, MIME type, ETag, Last-Modified, max-age, epoch stored time, and a body slice in a fixed body pool. Storage gives each session a VFS-backed directory and validates storage keys before reading, writing, or deleting.

**State area**

**Cookies:** Session-scoped records with domain, path, Secure, HttpOnly, SameSite, and expiry metadata.

**Cache:** Bounded response metadata and small cached body storage for GET responses.

**Storage:** Per-session VFS path under the browser storage root with validated ASCII keys.

**Temporal snapshot:** Saves session identity, navigation history, cookies, and download jobs.

**Excluded state:** Response cache bodies and VFS storage entries are not included in temporal snapshots.

This split is sensible. Cache bodies can be large, and VFS storage is already persistent. The temporal layer snapshots the compact trust state that helps reconstruct the fetch service after lifecycle events.

## Download model

Downloads are modeled as explicit jobs. A response can be offered as a download when policy or content filtering says it should not be relayed inline. The download job records the session, request id, suggested filename, MIME type, size hint, destination path, written byte count, and state.

**Download state**

**Pending:** Offered to the client and waiting for accept or reject.

**Active:** Accepted and being written.

**Complete:** Write completed.

**Rejected:** Client rejected the offer or the kernel aborted it.

**Error:** A write failure occurred.

This is the correct direction because writing remote content to disk should not be automatic. The client has to accept a download and provide a destination. The service also checks that the download belongs to the same session before accepting or rejecting it.

The maturity work is making the path more policy-rich. Destination paths need stronger authority checks, filename normalization, overwrite policy, quarantine metadata, MIME evidence, audit records, and integration with storage permissions.

## Temporal model

The temporal file defines a versioned snapshot format. It serializes session records, navigation history, cookie records, and download records into a bounded caller-provided buffer. Restore validates the snapshot magic and version, then rebuilds sessions, navigation history, cookies, and downloads.

**Snapshot area**

**Header:** Magic, version, session count, cookie count, download count, and reserved field.

**Session records:** Session id, process id, capability, alive flag, next request id, navigation ring state, and URL entries.

**Cookie records:** Session id, expiry, flags, name, value, domain, and path.

**Download records:** Download id, session id, state, filename, MIME type, size hint, bytes written, and destination path.

**Not snapshotted:** Response cache body data and VFS-backed storage entries.

Temporal restore is useful, but it is also security-sensitive. Restoring session capabilities and cookies means the snapshot must eventually be authenticated, versioned carefully, and tied to the broader persistence trust model. The current code validates structure, lengths, magic, and version, but the README should treat production snapshot authenticity and rollback resistance as future maturity work.

## Security boundaries

The fetch service touches several boundaries at once. It is not only a network helper. It is the place where remote input, local session authority, persistent state, downloads, and temporal restore meet.

**Network boundary**

Remote servers can return hostile headers, malformed responses, oversized bodies, redirect chains, unexpected MIME types, and connection failures. The fetch service has to parse that input without trusting it.

**Session boundary**

One session should not read another session's cookies, cache entries, storage, downloads, events, or navigation state.

**Origin boundary**

Remote content should be constrained by origin policy, same-origin checks, allowlists, mixed-content blocking, and redirect rules.

**Storage boundary**

Downloads and per-session storage turn remote bytes into local filesystem state. That path needs explicit destination authority and strong path validation.

**Temporal boundary**

Snapshot and restore can resurrect cookies, capabilities, sessions, and download records. That makes snapshot authenticity and rollback handling essential for production.

**Renderer boundary**

The kernel emits bytes and events. The renderer decides how to display or execute user-facing web content. That boundary prevents the kernel from becoming a full browser.


## Fetch session capabilities: issuance, validation, and revocation

### Current alpha capability flow

The current fetch session capability flow is intentionally small and easy to inspect. A client opens a fetch session, the service allocates a live session record, stores the process id, generates a capability token, registers related origin and storage state, records a session-open audit event, and returns the session id and capability to the caller. After that point, most fetch operations require the caller to present both the session id and the capability.

**Current model:** The fetch service uses a local session table as the authority container for fetch operations.

**Authority shape:** A caller does not operate on the fetch service through raw socket ownership. It operates through a session id and capability pair.

**Alpha limitation:** The session is currently opened using a process id supplied inside the fetch request itself, rather than a process identity supplied by the authenticated IPC layer.

This is the most important distinction in the current alpha flow. The service has the right general shape because fetch authority is explicit, but the source of caller identity is not yet strong enough. In a final Oreulius authority model, the fetch service should not trust a client to describe which process it is. The process identity should arrive from the IPC or execution layer as authenticated metadata outside the request body.

| Area | Current behavior | Audit note |
|---|---|---|
| Session open | Caller sends a process id | Useful for scaffolding, but not final authority |
| Session ownership | Session stores process id and capability | Good structure, weak identity source |
| Session quota | One live session per process id | Only meaningful if process id is authentic |
| Session response | Service returns session id and capability | Correct alpha API shape |
| Linked state | Origin and storage are registered on open | Good subsystem coordination |

The current model should therefore be described as an alpha local capability flow. It is not wrong as a development step, but it should not be presented as complete process-bound authority yet. The code is already organized in a way that makes future hardening straightforward: the open path is centralized, session state is centralized, and the capability check path is centralized. The main work is to replace caller-supplied identity with authenticated IPC identity and then make validation prove both possession of the capability and ownership by the real caller.

The current alpha flow is structurally sound, but identity binding is incomplete. The session id and capability pair works as a local bearer token, not yet as a fully bound Oreulius capability relationship.

### Session capability issuance

Session capability issuance happens inside the fetch session table. When a session opens, the table finds a free slot, derives a session id from that slot, generates a capability token, resets the slot, writes the new session id, process id, capability, and live flag, then returns the slot index to the service.

**Good design choice:** Capability issuance is localized in one place, which makes the code easier to audit.

**Good design choice:** Empty sessions use a zero capability and are marked not alive.

**Important weakness:** The current capability generator is deterministic and starts from a fixed seed.

The capability generator is the part that needs the most precise documentation. The current implementation uses a simple deterministic generator, not a cryptographic authority primitive. That means the implementation should not be described as a cryptographic MAC or as unguessable in the strong production sense. It is currently better understood as a temporary alpha token generator.

| Area | Current behavior | Hardening direction |
|---|---|---|
| Session id | Derived from slot index | Add generation awareness |
| Capability token | Generated locally by session table | Replace with kernel capability issuance |
| Empty capability | Zero value | Keep zero invalid |
| Slot reuse | Same session id can appear again later | Require generation or fresh authority object |
| Restore path | Can restore stored capabilities | Define restore reissue or reuse policy |

The deeper issue is that the session id is not the secret. It is predictable because it is derived from the slot. That is fine if the capability is strong, but the current capability token is also deterministic. In practice, the capability is the real bearer authority. If an untrusted caller can guess, infer, copy, or recover a valid capability, the validation path will treat that caller as authorized unless caller identity is checked elsewhere.

The restore path also matters. A restored session can install a historical capability into a live session slot. That might be the intended behavior for temporal continuity, but it turns temporal restore into part of the authority model. If capabilities survive restore, then snapshots need authenticity, rollback protection, and a clear rule for whether old session authority remains valid. If capabilities do not survive restore, then the restore path should reissue fresh capabilities and force clients to reacquire authority.

**Implementation status:** The current implementation issues fetch session capabilities locally from the session table. This is acceptable for alpha scaffolding, but it is not the final authority model.

**Production direction:** Production fetch sessions should receive authority from the kernel capability subsystem or from a boot-secret-backed authority mechanism.

**Binding requirement:** Session capabilities should be bound to the authenticated caller, session id, authority class, and revocation generation.

**Temporal requirement:** Temporal restore must define whether old capabilities are restored, reissued, or rejected.

The issuance path is cleanly placed, but the token source is not strong enough yet. The README should explain this as alpha-local capability issuance and explicitly separate it from the future production capability model.

### Capability validation path

The current validation path is centralized in the fetch service. A request presents a session id and capability. The service looks up the session id, retrieves the live session, compares the stored capability with the presented capability, and rejects the request if the presented capability is zero.

Most of the public fetch operations pass through that validation helper before they mutate session state or expose session-owned data. Navigation validates before URL parsing and fetch dispatch. Closing a session validates before state is purged. Subscription, abort, download acceptance, download rejection, and event polling also pass through the same check. This gives the service a coherent validation shape, but it should still be understood as a narrow bearer-token check rather than a complete authority decision.

| Validation area | Current behavior | Audit note |
|---|---|---|
| Session lookup | Session id maps to a live slot | Simple and bounded |
| Capability check | Stored cap must equal supplied cap | Clear bearer-token model |
| Zero cap | Rejected | Prevents empty-token authority |
| Caller identity | Not checked in validation | Main missing authority binding |
| Failure result | Boolean validation | Loses useful failure reasons |
| Invalid attempts | No explicit audit in validation path | Should be added later |

The most important observation is that the session stores a process id, but the validation function does not use it. That means the stored process id currently affects session quota during opening, but not the authority check for later operations. After a session exists, possession of the numeric capability is enough to operate it. That is acceptable for a narrow alpha bearer-token model, but it is not enough for a production process-bound capability system.

A stronger validation path would receive the authenticated caller identity from the service entrypoint. It would then check that the session exists, the capability is valid, the capability matches the live session, the authenticated caller owns the session, and the capability generation has not been revoked. It should also return typed validation errors rather than a plain true or false result.

The current validation path checks session id and token possession, but it does not yet bind the request to authenticated IPC caller identity. It also does not yet check a revocation generation or authority class. Later versions should be able to distinguish invalid session, invalid capability, wrong caller, stale generation, and revoked authority.

The validation logic is already easy to locate, but its authority semantics are still incomplete. It validates a local bearer token today, while the mature Oreulius model should validate a process-bound capability tied to authenticated IPC identity and explicit revocation state.te.

### Capability revocation on session close

The close-session path does perform a meaningful form of revocation by clearing the session slot and purging the origin policy, cookies, cache, downloads, and storage registration associated with that session. That is a good start because closing a session does not merely flip a visible flag. It also attempts to remove the major pieces of fetch state that belong to that session.

**Current revocation action:** Closing a session resets the session slot and removes the related fetch-owned state.

**Revoked state:** Origin policy, cookies, cache entries, downloads, and storage registration are purged for the closed session.

**Remaining gap:** Revocation currently depends on slot clearing and token mismatch rather than an explicit revocation generation.

| Revocation area | Current behavior | Audit note |
|---|---|---|
| Session table | Slot is reset to an empty session | Good immediate invalidation |
| Origin policy | Session origin policy is unregistered | Good cleanup |
| Cookies | Session cookies are purged | Good privacy and isolation behavior |
| Cache | Session cache entries are purged | Good containment behavior |
| Downloads | Session downloads are purged | Good state cleanup |
| Storage | Session storage registration is removed | Good ownership cleanup |
| Generation | No explicit generation check | Needs maturity work |

The current revocation model is useful because a closed session no longer resolves as live. Since validation begins by looking up the session id, a closed session should fail before any operation can continue. This gives the service a simple and effective local revocation mechanism for the current alpha model.

However, the revocation model is still incomplete because session ids are derived from table slots and can be reused over time. That means the system depends heavily on the next capability value being different from the previous one. A mature version of this model should include an explicit session generation or revocation generation, so an old authority can be rejected because it belongs to a previous lifetime of the same slot, not merely because the raw token no longer matches.

This matters most when slot reuse and temporal restore enter the same authority story. If a session slot is closed, reopened, and later restored from a snapshot, the system needs a clear way to distinguish a current authority from a stale authority. Without generation tracking, revocation is mostly represented by whether the live slot currently contains the same raw token. That is too narrow for a kernel capability model.

A stronger close-session path would invalidate the live session, increment or retire a generation, purge associated state, and emit audit evidence for the revocation. If stale requests arrive after close, the service should be able to distinguish between an invalid session, a wrong capability, a stale generation, and a wrong caller. Those distinctions are useful for both security policy and debugging.

The next hardening step is to stop accepting process identity from the request body and instead bind session creation to authenticated IPC caller identity. Once the fetch service receives the real caller identity from the IPC layer, capability validation can prove both token possession and caller ownership. That would prevent the fetch session from behaving like a plain bearer-token system where any holder of the session id and capability can operate the session.

The deterministic local token generator should also be replaced with either kernel capability issuance or a boot-secret-backed authority mechanism. The current flow is useful for alpha scaffolding, but the final model should bind authority to the caller, session id, authority class, and generation. Temporal restore also needs a clear decision: restored capabilities should either be reissued, explicitly reused under an authenticated snapshot policy, or rejected when the restored authority cannot be trusted.

Invalid capability attempts, wrong-caller attempts, stale-generation attempts, close-session revocations, and restore-related authority decisions should eventually become audit-visible events. That would make the revocation path not only stricter, but also more inspectable. The fetch service already has the right shape for this because session close is centralized and already purges the major state tables. The missing piece is explicit revocation semantics that survive slot reuse, restore, and cross-process authority checks.

### Future capability-subsystem integration

The fetch service currently has a capability-shaped local authority model, but it is not yet integrated into the main Oreulius capability subsystem. Fetch sessions use their own session id and local capability token, and fetch validation checks that local token against the value stored in the session table. That gives the fetch service a clear alpha authority boundary, but it keeps fetch authority separate from the kernel-wide capability lifecycle.

The main Oreulius capability subsystem is already richer than the fetch-local model. It defines capability types, rights, object ids, owner binding, origins, grant timestamps, signed tokens, parent capability provenance, attenuation, per-task capability tables, capability lookup, removal, revocation, remote leases, IPC transfer staging, and audit events. Fetch session capabilities do not currently participate in that machinery. They are not installed into the caller’s per-task capability table, they are not represented as an OreuliusCapability object, and they are not checked through the main capability verification path.

The capability taxonomy also does not yet give fetch a first-class authority class. The existing capability types cover channels, tasks, spawners, console, clock, store, filesystem, service pointers, and cross-language links. Fetch is still represented as a service-local session token instead of a dedicated capability type or service authority class. For a mature kernel-owned internet layer, fetch should eventually have a defined capability identity inside that taxonomy, either as its own fetch capability type or as a constrained service-pointer authority with fetch-specific rights.

| Integration area | Current fetch behavior | Mature capability behavior |
|---|---|---|
| Authority object | Local session id and token | Kernel capability object |
| Capability type | No dedicated fetch type | Fetch or service-specific authority class |
| Rights model | All session operations use the same local token | Operation-specific rights |
| Owner binding | Process id is stored in the session | Authenticated owner binding in capability validation |
| Token validation | Local equality check | Signed capability token verification |
| Revocation | Session close and slot reset | Capability manager revocation |
| Audit | Fetch-local audit hooks | Main capability audit events |
| Transfer | No fetch capability transfer model | IPC ticketed transfer with delegation rights |
| Provenance | No parent capability chain | Parent capability id and attenuation history |
| Remote authority | No remote fetch lease model | Remote leases and CapNet policy |

A future fetch capability should not only prove that the caller knows a numeric token. It should prove that the caller holds a capability of the correct class, for the correct fetch session object, with the rights needed for the requested operation. Navigation, event polling, abort, download acceptance, storage access, introspection, and delegation should not necessarily be the same authority. The current local session token treats them as one bundle. That is acceptable for the alpha implementation, but it should not be the final authority shape.

A mature fetch authority model can divide fetch rights into smaller operation classes. A client that can poll events should not automatically need authority to accept downloads. A renderer that can observe headers and body chunks should not automatically need authority to open new sessions or alter session policy. A delegated client should be able to receive attenuated fetch authority that is narrower than the authority held by the original session owner.

| Future fetch right | Purpose |
|---|---|
| FETCH_SESSION_CONTROL | Open, close, or manage fetch session lifecycle |
| FETCH_NAVIGATE | Start navigation or subresource fetches |
| FETCH_POLL_EVENTS | Read queued fetch events |
| FETCH_ABORT | Abort in-flight requests |
| FETCH_ACCEPT_DOWNLOAD | Accept or reject download offers |
| FETCH_STORAGE_ACCESS | Read, write, or delete fetch storage state |
| FETCH_INTROSPECT | Inspect session state, policy, or audit-visible metadata |
| FETCH_DELEGATE | Transfer or attenuate fetch authority |

The capability manager already supports a per-task table model where capabilities can be installed, looked up, removed, attenuated, revoked, listed, and audited. Fetch should eventually use that table rather than storing all session authority only inside BrowserSession. The fetch session can still keep its own runtime state, but the authority to operate that state should be represented in the caller’s capability table. That would make fetch authority visible to the same auditing, revocation, transfer, and provenance logic as other kernel authority.

This integration also changes revocation semantics. Today, closing a fetch session resets the local session slot and purges related state. In the future model, closing a session should also revoke or retire the corresponding kernel capability. Process exit, crash cleanup, policy revoke, and temporal restore should all interact with that same capability lifecycle. A stale fetch capability should fail because the capability manager knows it was revoked or belongs to an old generation, not only because the current session slot no longer contains the same local token.

The main capability subsystem also has IPC transfer machinery. It can export a capability into a ticketed IPC envelope, stage the transfer, consume it once, and roll it back if transfer fails. Fetch session authority is not currently represented in that transfer ledger. Future fetch delegation should use the same path. If a process transfers fetch authority to another process, that transfer should require delegation rights, preserve provenance, and install an attenuated capability in the receiving task’s capability table.

Remote leases are another part of the future integration. The capability manager already represents remote authority with owner, object id, capability type, rights, validity window, revoked state, and optional use budget. Fetch does not currently use that model. If CapNet eventually allows remote authority over fetch operations, the fetch service should define which remote leases can open sessions, use existing sessions, poll events, accept downloads, or only invoke a constrained fetch service pointer.

The security capability-check helper also shows a separate validation path for nonce matching, rights-subset validation, and transfer constraints. Fetch validation is not using that path yet. Fetch currently checks local token equality, while the broader capability model can reason about rights escalation, transfer validity, owner identity, and structured security violations. Future integration should move fetch toward that broader validation style so fetch operations fail for typed authority reasons rather than a single invalid-capability result.

The important audit point is that fetch is already shaped like a capability service, but it is still running a local authority model. The next maturity step is to make fetch authority a first-class kernel capability: typed, signed, rights-bearing, owner-bound, attenuatable, revocable, transferable, auditable, and compatible with remote leases where policy allows it.

## Fetch caller identity and IPC session binding

The current fetch caller identity model is implemented as an alpha session-binding path. A fetch session is opened through the public fetch protocol, and the open request carries a process id as part of the request body. The service dispatcher receives that request, extracts the process id, and passes it directly into the session-open path. The session table then records that process id inside the browser session record alongside the session id, local capability token, policy profile, subscription flag, event queue, navigation history, and request counter.

This means caller identity exists in the current fetch service, but it is not yet authenticated at the fetch boundary. The service stores a process id and uses that process id to enforce the current one-session-per-process rule, but the process id is supplied by the caller through the fetch request rather than being attached by the IPC layer as trusted caller metadata. The IPC codebase already has message source identity and channel capability structures, but the fetch service dispatch path is not yet wired to consume an authenticated IPC caller envelope. The current model is therefore useful for wiring the service together, but identity binding remains an alpha boundary that should move out of the request body and into the IPC/session authority layer.

### Current caller-supplied process id model

The current caller identity model is implemented directly inside the fetch protocol. Opening a session requires an `OpenSession` request, and that request carries a process id as one of its fields. The service dispatcher receives the request, extracts the supplied process id, and passes it into the session creation path. The session table then stores that process id inside the live browser session record together with the session id, local capability token, policy profile, subscription flag, navigation history, event queue, and request counter.

This gives the fetch service a simple alpha identity model: the caller says which process it is, the fetch service records that value, and the session table uses it as the owner marker for the new session. That owner marker is then used for the one-session-per-process check. If a live session already exists with the same stored process id, the service rejects the new open request with a session quota error. If no matching session exists, the table allocates the first free slot, derives the session id from that slot, generates the local capability token, writes the supplied process id into the session, and marks the session alive.

| Area | Current behavior | Audit note |
|---|---|---|
| Identity source | Process id is provided inside OpenSession | Caller-controlled at the fetch request boundary |
| Session owner field | BrowserSession stores the supplied process id | Ownership is recorded, but not authenticated here |
| Duplicate session check | Existing sessions are searched by stored process id | The check depends on the trustworthiness of the supplied value |
| Session allocation | First free slot is assigned to the supplied process id | Slot ownership follows request data |
| Session id | Derived from slot index | Predictable handle, not identity proof |
| Capability token | Generated locally by the fetch session table | Used as the real bearer authority after open |
| Later operations | Validate session id and local capability token | Stored process id is not part of later authorization |

The major limitation is that the process id is not being derived from the IPC or scheduler boundary at the point where the fetch session is opened. It is accepted as request data. That means the fetch service records identity, but it does not yet authenticate identity. The distinction matters because a process id stored inside a session is only meaningful if the service can trust where that process id came from. In the current model, the fetch service does not independently prove that the caller opening the session is the same process named in the request.

The IPC side of the codebase already has process identity concepts. IPC messages carry a source process id, and channel operations are built around channel capabilities and process ownership. That gives the kernel a path toward authenticated service calls where the caller identity arrives with the message envelope rather than inside the service payload. The fetch service has not yet been wired to that model. Its dispatcher accepts a fetch request as the authority context and does not receive a separate authenticated caller argument.

The result is that caller identity currently affects session creation more than session operation. The stored process id is used to prevent duplicate sessions for the same supplied process id, but later fetch operations are authorized through the session id and local capability token. Navigation, close, subscribe, unsubscribe, abort, download acceptance, download rejection, and event polling do not compare the active caller against the stored session owner. Once a caller has the session id and capability token, the current validation path treats that as enough authority to operate the session.

This is a clear alpha boundary. The code has a useful shape for development because it already records a process owner, limits sessions by that owner, and keeps session state grouped under that owner. The missing piece is that ownership needs to come from the kernel’s caller context, not from the client-controlled request fields. When fetch dispatch receives authenticated IPC caller identity, the service can bind new sessions to the real caller and validate later operations against that same caller.

The mature model should remove trusted process identity from the open-session payload. OpenSession can still carry profile or session configuration fields, but not the authoritative owner. The owner should be provided by the service invocation layer. Session creation should bind to that caller, duplicate-session checks should use that caller, and capability validation should verify that the caller presenting the session capability is the same caller that owns the session or holds a deliberately delegated fetch authority.

This also affects audit quality. Under the current model, a rejected duplicate session can be logged against the supplied process id, but a forged identity attempt cannot be reliably distinguished from an ordinary request because the fetch service has no separate authenticated caller identity to compare against. Once the IPC caller is available, the service can audit mismatches between the real caller and any attempted target identity, as well as wrong-caller attempts against existing sessions.

The current caller-supplied model is therefore best documented as a scaffolding layer. It proves out the session table, session ownership field, one-session lookup, and local capability flow. It does not yet establish process-bound fetch authority. The next step is to move caller identity out of the request body and into the IPC/session authority layer, then make every session operation validate both capability possession and caller ownership.

### Authenticated IPC caller identity

The IPC layer already carries process identity as part of its message model. An IPC message has a source process id, and the message constructor stamps that source into the message identity and stores it on the message. IPC channel creation also works through a creator process id, and channel authority is granted through the capability manager when a channel is created for a process. That means the codebase already has the pieces needed for service-level caller identity: a process source on messages, channel capabilities, capability-backed channel creation, and admission checks for send and receive rights.

The fetch service is not yet bound to that authenticated IPC caller identity. The fetch protocol still accepts an `OpenSession` request that contains a process id inside the request itself. The fetch dispatcher then passes that process id directly into the session open path. The session table stores it as the session owner, and the one-session-per-process rule searches against that stored value. That gives fetch a local identity field, but not an authenticated caller boundary. The owner is still derived from the fetch request payload instead of the IPC message envelope or scheduler caller context.

| Area | IPC implementation | Fetch implementation | Audit note |
|---|---|---|---|
| Caller identity | IPC Message stores source process id | OpenSession carries pid in request body | Fetch is not yet using IPC source as caller authority |
| Capability channel | Channel capabilities carry owner and rights | Fetch uses local session Cap | Different authority paths |
| Service dispatch | IPC sends messages through channel authority | Fetch dispatch accepts FetchRequest directly | No authenticated caller parameter enters fetch dispatch |
| Admission checks | IPC checks send and receive rights | Fetch checks session id and local token | Fetch does not check caller identity after open |
| Session owner | IPC has source/owner concepts | BrowserSession stores pid | Stored owner is not used as caller validation |
| Audit potential | IPC/capability paths can report capability failures | Fetch audits session lifecycle locally | Caller mismatch audit needs authenticated caller input |

The IPC admission layer also gives the broader direction this should take. IPC send and receive paths evaluate the channel capability, check send or receive rights, verify that the capability is for the right channel, and apply predictive security restrictions through the security subsystem. That is a stronger pattern than the current fetch path because it evaluates an operation against a capability and an owner-bearing channel object. Fetch validation currently checks whether the supplied session id resolves to a live session and whether the supplied local token matches. It does not yet ask whether the authenticated IPC source is the owner of that session.

The correct integration point is the fetch service boundary. Fetch dispatch should not treat the request body as the whole authority context. It should receive a trusted caller identity from the IPC service invocation path, then pass that identity into session open and capability validation. Under that model, `OpenSession` would bind the new session to the authenticated caller, while later calls such as navigation, close, subscribe, abort, download accept, download reject, and poll events would validate both the session token and the caller identity. The stored process id would become an enforced ownership field instead of merely a recorded field.

The current code also shows why this needs to happen before stronger audit records can be meaningful. Without an authenticated caller identity, the fetch service cannot reliably tell the difference between a normal open request and a forged process id. It can reject duplicate sessions for whatever process id was supplied, but it cannot compare that value against the real sender. Once the IPC caller identity is passed into fetch dispatch, the service can audit wrong-caller attempts, forged identity attempts, caller/session mismatches, and attempts to operate a session from the wrong process context.

A mature fetch IPC binding should therefore use the IPC source process as the caller authority, not the fetch request payload. The request can still carry profile, policy, navigation, method, body, redirect, and download fields, but process ownership should come from the service envelope. The fetch service already has the session table and owner field needed to store the result. What is missing is the authenticated caller argument at dispatch time and the validation logic that compares that caller against the stored session owner.

### One-session-per-caller enforcement

The current fetch service enforces a one-session-per-caller rule through the process id stored in the fetch session table. When `OpenSession` reaches the service, the dispatcher passes the request-provided process id into the session-open path. Before allocating a new session slot, the service searches the session table for an existing live session with that same process id. If one is found, the service rejects the request with a session quota error. If no live session exists for that process id, the service allocates a free slot and stores the supplied process id in the new `BrowserSession`.

This gives the fetch service an early form of caller scoping. A session is not completely global, and the service does not allow unlimited sessions for the same recorded process id. That is useful for containing session-owned state such as cookies, cache entries, origin policy, downloads, storage registration, navigation history, and event queues. The enforcement point is also simple: duplicate-session rejection happens before session allocation, before origin registration, and before storage registration.

The limitation is that the current enforcement depends on the trustworthiness of the process id that reaches `do_open_session`. Right now, that process id comes from the `OpenSession` request body. The session table correctly searches by process id, but the fetch service does not yet prove that the caller is actually the process named by that id. That means the one-session-per-caller rule is currently better described as one-session-per-supplied-process-id, not one-session-per-authenticated-caller.

| Area | Current behavior | Audit note |
|---|---|---|
| Enforcement point | `do_open_session` checks for an existing session before allocation | Correct placement for duplicate-session prevention |
| Lookup mechanism | `find_by_pid` searches live sessions by stored process id | Simple and bounded |
| Caller identity source | Process id comes from `OpenSession` request data | Not yet authenticated at the fetch boundary |
| Rejection behavior | Duplicate open returns session quota error | Useful alpha behavior |
| Session allocation | First free slot is used when no duplicate process id exists | Bounded session table behavior |
| Stored owner | New session stores the supplied process id | Owner is recorded, but not independently verified |
| Later validation | Later operations check session id and capability | Caller identity is not rechecked after open |

The current model also has a design tension with the README wording. The protocol comment describes opening a new fetch session as “one per tab / navigation context,” while the implementation enforces one live session per process id. Those are not always the same thing. If a process is expected to own multiple navigation contexts later, the current rule will be too strict. If the intended design is one fetch session per process, then the “tab / navigation context” language should be tightened so the documented model and the implementation agree.

That decision matters because it affects the future API shape. A strict one-session-per-process model is simple and easy to clean up on process exit, but it makes multi-tab or multi-context clients awkward unless each tab maps to a separate process. A one-session-per-context model gives a renderer or browser shell more flexibility, but then the service needs an authenticated caller identity plus a separate context id, profile id, or session class. The current implementation has a `profile` field in `OpenSession`, but the inspected dispatch path ignores it when opening the session, so it is not currently part of the duplicate-session rule.

The enforcement also needs to be connected to authenticated IPC caller identity. The broader IPC layer already has source process identity on messages and capability-backed channel operations, but the fetch dispatcher does not yet receive that caller identity as a trusted parameter. Once fetch dispatch receives an authenticated caller, duplicate-session enforcement should search by that real caller identity. If the model later supports multiple sessions per caller, the duplicate key should become something like caller plus profile, caller plus context id, or caller plus session class, rather than only caller.

There is also a lifecycle cleanup angle. A one-session-per-caller rule is only complete if sessions are closed when the caller exits, crashes, is killed, or loses authority. The current fetch path supports explicit close, and close purges session-owned state, but one-session-per-caller enforcement should eventually be tied to process lifecycle events. Otherwise, a dead process could leave a live session occupying that caller slot until explicit cleanup occurs. That would turn the duplicate-session rule into a stale-session problem.

Temporal restore also needs to be considered. Restored sessions include process identity, session id, and capability state. If a restored session claims a process id that is no longer valid, belongs to a different process lifetime, or conflicts with a live authenticated caller, the one-session rule needs a clear policy. Restore should not blindly recreate a session that blocks a real caller or resurrects authority for a stale process identity. A mature model should bind restored sessions to a persistence generation, process generation, or authenticated restore policy.

The current implementation is therefore a useful alpha enforcement point, but not a complete identity boundary. It prevents duplicate live sessions for the same recorded process id, but that process id is still caller-supplied. The next maturity step is to move the duplicate-session key from request-provided process id to authenticated IPC or execution-layer caller identity, then decide whether the final rule is one session per process, one session per caller context, or one session per caller/profile pair.

### Session cleanup on process exit or crash

The current fetch service has a clear explicit cleanup path through `CloseSession`. When a caller closes a session with the correct session id and capability, the service resets the session slot and purges the major pieces of state owned by that session. Origin policy is unregistered, cookies are purged, cache entries are purged, download jobs are purged, storage registration is removed, and a session-closed audit event is recorded. This is the main cleanup path currently implemented inside the fetch service.

The missing part is lifecycle-driven cleanup. The code path reviewed shows cleanup when the fetch service receives an explicit close request, but not a direct process-exit or crash hook that tells the fetch service to clean up every session owned by a dead process. The session table stores a process id in each `BrowserSession`, and it can find sessions by process id, so the data needed for lifecycle cleanup is already partly present. What is not yet present is the binding from scheduler/process lifecycle events into the fetch service cleanup path.

This matters because fetch sessions own more than a handle. A live session can carry cookies, cache entries, origin policy, storage registration, downloads, queued events, navigation history, and pending request state. If a process exits or crashes without sending `CloseSession`, the fetch service needs a trusted kernel-side cleanup path that does not depend on the dead process making one final request. Otherwise, session-owned state can remain live after the owner is gone.

| Cleanup area | Current behavior | Audit note |
|---|---|---|
| Explicit close | `CloseSession` validates session id and capability | Implemented as the main cleanup path |
| Session table | Session slot is reset to empty | Good local invalidation |
| Origin policy | Session origin policy is unregistered | Covered by explicit close |
| Cookies | Session cookies are purged | Covered by explicit close |
| Cache | Session cache entries are purged | Covered by explicit close |
| Downloads | Session download jobs are purged | Covered by explicit close |
| Storage | Session storage registration is removed | Covered by explicit close |
| Process exit | No direct fetch cleanup hook reviewed | Needs lifecycle integration |
| Process crash | No direct fetch cleanup hook reviewed | Needs forced cleanup path |
| Active requests | No complete lifecycle cleanup model reviewed | Needs explicit policy |
| Queued events | Reset through session slot close | Needs process-death semantics |
| Temporal restore | Restored sessions carry process identity | Needs stale-process handling |

The explicit close path is a useful foundation because it already centralizes most of the state that must be purged. A lifecycle cleanup hook should reuse the same cleanup semantics rather than inventing a separate partial cleanup path. The service should expose or implement a kernel-internal cleanup operation that takes an authenticated process id and closes every fetch session owned by that process. That operation should not require the process to present the session capability, because the owner may already be gone or compromised.

The main difference between explicit close and forced cleanup is authority. Explicit close is caller-driven and should require session authority. Forced cleanup is kernel-driven and should be authorized by process lifecycle, scheduler state, or policy revocation. If the scheduler says a process has exited, crashed, or been killed, the fetch service should trust that lifecycle event and clean the session without waiting for a fetch request from the dead process.

The current one-session-per-process rule also depends on this cleanup story. If a dead process leaves a session behind, the stored process id can continue occupying the caller slot. That can cause future open attempts for the same process identity to fail with a session quota error, even though the original owner is no longer alive. Once caller identity becomes authenticated and process generations are introduced, cleanup should distinguish between a current live process and a stale session restored or left behind from an older process lifetime.

Temporal restore makes this more important. Restored fetch sessions can carry stored process ids, session ids, and capability state. A restored session should not automatically become live just because its snapshot structure is valid. The restore path needs to check whether the stored process identity still exists, whether it belongs to the same process generation, and whether the restored authority is allowed under the current persistence policy. Without that, restore can reintroduce sessions for dead or replaced process identities.

Active requests and downloads also need explicit behavior. If a process exits during a fetch, the service needs to decide whether the in-flight request is aborted immediately, allowed to finish and then discarded, or converted into an error event before the session is purged. Downloads need similar rules. Pending download offers should be rejected or purged. Active downloads should be cancelled or marked failed. Completed downloads should keep whatever final evidence policy requires, but the session’s control authority should be gone.

The audit path should treat forced cleanup as a security-relevant lifecycle event. Normal close, process-exit cleanup, crash cleanup, kill cleanup, and policy-revoke cleanup are not identical events. They should be distinguishable in audit records because each one tells a different story about why fetch authority ended. A normal close means the session owner ended the session. A crash cleanup means the kernel removed fetch state because the owner failed. A policy revoke means authority was deliberately withdrawn.

A mature cleanup model should therefore make process lifecycle a first-class input to fetch session management. The fetch service already has the local cleanup pieces. The next step is to connect them to authenticated process lifecycle events, process generations, capability revocation, and temporal restore policy so session state cannot outlive its owner accidentally.

### Forged identity audit records

The current fetch service records normal session lifecycle events, but forged identity attempts are not yet auditable in a precise way because the service does not receive authenticated caller identity at the fetch boundary. `OpenSession` accepts a process id from the request body, and the session-open path treats that value as the owner used for session storage and duplicate-session checks. Without an authenticated caller identity from IPC, the fetch service cannot compare “who sent this request” against “which process id the request claims.” That means it cannot reliably distinguish a normal open request from an attempt to open a session under another process id.

This is why forged identity auditing depends on the previous caller-identity hardening work. The audit system can only produce meaningful identity-failure records once the service receives two separate facts: the authenticated caller supplied by IPC or the execution layer, and any requested or implied target identity from the fetch operation. If those values differ, the fetch service can record a forged identity attempt. In the current model, there is only the process id provided by the request, so the service has no second trusted identity source to compare against.

Once authenticated caller identity is available, identity-related failures should become first-class audit events. Opening a session for another process, operating a session owned by another caller, reusing a valid session token from the wrong caller context, attempting to restore a session for a stale process id, and repeatedly triggering invalid identity paths should all leave evidence. These records should be separate from ordinary invalid-capability failures because they describe a different class of problem: the caller is not merely missing the right token, but presenting authority under the wrong identity.

| Audit area | Current behavior | Required maturity |
|---|---|---|
| Session open | Records normal session-open events | Also record forged open attempts |
| Caller identity | Comes from request-provided process id | Use authenticated IPC or execution-layer identity |
| Identity comparison | No trusted caller-to-request comparison yet | Compare real caller against requested or stored owner |
| Wrong-caller operation | Collapses into local capability validation limits | Record caller/session owner mismatch |
| Duplicate session rejection | Rejects duplicate supplied process id | Audit duplicate attempts against authenticated caller |
| Restore identity | Restores stored process ids | Audit stale or invalid restored owner identity |
| Repeated failures | No dedicated identity-failure class | Add rate-limited or coalesced audit records |

The audit records should be specific enough to support later debugging and security review without leaking unnecessary data. A forged identity record should include the authenticated caller id, the claimed or target process id where applicable, the session id if one was involved, the operation family, and a typed reason. The reason should distinguish cases such as forged open, wrong caller for session, stale process identity, restored process mismatch, duplicate session under authenticated caller, and revoked caller authority.

The audit path also needs to avoid turning identity failures into audit-ring noise. A hostile or broken client could repeatedly send forged identities or wrong-caller requests. Those attempts should be visible, but repeated identical failures should be rate-limited, counted, or coalesced so they do not evict more important audit events. The service should preserve evidence that repeated identity failures happened while still protecting the audit ring from being flooded.

Forged identity audit records should also connect to forced cleanup. If a process dies and its session remains stale, a later caller should not be mistaken for that old process just because the numeric process id matches. If process generations are introduced, the audit path should be able to distinguish a wrong process generation from a plain wrong caller. This becomes especially important for temporal restore, where a snapshot can reintroduce process ids, session ids, and capability state from an older lifecycle.

The current fetch service has the right foundation for this work because session open, session close, and validation are centralized. The missing piece is authenticated caller identity at dispatch time. Once that exists, forged identity auditing can be built around direct comparisons between the real caller, the stored session owner, and any claimed identity in the request or restored state.

## Fetch event delivery, queue overflow, and loss markers

The fetch service sends results back to the caller through a session-owned event queue. Instead of returning everything at once, a request is accepted first, then the caller polls for updates. Those updates represent the important moments of a fetch: headers arrived, body data arrived, a redirect happened, a policy rule blocked something, TLS state changed, a download was offered, the request completed, or the request failed.

**Current shape:** Each fetch session owns its own event queue.

**Delivery model:** The caller submits a request, receives an accepted response, then polls for queued events.

**Memory model:** The queue is fixed-size, which keeps event delivery bounded and predictable.

**Main weakness:** When the queue fills, new events can be dropped without telling the caller.

| Area | Current behavior | Audit note |
|---|---|---|
| Queue ownership | Each session owns its own event queue | Events are scoped to a session |
| Queue size | Fixed at 64 events | Bounded, but can fill under load |
| Poll size | Polling returns up to 8 events | Predictable response size |
| Event types | Headers, body chunks, redirects, policy blocks, TLS state, downloads, complete, errors | Covers the main fetch lifecycle |
| Overflow behavior | Full queue drops new events | Loss is silent |
| Loss marker | No explicit loss marker yet | Caller cannot tell the stream is incomplete |
| Loss counter | No visible dropped-event count yet | No recovery signal |
| Audit coverage | No direct overflow audit record yet | Event loss is not evidence-visible |
| Subscription behavior | Polling works with session id and capability | Subscription semantics need clarification |

The current design is intentionally bounded. That is the right direction for a kernel service, because one fetch request should not be able to grow memory without limit. The tradeoff is that a bounded queue needs a clear overflow policy. Right now, the queue can fill up, especially when a large response produces many body events, and the service does not yet tell the caller when that happens.

The main issue is silent loss. If the session event queue is full, the new event is simply not added. There is no marker saying that the stream was truncated, no count of how many events were lost, and no audit record showing that overflow happened. That means the caller can receive an incomplete event stream and still have no way to know that the stream is incomplete.

**Why this matters:** Fetch events are not just UI updates.

**Security relevance:** A lost TLS event, policy block, redirect, or error can change how the caller understands the request.

**Correctness relevance:** A lost completion event can make a finished request look unfinished.

**Audit relevance:** A missing overflow record makes the fetch history look cleaner than it really was.

The highest-pressure case is body streaming. Body chunks can arrive frequently, especially for larger resources, and they can fill the queue before the caller has time to drain it. If body chunks fill the queue, more important terminal or security-related events can be dropped behind them. The current event queue does not reserve space for these higher-importance events and does not treat body chunks differently from policy blocks, TLS state, errors, or completion.

The polling model is simple and useful, but it needs a way to report loss. A poll that returns no events currently only means the queue is empty at that moment. It does not prove that no events were dropped earlier. For a normal application queue, that might be tolerable. For a kernel fetch service, the event stream should be honest about whether it is complete.

**Needed behavior:** If events are lost, the caller should be told.

**Minimum fix:** Add an event-loss marker.

**Better fix:** Track how many events were lost and report that count.

**Best direction:** Report loss to the caller and also record it in the audit log.

The service should eventually add an explicit event-loss marker. If the queue overflows, the session should remember that loss happened. When the caller polls again, the caller should receive a clear event saying that some fetch events were dropped. Ideally, the marker should include a count of how many events were lost. If the service can connect the loss to a request, it should include that request. If it cannot, it should still report the loss at the session level.

Overflow should also become audit-visible. Losing events affects the reliability of the fetch history, so it should not only be a client-facing detail. The audit log should record that a session experienced event queue overflow. That gives the system a way to explain why a client-side event stream may be incomplete.

The service also needs to decide whether all events are equally droppable. Body data is different from a TLS failure, a policy block, or a completion event. A mature design may reserve space for terminal and security-relevant events, drop body chunks first under pressure, or fail the request if the service cannot safely represent the event stream. The important part is that the behavior should be deliberate and documented.

**Possible mature policies:** Reserve space for security and terminal events.

**Alternative policy:** Drop body chunks before dropping policy, TLS, error, or completion events.

**Strict policy:** Treat event overflow as a request failure when the stream can no longer be represented honestly.

There is also a smaller semantic issue around subscription. The service has subscribe and unsubscribe operations, but polling can still drain events as long as the caller has the session id and capability. That may be fine if subscription is meant for future push or wakeup behavior. If subscription is supposed to control access to events, then polling should enforce it. The README should make that distinction clear.

The current event model is a good alpha foundation: per-session queues, fixed-size batches, bounded memory, and a straightforward polling API. The missing maturity layer is loss evidence. The caller should know when the event stream is incomplete, and the audit log should know when overflow happened.

### Event queue ownership and depth

Each fetch session owns its own event queue. Events are not stored in one shared global stream, and they are not broadcast across sessions. A response event belongs to the session that created the request, which keeps fetch state scoped to the session that owns it. That is the right basic model for Oreulius because fetch activity should stay tied to the session, policy, cookies, cache state, downloads, and storage context that produced it.

**Ownership model:** Events are owned by the fetch session.

**Queue location:** The event queue lives inside the browser session state.

**Isolation goal:** One session should not be able to drain or observe another session’s events.

**Current authority check:** Polling requires the session id and local capability token.

**Remaining authority gap:** Polling does not yet verify authenticated caller identity against the stored session owner.

The queue is bounded at a fixed depth. This keeps the event system predictable and prevents a large or hostile response from growing memory without limit. That matters because body chunks, redirects, errors, headers, and download events all pass through the same event delivery path. Without a fixed queue depth, a slow or stalled caller could let events pile up indefinitely.

| Area | Current behavior | Audit note |
|---|---|---|
| Queue owner | Each session owns its own event queue | Correct session-local shape |
| Queue depth | Fixed at 64 events per session | Bounded, predictable memory use |
| Poll batch | Up to 8 events returned per poll | Caller drains queue in small batches |
| Event storage | Events are stored inside BrowserSession | Event state is tied to session state |
| Queue sharing | No shared global event stream | Reduces cross-session exposure |
| Overflow behavior | New events are dropped when full | Needs loss evidence |
| Priority model | No event priority yet | Body chunks can crowd out terminal events |
| Caller binding | Capability token gates polling | Needs authenticated caller check later |

The fixed depth is a good kernel-side constraint, but it creates pressure when a response produces more events than the caller drains. A large response can generate many body chunks, and those chunks can consume the same queue space needed for headers, policy blocks, TLS state, download offers, errors, and completion. The queue currently treats these events equally. That means a high-volume body stream can compete with events that are more important for correctness and security.

The queue depth should therefore be treated as a security-relevant design parameter, not just a capacity constant. Sixty-four events may be enough for ordinary responses, but it is still possible for one request to fill the queue before polling catches up. Since polling returns only a small batch at a time, the service needs clear behavior for what happens under sustained event pressure.

**Depth concern:** A fixed-depth queue protects memory, but it also creates overflow cases.

**Streaming concern:** Body chunks can be frequent enough to fill the queue.

**Correctness concern:** Completion or error events can be lost if the queue is already full.

**Security concern:** Policy, redirect, or TLS events can be lost without caller-visible evidence.

**Audit concern:** Overflow is not currently represented as an audit-visible event.

The current ownership model is strong enough for an alpha design because event state is scoped to a session and polling requires session authority. The depth model is also sensible because it bounds memory. The missing maturity layer is a clearer policy for event pressure. The service should eventually define whether all events use the same queue, whether some events are protected from dropping, whether body chunks are lower priority, and whether overflow should create a loss marker or fail the request.

A mature version should keep the per-session queue, but add explicit loss behavior. If the queue reaches capacity, the session should remember that the event stream is no longer complete. The next poll should report that loss, ideally with a dropped-event count. The audit log should also record that overflow occurred, because an incomplete event stream affects the reliability of both debugging and security review.

The clean direction is to keep ownership session-local, keep queue depth bounded, and make overflow honest. The queue should not grow without limit, but it also should not lose meaningful fetch history silently. Bounded memory and truthful delivery need to exist together.

### Polling model and event batches

The fetch service uses a bounded polling model for event delivery. A caller starts work through a request such as navigation, then retrieves the resulting fetch events through PollEvents. The response format is fixed: each poll can return up to 8 events and a count. Internally, those events come from the session-owned queue, which has a fixed depth of 64 events.

The polling path is simple. PollEvents first checks the session id and local capability token. If the capability check passes, the service finds the live session, drains up to 8 queued events, and returns them to the caller. This gives the fetch service predictable memory behavior because both the session queue and the poll response are bounded.

The main limitation is that polling only reports what remains in the queue. If events were dropped earlier because the session queue filled, the caller receives no signal that the stream is incomplete. A poll with zero events only means the queue is empty at that moment. It does not prove that no events were lost.

The subscription behavior also needs clearer semantics. Subscribe and Unsubscribe toggle a session flag, but PollEvents does not currently check that flag before draining events. That means event access is controlled by session id and capability, not by the subscription flag. This may be intentional if subscription is meant for future push or wakeup behavior, but the README should say that clearly. If subscription is intended to gate event access, PollEvents should enforce it.

The current polling model is a useful alpha shape because it is small, bounded, and easy to test. The next maturity step is to make event loss visible, clarify what subscription means, and eventually bind polling to authenticated caller identity once the IPC caller identity work is available.

### Current overflow behavior

The current overflow behavior is simple, bounded, and lossy. Each browser session owns a fixed event queue with room for 64 events. When the fetch service tries to enqueue a new event, the session checks whether the queue is already full. If it is full, the function returns immediately and the new event is discarded. There is no loss marker, no dropped-event counter, no request failure, and no audit record for the overflow.

**Current policy:** The event queue uses drop-new behavior when full.

**What that means:** Existing queued events stay in place, but any new event that arrives after the queue reaches capacity is discarded.

**Why it matters:** The discarded event may be ordinary body data, but it may also be a completion event, error, policy block, TLS state, redirect event, or download offer.

The queue implementation tracks a head, tail, and count. A successful enqueue writes the event at the tail, advances the tail, and increases the count. A failed enqueue does not change the queue. That keeps the structure stable, but it also hides loss from the rest of the service because enqueue does not return a success or failure result.

**Queue depth:** Each session can hold 64 queued events.

**Poll batch size:** PollEvents drains up to 8 events at a time.

**Resulting pressure:** A full queue takes several polls to drain, and new events can be lost while the caller is still catching up.

The drop-new policy has one useful property: it protects older queued events from being overwritten. If a caller is behind on polling, the earliest events remain available until drained. The cost is that newer events may contain the most important state. A request often becomes most meaningful at the end, when it completes, fails, redirects, gets blocked, or offers a download. The current queue does not treat those later terminal or security-relevant events differently from ordinary body chunks.

The navigation path uses the same enqueue behavior in several places. Cache hits enqueue headers, an optional body chunk, and completion. Normal fetch work first collects events into a fixed local event array, then transfers each event into the session queue. Redirect handling, redirect-disabled errors, and cross-origin redirect policy blocks also enqueue events into the same queue. In all of those paths, enqueue does not report whether the event was actually stored.

**Silent failure point:** The service calls enqueue, but does not know whether the event entered the queue.

**Service impact:** Higher-level fetch code cannot respond to overflow because the queue hides it.

**Caller impact:** PollEvents can return a normal-looking batch even if earlier events were dropped.

The audit layer does not currently define a dedicated event-overflow record. It records session lifecycle events, navigation activity, fetch completion, policy blocks, TLS events, download events, cache hits and misses, aborts, redirects, content filtering, and internal errors. Event queue overflow is not one of the recorded audit classes. That leaves a gap between what happened in the event stream and what the audit log can later explain.

**Audit gap:** Event loss is not currently recorded.

**Evidence problem:** A session can lose client-facing events without leaving a clear audit trail.

**Debugging problem:** A caller may see an incomplete stream while the audit log never says the stream overflowed.

The highest-risk overflow scenario is a body-heavy response. BodyChunk events can arrive repeatedly and fill the queue. Once the queue is full, later events are dropped. If the later event is another body chunk, the caller loses response continuity. If the later event is Complete or FetchError, the caller loses the terminal state. If the later event is PolicyBlocked, TlsState, Redirect, or DownloadOffered, the caller loses a security or decision point.

Cache hits have a smaller but still important version of the same problem. On a cache hit, the service enqueues headers, a body chunk if body data exists, and complete. If the queue is already near capacity, any part of that sequence can be dropped. The service can still return RequestAccepted and audit a cache hit, while the caller receives only part of the event sequence or none of it.

Redirect handling has the same weakness. Redirect-disabled and cross-origin redirect-block paths enqueue terminal or policy-relevant events after the fetch outcome is known. If the queue is full at that moment, the immediate caller may never receive the event that explains why the redirect did not proceed. The audit log may record an internal error or policy block, but the event delivery path remains incomplete.

**Body-heavy response risk:** Body chunks can fill the queue before terminal events arrive.

**Cache-hit risk:** Headers, body, or completion from a cached response can be dropped independently.

**Redirect risk:** The event explaining a blocked or disabled redirect can disappear if the queue is full.

**Terminal-event risk:** Completion and failure events are not protected from overflow.

The current overflow behavior should be documented as alpha best-effort event delivery. It is memory-safe and bounded, but not yet evidence-complete. The design protects the kernel from unbounded event growth, but it does not yet protect the caller from silent loss.

The cleanest next step is to make enqueue return a delivery result. Once the service can tell that an event was not stored, it can update a per-session lost-event counter, emit an event-loss marker on the next poll, and record overflow in the audit log. That keeps the bounded-memory model while making event loss explicit. Later, the service can decide whether terminal and security-sensitive events deserve reserved space, priority delivery, or request failure when they cannot be represented safely.

**Immediate improvement:** Make enqueue report whether the event was stored.

**Client-facing improvement:** Add an event-loss marker.

**Audit improvement:** Add an event queue overflow audit record.

**Policy improvement:** Decide whether terminal and security-relevant events need reserved space or priority.

**Long-term goal:** Keep the queue bounded while making event loss visible, explainable, and testable.

### Explicit event-loss markers

The current fetch event protocol does not define an event-loss marker. FetchEvent includes headers, body chunks, redirects, policy blocks, TLS state, download offers, download completion, completion, and fetch errors, but it has no variant that tells the caller that events were dropped from the stream. PollEvents returns up to 8 events and a count, but that response only describes what was successfully stored in the queue and then drained. It does not describe what failed to enter the queue earlier.

**Current event model:** FetchEvent represents fetch lifecycle events, but not event-stream integrity.

**Missing marker:** There is no event type for EventLost, EventOverflow, QueueOverflow, or any equivalent loss signal.

**Caller impact:** A caller can poll normally and still not know that part of the stream was discarded.

The missing marker matters because the session queue already has a silent overflow path. Each session can hold 64 events. When the queue is full, enqueue returns immediately and drops the new event. Since enqueue returns no success or failure value, the service layer cannot tell whether the event was delivered into the queue. That makes it impossible for the current service code to emit a fallback marker after a failed enqueue, increment a counter, or change the request outcome.

**Queue behavior:** The queue uses drop-new behavior when full.

**Hidden failure:** The enqueue function does not report whether storage succeeded.

**Protocol gap:** PollEvents cannot report loss because no loss state is tracked and no loss event exists.

This creates a split between bounded memory and honest delivery. The bounded queue protects the kernel from unbounded growth, which is necessary. The problem is that bounded delivery becomes best-effort without being declared as such to the caller. A mature fetch service can keep the same memory limits, but it needs a way to say that the event stream is no longer complete.

The cleanest design is to add a first-class loss marker to the fetch event stream. That marker should be delivered through the same PollEvents path as other events, because event loss is part of the caller-visible fetch history. It should not be hidden only in the audit log. The caller needs to know when it can no longer trust the event stream as complete.

**Marker purpose:** Tell the caller that one or more fetch events were dropped.

**Minimum payload:** A dropped-event count.

**Better payload:** A dropped-event count plus request id when the loss can be attributed to one request.

**Fallback payload:** Session-level loss when request-level attribution is not possible.

The session should also track loss state separately from the normal queue. If the queue is already full, the service cannot rely on enqueuing the loss marker immediately, because that marker could be dropped too. The session needs a small out-of-band counter or pending-loss flag that survives overflow. On the next poll, the service can synthesize the loss marker before draining ordinary events, or reserve space in the returned batch for it.

**Important detail:** A loss marker should not depend on the same full queue that caused the loss.

**Practical fix:** Store dropped-event count outside the event queue.

**Polling fix:** Emit the marker during PollEvents before ordinary queued events.

That design also avoids a second-order overflow bug. If every failed enqueue tries to enqueue a loss marker into the same full queue, the marker will fail too. The loss marker should be generated from session metadata, not inserted as just another ordinary event during the overflow moment. Once the caller receives the marker, the counter can be reset or reduced according to the number of reported losses.

The marker should also be careful about event ordering. If the service reports a loss marker before queued events, it tells the caller that the stream had already become incomplete before the events it is about to read. If it reports the marker after queued events, the caller may process a partial stream before learning that it was partial. For a kernel fetch service, reporting loss early is usually cleaner because it changes how the caller should interpret the batch.

**Ordering choice:** Report loss before ordinary events in the next poll.

**Reason:** The caller should know the batch belongs to an incomplete stream before trusting it.

**Reset behavior:** Clear the pending-loss state only after reporting it.

The code also needs audit support for this. The audit module currently records many fetch-relevant events, but it does not have a queue-overflow audit kind. Event-loss markers should be caller-visible, while audit overflow records should be system-visible. These are related but not interchangeable. The caller needs immediate stream integrity information, while the audit log needs durable evidence that the session lost events.

**Client-visible path:** Event-loss marker through PollEvents.

**Audit-visible path:** Dedicated audit record for event queue overflow.

**Why both matter:** The caller needs to react now, and the system needs evidence later.

There is also a question of what to do with terminal and security-relevant events. A loss marker tells the caller that something was dropped, but it does not fully solve the problem of dropping completion, errors, policy blocks, TLS failures, redirect denials, or download offers. The marker makes the loss honest. A later hardening step should decide whether those events receive priority, reserved space, or request-failure behavior when the queue is under pressure.

**Loss marker limitation:** It reports that loss happened, but it does not recover the lost event.

**Security concern:** Losing a policy block or TLS failure still matters even if loss is reported.

**Future policy:** Terminal and security-relevant events may need priority or reserved capacity.

The current implementation is therefore missing the main mechanism that would make bounded event delivery trustworthy. The service already has a clear polling path and a fixed queue, but without explicit loss markers, overflow creates silent gaps in the caller’s view of the request. The next step is not to make the queue unbounded. The next step is to keep the bounded design while making loss visible, counted, auditable, and testable.

### Overflow audit and recovery expectations

The current fetch service has bounded event delivery, but it does not yet have a complete recovery story for event overflow. Each session owns an event queue, and polling drains that queue in small batches. When the queue fills, new events are dropped silently. The service keeps memory bounded, but the caller does not receive proof that the stream became incomplete, and the audit log does not record a dedicated overflow event.

**Current behavior:** Overflow is handled locally inside the session queue.

**Audit gap:** The audit log records many fetch lifecycle events, but it does not currently define a specific queue-overflow event.

**Recovery gap:** The caller has no protocol-level instruction for what to do after event loss, because event loss is not reported yet.

The most important audit problem is that overflow changes the meaning of the event stream. A caller may poll and receive a normal-looking batch, but that batch may only be the surviving part of a larger sequence. If the dropped event was a body chunk, the response data became incomplete. If the dropped event was completion, the request may appear to hang. If the dropped event was a policy block, TLS failure, redirect denial, fetch error, or download offer, the caller may miss the event that explains the security decision.

Audit and recovery should be treated as two separate responsibilities. The audit log should preserve evidence that overflow happened, even if the caller never polls again. The event stream should tell the caller that it cannot treat the delivered events as complete. One path explains the system later. The other lets the caller respond immediately.

**Audit expectation:** Overflow should produce a durable record with the session id and request id where possible.

**Client expectation:** The next poll after overflow should report that events were lost.

**Recovery expectation:** The client should treat the affected stream as degraded, incomplete, or failed according to the chosen policy.

The current service cannot implement that cleanly until the queue reports delivery failure. The enqueue path does not return a result, so higher-level code cannot tell whether headers, body chunks, completion, redirect events, policy blocks, or errors actually entered the queue. That makes recovery decisions impossible at the service layer. A mature path should make event delivery observable inside the service, then connect failed delivery to a loss counter, a loss marker, and an audit record.

The recovery policy needs to distinguish between event classes. Losing ordinary body data is a stream integrity problem. Losing completion or fetch error is a terminal-state problem. Losing a policy block, TLS failure, redirect denial, or download offer is a security and decision visibility problem. A single overflow marker can tell the caller that loss occurred, but the service still needs a rule for whether some classes of loss should force the request into a failed state.

**Recoverable loss:** Some body loss may be recoverable by refetching, closing the session, or restarting the request.

**Terminal loss:** Losing completion or error state should not leave the request ambiguous.

**Security-relevant loss:** Losing policy, TLS, redirect, or download-decision events should either preserve a stronger event path or force a visible failure.

The audit log should record overflow even if the request continues. It should also record the reason when overflow forces a request failure. If the service can attribute the lost event to a request, the audit entry should include that request. If the service cannot attribute loss precisely, it should still record session-level overflow. Silence is the part that needs to disappear.

Recovery should also avoid pretending that polling fixes the problem. Polling drains what survived. It does not reconstruct what was dropped. Once overflow happens, the service should tell the caller that the stream is incomplete and define what the caller should do next. For a browser-facing client, that might mean refetching the resource, closing the session, showing a degraded response, or treating the request as failed.

The expected mature behavior is straightforward: keep the queue bounded, but make overflow visible. The session should count dropped events outside the queue, PollEvents should surface a loss marker before ordinary events, and the audit log should record overflow as evidence. If the lost event belongs to a class that cannot safely disappear, the request should fail in a visible way rather than appearing quiet or partially successful.

## Fetch URL parsing, normalization, and size limits

The fetch service has a compact URL parser built around fixed-size storage. A parsed URL stores its scheme, host, port, path, and query in bounded fields, which fits the kernel design: no heap allocation, no unbounded string growth, and no dependency on a browser-grade URL library. The parser accepts HTTP and HTTPS URLs, rejects unsupported schemes, and treats the origin as scheme plus host plus port.

**Current URL limit:** The service defines a maximum raw URL size and separate fixed limits for host, path, and query storage.

**Supported forms:** The parser accepts HTTP and HTTPS URLs with a host, optional port, optional path, and optional query.

**Security unit:** The parsed origin is built from scheme, host, and port.

The fixed-buffer model is a good foundation for a kernel service, but the parser needs stricter fail-closed behavior around fields that change the meaning of a request. The host path is already stricter than the path and query paths. An empty host is rejected, and a host longer than the host buffer is rejected. That is the right behavior because the host participates in origin policy, cache keys, cookie scope, TLS hostname validation, and audit meaning.

The path and query handling are weaker. The parser copies the path up to the path buffer size and copies the query up to the query buffer size. It does not reject overlong path or query input. That makes the accepted URL different from the caller’s original URL whenever those fields exceed the fixed limits. For a kernel fetch boundary, silent truncation is a correctness problem because the service may check, cache, audit, or request a shortened version of what the caller supplied.

**Host behavior:** Empty and oversized hosts fail parsing.

**Path behavior:** Overlong paths are truncated to the path buffer size.

**Query behavior:** Overlong queries are truncated to the query buffer size.

**Audit concern:** A truncated URL can make logs and policy decisions describe a different effective request than the caller intended.

Port parsing also needs a stricter rule. The parser recognizes a port by looking for the last colon in the authority section. If the bytes after that colon do not parse as a valid 16-bit decimal port, the parser currently falls back to the scheme’s default port. That makes malformed explicit ports look like omitted ports. A URL with a nonnumeric, empty, or out-of-range port should not quietly become port 80 or port 443. It should fail parsing, because an explicit malformed port is different from no port at all.

**Current port behavior:** Missing ports use the scheme default.

**Problem case:** Malformed explicit ports also fall back to the scheme default.

**Safer behavior:** Missing ports should default, malformed explicit ports should fail.

The parser also performs only limited normalization. It recognizes lowercase HTTP and HTTPS scheme prefixes, copies the host bytes as supplied, defaults an empty path to slash, and separates the query at the first question mark. It does not lowercase hosts, does not normalize percent encoding, does not resolve dot segments, and does not document whether fragments, userinfo, IPv6 literals, or unusual authority forms are supported. Some of that may be intentional for an alpha kernel service, but the behavior should be explicit because different subsystems may later compare URLs, origins, cache entries, and audit records.

The biggest maturity requirement is consistency. The same accepted URL representation should drive origin checks, cache keys, cookies, redirects, navigation history, audit records, and transport. If one subsystem uses the raw URL while another uses the truncated parsed fields, the service can make contradictory decisions. A fetch boundary does not need to implement every browser URL edge case immediately, but it does need one clear rule for what it accepts, what it rejects, and what representation becomes authoritative after parsing.

A mature version should keep the fixed-size design and make the parser stricter. Unsupported schemes should fail. Empty hosts should fail. Oversized hosts, paths, and queries should fail rather than truncate. Malformed explicit ports should fail instead of falling back. Normalization should be documented before other subsystems rely on it. That gives the fetch service a bounded URL model without letting malformed or overlong input quietly change meaning at the boundary.

### Supported URL forms

The fetch parser currently accepts a narrow, intentional set of URL forms. It is built for absolute web requests, not for the full browser URL universe. In practice, that means HTTP and HTTPS URLs with a host, an optional port, an optional path, and an optional query string.

The narrow surface is a strength at this stage. The fetch service lives in the kernel, so every accepted URL form becomes part of policy checks, origin identity, cache behavior, cookie scope, transport routing, audit history, and navigation state. A smaller accepted surface gives the service fewer ambiguous cases to explain and fewer malformed inputs to accidentally reinterpret.

**Accepted shape:** An absolute HTTP or HTTPS URL with a host.

**Optional parts:** The URL may include a port, path, and query string.

**Default path:** If no path is supplied, the parser uses slash.

**Default port:** If no port is supplied, the parser uses the scheme default.

**Origin identity:** The service builds the origin from scheme, host, and port.

The parser does not currently need to act like a browser-grade URL engine. Relative URLs, scheme-relative URLs, fragments, userinfo, file URLs, data URLs, blob URLs, and unusual authority forms should remain outside the supported contract unless the README deliberately brings them in. That keeps fetch focused on its job: controlled intake of web resources through a predictable kernel representation.

The important line is between missing fields and malformed fields. A missing port can safely fall back to the default for HTTP or HTTPS. A malformed explicit port should fail. A missing path can become slash. An oversized path or query should not silently become a shorter request. The parser should either accept the URL exactly under the documented rules or reject it before policy, cache, transport, or audit code sees it.

The supported forms should stay conservative until normalization rules are fully defined. Host case handling, percent encoding, dot segments, fragments, IPv6 literals, and userinfo all change how a URL should be compared or routed. Until those rules are explicit, the safest contract is simple: accept absolute HTTP and HTTPS URLs in the documented shape, reject everything else, and treat the parsed representation as the only authority for downstream fetch behavior.

### Scheme, host, port, path, and query parsing

The current parser breaks a URL into five main pieces: scheme, host, port, path, and query. That gives the fetch service a compact representation that other parts of the system can use for origin checks, cache lookup, cookie scope, transport routing, audit records, and navigation history. The parser keeps each piece inside fixed-size storage, which matches the kernel-side design goal of bounded memory.

The scheme handling is intentionally narrow. The parser accepts lowercase HTTP and HTTPS forms and rejects anything else at the first step. That is a good starting point because unsupported schemes should not reach policy, cache, transport, or storage code as if they were ordinary web requests. The README should make clear whether uppercase or mixed-case schemes are intentionally rejected or whether later normalization will accept them.

**Scheme parsing:** The parser recognizes HTTP and HTTPS URL prefixes.

**Unsupported schemes:** Anything outside those forms fails parsing before the rest of the URL is processed.

**Case behavior:** The current accepted shape is lowercase scheme text, so case normalization should be documented before broader scheme matching is added.

Host parsing happens after the scheme is removed. The parser treats everything before the first slash as the authority section, then separates host and port inside that authority section. Empty hosts fail, and hosts longer than the fixed host limit fail. That is the right fail-closed behavior because host identity affects the most security-relevant parts of the fetch service, including origin identity, TLS hostname checks, cookie scope, cache scope, and audit meaning.

Port parsing needs a stricter rule. If the authority contains a colon, the parser treats the bytes after the last colon as the port. If those bytes parse as a valid decimal 16-bit port, that value becomes the URL port. If parsing fails, the current behavior falls back to the scheme default. That makes malformed explicit ports behave like omitted ports, which is not the right distinction for a fetch boundary. A missing port can default to 80 or 443. An explicit bad port should fail.

**Host parsing:** The parser requires a non-empty host and rejects hosts that exceed the host limit.

**Port parsing:** Missing ports use the scheme default.

**Port weakness:** Malformed explicit ports can currently fall back to the scheme default instead of failing.

Path parsing is simpler. The parser separates the path from the authority at the first slash. If no path exists, it stores slash as the effective path. If a path exists, it copies the path into a fixed path buffer. The current behavior shortens overlong paths to fit that buffer rather than rejecting them. That keeps memory bounded, but it can change the effective request. For a security-sensitive service, an oversized path should fail rather than quietly become a shorter path.

Query parsing follows the path split. The parser separates the query at the first question mark inside the path and query portion. It copies the query into a fixed query buffer and records its length. Like path handling, overlong query input is currently shortened to fit the buffer. That creates the same correctness issue: the accepted parsed URL may no longer match the caller’s original request.

**Default path:** A URL with no path becomes slash.

**Path limit behavior:** Overlong paths are currently shortened to fit the fixed buffer.

**Query limit behavior:** Overlong queries are currently shortened to fit the fixed buffer.

**Safer rule:** Oversized path and query fields should fail parsing instead of producing a different effective URL.

The parser does not yet define a full normalization contract for host case, percent encoding, dot segments, fragments, userinfo, IPv6 literals, or unusual authority forms. That is acceptable for an alpha parser as long as the README states the supported shape clearly. The important rule is that every accepted URL should have one authoritative parsed representation, and every subsystem should use that same representation. Origin policy, redirects, cache, cookies, audit, navigation history, and transport should not each invent their own interpretation of the original URL.

The parser is already close to the right kernel shape: small, fixed-size, narrow, and easy to reason about. The main maturity step is to make malformed and oversized input fail closed. The service should accept a URL only when it can represent the scheme, host, port, path, and query without changing their meaning.

### Fixed-size URL field limits

The fetch service uses fixed-size URL fields because it is built for kernel-side parsing. A URL is not stored as an unbounded string. It is broken into bounded pieces: host, path, and query, with each piece copied into a fixed buffer and tracked by a length field. That design keeps parsing predictable and avoids heap-dependent behavior at the fetch boundary.

**Raw URL limit:** The service defines a maximum raw URL size.

**Host limit:** The host field has its own fixed maximum length.

**Path limit:** The path field has its own fixed maximum length.

**Query limit:** The query field has its own fixed maximum length.

The fixed-field model is the right direction, but every field needs the same fail-closed rule. The host already follows that pattern: an empty host fails, and a host that exceeds the fixed host limit fails. Path and query should be brought into the same model. Today, overlong path and query values are shortened to fit their buffers. That preserves memory safety, but it can change the effective request.

A kernel fetch service should not quietly turn a long URL into a shorter URL. The parsed URL becomes the representation used by origin policy, cache identity, cookie scope, transport routing, audit records, and navigation history. If the parser truncates a path or query, downstream code may make decisions about a request that is not the same request the caller supplied.

**Correct host behavior:** Empty and oversized hosts fail.

**Weak path behavior:** Overlong paths can be shortened instead of rejected.

**Weak query behavior:** Overlong queries can be shortened instead of rejected.

**Safer rule:** If a field cannot be represented exactly, parsing should fail.

The README should document the limits directly. Developers should not need to read the source to know how large a URL, host, path, or query can be. The documentation should also state that these limits are part of the security contract, not just implementation details. They control what the kernel will accept at the boundary where public web input becomes internal fetch state.

The mature behavior should be simple. Accept a URL only when every field fits the documented limits without changing meaning. Reject overlong fields before origin checks, cache lookup, cookie handling, audit logging, or transport setup. That keeps the fixed-buffer design while preventing silent conversion of malformed or oversized input into a different effective request.

### Invalid port and malformed authority handling

The parser currently treats the authority section as the part of the URL between the scheme and the first slash. It then looks inside that authority section for the last colon. If there is no colon, the URL uses the default port for the scheme. If there is a colon, the parser treats the bytes after it as the explicit port and the bytes before it as the host.

That basic shape works for simple HTTP and HTTPS URLs, but the error handling around explicit ports needs to become stricter. A missing port and a malformed port are not the same thing. A missing port can safely use the default for the scheme. A malformed explicit port should fail because the caller supplied authority data that the parser could not represent correctly.

**Current missing-port behavior:** A URL with no explicit port uses the default port for HTTP or HTTPS.

**Current explicit-port behavior:** A URL with a parseable numeric port stores that port.

**Current weakness:** A URL with an invalid explicit port can fall back to the default port.

**Safer rule:** Default ports should apply only when the port is omitted, not when the caller supplied a malformed port.

The malformed-port behavior can change the effective URL. A caller might provide a URL with an empty port, nonnumeric port, or out-of-range port, and the parser can still produce a valid URL by using the scheme default. That converts a bad authority section into a normal-looking request. For a kernel fetch boundary, that is too permissive. Invalid authority should stop at parsing before origin policy, cache lookup, transport routing, audit records, or navigation history see it as accepted input.

Malformed authority handling also needs explicit rules for cases beyond ordinary host and port. Userinfo, extra separators, unsupported IPv6 bracket syntax, empty authorities, ambiguous colon placement, percent-encoded authority bytes, and unusual host forms should not accidentally pass as ordinary host data. If the fetch service does not support those forms yet, they should fail under a documented rule.

**Empty authority:** A URL without a usable host should fail.

**Empty explicit port:** A colon with no port bytes should fail.

**Nonnumeric explicit port:** A port containing non-digit bytes should fail.

**Out-of-range explicit port:** A port outside the valid range should fail.

**Unsupported authority forms:** Userinfo, unsupported IPv6 syntax, and ambiguous separators should fail unless deliberately supported later.

The host field already follows a stricter pattern. Empty hosts fail, and hosts that exceed the fixed host limit fail. Port and authority handling should follow the same philosophy. The parser should accept only authority sections that it can represent exactly as host plus port. If the authority is ambiguous or malformed, the service should reject the URL instead of normalizing it into a different request.

The downstream impact is important. The parsed authority feeds origin identity, TLS hostname expectations, cookie scope, cache identity, transport routing, navigation history, and audit meaning. If malformed authority becomes a default-port URL, later subsystems will treat it as a clean request even though the original input was not clean. That makes debugging harder and weakens the boundary between raw caller input and accepted fetch state.

The mature behavior should be direct: accept omitted ports, accept valid explicit decimal ports, reject malformed explicit ports, and reject authority forms the parser does not intentionally support. That keeps the URL parser narrow, predictable, and honest about what it can safely represent.

### URL normalization and fail-closed behavior

URL normalization is not a cosmetic parser feature in this service. It determines whether two byte strings refer to the same origin, the same cache entry, the same cookie scope, the same TLS peer, and the same audited request. Once the kernel accepts a URL, every later decision needs to operate on one authoritative representation. If parsing, policy, transport, history, and audit interpret the input differently, the service can approve one resource, connect to another effective target, and record a third description of what happened.

The current implementation does not yet provide that invariant. It recognizes only lowercase HTTP and HTTPS prefixes, preserves host bytes exactly as supplied, defaults an absent path to slash, and separates the query at the first question mark after the authority. It does not lowercase DNS names, remove dot segments, normalize percent encoding, classify fragments, reject control bytes, or define an ASCII and internationalized-domain policy. It also has no explicit canonical serialization method. Different parts of the service therefore consume different projections of the request: origin code compares parsed scheme, host, and port; transport uses parsed host, port, path, and query; cache code derives a bounded digest from parsed fields; navigation history serializes parsed fields; redirect events reconstruct a partial URL; and audit calls often receive short labels or raw redirect bytes.

Host case is the clearest example of the resulting inconsistency. DNS hostnames are case-insensitive, and the denylist already compares them without ASCII case sensitivity, but origin equality compares the stored host bytes exactly. HTTPS URLs for the same DNS name with different letter case can therefore be treated as different origins even though transport resolves them to the same host. Cache identity and history can preserve the same artificial distinction. A production parser should normalize DNS hostnames to lowercase ASCII before origin creation, policy comparison, cache lookup, TLS hostname use, and serialization. If internationalized names are supported later, the service needs one validated ASCII-compatible conversion path rather than accepting arbitrary non-ASCII host bytes.

Path handling presents a different problem. Paths are generally case-sensitive and cannot be lowercased, but dot segments and percent-encoded octets can produce multiple textual forms with related or equivalent routing behavior. Normalization must remain conservative because decoding reserved characters can change path boundaries and server semantics. The service should validate percent triplets, reject malformed encodings, remove literal dot segments according to a documented algorithm, and preserve encoded reserved characters unless the URL contract explicitly permits a safe normalization. It should never decode an encoded slash or question mark into a structural delimiter during a generic normalization pass.

Queries require even less transformation. Query syntax belongs largely to the remote application, so reordering parameters, converting plus signs, decoding reserved characters, or changing percent-encoding case can alter application behavior. The safe kernel contract is to validate that the query is representable and contains no forbidden bytes, then preserve its accepted bytes exactly. Canonical origin identity does not include the query, while cache and request identity do, so the service must keep those concepts separate rather than applying one broad equivalence rule to every URL component.

Fragments should not enter the transport request because HTTP clients do not send them to the server. The current parser has no fragment rule, which means a fragment can remain inside the path or query and affect transport and cache identity. Production behavior should either reject fragments at this kernel boundary or parse and remove them before request construction while retaining any client-facing navigation state outside the fetch identity. Rejection is the simpler fail-closed choice for the current narrow URL model.

Authority parsing needs the same discipline. Userinfo, unbracketed multiple-colon forms, unsupported IPv6 literals, empty explicit ports, nondecimal ports, and ports outside the valid range should fail before origin policy or DNS resolution. The parser currently treats the last colon as a port separator and falls back to the scheme default when the explicit port is invalid. It can also admit bytes such as an at sign as part of the host because it does not validate the authority grammar. That behavior converts malformed authority into trusted structured state. A missing port may use the scheme default; a supplied port that cannot be parsed exactly must reject the URL.

Size handling is part of normalization because truncation is an implicit and unsafe rewrite. The parser rejects an oversized host but shortens oversized paths and queries. It also does not enforce the declared raw URL maximum inside the parser. This preserves memory safety while violating request identity. A path or query that does not fit can become a different resource, collide with another cache key, produce misleading history, and make audit evidence describe the truncated request rather than the input presented by the caller. Production parsing must reject the raw URL or any component that exceeds its limit before constructing a usable URL.

The current redirect path amplifies these weaknesses. A redirect location is copied into a fixed buffer, but the service only parses it when cross-origin following is disabled. If parsing fails in that branch, the code does not block the redirect for invalidity; it proceeds to audit and emit the raw location as though it were followed. The service does not actually reissue the request, does not resolve relative locations, does not apply the redirect policy checker, and does not run a normalized target through the full scheme, downgrade, origin, denylist, and size checks. A production redirect transition must parse or deliberately resolve the target, normalize it under the same rules as an initial navigation, reject any target that has no authoritative representation, and then repeat every policy decision before transport.

This area fits Oreulius’s design philosophy in structure but not yet in enforcement. The fixed arrays, narrow HTTP and HTTPS surface, explicit origin type, bounded cache key, and kernel-owned policy boundary all support deterministic memory use and constrained authority. Those choices keep URL handling reviewable and avoid importing a browser-sized parser into the trusted core. The implementation falls short where it silently recovers from malformed input or permits multiple internal meanings for one network target. Oreulius treats authority as explicit, bounded, and verifiable; URL identity needs the same treatment because a URL is the object over which fetch authority is exercised.

The production contract should be transactional. Parsing should either return a complete accepted URL with validated components and a canonical serialization, or return a typed failure without updating origin state, cache state, navigation history, cookies, audit success records, or transport state. Normalization must happen once, before policy, and the resulting value must be immutable for the lifetime of the request. Raw input may be retained separately for diagnostic evidence, but it must never compete with the accepted URL as a source of policy or routing decisions.

The error model also needs more precision than a single invalid URL response. Internal parser results should distinguish unsupported scheme, malformed authority, invalid host byte, unsupported host form, invalid port, oversized raw URL, oversized component, malformed percent encoding, forbidden control byte, unsupported fragment, and unsupported relative reference. The public protocol may collapse some classes when disclosure is undesirable, but policy and audit code need stable machine-readable reasons. Rejected input should be audited with bounded evidence or a digest so diagnosis does not require storing attacker-controlled URL text in full.

Production readiness requires focused tests around identity, not only successful parsing. Boundary tests should cover every component at its exact limit and one byte beyond it. Equivalence tests should prove that host case and default ports produce the chosen canonical origin, while distinct path and query bytes remain distinct where server semantics require it. Adversarial tests should cover control characters, embedded delimiters, malformed percent triplets, userinfo, empty and invalid ports, unsupported IPv6 forms, fragments, dot segments, relative references, and redirect targets. Cross-module tests should prove that origin checks, cache keys, TLS hostname selection, request construction, navigation history, redirect events, and audit evidence all derive from the same accepted URL.

The parser is therefore an alpha-quality bounded parser rather than a production URL authority layer. It has the correct memory shape and a deliberately small feature surface, but it is not fail-closed wherever interpretation affects identity. The required endpoint is not full browser compatibility. It is a smaller and stricter contract: accept only the URL forms Oreulius can represent exactly, canonicalize only where equivalence is unambiguous, preserve application-sensitive bytes, reject every ambiguous or lossy case, and make the resulting representation authoritative across the complete fetch lifecycle.

## Fetch redirect handling and cross-origin transition policy

Redirect handling crosses several fetch-service boundaries at once. The response parser decides whether a status code represents a redirect and extracts the Location header. The service then decides whether the client policy permits the transition, whether the target remains inside the allowed origin boundary, what event the caller receives, and what evidence enters the audit log. A production implementation must treat those steps as one state transition because a redirect changes the effective network target while preserving the authority and request context of the original navigation.

The current code has the pieces of that model but does not yet connect them into a complete redirect lifecycle. The status-code helper recognizes the conventional permanent, temporary, and method-preserving redirect codes. The fetch pipeline returns a redirect outcome when it finds a nonempty Location value. The public protocol can carry a redirect event, the request contains a maximum redirect count and a cross-origin-follow flag, the policy module contains a single-hop redirect checker, and the audit ring defines a followed-redirect record. Those components establish a bounded and reviewable shape that fits Oreulius.

The operational behavior is much narrower than those types and comments imply. One invocation of the fetch pipeline performs one network request and returns when it encounters a redirect. The service does not issue another request to the target, does not maintain a chain or hop count, and does not call the redirect checker. It emits a redirect event after limited policy handling and returns an accepted request response. Redirect following is therefore neither implemented internally nor clearly delegated to the client through a protocol that carries chain state. The existing RedirectFollowed audit name and the protocol comment that says the event is emitted before following overstate what the service actually does.

The production model should choose one owner for the redirect chain. A kernel-owned loop would preserve one request identity, maintain a bounded hop counter, resolve targets, repeat policy checks, apply method rules, and emit evidence for each transition. A client-mediated model would return a typed redirect decision and require a new navigation request, but it would need an unforgeable continuation context so the client could not reset the hop count or discard downgrade and provenance state. The existing design points more naturally toward a kernel-owned bounded loop because the service already owns origin policy, transport, cache state, TLS evidence, request events, and audit history.

Across either model, every redirect target must pass through the same accepted URL representation used for initial navigation. The service must resolve relative references if it supports them, reject malformed or unsupported locations, normalize the resulting target, enforce scheme and downgrade policy, compare origins, apply denylist and capability constraints, select cookies and cache state for the target, and only then connect or report a followed transition. No redirect should inherit trust merely because the first request passed policy.

### Redirect response detection

Redirect response detection begins with the HTTP status code. The status helper recognizes 301, 302, 303, 307, and 308. It does not classify 300, 304, 305, or 306 as redirects, which is a reasonable narrow contract for automatic navigation behavior. The fetch pipeline then looks up the first parsed Location header. If that value is present and nonempty after optional whitespace is removed, the location parser copies it into a fixed 2048-byte buffer and returns a redirect outcome containing the status and copied bytes.

This path is bounded and avoids allocation, but its validation is too weak for a trust-boundary decision. The Location parser does not parse a URL, resolve a relative reference, validate bytes, or reject overflow. It silently truncates values longer than its output buffer. The general header parser can also truncate every header value before redirect detection, so the Location value may already have been shortened to the response-header value limit before the location parser sees it. The resulting redirect target can therefore differ from the server-provided target without producing an error.

Malformed redirect responses also fall through inconsistently. If a recognized redirect status has no Location header, an empty Location header, or a Location line that was skipped by header parsing, the fetch pipeline treats the response as an ordinary final response and streams its body. That behavior can be valid for a response that is not automatically followed, but the service does not expose a typed distinction between a redirect status without a usable target and an ordinary non-redirect response. The caller receives headers and completion without evidence that redirect interpretation failed.

Duplicate Location headers are resolved by the generic first-match header lookup. The code does not reject conflicting values or record that duplicates existed. Since a redirect target controls the next authority boundary, production behavior should reject ambiguous duplicates rather than selecting one according to parser order. The parser should also prove that the entire header block terminated correctly before making any redirect decision; currently, an unterminated or maximum-sized header block can still be parsed from the bytes that were collected.

Method semantics are absent from detection and later handling. A 303 normally changes most methods to GET, while 307 and 308 preserve the method and body. Historical handling of 301 and 302 also requires an explicit service policy. The current outcome records only status and location, so it has enough evidence to make that decision later, but no code currently does so. Production detection should produce a validated redirect response object that retains the status, target, original method, and body-replay constraints for the transition layer.

### Redirect limit enforcement

The code defines redirect limits in three places. The request policy carries a caller-selected maximum, the session profile carries a maximum, and the policy module defines a hard maximum of ten. The service computes the smaller of the session and request values and stores it in the local profile passed to the fetch pipeline. That shape correctly expresses layered policy: a caller may request fewer redirects but should not be able to exceed the session or kernel ceiling.

The limit is not enforced. The fetch pipeline never reads the profile maximum during redirect handling. It has no redirect-count argument or loop state. The service checks only whether the original request policy set the maximum to zero. Any positive value, including one, five, or ten, follows the same path because the service emits one redirect event and stops. The policy checker accepts a redirect count and compares it only with the global maximum, but no caller invokes that function, and it does not use the effective per-session maximum.

The zero case is also semantically inaccurate. When redirects are disabled, the service emits a fetch error classified as too many redirects and audits an internal error labeled redirect-disabled. No redirect count was exceeded. A distinct redirect-not-followed or redirects-disabled result would preserve the difference between policy refusal and chain exhaustion. The response has already consumed network resources and received a valid redirect, so the event should also carry the target and status if policy permits that evidence to be disclosed.

Production enforcement needs request-owned chain state. The state should hold the current accepted URL, original URL, effective maximum, completed-hop count, visited-target evidence, current method, body replay status, and the security state inherited from earlier hops. The service should define whether the first redirect is hop one and reject before opening the connection that would exceed the maximum. A zero maximum should permit the initial request and refuse its first redirect. An exact-limit chain should complete its permitted transitions and reject the next one.

A numeric limit bounds work but does not explain loops. The service can stop all loops at the hop ceiling, yet retaining a bounded digest set of visited canonical targets would allow a typed redirect-loop result and clearer audit evidence. Both exhaustion and loop detection must terminate the request visibly, close transport state, emit a terminal event, and prevent a partial chain from being recorded as a successful navigation.

### Cross-origin redirect policy

The request policy contains a boolean that controls cross-origin following. When that flag is false, the service attempts to parse the Location bytes as an absolute URL, constructs origins for the source and target, and blocks the transition if exact origin equality fails. The block produces an origin-not-allowed event and a policy audit record. This is the only active redirect-origin check in the current service.

The check has two serious fail-open paths. It runs only when cross-origin following is disabled, and a target that fails URL parsing is not blocked. The service simply skips the comparison, records the redirect as followed, and emits the raw target. Relative redirects always fail the absolute URL parser, so they bypass the cross-origin check even though resolving them against the source would normally keep them same-origin. Malformed and unsupported targets bypass it for the same reason.

When cross-origin following is enabled, the redirect target does not pass through the session origin table at all. The service does not apply allowlist rules, top-origin policy, opaque-origin rejection, or same-site classification. The boolean therefore acts as broader authority than the rest of the origin model suggests. It permits the service to report any parseable or unparseable redirect target without consulting the registered per-session policy.

Exact origin comparison also inherits the URL parser’s normalization weaknesses. Host comparison is byte-sensitive, default and explicit ports are not canonically serialized, and malformed ports can fall back to defaults. Two DNS names differing only by ASCII case may appear cross-origin, while malformed authority can be converted into a normal-looking target. Redirect policy cannot be stronger than the URL identity on which it operates.

Production behavior should resolve and validate the target first, then classify the transition using the same origin implementation used by navigation and subresource checks. The effective rule should combine the request’s willingness to follow cross-origin redirects with the session’s allowlist and cross-origin authority. Request policy may narrow session authority but must never broaden it. Cookie selection, authorization headers, referrer evidence, cache lookup, and credential forwarding must be recomputed for every target rather than copied across the boundary.

The service should also distinguish same-origin, same-site, and cross-origin transitions in events and audit records even if policy ultimately allows them. That evidence matters because a redirect chain can cross several authorities before reaching its final resource. The final top origin and navigation history should change only after the terminal response succeeds, not when an intermediate redirect is observed.

### HTTPS-to-HTTP downgrade blocking

The policy module contains a single-hop check that rejects a transition from HTTPS to HTTP with the mixed-content reason. Its comment contains a contradictory phrase describing HTTP-to-HTTPS as a downgrade before correctly implementing the HTTPS-to-HTTP comparison. The implementation itself expresses the expected secure default, but the service never calls it.

The active redirect path therefore does not block transport downgrades. With cross-origin following enabled, an HTTPS response can point to an HTTP target and the service will audit and emit that target without a downgrade decision. With cross-origin following disabled, the origin comparison will usually block the transition because the scheme changed, but the reported reason is origin-not-allowed rather than a typed transport-security downgrade. If target parsing fails, even that incidental protection disappears.

This distinction matters because origin policy and transport-security policy protect different properties. A same-host downgrade changes the origin because the scheme changes, but its primary security meaning is loss of confidentiality, integrity, and authenticated peer identity. A cross-origin HTTPS redirect can be permissible while an HTTPS-to-HTTP redirect should still be denied. The policy layers must remain independently visible.

Production handling should run downgrade checks after target resolution and normalization but before DNS, cache, cookies, or connection setup for the next hop. The default must reject HTTPS-to-HTTP transitions across the entire chain, including transitions reached after earlier HTTP-to-HTTPS upgrades. If Oreulius ever supports an explicit development exception, that authority should come from a privileged session policy rather than an ordinary request flag, and the event and audit stream should identify that weaker transport was deliberately accepted.

The service should use a dedicated downgrade denial reason rather than reusing mixed content. Mixed content usually describes insecure subresources inside a secure page, while a top-level redirect downgrade is a navigation transition. Separate types improve policy clarity, client presentation, testing, and audit analysis. Tests must prove that no raw, relative, malformed, or case-variant target can evade the downgrade check.

### Invalid or unsupported redirect targets

The current Location parser accepts any nonempty byte sequence after trimming surrounding spaces and tabs. It does not require an HTTP or HTTPS scheme, valid UTF-8 or ASCII, a valid authority, or a representable path and query. It truncates rather than rejects oversized values. The fetch pipeline then returns those bytes as a redirect outcome without validating them against the URL parser.

The service parses the target only for the optional cross-origin comparison. Unsupported schemes, relative references, network-path references, fragments, control bytes, malformed authority, invalid ports, and overlong URL components therefore have no consistent rejection path. If parsing fails, the service still records RedirectFollowed and emits a Redirect event. This is the reverse of fail-closed behavior: the cases the parser understands receive some policy inspection, while the cases it cannot understand can proceed to a success-like result.

Relative Location values need a deliberate decision rather than accidental rejection or bypass. HTTP servers commonly use absolute-path, relative-path, query-only, and network-path references. Supporting them requires a bounded reference resolver that combines the target with the current canonical URL, removes dot segments under the URL contract, preserves query semantics, and then reparses the result as a complete accepted URL. If that resolver is not implemented, the service should reject every nonabsolute target with a typed unsupported-relative-redirect result.

Unsupported schemes should fail before any followed event or audit record. The same rule applies to an empty target, conflicting Location headers, a target containing forbidden controls, a target that exceeds any fixed field, or a target whose normalization is lossy or ambiguous. A malformed redirect is a protocol failure associated with the response, not permission to continue with raw bytes.

Redirect method and body behavior also belongs to target validation. The service must decide whether the next request can safely reuse the body. A nonreplayable or sensitive body must not be resent automatically across origins. The status-specific conversion rules for 301, 302, 303, 307, and 308 should produce an explicit next-method decision before a target is accepted. Header forwarding must similarly remove or recompute host-bound and credential-bearing fields.

The mature result should contain a canonical target URL, transition classification, next method, body replay decision, and typed policy verdict. Only that structured result should reach transport, events, history, cache, cookies, or audit. Raw Location bytes may remain as bounded evidence, but they should never serve directly as the next fetch target.

### Redirect audit events

The audit layer defines one redirect-specific kind: RedirectFollowed. Its helper stores the target bytes in a 32-byte free-form note, truncating longer values. The service calls that helper after the zero-redirect and optional cross-origin checks, then emits the redirect event. Since no second request is issued, the record currently means that a redirect was accepted for reporting, not that it was followed to another network response.

Blocked cross-origin redirects use the general PolicyBlocked kind with a short redirect-cross-origin note. Redirect-disabled responses use InternalError with redirect-disabled. There is no dedicated record for redirect observed, redirect emitted, redirect rejected as malformed, unsupported scheme, downgrade attempt, loop, limit exhaustion, method rewrite, or final redirect-chain commit. The audit vocabulary therefore cannot reconstruct the redirect state machine or distinguish policy outcomes cleanly.

The evidence format is also insufficient for target identity. Storing the first 32 target bytes can collapse unrelated long URLs and can include attacker-controlled bytes without a defined escaping policy. The record does not contain the source URL, status code, hop number, origin classification, policy verdict, or a digest of the complete canonical target. The fixed ring overwrites old entries, so a long or hostile redirect sequence can also displace earlier evidence without chain-level summarization.

Production audit records should describe transitions rather than raw strings. A redirect observation should bind the request, hop number, status, source-origin digest, target-origin digest, canonical-target digest, method decision, and verdict. Separate kinds should represent observed, followed, blocked, malformed, downgrade denied, loop detected, limit exhausted, and chain committed. Bounded human-readable annotations can remain useful, but stable typed fields and full-value digests should carry identity.

Audit order must match event and transport order. The service should record observation after parsing the response, record the policy verdict before opening the next connection, record follow only after the next-hop transition is committed, and record chain completion only after the final response succeeds. If event enqueueing fails, the audit trail should also show that caller-visible redirect evidence was lost. This ordering would let later analysis distinguish what the server requested, what policy allowed, what the kernel attempted, and what ultimately completed.

The current fixed-size audit ring fits Oreulius’s bounded observability model, but redirect evidence needs enough structure to remain trustworthy under adversarial input. Tests should verify record kinds, ordering, hop attribution, canonical target identity, blocked outcomes, and behavior when the ring or event queue is under pressure.

## Fetch request body handling and upload limits

Request-body handling begins in the public Navigate request. Every request carries a fixed 4096-byte body array and a separate caller-supplied body length. The dispatcher converts that pair into a slice, passes it unchanged through the service and fetch context, and gives it to the transport request builder. The transport writes the request headers into a fixed scratch buffer and then sends the body as a separate byte sequence.

That structure matches Oreulius’s preference for bounded IPC messages and heap-free kernel processing. The body has an apparent upper bound, transport does not need to assemble headers and payload into one large allocation, and the accepted bytes can move through the pipeline without copying into another unbounded container. The design is not production-safe yet because the length, method, policy, and transmission states are not validated as one operation.

The most immediate defect occurs before fetch policy runs. The dispatcher slices the body array using the supplied body length without checking that the length is at most 4096. A larger value causes an out-of-bounds slice panic rather than a typed request rejection. This turns untrusted protocol metadata into a kernel availability risk. The URL and download destination fields use the same general pattern, but request bodies make the impact especially clear because their length is expected to vary and is directly associated with network output.

The service also does not validate method and body combinations. The method type contains a helper that identifies POST and PUT as body-bearing methods, and the protocol comment says bodies are ignored for GET and HEAD. Neither rule is enforced. Any nonempty accepted body reaches transport for GET, HEAD, DELETE, and OPTIONS as well as POST and PUT. The transport decides whether to emit Content-Length and send payload bytes solely from whether the body slice is empty.

No request-upload quota is applied after the IPC array bound. The policy profile contains a maximum body size, but that setting governs response bodies and defaults to 64 MiB. The service does not define a separate request-body maximum, per-session upload budget, per-origin quota, aggregate session quota, or rate limit. The current effective upload ceiling is therefore intended to be 4096 bytes only because of the protocol array, not because a validated policy explicitly accepts that amount.

The send path has no partial-write transaction model visible to the fetch layer. The transport sends the complete header block first and then sends the body in a second call. Its send helper loops internally, but if body transmission fails after headers have reached the peer, the server may have received a valid prefix or may wait for bytes promised by Content-Length. The fetch layer reports a general connection failure and closes the transport, but events and audit records cannot distinguish header construction failure, header send failure, partial body send, timeout, or peer rejection.

Production request-body handling should begin with one validated request descriptor. It should prove that every declared length fits its backing array, decide whether the method permits a body, enforce the effective upload quota, bind an explicit media type when required, and determine whether the body is replayable before DNS or transport begins. Only the validated slice and its derived length should reach request construction. Rejected metadata must not allocate a request id when avoidable, touch cache state, emit a navigation-start audit record, or open a connection.

Request bodies also interact with redirects, cancellation, credentials, and audit privacy. A body may contain secrets, authentication material, form data, or update payloads. The service must not replay it across a redirect without a status-specific method decision and origin policy. Abort and timeout behavior must define whether the peer may have received a prefix. Audit records should describe method, accepted length, digest or classification, and outcome without storing body contents.

The production goal is not arbitrary large uploads inside the kernel. It is a small, explicit upload contract whose limits and state transitions are enforced before network side effects. The fixed-array model is a good default for control requests and compact payloads. Larger uploads should use a separate capability-gated streaming design rather than increasing the IPC envelope until it becomes an expensive implicit buffer.

### Supported methods with request bodies

The method enum supports GET, POST, HEAD, PUT, DELETE, and OPTIONS. Its body helper returns true only for POST and PUT. The public request documentation follows that model by describing the body as a POST or PUT field and saying it is ignored for GET and HEAD.

The executed code does not use the helper. The service passes the body for every method, and transport sends any nonempty body regardless of method. A GET with a body therefore receives Content-Length and payload bytes. The same is true for HEAD, DELETE, and OPTIONS. Empty POST and PUT requests omit Content-Length entirely because transport keys header generation to body emptiness rather than method semantics.

HTTP permits bodies on more methods than many application conventions expect, but permissibility is not the same as a safe service contract. GET and HEAD request bodies have poorly defined interoperability and can create cache, proxy, and request-smuggling ambiguity. DELETE bodies are used by some APIs but require an explicit policy. OPTIONS can carry content in specialized protocols, yet the current service has no content type or extension negotiation. Oreulius should define a narrower contract rather than forwarding every combination accidentally.

The initial production contract should allow bounded bodies for POST and PUT, require an empty body for GET and HEAD, and either reject DELETE and OPTIONS bodies or add them deliberately with documented semantics. Rejection is safer than silently ignoring bytes because callers need to know whether submitted data affected the request. A method-body mismatch should produce a typed error before cache lookup or transport.

Method semantics must remain connected to redirects. A 303 transition generally converts the next request to GET and drops the body, while 307 and 308 preserve both. Policies for 301 and 302 need an explicit compatibility rule. A body-bearing method must never be replayed merely because the initial request permitted it, particularly across origins or after a partial send.

Tests should inspect the exact transmitted request for every method with empty and nonempty bodies. They should prove that forbidden combinations never reach transport, accepted combinations send exactly the validated bytes, and redirect processing applies the chosen method and replay rules.

### Fixed request body buffer limit

The Navigate protocol embeds a 4096-byte body array. This makes the IPC message self-contained and places a hard storage ceiling on the request representation. The body length selects the meaningful prefix, so a zero length represents no body and a length of 4096 should represent a full buffer.

The implementation does not safely enforce that ceiling. The dispatcher constructs a slice from zero to the caller-provided length before calling the navigation handler. Values above 4096 panic. There is no checked conversion, no invalid-length response, and no audit evidence. Because the array and length travel together as protocol data, the kernel must treat their consistency as untrusted input even when the Rust enum itself is constructed through an IPC decoder.

The limit is also anonymous. There is no named request-body constant shared by protocol validation, service policy, tests, and documentation. The response-body maximum has a policy constant, but it is unrelated and much larger. Without a distinct upload constant, later code can confuse inbound response limits with outbound request limits or change the array without updating validators.

A production protocol should define one request-body maximum and validate the length before any slicing. The service should use a checked accessor or validated constructor so invalid body state cannot exist beyond decoding. Exact-limit bodies should be accepted only for methods and sessions whose upload policy permits them. Values above the limit must return a typed malformed-request or quota error without panicking or truncating.

The fixed limit should be interpreted as a complete-message limit, not an invitation to send the first 4096 bytes of a larger payload. Silent truncation would change application semantics while Content-Length described only the shortened body. Callers that need larger payloads should use a separate streaming interface with explicit total-size and chunk authority.

Boundary tests must cover zero, one byte, one byte below the limit, the exact limit, and one byte above it. Decoder and dispatch fuzzing should assert that arbitrary length fields cannot panic, read beyond the array, produce partial requests, or create network side effects after rejection.

### Content-Length generation

The transport builds Content-Length whenever the body slice is nonempty. It converts the in-memory slice length to decimal, writes one header, terminates the header block, and then sends exactly that slice. For a successfully validated body, this creates a useful local invariant: the generated value and the number of bytes offered to the send loop come from the same length.

That invariant is weakened by the lack of validation before the transport call and by method-independent behavior. Any method receives Content-Length when its body is nonempty, including GET and HEAD. Empty POST and PUT requests omit the header rather than explicitly sending zero. The service does not define whether that distinction matters to its supported servers and intermediaries.

The caller cannot supply arbitrary request headers through this protocol, so duplicate caller-provided Content-Length and Transfer-Encoding are not currently possible. That narrow header surface is a security advantage. The transport also does not support chunked request encoding, trailers, Expect handling, or caller-selected transfer codings. Production documentation should preserve that restriction unless a structured header policy is introduced.

The header scratch buffer is 4096 bytes and contains the method, request target, Host field, fixed headers, and generated Content-Length. The body does not consume that buffer, but a long path and host can cause request construction to fail before transmission. The resulting error is reported as a general connection failure even though no connection-write problem may have occurred. Request-construction errors should be typed separately from transport failures.

Production generation should occur only after method and body validation. The service should define whether accepted empty body-bearing methods emit Content-Length zero, and it should never generate the header for a method whose body was rejected. The declared length, accepted body length, body digest used for evidence, and send-loop byte count should derive from the same immutable request descriptor.

Tests should capture exact request bytes for empty and nonempty POST and PUT requests, rejected method combinations, maximum bodies, and long request targets. They should verify one Content-Length field, correct decimal formatting, no request Transfer-Encoding, an exact header-body boundary, and no mismatch after partial transport writes or redirects.

### Rejected oversized body declarations

The protocol does not carry a separate wire-level declared body size beyond the body length field. That field is both the caller’s declaration and the slice boundary used by the dispatcher. The current code rejects nothing before slicing, so an oversized declaration does not produce a policy result; it can panic the kernel path.

Lengths within 4096 are accepted without reference to method or session policy. There is no smaller configurable upload limit, aggregate request budget, or check against the policy profile. The response-body checker does not apply to uploads. Describing current behavior as oversized-body rejection would therefore be inaccurate.

Production decoding must validate every length-bearing field before constructing slices. A body length greater than the backing array is malformed protocol data. A length that fits the array but exceeds the effective session or operation quota is a policy or quota violation. Those cases should have distinct typed results because one indicates invalid representation and the other indicates valid input outside granted authority.

Rejection must occur before request-id allocation, cache lookup, navigation-start recording, DNS, TLS, header construction, or any send. The event stream should not imply that a fetch began. The audit layer should record bounded metadata such as method, declared length, applicable limit, and denial class without recording body bytes.

No failure path should shorten the length to fit. Sending a prefix can transform a signed payload, structured document, or form submission into different data while presenting the action as accepted. Fail-closed behavior requires all-or-nothing admission at the service boundary, followed by a separate transport outcome that can still report partial network delivery if sending later fails.

Tests should distinguish malformed lengths above the array, policy-denied lengths within the array, exact-limit acceptance, forbidden method-body combinations, and requests rejected before transport. Fuzzing should prove that arbitrary body lengths cannot panic or trigger reads beyond initialized protocol storage.

### Future streaming upload model

The present fixed-body model is suitable for compact forms, control messages, and small structured payloads. It is not a general upload facility. Increasing the embedded array would enlarge every Navigate request, increase kernel stack and IPC copying pressure, and retain the entire payload inside the trusted service even when transport could consume it incrementally.

A future streaming model should be a separate protocol with explicit lifecycle states. The client would first open an upload under a session capability, declare or bound the total size, method, destination URL, content type, and replay policy, then submit ordered chunks under a dedicated upload capability. The service would track admitted bytes, sent bytes, finalization, cancellation, timeout, transport failure, and whether any prefix may have reached the peer.

Backpressure is essential. The kernel should expose a small bounded staging window rather than accepting chunks faster than transport can send them. Per-upload, per-session, and global quotas should limit buffered bytes, total bytes, concurrent uploads, and upload duration. Chunk sequence numbers and an explicit final marker should prevent gaps, duplication, and ambiguous completion.

Streaming makes authority narrower, not broader. Each upload capability should bind one session, URL or origin policy, method, maximum size, content classification, expiry, and use budget. Delegation and revocation should integrate with the existing Oreulius capability model. A client must not be able to redirect an admitted upload to another authority or reuse the capability for a second request.

Retries and redirects require conservative rules. Once any non-idempotent body bytes may have reached a peer, automatic retry can duplicate effects. A 307 or 308 cannot safely replay a stream unless the source is rewindable and policy explicitly permits it. Cross-origin replay should default to denial. The service should expose whether failure occurred before transmission, during a partial send, or after all bytes were sent while awaiting a response.

Content integrity should be optional but structured. Callers may provide an expected digest or the kernel may compute one incrementally for audit and end-to-end verification. Audit records should store metadata and digests, never payload contents. Sensitive buffers should be cleared when their lifecycle ends if the memory model does not already guarantee safe reuse.

Production work should begin only after abort, timeout, backpressure, event delivery, and transport partial-write semantics are mature. Tests will need deterministic simulated peers that stall, reset, redirect, acknowledge partial data, and close at every boundary. Until those guarantees exist, the fixed validated request body is the safer Oreulius design.

## Fetch response header parsing and size limits

Response headers are the point where remote, attacker-controlled bytes become structured kernel state. They determine response framing, redirect targets, declared body length, transfer coding, MIME classification, download behavior, cookies, cache metadata, and the evidence delivered to clients. A bounded parser is necessary inside the kernel, but bounded storage is only safe when overflow and ambiguity cause a visible failure rather than a partial interpretation.

The current path uses two levels of fixed storage. The fetch pipeline reads up to 16 KiB while searching for the header terminator. It then parses at most thirty-two fields into records containing a sixty-four-byte name and a 256-byte value. Header names are lowercased, surrounding spaces and tabs are removed from values, and downstream helpers retrieve the first matching field.

| Boundary | Current behavior | Security consequence |
|---|---|---|
| Header block | Stops at 16 KiB or transport EOF | An incomplete block can still be parsed |
| Header count | Stores the first 32 fields | Later security fields disappear silently |
| Header name | Truncates to 64 bytes | Distinct names can collapse into one stored name |
| Header value | Truncates to 256 bytes | Framing, redirect, cookie, and metadata values can change meaning |
| Malformed line | Skips the line | The response continues from a partial field set |
| Duplicate field | First match wins | Conflicting framing and routing evidence is not rejected |

The 16 KiB reader does not report why it stopped. A return value greater than zero can mean that a complete terminator was found, that the peer closed early, that a read failed, or that the buffer filled. The fetch pipeline searches again for the terminator and, when none exists, treats every collected byte as a header block. It then continues into semantic extraction and body streaming. This allows incomplete or oversized headers to become an apparently valid response.

The reader also discards response bytes that arrive after the header terminator in the same transport read. It copies the entire read into the header buffer, notices that the terminator exists, and returns only a total length. Later code identifies the end of the header block but does not preserve the bytes after it as the beginning of the body. This is not only a body-streaming defect; it shows that the parser lacks a response framing object that separates consumed header bytes from already-received payload bytes.

The field parser provides no completeness or error result. Its only output is the count of fields successfully stored. A count of thirty-two can mean exactly thirty-two headers or an arbitrary larger set whose remaining fields were dropped. A smaller count can mean a genuinely small field set or several malformed lines that were skipped. Downstream code cannot distinguish those states, so it cannot decide whether Content-Length, Transfer-Encoding, Location, Content-Type, Set-Cookie, or cache metadata was represented completely.

This is especially dangerous because header semantics are not uniform. Some fields must occur once, some may be repeated as separate records, some permit comma combination, and some become invalid when conflicting duplicates appear. A generic first-match lookup cannot safely implement all of those rules. Content-Length and Transfer-Encoding control message framing. Location controls redirect authority. Set-Cookie must preserve multiple independent fields. Content-Type affects rendering and download classification. Each needs a typed extraction rule that sees the complete validated field set.

The current implementation fits Oreulius’s bounded-memory philosophy in shape, but not yet its fail-closed philosophy. Fixed arrays, explicit lengths, lowercase names, and a small parser surface make the code reviewable. Silent truncation and silent omission undermine that advantage because the kernel cannot prove that the structured result means the same thing as the received response.

Production parsing should be transactional. The transport reader should return a complete-header result containing the exact header bytes, the header terminator position, any body prefix already read, and a typed failure reason. The field parser should either return a complete validated header collection or reject the response. No redirect, cache, cookie, MIME, framing, event, or body decision should occur from a partial collection.

The service does not need unlimited header support. It needs a strict contract that states the accepted block size, line size, field-name size, field-value size, and field count. A response outside that contract should fail with a protocol error before body bytes are relayed. That preserves deterministic memory use while making the boundary honest.

### Status line parsing

The status parser requires the response to begin with HTTP/1. and requires at least twelve bytes plus a carriage-return and line-feed terminator. It reads the three bytes at offsets nine through eleven as decimal digits and returns zero on failure. The fetch pipeline maps zero to a protocol error and closes the transport.

This catches missing prefixes, short lines, absent line termination, and nondigit status codes. It remains too permissive about the structure around those digits. The parser does not validate the HTTP minor version byte, the required space after the version, the space or end condition after the status code, or the status-code range. Inputs shaped like HTTP/1.x followed by any byte at the separator position can be accepted if offsets nine through eleven contain digits. Codes below 100 and otherwise undefined three-digit values are also accepted.

The parser does not place an independent maximum on the status-line length. The line is indirectly bounded by the 16 KiB header block, so a hostile reason phrase can consume most of the buffer and crowd out fields. The reason phrase is not used, which simplifies the trusted state, but the parser should still reject controls and an excessive line before field parsing begins.

Informational responses are not handled as a sequence. A 100 Continue, 102 Processing, or 103 Early Hints response can be treated as the final response because the fetch pipeline parses only one status line and one header block. Production HTTP/1.1 handling must either consume supported informational responses until the final status arrives or reject them explicitly. Upgrade and switching-protocol responses should remain unsupported unless a separate protocol path owns them.

The mature parser should accept only explicitly supported HTTP versions, validate separators exactly, require a status from 100 through 599, bound the line length, and return a typed status object rather than using zero as an error sentinel. The result should distinguish malformed status syntax, unsupported version, unsupported informational response, and unsupported protocol switch.

Tests should cover exact HTTP/1.0 and HTTP/1.1 forms, invalid minor versions, missing spaces, extra separators, short and long lines, every status-code boundary, informational sequences, line-ending variants, embedded controls, and fragmented transport delivery.

### Header name and value limits

Each stored field reserves sixty-four bytes for its name and 256 bytes for its value. The parser validates every original name byte against the HTTP token-character set, lowercases the stored prefix, trims optional spaces and tabs around the value, and copies both components into fixed arrays.

The parser truncates rather than rejects when either component exceeds its storage. Name truncation is particularly unsafe because lookup operates on the stored name. Two distinct remote field names with a common sixty-four-byte prefix can become indistinguishable, and an overlong name can be converted into the exact spelling of a security-sensitive shorter name. The original validation does not prevent this identity change.

Value truncation changes semantics while preserving a normal-looking field. A long Location becomes a different redirect target. A long Content-Disposition can lose filename or attachment parameters. A long cache directive, ETag, cookie, content type, or transfer-coding list can lose the bytes that determine its meaning. Even when Content-Length normally fits within 256 bytes, a generic truncation policy makes it impossible for downstream code to know that its input was complete.

The name validator also accepts an empty name because the all-bytes predicate succeeds for an empty slice. A line beginning with a colon can therefore become a stored field with a zero-length name. Values are not checked for prohibited controls, bare carriage returns, bare line feeds, or obsolete line folding beyond the parser’s line splitting behavior. Production input should reject these forms rather than preserving arbitrary bytes in events.

The correct bounded rule is exact representation or failure. Names and values at the documented limit may be accepted. Values one byte beyond it must reject the response unless a particular field has a deliberately larger dedicated representation. Security-sensitive fields should be parsed from validated complete bytes before any smaller client-facing projection is created.

One storage size may not suit every field. A compact generic event record can remain useful for presentation, while internal typed parsers retain dedicated bounded capacities for Location, Set-Cookie, ETag, and other fields. The event projection must carry an omission or redaction marker if it does not reproduce the full accepted header set.

### Maximum response header count

The response event can carry thirty-two headers, and the field parser stops as soon as it fills those slots. This bounds event size and parsing work, but it silently ignores every later field. The returned count contains no overflow flag, so the caller and fetch pipeline cannot distinguish an exact thirty-two-field response from one containing hundreds of additional lines.

Header ordering then becomes a security control chosen by the remote server. An attacker can place harmless fields first and move Content-Length, Transfer-Encoding, Location, Content-Type, Set-Cookie, cache directives, or other meaningful fields beyond the storage limit. Those fields vanish from semantic processing. The inverse is also possible: an early framing field is accepted while a later conflicting duplicate is hidden beyond the limit.

The current parser also counts only successfully parsed fields. Malformed lines do not consume slots. This means the numeric count reveals neither the number of received lines nor whether the collection was complete. A production parser needs separate state for received field count, accepted field count, malformed input, overflow, and complete termination.

The service should reject a response whose field count exceeds the supported maximum before using any field. Selectively preserving important fields while dropping others is unsafe unless a complete first pass validates the entire block and applies field-specific aggregation rules. With a 16 KiB block bound, a complete validation pass remains deterministic even if only a smaller projection is emitted to clients.

The maximum should also account for repeated fields whose multiplicity is legitimate. Set-Cookie cannot be combined as a simple comma-separated value. A production design may need a dedicated cookie extraction path and a generic event projection, but both must derive from the same complete validation result.

Tests should place security-sensitive fields at, before, and after the count boundary; add conflicting duplicates beyond the boundary; mix malformed and valid lines; and prove that overflow always rejects rather than changing which semantics the kernel observes.

### Duplicate and malformed header behavior

Malformed field lines are currently skipped. A line without a colon disappears. A line whose name contains a non-token byte disappears. Parsing then continues and the response may complete successfully. This is tolerant, but it is not appropriate for a kernel parser when the omitted line may have been intended to control framing, authority, caching, cookies, or content classification.

Duplicate handling is equally generic. The lookup helper scans from the beginning and returns the first case-insensitive name match. Content-Length therefore uses the first stored value and ignores every later one. Transfer-Encoding, Content-Type, and Location behave the same way. Conflicting duplicates do not cause a protocol error, and duplicate fields hidden after the thirty-second slot are not visible at all.

Different fields require different rules. Multiple Content-Length values are safe only when every valid decimal value is identical under the chosen HTTP policy; conflicting values must reject the response. Transfer-Encoding must be parsed as an ordered coding list, and its coexistence with Content-Length requires a strict anti-smuggling rule. Location should reject ambiguity for redirect processing. Content-Type should have one authoritative value. Set-Cookie should preserve each field separately rather than first-match it. Comma-combinable fields need field-aware joining, not generic selection.

The Content-Length parser has its own ambiguity. It uses saturating arithmetic, so a decimal value larger than the unsigned sixty-four-bit range becomes the maximum value instead of failing overflow. Invalid values become absent because extraction uses an optional result. The body stream then treats the response as unknown-length rather than rejecting malformed framing. Production parsing must distinguish absent, valid, invalid, duplicated, conflicting, and overflowed framing metadata.

Transfer-Encoding detection searches for the byte sequence chunked anywhere inside the first value. That can match a token embedded inside an invalid larger token, ignores duplicate fields and coding order, and does not reject unsupported codings. Combined with first-match lookup and Content-Length acceptance, this creates request-framing ambiguity at the response boundary.

Malformed syntax should reject the complete response unless a narrowly documented field rule permits recovery. The parser should return structured errors with the line position and class while keeping attacker-controlled text out of logs. Semantic extraction should happen through field-specific functions that consume the complete validated collection and return typed decisions.

### Oversized header failure policy

The raw header block is bounded at 16 KiB, but reaching that boundary is not treated as an error. The reader stops when the buffer fills. The fetch pipeline then uses the full collected length when no terminator exists and asks the field parser to interpret it. A response that exceeds the limit can therefore be accepted as a partial header set.

Transport EOF and read errors before the terminator have similar behavior. The reader breaks and returns the bytes collected so far. Only a total of zero becomes a no-response error. Any nonzero partial status and field prefix can proceed. The code loses the difference between complete, oversized, truncated, timed out, and failed reads.

Per-field and field-count overflow are also silent. Names and values are shortened, later fields are dropped, and malformed lines are omitted. None of these conditions produce a FetchError event, a policy block, an audit record, or an incompleteness marker in the Headers event.

Production behavior should fail the response whenever the terminator does not arrive within the block limit, the status line exceeds its limit, a field exceeds its name or value capacity, the field count exceeds the maximum, a prohibited control appears, or the transport ends before completion. The failure should occur before redirect handling, framing decisions, body relay, cache insertion, cookie processing, content filtering, or a successful Headers event.

The reader should return a typed result such as complete, too large, premature end, timeout, or transport error, together with any body prefix only on complete success. The parser should return a complete collection or a typed syntax or capacity error. The event and audit layers can then report a bounded reason without exposing raw hostile fields.

Failing closed does not require larger buffers. It requires making every limit observable and atomic. Tests should force each boundary independently and in combination, including a terminator split across reads, a terminator at the final accepted byte, one byte beyond the block limit, oversized individual fields, too many fields, premature EOF, read failure, and body bytes arriving in the same read as the terminator.

## Fetch chunked transfer decoding

Chunked transfer coding is a message-framing protocol, not merely a way to split a body into convenient pieces. The decoder must prove where every chunk begins and ends, distinguish incomplete input from invalid input, preserve every decoded byte exactly once, require the terminal zero-size chunk, and define what happens to trailers. Any ambiguity can turn one remote byte stream into a different body inside the kernel.

The current implementation has three layers. Header inspection decides whether the response is chunked. The body loop accumulates transport reads in a 16 KiB leftover buffer. The decoder scans size lines, copies decoded bytes into one 4096-byte output buffer, reports how many source bytes it consumed, and tells the caller whether it saw a zero-size chunk.

| Stage | Current representation | Current result |
|---|---|---|
| Transfer coding | First stored Transfer-Encoding value | Substring match for chunked |
| Input staging | 16 KiB leftover buffer | New bytes may be dropped when full |
| Decoded staging | One 4096-byte buffer | Additional decoded bytes can be discarded |
| Decoder status | Decoded count, consumed count, done flag | Cannot distinguish incomplete from malformed |
| End of body | Zero size or transport EOF | Both paths lead to Complete |
| Trailers | Bytes after zero-size line | Ignored when done becomes true |

The shape is bounded and allocation-free, which suits Oreulius. The weakness is that every boundary collapses distinct protocol states. Invalid syntax can look incomplete or complete. Capacity exhaustion can look like successful consumption. Premature connection closure can look like a valid body end. The caller receives no typed framing evidence from which to fail closed.

The most severe integrity defect appears when decoded output exceeds 4096 bytes in one decoder call. The decoder limits each copy to the remaining output capacity, but it advances the source cursor by the full declared chunk size. Once the output buffer fills, later complete chunks can be consumed with a zero-byte copy. Their payload disappears while framing continues. A response containing several chunks in one transport accumulation can therefore complete successfully with missing body bytes.

The leftover buffer has a related liveness and integrity problem. Appending uses the remaining capacity as a silent cap. If the buffer is full and the decoder cannot consume a complete frame, later transport reads are copied zero bytes. Those bytes disappear. The loop can continue until EOF, then emit Complete even though the original chunk remained incomplete and later network data was discarded.

The decoder needs an explicit incremental state machine rather than a tuple of counts. A mature state should represent reading a size line, reading chunk data, requiring the data terminator, reading trailers, complete, and failed. Each transition should report whether it needs more input, produced output, reached a valid end, or encountered a typed protocol error. Buffer pressure must stop transport consumption until existing input or output is drained.

| Required state | Completion condition | Failure examples |
|---|---|---|
| Size line | Complete validated hexadecimal line | Empty line, invalid digit, overflow, excessive extension |
| Chunk data | Exactly the declared byte count | Premature EOF, body quota exceeded |
| Data terminator | Exact carriage return and line feed | Missing or malformed terminator |
| Trailer section | Valid bounded fields and final empty line | Forbidden field, malformed syntax, overflow |
| Complete | Terminal chunk and trailer terminator consumed | Extra unframed bytes under connection-close policy |

The production contract should preserve the existing bounded-memory direction while making capacity part of control flow. Large chunks do not require large kernel buffers. The decoder can retain a remaining-byte count, emit several bounded body events, and consume only the source bytes actually delivered. It must never advance over decoded bytes that did not enter an event or another trusted sink.

Chunked handling also inherits the header-parser obligations described above. Transfer-Encoding must come from a complete validated header set, Content-Length conflicts must be resolved before body processing, and body bytes received with the headers must enter the decoder as its initial input. A correct chunk decoder cannot repair incomplete framing decisions made earlier.

### Chunked response detection

Detection currently reads the first stored Transfer-Encoding value and returns true when that value equals chunked or contains the seven-byte sequence chunked anywhere, ignoring ASCII case. This accepts ordinary values such as gzip, chunked, but it also accepts invalid tokens containing the same substring. It ignores later Transfer-Encoding fields, coding order, parameters, header truncation, and field-count overflow.

HTTP transfer codings form an ordered list. Under the service’s intended support, chunked must be recognized as a complete token and must be the final coding. Any preceding coding must either be implemented and decoded in reverse order or cause rejection. A response using gzip, chunked cannot be treated as plain decoded content after only removing chunk framing because the remaining representation is still gzip encoded.

The coexistence of Transfer-Encoding and Content-Length needs an explicit anti-smuggling rule. The current pipeline parses both, selects chunked mode when the substring detector succeeds, and otherwise may use Content-Length. It does not reject the conflict. Production behavior should reject ambiguous framing before body bytes are emitted rather than relying on one field while exposing the other in events.

| Header shape | Current behavior | Required behavior |
|---|---|---|
| Transfer-Encoding: chunked | Chunked mode | Accept |
| Transfer-Encoding: gzip, chunked | Chunked mode without gzip decoding | Reject until gzip transfer coding is implemented |
| Transfer-Encoding: xchunked | Chunked mode | Reject invalid or unsupported coding |
| Two Transfer-Encoding fields | First field only | Parse the complete ordered list or reject |
| Transfer-Encoding plus Content-Length | Both retained, chunked may win | Reject under strict framing policy |
| Truncated Transfer-Encoding | Uses truncated value | Reject the response before detection |

Detection should return a typed framing decision rather than a boolean. The result should distinguish identity framing, valid chunked framing, unsupported transfer coding, invalid coding syntax, duplicate ambiguity, and Content-Length conflict. Only a valid chunked result should enter the chunk decoder.

### Chunk-size parsing

The size parser reads hexadecimal digits up to the first semicolon and uses saturating arithmetic. It returns the accumulated value immediately when it encounters a nonhexadecimal byte. It also returns zero for an empty size portion. The decoder interprets every zero result as the terminal chunk.

This creates a direct fail-open path. A size line beginning with an invalid character, an empty line, or a semicolon with no preceding digits becomes a valid-looking zero-size terminator. A line containing valid digits followed by an invalid character becomes the valid numeric prefix rather than an error. An overflowing value saturates to the maximum machine-sized integer instead of producing an overflow result.

Chunk extensions are ignored after the first semicolon without validation or a length limit. Ignoring extensions can be acceptable, but only after validating their bounded syntax sufficiently to locate the line ending safely. The current parser treats every byte after the semicolon as irrelevant, including prohibited controls.

The size type is architecture-dependent because it uses the machine-sized integer. Oreulius builds for multiple architectures, so the same oversized size line can produce different saturated values and capacity behavior on different targets. Protocol parsing should use a fixed-width integer and then compare it with explicit response and platform limits.

| Input size line | Current result | Correct classification |
|---|---|---|
| A | Ten bytes | Valid |
| 10;name=value | Sixteen bytes | Valid only after bounded extension validation |
| Empty line | Zero and terminal | Malformed |
| Z | Zero and terminal | Invalid hexadecimal |
| 1G | One byte | Invalid hexadecimal |
| Excessively large hexadecimal | Saturated machine maximum | Numeric overflow |

The parser should return a typed result containing the validated size and extension disposition. It must require at least one hexadecimal digit, reject every invalid digit before the semicolon, detect multiplication and addition overflow, enforce a size-line limit, and reject a size above the configured response-body quota before waiting for that many bytes.

Tests should cover uppercase and lowercase digits, leading zeros, empty input, invalid prefixes and suffixes, overflow on every supported architecture width, extension boundaries, controls, excessive line length, and sizes larger than the remaining response quota.

### Body chunk emission

Decoded body data is emitted through fixed 4096-byte BodyChunk events. This is the right event size for bounded delivery, but the decoder currently assumes that one output buffer is enough for every set of complete chunks present in the leftover input. It is not.

When a declared chunk is larger than the remaining output capacity, the decoder copies only the prefix that fits but advances past the entire chunk. When several chunks together exceed the output buffer, later chunks can be consumed without copying any payload. In both cases the event stream loses bytes while the decoder reports the source as consumed.

The caller invokes the decoder once per transport read and emits at most one body event from that invocation. It does not call again to drain additional decoded output already present in the leftover buffer. Compaction removes all source bytes that the decoder claimed to consume, including payload that never reached an event.

The event array used by one fetch call is also bounded at sixty-four entries. The generic push helper silently drops events after it fills. Chunked decoding has no backpressure connection to that capacity. Even a correct decoder could therefore continue consuming body bytes after body events can no longer be retained, and the Complete event can also be lost.

| Pressure point | Current response | Required response |
|---|---|---|
| Chunk larger than 4096 bytes | Copies prefix and consumes full chunk | Retain remaining count and emit multiple events |
| Several chunks exceed output buffer | Later payload may be discarded | Stop source consumption when output is full |
| Leftover input still contains complete chunks | Waits for another network read | Drain buffered input before reading again |
| Local event array is full | Drops new events silently | Apply backpressure or fail the request visibly |
| Session event queue is full | Drops events silently | Preserve loss evidence or terminate |

A production decoder should report consumed source bytes and produced output bytes with the invariant that every consumed payload byte was emitted or retained in explicit decoder state. The body loop should drain buffered input repeatedly before reading more transport data. Event delivery must provide success or backpressure feedback so decoding stops before output is lost.

The is_last flag also needs precise semantics. If decoded payload ends in the same call that recognizes the terminal chunk, the last emitted data event may carry true. If the terminal chunk follows an earlier fully emitted data event in a later read, there is no new data event on which to place the flag. The separate Complete event should therefore remain the authoritative terminal marker, or the protocol should permit an empty final body event under a documented rule.

### Malformed chunk handling

The decoder cannot currently report malformed input. Its tuple distinguishes only produced bytes, consumed bytes, and whether a zero size was observed. Missing size-line termination returns an incomplete-looking result. Invalid size syntax can become zero or a numeric prefix. Missing carriage return and line feed after chunk data is tolerated. Premature EOF exits the body loop and still emits Complete.

This makes malformed and incomplete messages indistinguishable from successful connection-close termination. Chunked framing explicitly requires the terminal zero-size chunk, so transport EOF before that marker must be a protocol error. The service should never commit navigation, cache data, or report completion from an unterminated chunked response.

The current loop can also lose data when the leftover buffer fills. It silently copies only what fits. If the decoder consumes nothing, subsequent reads may be discarded while the same incomplete prefix remains. EOF then converts the stalled parse into success. A malicious peer can use a long unterminated size line or a declared chunk larger than the staging buffer to exercise this path.

| Malformation | Current behavior | Required outcome |
|---|---|---|
| Invalid size digit | Prefix value or zero | Protocol error |
| Missing size-line terminator | Waits until EOF, then completes | Protocol error on limit or EOF |
| Missing chunk-data terminator | Continues parsing later bytes | Protocol error |
| EOF before zero chunk | Emits Complete | Truncated-body error |
| Staging buffer exhausted | Drops later reads | Backpressure or bounded overflow error |
| Bytes after completed trailers | Ignored by current early break | Defined connection or protocol policy |

Malformed handling must be terminal and typed. The decoder should report invalid size, size overflow, excessive size line, missing data terminator, premature EOF, body quota exceeded, trailer error, and unexpected extra data separately. The fetch layer should emit a protocol error, close the transport, suppress Complete, and prevent partial data from entering cache or navigation success state.

The service also needs a policy for body events emitted before a later framing failure. It cannot retract bytes already delivered. The terminal error must mark the response stream as invalid and incomplete, and clients must not treat earlier data as a successful resource. For sensitive consumers, buffering or digest verification before commit may be required.

### Trailer support or rejection policy

After a terminal zero-size chunk, HTTP chunked coding carries a trailer section terminated by an empty line. The current decoder sets done as soon as it parses a zero size. It optionally skips one immediate carriage return and line feed, returns, and causes the body loop to stop. It does not parse trailer fields, require the final empty line, preserve trailer bytes, or reject forbidden trailer content.

For the common no-trailer sequence, the bytes after the zero-size line are one empty-line terminator. The optional skip happens to consume that sequence when it is already buffered. If the final carriage return and line feed arrives in a later read, the decoder can still report completion before receiving it. If actual trailer fields follow, they remain in leftover storage and are discarded when the caller breaks.

Trailers cannot be allowed to revise security decisions already made from initial headers. Framing fields such as Content-Length and Transfer-Encoding, routing fields such as Location, authentication fields, cookie mutation, and content classification should either be forbidden in trailers or handled under a narrowly defined policy. Generic reuse of the initial-header parser would not be sufficient without a trailer-specific allowed-field model.

| Trailer policy | Benefits | Cost and risk |
|---|---|---|
| Reject all nonempty trailers | Smallest trusted surface | Loses legitimate digest and metadata use |
| Validate and ignore allowed trailers | Preserves framing correctness | Caller cannot consume trailer evidence |
| Expose a strict allowlist | Supports digest and integrity metadata | Adds event, audit, and duplicate rules |

The safest initial Oreulius policy is to require the terminal chunk, parse the trailer section with the same bounded line discipline, permit only an empty trailer section, and reject any nonempty trailer with a typed unsupported-trailer error. Later support can add an allowlist for integrity fields after defining how they bind to the decoded body and how clients receive them.

Completion must occur only after the final empty trailer line has been consumed. Trailer bytes split across reads must remain in decoder state. Tests should cover empty trailers, one and multiple fields, forbidden fields, malformed lines, oversized trailers, missing final termination, split termination, and body bytes or unrelated protocol data after completion.

## Fetch TLS identity, certificate evidence, and failure reporting

TLS in the fetch service currently provides encrypted record transport and handshake transcript confirmation, but it does not provide authenticated web identity. The transport allocates a TLS session for the parsed host and resolved IPv4 address, drives the handshake for a fixed number of ticks, and treats the session as established when the underlying state reaches Connected. The fetch pipeline then emits an Established event and begins sending HTTP.

The underlying TLS state machine implements important cryptographic mechanics. It offers TLS 1.3, X25519, AES-128-GCM, and SHA-256-based key derivation. It sends the requested hostname through Server Name Indication, derives handshake and application traffic keys, authenticates encrypted records, maintains record sequence numbers, and verifies the server Finished value against the transcript. These properties can detect record tampering and prove that the peer completing the handshake possesses the negotiated ephemeral traffic secrets.

They do not prove that the peer is authorized to speak for the requested hostname. The state machine accepts a Certificate handshake message by advancing from WaitCertificate to WaitCertVerify without parsing the certificate list. It accepts CertificateVerify by advancing to WaitFinished without checking the signature. It has no trust-anchor store, path builder, certificate-policy engine, validity-time check, revocation check, subject alternative name parser, wildcard matcher, or hostname verifier. The net module separately exposes an error saying HTTPS is blocked because strict certificate validation is unavailable, but the fetch transport directly uses the lower-level TLS session and does not apply that fail-closed policy.

| Property | Current implementation | Security meaning |
|---|---|---|
| Server Name Indication | Sends the parsed host | Helps the server choose a certificate |
| Ephemeral key agreement | X25519 | Establishes shared traffic secrets |
| Record protection | AES-128-GCM | Protects confidentiality and integrity after key establishment |
| Finished verification | Verifies server transcript MAC | Detects handshake transcript tampering |
| Certificate parsing | Not implemented | No certificate identity is extracted |
| CertificateVerify | Message presence advances state | No proof that the certificate key signed the handshake |
| Chain validation | Not implemented | No trust anchor or issuer authorization |
| Hostname validation | Not implemented | No binding between URL host and certificate |

The current Established label is therefore materially stronger than the evidence supports. It means that the custom TLS state machine reached its Connected state, not that a publicly trusted or locally authorized certificate was validated for the requested origin. Calling the connection secure without qualification risks causing callers, audit consumers, and later policy code to treat encryption as authenticated identity.

The handshake parser also tolerates several malformed states by ignoring them. Encrypted handshake decryption failure returns without setting an error. Unexpected messages are ignored. Truncated handshake messages break the local loop and wait for more bytes even though the implementation does not retain a dedicated fragmented-handshake message buffer separate from record processing. ServerHello parsing can return early without setting an error, and it can derive keys from an all-zero peer key if no valid key-share extension was captured. These behaviors weaken the meaning of Connected even before certificate validation is considered.

Key generation uses scheduler ticks and deterministic transformations to derive the X25519 private key and ClientHello random. That is not a cryptographically strong entropy source. Production TLS requires a kernel cryptographic random generator with health checks, reseed policy, fork or snapshot safety, and no predictable relationship between session values.

TLS errors are collapsed as they cross layers. The TLS session stores a short byte message, transport reduces all observed handshake errors and handshake timeout to TlsHandshakeFailed, and the fetch protocol exposes only Failed. Session-pool exhaustion is also grouped with handshake failure in the fetch layer. Record authentication failures during application reads can appear as zero bytes rather than a typed TLS integrity failure because the lower layer does not propagate a rich result through read.

The intended Oreulius direction is visible elsewhere in the network surface: when strict identity validation is unavailable, HTTPS should fail closed. The fetch service currently bypasses that rule. Production readiness requires either integrating a complete, reviewed certificate-validation path or refusing HTTPS requests by policy. Encryption without identity must not be silently promoted to trusted HTTPS.

The mature TLS result should be evidence-bearing. A successful result should bind the canonical hostname, port, resolved address, negotiated version and cipher suite, certificate-chain validation result, hostname result, trust-anchor identity, leaf certificate fingerprint, validity decision, and policy generation to the request. A failed result should carry a stable typed reason without exposing unbounded certificate contents.

### TLS handshake state event

The public TLS event has three values: Established, Failed, and Plaintext. The fetch pipeline emits Failed followed by a fetch error when transport reports TLS allocation or handshake failure. It emits Established immediately after TransportHandle returns an HTTPS connection. For HTTP, it emits Plaintext.

This gives callers a simple request-correlated transport signal before headers and body events. The ordering is sensible in the successful path: the connection event is queued before request transmission and response processing. The failure path also attempts to place the TLS event before the terminal fetch error.

The event is best-effort rather than guaranteed. It enters the same fixed local event array and session queue as body data, redirects, policy blocks, completion, and errors. Neither enqueue layer reports loss. A caller can therefore receive later response events without receiving the TLS state that explains the connection, or can miss both failure evidence and the terminal error under pressure.

Established currently represents only handshake-state completion. It does not encode certificate validation, hostname validation, negotiated parameters, or whether the TLS implementation is operating under a development-only trust policy. Plaintext is also described as a handshake result even though no TLS handshake occurred. A production protocol should separate transport mode from authenticated TLS verdict.

| Event concept | Current value | Production evidence |
|---|---|---|
| HTTP transport | Plaintext | Explicit unencrypted transport mode |
| TLS cryptographic handshake | Established | Handshake-complete result with negotiated parameters |
| Server identity | Implied by Established | Separate certificate and hostname verdict |
| TLS failure | Failed | Typed failure phase and reason |

The event model should represent connecting, handshake complete but identity unverified when development policy permits it, authenticated, failed, and closed or invalidated states as needed. Production policy should only permit HTTP request transmission after an authenticated verdict. Events must be ordered, request-bound, and delivered through a path that cannot silently lose the trust decision while retaining dependent response data.

### Certificate identity evidence

The TLS session receives Certificate and CertificateVerify handshake messages, but it does not extract any certificate evidence. The certificate body is not parsed into a leaf certificate or chain. No DER structure, public key, signature algorithm, subject alternative name, issuer, serial number, validity period, key usage, extended key usage, policy constraint, or fingerprint reaches the fetch layer.

CertificateVerify is treated only as the expected next message type. The implementation does not parse its signature scheme or verify its signature against the public key from the leaf certificate. The subsequent Finished verification authenticates the transcript under handshake traffic secrets, but without CertificateVerify and chain validation it does not establish the certified identity of the peer.

The fetch protocol has nowhere to carry certificate evidence. Its TLS event contains only the three-state result. The audit record has a thirty-two-byte note but no structured certificate fields. This prevents callers and operators from explaining which identity was accepted, which trust anchor authorized it, or why a failure occurred.

Production evidence should remain bounded. The kernel does not need to emit complete certificates to every client. A useful summary can contain the leaf SHA-256 fingerprint, selected subject alternative name or matched identity, issuer or trust-anchor identifier, serial-number digest, validity interval, public-key algorithm, signature algorithm, chain depth, and validation-policy generation. Detailed certificates can remain in a separately authorized diagnostic interface if needed.

Evidence must be derived from the exact chain that validation accepted and bound to the canonical request hostname and handshake transcript. Truncating arbitrary subject strings is weaker than carrying hashes and typed identifiers. Sensitive or attacker-controlled certificate text should not enter fixed audit notes without encoding and length discipline.

### Hostname and chain validation result

The requested host is copied into the TLS session and sent in the ClientHello Server Name Indication extension. That is the only active hostname use inside the TLS state machine. Server Name Indication is a routing hint to the server; it is not verification.

No code compares the requested host with a certificate subject alternative name or common name. There is no DNS-name normalization contract shared with URL parsing, no wildcard policy, no IP-address identity rule, no internationalized-domain handling, and no distinction between DNS hostnames and literal addresses. A malicious endpoint at the resolved address can complete the current handshake regardless of the certificate it sends.

Chain validation is also absent. The implementation does not parse issuers, verify certificate signatures, enforce a maximum path length, select a trust anchor, apply name constraints, check basic constraints, key usage, extended key usage, validity periods, critical extensions, or revocation state. It does not have a trustworthy wall-clock input for certificate validity decisions.

| Validation layer | Current state | Required production verdict |
|---|---|---|
| Certificate message structure | Unparsed | Structurally valid bounded chain |
| CertificateVerify signature | Unchecked | Valid signature over the TLS 1.3 context and transcript |
| Chain signatures | Unchecked | Valid path to an authorized trust anchor |
| Validity period | Unchecked | Current trusted time within certificate interval |
| Key usage and constraints | Unchecked | Certificate authorized for TLS server authentication |
| Hostname | Unchecked | Canonical request identity matched by accepted SAN |
| Revocation | Unchecked | Policy-defined revocation or freshness result |

Production validation should return separate hostname and chain results because they fail for different reasons and support different audit evidence. Both must succeed before the fetch service emits an authenticated TLS state or sends HTTP request bytes. Unknown time, unknown revocation state, unsupported critical extensions, and unsupported name forms should fail closed under production policy.

The trust-store model also needs an Oreulius-specific authority boundary. System roots, enterprise roots, pinned service identities, update infrastructure roots, and development roots should not be one ambient list. Trust-anchor use should be capability- and policy-scoped, versioned, revocable, and auditable.

### Typed TLS failure reasons

The lower TLS layer records free-form messages such as short ServerHello, server alert, and bad server Finished. The transport exposes TlsAllocFailed and TlsHandshakeFailed, but the fetch layer maps both to one Failed event and one TlsHandshakeFailed fetch error. The fixed tick budget is also reported as handshake failure rather than timeout.

Several distinct failures collapse even earlier. A missing session handle, pool exhaustion, malformed handshake, cryptographic verification failure, peer alert, timeout, unsupported negotiation, and internal state error can become the same result. Certificate and hostname failures cannot be reported because they are not performed. Application-record authentication and closure errors are not represented through the fetch TLS event.

Typed failures should identify both phase and cause. Useful phases include DNS handoff, TCP connection, ClientHello construction, ServerHello negotiation, encrypted extensions, certificate parsing, CertificateVerify, chain validation, hostname validation, Finished verification, application record processing, and closure. Causes should include timeout, pool exhaustion, malformed message, unsupported version, unsupported cipher, unsupported group, bad key share, decrypt failure, peer alert, invalid certificate structure, unknown issuer, expired or not-yet-valid certificate, wrong hostname, revoked certificate, bad signature, weak algorithm, policy denial, and internal invariant failure.

The public client may receive a coarser disclosure class than the internal audit path, but both should derive from the same stable enum rather than free-form text. Error mapping must not turn resource exhaustion into certificate failure or timeout into cryptographic failure. Typed errors also determine whether retry is safe, whether another address may be attempted, and whether policy should quarantine the origin.

### TLS audit records

The audit schema defines TlsEstablished and TlsFailed kinds, and helper methods exist for both. The fetch service does not call those helpers. Successful and failed TLS decisions therefore leave no dedicated fetch audit record. A failure eventually becomes a generic InternalError through the FetchOutcome error path, while success is represented only by the caller-facing event.

That gap is important because event delivery is lossy and client-controlled polling is not durable evidence. TLS identity is a kernel trust decision and should remain reconstructable even if the client crashes, the event queue fills, or a later response error occurs.

The existing audit entry cannot carry sufficient TLS identity by itself. It stores session, request, kind, and a thirty-two-byte note. A production TLS audit record needs structured fields or linked evidence for hostname digest, endpoint address, negotiated version and cipher, validation-policy generation, trust-anchor identifier, leaf fingerprint, hostname verdict, chain verdict, failure phase, failure reason, and whether weaker development policy was active.

Audit ordering should follow the trust transition. A handshake-start or validation-start record may be useful for timeouts. A failure record should occur before returning the terminal fetch error. An authenticated-success record should occur before HTTP request bytes are sent. Closure and post-handshake integrity failures should be associated with the same request and session.

The audit path must not claim Established under the current implementation. Until certificate and hostname validation exist, it should record validation-unavailable and block production HTTPS. If an explicit development mode allows encryption without identity, the audit kind must name that weaker state directly rather than presenting it as authenticated TLS.

## Fetch cache keys, freshness, and revalidation

The response cache is designed as a session-partitioned, fixed-memory accelerator for small GET responses. It owns thirty-two metadata entries, a shared two-mebibyte body pool, and a maximum cached body size of 256 KiB. Each entry records session identity, a bounded URL-derived key, status, MIME type, ETag, Last-Modified, max-age, storage epoch, and a body range.

That design matches Oreulius’s preference for bounded state and explicit ownership. Cache memory cannot grow with hostile traffic, entries remain associated with one fetch session, and closing a session purges its metadata. The current implementation is not active end to end, however. The service checks the cache before network dispatch, but no fetch completion path calls the cache store operation. Under the current service call graph, ordinary fetches produce cache misses indefinitely unless another future path populates the cache directly.

The dormant code should not be activated without further hardening. The URL key is not a cryptographic digest. It is a 512-byte serialization buffer that silently stops copying when it fills. Long URLs can therefore collapse to the same stored prefix. The body pool is managed as a ring, but overlap invalidation occurs only when an allocation wraps to offset zero. Allocations made after a wrap can overwrite still-active entries farther into the pool without invalidating them. A cache hit can then return body bytes belonging to a later entry while retaining the earlier entry’s status and MIME metadata.

Cache-hit delivery has another integrity defect. The service reads a cached body into one 4096-byte event buffer, emits at most that prefix, and immediately emits Complete. Entries may contain up to 256 KiB. For bodies larger than one event, the is-last flag becomes false, but Complete still follows and the remaining cached bytes are never delivered.

| Cache layer | Current implementation | Production blocker |
|---|---|---|
| Population | Store operation exists but is not called | Cache is effectively read-only and empty |
| Key | Bounded URL serialization | Long-key collisions and missing request dimensions |
| Freshness | Tick-epoch comparison | Units are not HTTP seconds and zero means immortal |
| Validators | Stored helper values | No conditional requests or 304 merge path |
| Body pool | Shared ring allocation | Active entries can survive overwritten body ranges |
| Cache hit | One body event then Complete | Cached bodies above 4096 bytes are truncated |

A production cache needs an explicit admission and commit transaction. It should collect a fully validated response, decide whether policy permits storage, reserve body space without corrupting active entries, store complete key and metadata evidence, and publish the entry only after the body and metadata are internally consistent. Partial, malformed, unauthenticated, policy-blocked, or event-incomplete responses must never become cache entries.

The cache also needs a clear role. It should accelerate responses without becoming an alternate authorization path. Every hit must remain subject to current scheme, origin, transport-security, mixed-content, denylist, session, and content-handling policy. Cache state cannot preserve authority that the session no longer has.

### Session-scoped cache ownership

Each cache entry stores a session identifier. Lookup requires the same session identifier, replacement searches are session-specific, and session closure marks that session’s entries inactive. This prevents direct cache reuse across distinct active session identifiers.

The partition is useful but incomplete as a security model. Session identifiers are small numeric handles, and temporal restore reconstructs sessions while deliberately excluding cache contents. That exclusion avoids restoring stale body data, but the live cache still needs generation binding so a closed and later reused session identifier cannot inherit entries if cleanup fails or lifecycle ordering changes.

Session scope also does not capture every partition that affects web response identity. A response can depend on top-level origin, cookie state, authorization state, client profile, trust policy, content-filter policy, and request headers. Two requests inside one session may not be safely interchangeable merely because their URLs match.

The current cache purge only deactivates metadata. It does not clear body bytes or validator storage. That is normally acceptable if inactive ranges are never exposed, but sensitive cached content may remain in kernel memory until overwritten. A production privacy policy should decide when body ranges and metadata require zeroization.

Ownership should bind each entry to a session generation and relevant policy generations, not only a session number. If shared caching is added later, it should be a separate explicitly partitioned design rather than weakening the current session boundary.

### URL digest and cache key inputs

The cache calls its key a URL digest, but the value is a bounded byte serialization. It writes scheme, a colon, host, an explicit numeric port, path, and sometimes query into 512 bytes. Equality compares the stored length and bytes directly.

The serialization does not fail on overflow. Host and path are copied only while space remains. The query is omitted entirely unless the whole separator and query satisfy a strict less-than capacity check. Distinct long URLs can therefore produce the same key. This compounds the URL parser’s own truncation and normalization limitations.

The format lacks unambiguous component framing. Scheme and host have a colon separator, but host and path rely on the path beginning with a slash. A malformed accepted path or unusual authority representation can weaken that assumption. The key also always serializes the parsed port when nonzero, including default ports, while navigation history omits default ports. Cache identity therefore has its own serialization contract rather than sharing one canonical URL representation.

The key excludes request method, although lookup is currently attempted only for GET. It also excludes request headers, cookies, authorization state, redirect provenance, body, content negotiation, top-level site, policy generation, TLS identity, and server Vary semantics. The fetch protocol currently sends few request headers, but cookies and richer request metadata are expected parts of the subsystem design. Activating cache before those dimensions are modeled would create incorrect reuse.

| Key input | Current state | Required decision |
|---|---|---|
| Canonical URL | Partial bounded serialization | Exact canonical encoding or collision-resistant digest |
| Session | Compared separately | Bind session generation |
| Method | Implicit GET lookup | Include or enforce GET-only admission |
| Cookies and authorization | Excluded | Partition, bypass, or include a safe representation |
| Request headers | Excluded | Implement Vary-aware selection |
| Policy and TLS generation | Excluded | Bind or invalidate when trust changes |

Production keys should be built from a canonical, length-delimited representation and hashed with a collision-resistant digest while retaining enough evidence to confirm equality. A key match must not rely on a truncated prefix. Cache eligibility should reject responses whose request-dependent dimensions cannot be represented safely.

### Max-age freshness checks

Lookup computes age by subtracting the entry’s storage epoch from the current service epoch with saturation. When max-age is greater than zero, an entry is stale only when age is greater than max-age. When max-age is zero, the freshness check is skipped and the entry is returned indefinitely.

That zero behavior contradicts the entry comment, which says zero means revalidate always. Since revalidation is not implemented, zero should produce a miss, not an immortal hit. As written, the most conservative cache directive becomes the least restrictive state.

The epoch is incremented by each fetch-service tick, but the documentation does not establish that one epoch equals one second. HTTP max-age is measured in seconds. Comparing seconds to scheduler or service ticks produces environment-dependent freshness, and tick-rate changes alter cache lifetime.

The implementation does not parse Cache-Control or Age in the fetch path. It has no Date correction, response delay calculation, resident-time calculation, no-cache handling, no-store handling, private handling, must-revalidate behavior, stale controls, heuristic freshness, or shared-cache directives. The store caller supplies max-age directly, but no current caller derives it from validated response headers.

The boundary comparison should be explicitly defined. Treating age equal to max-age as fresh may or may not match the chosen HTTP age calculation, but it must be tested with the same units and rounding rules. Clock rollback, tick wrap, suspend, restore, and policy-generation changes also need defined invalidation behavior.

Production freshness should use a monotonic duration source calibrated to seconds and retain the response timing inputs required by the chosen HTTP caching subset. Until revalidation exists, max-age zero, no-cache, unknown freshness, and stale entries should all miss.

### ETag and Last-Modified revalidation

Cache entries contain fixed ETag and Last-Modified fields, and helper methods can copy those values out. The store operation truncates ETags to 128 bytes and Last-Modified values to sixty-four bytes. No service or transport code calls the helpers, emits If-None-Match or If-Modified-Since, recognizes 304 as a revalidation result, or merges 304 metadata into an existing entry.

The cache’s module description therefore overstates current behavior when it describes ETag and Last-Modified validation. The implementation stores optional validator-shaped bytes but does not revalidate.

Validator storage is not safely reset when an entry slot is reused. The store operation assigns new validator lengths only when new optional values are present. If a reused entry previously had an ETag or Last-Modified value and the new response omits it, the old length and bytes can remain associated with the new response. This is dormant while revalidation is unused, but it would produce conditional requests with stale validators after activation.

Truncation is unsafe for validators because byte identity matters. A shortened strong or weak ETag is a different validator. Last-Modified should be parsed and normalized under an HTTP-date policy rather than copied as arbitrary bytes. Duplicate and malformed validator headers must be rejected or ignored according to explicit field rules.

A production stale-entry path should select an eligible validator, build a structured conditional GET, and treat 304 as a metadata update that retains the prior body only after the response passes transport, TLS, header, origin, and policy checks. Revalidation failure should not silently extend freshness. A full 200 response should replace the entry transactionally.

### Cache isolation and policy bypass prevention

The service performs scheme and navigation-origin checks before cache lookup. That ordering prevents a simple hit from bypassing those two checks. Other policies are not applied on the hit path. The denylist is checked inside the network fetch pipeline, so a cached entry can bypass a denylist change. TLS is not re-evaluated, mixed-content context is not evaluated, content filtering is not rerun, and policy generations are not part of the entry.

The hit path also synthesizes a reduced response. It emits stored status and MIME type, a content length equal to the cached body, and an empty header array. Security and application semantics from Cache-Control, Content-Disposition, Content-Type parameters, validators, cookies, redirects, and other response headers are absent. A response originally classified as a download or otherwise restricted could be presented differently when served from cache unless classification evidence is stored and reapplied.

Cache insertion is currently absent, so these bypasses are latent. They become immediate once store is connected to fetch completion. Admission must not be added before the hit path reproduces the same policy-relevant decisions as a validated network response.

The body-pool corruption risk can itself cross isolation boundaries inside a session. Metadata for one URL may point at bytes overwritten by another entry. Session comparison still succeeds, but the wrong resource is returned under the requested URL’s status and MIME type.

Production entries should bind the response to the policy, trust-store, TLS-verdict, cookie, and content-classification generations that affect reuse. A hit should either prove those bindings remain valid or rerun the necessary checks. Policy changes should invalidate or bypass incompatible entries.

Cache events must also preserve delivery integrity. A hit should stream the entire body through the same observable backpressure path as a network response. It must not emit Complete after one prefix, and it must report queue overflow or fail visibly.

## Fetch cookie matching, isolation, and request attachment rules

Cookie handling is present as a bounded state component, but it is not yet part of the operational fetch pipeline. The service owns one fixed-capacity cookie jar, records a session identifier on every entry, purges entries during explicit session close, and includes cookies in temporal snapshots. The jar also contains parsers and selectors for Domain, Path, Secure, SameSite, and Max-Age. These pieces establish a useful no-allocation foundation, but the current response path never processes Set-Cookie fields and the request builder has no way to add a Cookie field. No ordinary navigation can therefore create or send a cookie through the service.

That distinction matters when evaluating the security claims in the module. Secure and SameSite checks exist inside the unused header-building helper, while HttpOnly is stored but never interpreted by an access boundary. The helper-level rules are not end-to-end enforcement until every accepted response mutation and every outbound request passes through them. Oreulius should treat the jar as dormant policy machinery rather than a completed cookie subsystem.

| Concern | Current code surface | Production assessment |
|---|---|---|
| Storage ownership | One global bounded jar with a session identifier on each entry | Useful isolation primitive, but not generation-bound |
| Response ingestion | Set-Cookie splitting and attribute parsing helpers exist | Not connected to response processing |
| Request attachment | A cookie selection and serialization helper exists | Not connected to HTTP request construction |
| Scope enforcement | Domain, path, Secure, SameSite, and expiry checks exist in the jar | Several rules are incomplete or incorrect |
| Persistence | Active entries are serialized and restored | Restore bypasses normal acceptance policy |
| Audit | A CookieSet audit kind and helper exist | No live cookie operation emits it |

The production design should keep cookie mutation and request attachment inside the trusted service boundary. Response headers must first pass complete header validation, then each Set-Cookie field must be parsed independently under dedicated quotas. The accepted request URL, response origin, request context, current trusted time, and session generation must all be available at that point. Outbound attachment must run after URL normalization and redirect resolution so that every target receives a fresh cookie selection. Cache behavior must also account for cookie state rather than reusing a response under a context that no longer matches the request that created it.

### Session-scoped cookie storage

Cookie entries carry a SessionId, and every lookup, update, deletion, attachment, and purge operation compares that identifier. Explicit session close calls purge_session before returning, which removes active entries associated with the closing session. The jar has a global maximum of 128 active entries, with fixed buffers for names, values, domains, and paths. This matches Oreulius’s preference for bounded kernel memory and makes capacity exhaustion predictable.

The ownership boundary is weaker than it first appears. Session identifiers are reusable values rather than generation-bearing identities, so stale cookies can become associated with a later session if lifecycle cleanup fails or restored state introduces an old identifier. The single global quota also permits one session to consume every slot and deny storage to all other sessions. Inactive entries retain their previous bytes, including cookie values that may contain authentication material, because deletion and purge only clear the active flag.

Insertion silently truncates names, values, request hosts, domains, and paths to their field capacities. Cookie identity is then computed from the truncated name and domain. This can merge distinct remote cookies, store a value different from the one the server supplied, or scope a cookie to a modified host. A security-sensitive state store must reject oversized fields before mutation. It must also validate cookie names, values, control bytes, prefixes, and reserved syntax rather than accepting arbitrary byte slices.

Replacement identity currently consists of session, name, and domain, but omits path. Two cookies with the same name and domain but different paths are valid distinct records; the current update path collapses them into one entry. Deletion has the same omission and can remove the wrong path variant. Name comparison is case-sensitive during replacement and case-insensitive during deletion, creating inconsistent identity rules.

Temporal persistence expands the ownership boundary. Snapshot records include all active cookies, including session cookies whose lifetime would normally end with the browsing session. Restore inserts entries directly without confirming that the referenced session was restored, that the cookie is unexpired, that its domain and path remain valid, or that Secure and prefix rules hold. Snapshot authenticity and rollback protection are therefore prerequisites for treating restored cookies as trusted authentication state.

### Domain and path matching

The attachment helper compares request hosts case-insensitively and permits either an exact match or a label-boundary suffix match. Its path helper accepts the root path, exact equality, or a prefix followed by a slash. Those matching functions capture part of standard cookie behavior and avoid the obvious sibling-domain error in which example.com would match notexample.com.

Storage does not establish the information needed to apply those rules safely. When Domain is absent, the jar copies the request host into the domain field, but it does not record that the cookie is host-only. Attachment consequently treats a host-only cookie as a domain cookie and sends it to subdomains. When Domain is present, set accepts it without checking that it domain-matches the response host. A response from one origin can therefore construct a cookie scoped to an unrelated domain if the helper is activated as written.

Domain attributes are copied without ASCII lowercasing, canonical host conversion, IP-address handling, trailing-dot policy, empty-value rejection, or public-suffix validation. Oversized domains are truncated rather than rejected. The code strips one leading dot, which is compatible with modern matching semantics, but that normalization is not enough to make the resulting scope trustworthy.

Path behavior is also incomplete. An absent Path produces an empty stored path, and an empty path bypasses path matching entirely, effectively making the cookie valid for every request path. Standard behavior derives a default path from the request URL. An explicitly malformed Path that does not begin with a slash should use the default-path rule rather than becoming an unrestricted value. The matching helper itself mishandles cookie paths that end in a slash: a cookie path such as directory slash should match deeper descendants, but the current boundary check examines the next request byte and rejects them.

Cookie ordering is unspecified. The serializer walks physical jar order rather than sorting longer paths before shorter paths and older creation times before newer ones. The entry does not retain creation time, so deterministic standard ordering cannot be reconstructed. This affects servers that intentionally use the same cookie name at multiple path scopes.

### Secure, HttpOnly, and SameSite enforcement

Secure has two helper-level checks. The set path rejects a Secure cookie received over a non-HTTPS request, and the attachment path suppresses Secure cookies for non-HTTPS targets. The second rule is essential. The first is stricter than common browser behavior in some localhost cases, but a kernel service may choose that stricter contract if it documents it and applies it consistently.

The current implementation does not protect existing Secure cookies from insecure overwrite. Replacement identity does not account for the security of the setting channel, so a non-Secure cookie received over HTTP can replace a Secure cookie with the same current identity. Prefix constraints are also absent. Cookies beginning with the Secure prefix should require Secure and a secure origin, while cookies beginning with the Host prefix should additionally reject Domain and require the root path.

HttpOnly is only a stored bit. It does not affect network attachment, which is correct because HttpOnly cookies still accompany HTTP requests. Its protection belongs at every non-network cookie API that can expose or mutate state. No such API currently exists, so the field has no active enforcement surface. Any future inspection, scripting, debugging, extension, or storage interface must omit HttpOnly values and prevent untrusted callers from replacing them through a weaker path.

SameSite enforcement is an approximation expressed as one boolean named is_cross_site. Strict cookies are suppressed in that context, Lax cookies are always allowed, and None cookies are allowed only when Secure. This cannot represent the information required for correct decisions. Lax depends on whether the request is a top-level navigation, whether the method is safe, and in some compatibility models how recently the cookie was created. Site calculation depends on the scheme and registrable domain, not merely origin inequality. Redirect chains also require a defined site-for-cookies policy across every hop.

Unknown SameSite values are converted to Lax, while missing values also default to Lax. That is a defensible fail-safe default, but malformed values should be distinguished from a valid Lax declaration for diagnostics and conformance. The set path should reject SameSite=None unless Secure is present instead of storing a cookie that can never be attached cross-site. None of these checks currently affect real traffic because neither storage nor attachment is integrated.

### Expiry and purge behavior

The attribute parser recognizes Max-Age and computes a saturating absolute expiry from the service epoch. A non-positive Max-Age deletes a matching cookie, and attachment lazily deactivates expired entries before selection. Explicit session close purges entries for that session. These operations provide a simple bounded lifecycle without background allocation.

The time model is not production-ready. The service epoch advances through kernel ticks rather than a defined wall-clock second source, while Max-Age is specified in seconds. Cookie expiry therefore depends on tick cadence and may not survive reboot or temporal restore coherently. The comparison uses current time greater than expiry, so a cookie remains eligible at the exact expiry value; expiration should occur when current time is equal to or later than the deadline.

Expires is not parsed at all. Cookies that rely on an HTTP date become session cookies, and when both Max-Age and Expires are present the required precedence cannot be implemented. The integer parser accepts a bare minus sign as zero, saturates overflow, and has no leading-plus policy. Saturating a remote duration into an effectively permanent deadline is not a sound failure mode.

Lazy expiry only runs when the attachment helper is called. Because attachment is disconnected, expired entries are never reclaimed during normal navigation. A full jar can therefore remain full of expired records, and set does not purge expired entries before rejecting new storage. Deletion omits path and stops after the first match. Session-cookie lifetime is also contradicted by temporal snapshots, which persist entries with an expiry of zero and restore them as active.

Production handling needs one trusted time abstraction with documented units, overflow behavior, suspend and resume semantics, and snapshot conversion rules. Expired entries should be removed before quota decisions, during lookup, and during controlled maintenance. Deletion and replacement must use the complete cookie key, and all deactivated records containing sensitive values should be cleared.

### Public suffix and registrable-domain limitations

The cookie subsystem has no public suffix data and no registrable-domain calculation. Domain acceptance can therefore permit scopes such as a top-level suffix or a shared hosting suffix. If activated without further validation, one tenant could set cookies that reach unrelated tenants beneath the same suffix. This is a direct isolation failure, not only a compatibility gap.

The same missing primitive prevents correct SameSite classification. Same-site relationships use schemeful sites based on registrable domains, while cookie Domain matching uses host and domain rules. Both features need the same canonical host representation and a maintained public suffix source, but they must apply different final comparisons. Treating same-origin, suffix matching, and same-site as interchangeable would either leak cookies or block valid requests.

Oreulius should make the public suffix data part of a versioned policy component rather than embedding ad hoc exceptions in the jar. The component needs a defined update and rollback model, deterministic behavior when data is unavailable, support for private suffix policy where required, and tests against a pinned conformance corpus. Cookie acceptance must fail closed for Domain attributes whose safety cannot be established. Host-only cookies can remain available without public-suffix lookup because they cannot widen scope beyond the response host.

Registrable-domain logic must operate after the URL layer has canonicalized DNS names. Internationalized names, trailing dots, IP literals, localhost-style names, and invalid labels need explicit policy. The result should feed cookie Domain validation, SameSite context construction, redirect credential decisions, cache partitioning, and audit evidence so those subsystems do not disagree about site identity.

## Fetch storage authority and per-session VFS mapping

The storage module provides a bounded registry of VFS-backed key-value views, but it is not yet an operational fetch-service feature. Each view constructs file paths beneath a browser directory from a numeric session identifier, validates a short filename-like key, and delegates reads, writes, and deletion to the kernel VFS. The service registers a view when it opens a session and unregisters it when the session closes. No FetchRequest variant exposes those operations, no fetch or response path uses them, and the protocol’s generic StorageError variant is never returned by live storage handling.

The implementation also describes itself as per-origin storage while partitioning only by SessionId. That is a material design mismatch. A session may navigate across origins, yet every origin in that session would resolve the same key to the same file. Conversely, closing and reopening a session can assign the same numeric directory to a different logical owner. The current path layout therefore provides neither durable origin identity nor durable session identity.

| Boundary | Current mechanism | Production consequence |
|---|---|---|
| Registry ownership | Fixed table keyed by SessionId | Bounded, but not generation-safe |
| Filesystem partition | Decimal session directory beneath the browser root | Not origin-scoped and vulnerable to identifier reuse |
| Caller authority | No storage IPC operations exist | Helpers are dormant rather than externally enforced |
| VFS authority | VFS evaluates the current process context | Logical fetch-session authority is not independently represented |
| Persistence | Unregister leaves all files intact | Data can outlive the authority that created it |
| Temporal state | Storage table and files are excluded from fetch snapshots | Restored sessions are not remapped to persisted storage |

Oreulius should first define which storage product this module implements. Ephemeral session storage should use a non-reusable session-generation namespace and remove its files when that session ends. Durable web storage should partition by a canonical origin or storage key, bind access to the current top-level and requesting origins, and use a stable profile or principal identity rather than a transient session number. One directory layout should not attempt to provide both lifetimes implicitly.

The fixed-array registry and stack-only path construction fit the kernel’s bounded-resource philosophy. The missing work lies in authority composition, lifecycle atomicity, quotas, and persistence semantics. Every storage operation must combine a verified fetch capability, a live session generation, an authorized origin context, a canonical storage partition, and VFS rights. Failure at any layer must stop the operation without creating partial state.

### Session storage registration

StorageTable contains sixteen slots, matching the current fixed upper bound used by the session service. Registration selects the first inactive slot, constructs its base path, attempts to create the directory, and records the entry. Lookup and unregister compare SessionId. This is simple, deterministic, and allocation-free.

Registration is not transactional. The call to ensure_dir discards its result, and do_open_session discards the boolean returned by register. The service can grant a session capability, install origin policy, and report success even when the registry is full, the browser root does not exist, VFS authority rejects creation, or the filesystem fails. Later storage lookup would either return no view or encounter write failures, but the caller receives no evidence that session initialization was incomplete.

The directory creation comment says mkdir is idempotent, but the VFS path needs an existing parent and its exact existing-directory behavior must be treated as part of the contract rather than assumed. No storage initialization creates the browser root. A clean system can therefore fail while attempting to create the per-session child directory. Registration also does not detect a duplicate active SessionId and can install multiple entries for the same session if called twice.

A production open operation should stage every required subsystem, including storage, and commit the session only when all mandatory registrations succeed. Failure should roll back the session slot, origin entry, storage mapping, and any directory created during the attempt. If storage is optional, the granted session must carry an explicit disabled state rather than silently presenting a partially initialized service.

Restored sessions currently receive no registration. Temporal restore reconstructs the session table, cookies, and downloads but excludes StorageTable, and no post-restore pass calls register for restored session identifiers. Any future storage request made by such a session would lack a registry entry even if matching files remained in VFS.

### Browser storage root layout

The code declares STORAGE_ROOT as the browser directory, but path construction duplicates the literal prefix instead of using that constant. Each base path is the root, a decimal SessionId, and a trailing slash. A key is appended directly as one final path component. Fixed buffers are large enough for the current u32 identifier and 64-byte key, so build_base_path should not truncate valid present-day identifiers.

The root constant is descriptive rather than authoritative. Nothing creates the root, verifies its inode type, checks its ownership and mount properties, or prevents another kernel component from pre-populating session-number directories. The storage wrapper relies on the general VFS authority checks applied to the current execution context. It does not establish a separate capability boundary for the fetch service’s logical session or origin.

Numeric session directories are unsafe for persistent data because session identifiers encode allocator position rather than durable ownership. When a closed slot is reused, a new process can be mapped to files left by the previous session. Explicit close unregisters only the in-memory view and deliberately leaves VFS files in place. This turns ordinary session reuse into a potential cross-principal disclosure path as soon as read operations become reachable.

An origin-aware durable layout needs a versioned namespace derived from a stable profile identity and a canonical storage partition. Raw origins should not become path components. A collision-resistant digest or an internal assigned identifier should map canonical scheme, host, effective port, and any top-level-site partition to a directory whose metadata records the full identity. An ephemeral layout should instead use a cryptographically unpredictable or generation-bearing session namespace and delete the directory on teardown.

The layout also needs filesystem invariants. The service should create and verify the root during initialization, refuse symlink or unexpected inode substitution, use no-follow operations where relevant, constrain storage to an approved mount, and define behavior across mount replacement, corruption, read-only transitions, and recovery. Directory creation and metadata initialization should be atomic enough that a crash cannot leave an apparently valid partition with incomplete ownership evidence.

### Storage key validation

validate_key rejects empty keys, keys longer than 64 bytes, ASCII control bytes, delete, forward slash, and backslash. This blocks direct path separators, NUL injection, and most obvious traversal strings. key_path then appends the accepted bytes to a fixed 128-byte buffer and passes only the calculated non-NUL prefix to the VFS.

The stated rule of printable ASCII is broader than a conservative filename grammar. It accepts spaces, a key consisting only of dots, double-dot tokens, colon, wildcard characters, quotes, shell metacharacters, and bytes above ASCII delete. The check only rejects values below space and exactly delete, so values from 128 through 255 pass validation and then fail UTF-8 conversion later as PathTooLong. That error classification is inaccurate and makes validation dependent on a second unrelated conversion.

The VFS normalizes paths after the storage wrapper constructs them. A key equal to double dot is therefore particularly dangerous: it contains no slash and passes validation, but the resulting path can normalize to the parent browser directory. A single dot can normalize to the session directory itself. Read, write, or unlink against those normalized paths can escape the intended final-file namespace or operate on a directory. Relying on separator rejection is insufficient when the downstream path layer interprets dot components.

Production key validation should use an allowlist that produces exactly one ordinary VFS component under all supported normalization rules. It should reject dot and double dot, leading or trailing whitespace, non-ASCII bytes unless a canonical encoding is deliberately supported, reserved device-like names where relevant, and any representation that changes under VFS normalization. The normalized full path should then be checked to remain an immediate child of the expected base directory.

If the intended API models browser key-value storage rather than files, arbitrary web keys should not be treated as filenames at all. The service can encode key bytes into a safe internal filename or store records in a bounded database format while retaining the original key separately. That separates web-visible key semantics from filesystem syntax and avoids future incompatibility when callers need Unicode or longer keys.

### Read, write, and delete authority

OriginStorage exposes direct read, write, and delete methods. They validate the key, construct a path, and call VFS operations that perform their own path normalization and process-based rights checks. Writes replace an existing file through write_path, reads copy up to the caller-provided output capacity, and delete unlinks the path.

The methods receive no session capability, process identity, origin, storage partition, or operation-specific policy. Their only scope comes from the OriginStorage object selected by StorageTable. This can be adequate as an internal capability if the object never crosses a trusted boundary and lookup occurs only after full request authorization. The service currently has no storage dispatcher, so that composition has not been implemented or tested.

Calling the VFS from the fetch service introduces a confused-authority risk. VFS authorizes the current process context, while the logical operation belongs to the process and fetch session named in an IPC request. The storage layer must prove that the VFS subject corresponds to the requesting principal or use an explicit delegated VFS capability scoped to the storage partition. A kernel service must not accidentally perform client-directed file operations with broader service authority.

VALUE_MAX claims to limit a single write to 64 KiB, but write never checks it. Oversized values are passed directly to VFS. There is no per-key, per-origin, per-session, or global storage quota; no file-count limit; no reserve accounting; and no rate limit. A reachable interface could consume filesystem capacity even though the registry itself remains bounded.

Reads cannot distinguish a complete value from a truncated value because read_path returns the number copied into the caller’s buffer without exposing the stored file size. A small output buffer can therefore produce a successful prefix. Writes have no compare-and-swap, generation, transaction, fsync, or atomic replacement contract. Concurrent callers can lose updates, and crash behavior depends entirely on VFS persistence. Delete maps every failure to VfsError rather than distinguishing absence, authority failure, wrong inode type, and backend failure.

Production operations need typed requests and responses with explicit lengths, complete-value semantics, quotas, and stable errors. Authorization must occur before path construction and again at the VFS boundary. Reads should report required size or fail when the supplied buffer cannot hold the complete value. Writes should enforce declared limits before touching VFS and use atomic replacement where durable semantics require it. Audit records should identify the session, origin partition, operation, bounded key digest, byte count, and result without exposing stored values.

### Storage cleanup and temporal interaction

Explicit session close removes only the StorageTable entry. It does not delete files, clear directory metadata, revoke a durable partition, or verify that no in-flight operation still holds a cloned OriginStorage. Because OriginStorage implements Clone and contains only a path, unregister is not a revocation mechanism for copies already handed out inside the kernel.

The service also lacks forced cleanup on process death in this code surface. If the owner exits without CloseSession, the registry entry and its session mapping can remain active until some external lifecycle integration removes them. Even when close runs correctly, persistent files survive and can be inherited when a numeric SessionId is reused. Cleanup must therefore address both in-memory authority and filesystem lifetime.

Temporal snapshots intentionally exclude StorageTable because VFS data already persists independently. Restore rebuilds sessions with their old identifiers but does not recreate registry mappings or verify the corresponding directories. This creates several inconsistent states: restored authority with no storage view, old files with no authenticated owner, a reused identifier pointing at stale files, or a rolled-back session observing storage written after the snapshot. VFS persistence and fetch temporal state currently have no shared generation or rollback protocol.

The correct interaction depends on the chosen storage product. Ephemeral session storage should be excluded from snapshots, revoked on temporal transition, and deleted when its session lifetime ends. Durable origin storage may remain outside the fetch snapshot, but restored sessions must reauthorize it from canonical origin and profile identity rather than from old SessionIds. Snapshot rollback must not roll storage authority backward or expose newer data under older policy without an explicit consistency model.

Cleanup should revoke registry access first, wait for or cancel in-flight operations, and then apply the configured retention policy. Deletion needs recursive, no-follow semantics constrained to the verified partition root. Failures must remain visible for retry and audit rather than being converted into successful session closure. Durable retention should preserve data while removing session bindings; ephemeral retention should remove both metadata and contents securely enough for the backing medium’s threat model.

Production tests must exercise session reuse, duplicate registration, missing roots, directory-creation failure, VFS denial, process death, cloned handles, concurrent close and write, partial reads, quota exhaustion, temporal restore, rollback, stale directories, symlink substitution, mount changes, and proof that one origin or principal cannot observe another partition.

## Fetch download destination, filename, and quarantine policy

The download subsystem currently consists of a bounded job table, protocol variants for offering and completing downloads, response classifiers, and accept or reject dispatch. Those pieces describe a sensible consent boundary: remote content should not become a local file until the owning session chooses a destination. The live fetch path does not yet implement that boundary. It emits response headers and body chunks inline for every non-redirect response, never creates a DownloadJob, never emits DownloadOffered, never diverts body bytes into a retained stream, and never writes accepted content to VFS.

AcceptDownload therefore changes only in-memory metadata. It copies the caller’s destination bytes, marks the job Active, and returns success. No destination validation occurs, no file is opened, and no data source exists for a later writer. The methods for progress, completion, error, and destination lookup have no call sites. The audit helpers for offered and completed downloads are similarly disconnected.

| Stage | Implemented state | Missing production behavior |
|---|---|---|
| Classification | Content filter and size policy can classify downloads | Fetch never calls them |
| Offer creation | DownloadManager can allocate a bounded pending job | No live code creates an offer |
| User consent | Accept and reject requests verify session capability | Accept does not validate or reserve a destination |
| Data transfer | Progress and completion methods exist | No response-body retention or VFS writer exists |
| Completion signal | DownloadComplete event and audit kind exist | Neither is emitted |
| Persistence | Active jobs are included in temporal snapshots | Restored jobs are not reconciled with files or network state |

This architecture can fit Oreulius well once the service makes the trust transition explicit. Fetching remote bytes and granting local write authority are separate operations. The kernel should classify and quarantine the remote object first, expose bounded evidence to the client, and begin a destination write only after capability validation and user consent. A destination path must select among authority the caller already holds; it must never create authority merely because the caller supplied a string.

**Remote evidence:** Source URL, redirect chain, TLS verdict, declared and sniffed media types, response headers used for classification, expected size, actual size, and content digest.

**Local authority:** Verified session generation, authenticated caller, delegated VFS rights, allowed destination root, overwrite policy, and atomic-write capability.

**Commit evidence:** Final path identity, bytes written, digest of committed bytes, completion time, quarantine metadata, and a terminal state that cannot be confused with an interrupted transfer.

The implementation should keep these evidence classes distinct. Remote metadata must not authorize a local filename or execution context, and a local path capability must not weaken content classification. The completed file should carry enough provenance for later launch, indexing, sharing, or scanning policy to make an independent decision.

### Download offer lifecycle

DownloadManager reserves sixteen fixed slots and allocates wrapping nonzero DownloadIds. offer records session, request, suggested filename, declared MIME, size hint, and Pending state. accept requires the matching session and Pending state before changing the job to Active. reject verifies the session, marks the job Rejected, and frees the slot by clearing active. Explicit session close purges all active jobs for that session.

The state model is useful but not enforced as a complete transition system. record_progress, complete, and error identify jobs only by DownloadId, without session, request, generation, writer token, or expected current state. Progress can be recorded on Pending, Complete, or Error jobs. complete can mark a Pending or errored job complete. Error clears active immediately, which removes the only queryable record of the failure, while Complete remains active indefinitely and consumes a slot.

DownloadId allocation wraps and checks neither existing identifiers nor generation. After enough offers, or after temporal restore advances next_id near wraparound, a new job can reuse an active identifier. get and internal progress operations search globally by id, so an identifier collision can mutate the wrong session’s job. Session checks on accept and reject reduce direct caller confusion but do not protect internal completion paths.

The live fetch pipeline has a deeper lifecycle gap. Classification must happen before body bytes are released inline, but useful MIME sniffing may require initial body bytes. The service needs a bounded preclassification buffer and a decision point that either commits to inline delivery, blocks the response, or creates a quarantined download stream. It must not emit body chunks to the client and later reinterpret the same response as a download.

An offer also needs ownership of the remote stream. The current synchronous fetch_request consumes and closes the transport before the client can accept. Production code must choose between bounded temporary quarantine storage, a resumable refetch after consent, or an asynchronous suspended transfer with strict resource limits. Holding a network connection open indefinitely while waiting for user input is not a robust default.

**Pending:** Classification completed, evidence captured, and content retained safely or reproducibly, but no destination authority granted.

**Accepted:** Destination capability validated and an exclusive writer transaction created. This should be distinct from Active if setup can fail.

**Active:** Bytes are moving from the quarantined source into the authorized temporary destination.

**Complete:** Size and digest verification succeeded, metadata was attached, and an atomic commit made the final file visible.

**Rejected, cancelled, expired, and failed:** Each should be a terminal state with reason evidence and deterministic cleanup. Terminal records may remain for bounded observation before reclamation.

Pending offers need deadlines and resource accounting. Closing the session, aborting the request, process death, temporal transition, storage pressure, or policy change must either cancel the offer or move it into a separately authorized durable queue. Every transition should emit correlated events and audit records, including failures to enqueue those records.

### Session ownership checks

AcceptDownload and RejectDownload first verify the session capability in the service, then DownloadManager verifies that the job’s SessionId matches the supplied session. This two-layer check is the strongest implemented part of the download flow. A caller with one valid session cannot accept or reject a job recorded under another session merely by guessing its DownloadId.

The ownership model still relies on reusable SessionIds and does not bind jobs to a session generation, authenticated process identity, origin, or profile. A stale or restored job can become associated with a later session that receives the same numeric identifier. Temporal restore directly inserts jobs and does not confirm that their owning sessions were restored. It also resets RequestId to zero, removing the original request correlation.

Internal mutation is less constrained than client mutation. record_progress, complete, error, get, and dest_path operate by DownloadId alone. Once a writer exists, it could update or retrieve a job across sessions if it receives a stale, collided, or attacker-influenced identifier. The write side needs an unforgeable transfer capability bound to the exact job generation, session generation, source object, destination transaction, and expected state.

Ownership must continue through every asynchronous boundary. The process that accepts a download may exit while network, scanning, or VFS work continues. Session close currently clears the job record but has no writer to cancel, no temporary file to remove, and no completion callback to suppress. Production teardown must revoke the transfer token, cancel outstanding work, prevent later completion events from entering a reused session queue, and retain enough terminal evidence to explain partial files.

Download visibility also needs policy. A session-scoped job table should not make a completed durable file session-owned by accident. The final file belongs to the principal represented by the delegated VFS capability, while job status belongs to the originating session or durable download controller. Those identities may differ and should be recorded explicitly.

### Destination path validation

The protocol accepts a 256-byte destination array and a separate length. Service dispatch slices the array using dest_len before any validation, so a malformed in-kernel request with a length greater than the array capacity can panic. The broader protocol boundary must validate every supplied length before slicing.

DownloadManager accept then copies at most 256 bytes and silently truncates longer paths. It accepts empty paths, NUL bytes, invalid UTF-8, relative paths, traversal components, device-like paths, directories, symlinks, mount boundaries, and destinations outside any approved download root. Because no VFS call follows, these values currently remain inert metadata. Connecting a writer without replacing this behavior would create an unsafe file-write interface.

A path string cannot serve as write authority. The caller should provide or select a VFS capability whose rights and root are already constrained. The service should resolve the destination under that delegated subject, use no-follow semantics for the final component and relevant parents, verify the mount and inode types, and bind the resolved object identity to the transaction. Re-resolving an untrusted string later creates time-of-check to time-of-use exposure.

Overwrite policy must be decided during reservation. If the target exists, the service should fail, create a unique sibling, or require an explicit replace permission. It should not inherit whatever overwrite behavior the generic VFS write helper happens to implement. Parent-directory write authority, target replacement authority, quotas, free space, filename limits, and filesystem support for atomic rename all belong in the acceptance result.

The safest write path creates a private temporary file in the authorized destination directory, writes and verifies content there, applies quarantine metadata, syncs according to policy, and atomically renames it to the reserved final name. The service must prevent symlink substitution and destination races between acceptance and commit. On any failure, the temporary object remains non-executable and is removed or retained under an explicit recovery policy.

**Reject before state change:** Empty or oversized paths, invalid supplied lengths, embedded NUL, invalid encoding, traversal, unsupported namespace forms, and destinations outside delegated authority.

**Resolve before transfer:** Parent identity, mount identity, existing target state, no-follow behavior, quota, free-space expectation, overwrite decision, and temporary-file support.

**Revalidate before commit:** Destination transaction generation, parent identity, target reservation, final size, digest, quarantine metadata, and caller revocation state.

### Suggested filename normalization

The content filter can scan Content-Disposition parameters for filename or filename-star, strip surrounding quotes, and copy at most 256 bytes. DownloadManager offer independently truncates any supplied filename to the same capacity. Neither function sanitizes path separators, control bytes, dot components, bidirectional controls, Unicode normalization, reserved names, trailing dots or spaces, dangerous extensions, or shell and desktop metacharacters.

The parser treats filename and filename-star identically. It does not implement the encoded character set and language syntax of filename-star, percent decoding, precedence between both parameters, escaped quoted-string characters, duplicate parameter policy, or malformed input rejection. It returns the first recognized parameter and silently truncates it. A remote server can therefore present a misleading, malformed, or path-shaped filename as trusted display metadata.

Suggested names should remain advisory. They must never be concatenated with a destination directory and written directly. The service should decode supported header forms under a strict bounded parser, preserve the raw header separately as evidence if needed, normalize the display name, remove all path semantics, and generate a safe fallback when no usable name remains.

Display safety and filesystem safety are related but distinct. A filename can be a valid single filesystem component while misleading the user through hidden extensions, right-to-left controls, confusable characters, or excessive whitespace. Oreulius should define a display form, an internal canonical name, and the actual reserved VFS name. UI layers should receive enough metadata to reveal executable or archive classifications rather than relying on the suffix alone.

Extension handling should not claim that a filename proves content type. A mismatch among filename extension, declared MIME, sniffed MIME, and signature should become evidence and may increase quarantine restrictions. Automatically rewriting extensions can also mislead users, so the policy should either choose a safe neutral suffix or present the mismatch explicitly.

### Overwrite, partial-write, and resume policy

No overwrite, writing, partial-file, or resume implementation exists in the download subsystem. accept marks a job Active before any destination operation succeeds. bytes_written is only an in-memory counter updated by an unused method, and complete does not compare it with size_hint. size_hint uses zero to mean unknown, which cannot represent a legitimate known zero-length response distinctly.

The network fetch currently streams body events and then closes the transport. It does not retain bytes for an accepted download. A production implementation must define where content lives between classification and destination consent. Temporary quarantine storage permits scanning and later atomic commit but consumes bounded disk space. Refetching after consent avoids retention but can retrieve different bytes unless validators, immutable URLs, digest expectations, and redirect policy are handled carefully. Suspending the connection preserves one response but creates unbounded connection and memory pressure.

Partial files should not appear at the final destination. Writing through a private temporary file prevents other processes from treating an incomplete executable or document as complete. The job should record source bytes received separately from destination bytes durably written, and completion should require expected framing, final decoded length, digest finalization, successful metadata attachment, and atomic publication.

Resume is a protocol, integrity, and authority feature rather than a counter. Safe resume requires a stable source identity, validators such as a strong ETag, verified Range semantics, known partial length, retained hash state or rehashing, unchanged destination authority, and protection against servers returning a full or different representation. Until those pieces exist, production policy should reject resume and restart into a new temporary transaction.

Overwrite should default to no replacement. Explicit replacement needs stronger VFS authority and must preserve atomicity so a failed download does not destroy the existing file. Unique-name generation must happen under directory synchronization, not by checking a name and later creating it. All terminal paths must define cleanup for temporary data, including cancellation, write errors, scanner failure, process death, reboot, and temporal restore.

| Failure point | Required file state | Required job state |
|---|---|---|
| Before destination reservation | No local file | Pending or terminal rejection |
| Temporary-file creation failure | No final file | Failed with VFS evidence |
| Mid-transfer interruption | Hidden quarantined partial only | Failed, cancelled, or resumable |
| Integrity or scan failure | No published final file | Blocked or failed |
| Metadata attachment failure | No published final file | Failed |
| Atomic commit failure | Existing target unchanged | Failed with recoverable temporary state policy |

### MIME, source URL, and quarantine evidence

DownloadJob stores only declared MimeType, suggested filename, size hint, destination path, byte count, session, request, identifier, and state. It does not store the source URL, final URL after redirects, redirect chain, response status, TLS evidence, declared Content-Disposition, sniffed MIME, signature classification, content digest, timestamps, cache provenance, policy generation, scanner result, or quarantine state.

The content filter can classify a small set of signatures as executable, archive, image, HTML, or unknown, but the fetch path never invokes it. Its current policy maps executable and archive signatures to Download rather than Block, and SniffResult includes Block without any classify branch returning it. Download should not imply safe. Executables, scripts, archives, disk images, and active documents require a quarantine and launch-policy decision after transfer, even when the user requested the file.

Quarantine metadata should be attached before the final file becomes visible and should survive rename, reboot, copying where supported, and temporal operations according to system policy. At minimum it should identify the untrusted remote origin, final source URL, acquisition time, transport trust result, content digest, media classifications, and scan disposition. If the VFS lacks extended attributes, Oreulius needs a protected sidecar or metadata service whose updates are transactional with file publication.

Source evidence must use the canonical effective URL and retain bounded redirect provenance. Recording only the initial URL can hide cross-origin or downgrade transitions. TLS evidence should identify the verified peer and trust generation without persisting unnecessary certificate material. Declared and sniffed MIME values should remain separate because their disagreement is itself security evidence.

Temporal snapshot currently serializes active download jobs, including Pending, Active, Complete, and Error states, destination paths, and byte counters. Restore trusts those fields, marks every record active, removes request correlation, and performs no file or source reconciliation. An Active job can reappear without a network stream or writer, and a Complete job can reappear without proving that the destination file exists or matches. Production restore should conservatively convert interrupted jobs to a recoverable terminal state unless a durable transfer journal proves the exact source, temporary file, byte range, digest state, destination transaction, and owner.

**Audit privacy:** Record bounded digests or internal identifiers for sensitive paths and URLs where full values would expose user data.

**Integrity evidence:** Bind the digest to the exact decoded bytes committed, not merely transport chunks or an unverified server header.

**Policy evidence:** Record the classifier, scanner, trust-store, content-policy, and quarantine-policy generations used for the decision.

**Release evidence:** Record who or what removed quarantine, under which authority, and whether the content changed afterward.

## Fetch abort, cancellation, and in-flight request cleanup

The fetch protocol exposes AbortRequest and defines an Aborted failure kind, but the service does not currently cancel requests. do_abort verifies the session capability, appends a RequestAborted audit record, and returns success without checking whether the request exists, whether it belongs to that session, whether it is still running, or whether any work stopped. No FetchError carrying Aborted is emitted.

The scheduling model prevents meaningful concurrent aborts. The public dispatcher locks the global fetch service and calls do_navigate while holding that lock. do_navigate executes DNS resolution, connection setup, TLS, request sending, response parsing, and body streaming synchronously before it returns RequestAccepted. Another caller cannot acquire the same service lock to submit AbortRequest during that interval. By the time abort dispatch can run, the network operation has completed or failed and its events have already been queued.

| Cancellation surface | Current state | Actual abort effect |
|---|---|---|
| Active-request registry | Absent | RequestId cannot be resolved to work |
| DNS, TCP, and TLS | Blocking or polling inside fetch_request | No cancellation observation |
| HTTP parsing and body reads | Synchronous local loops | No cancellation observation |
| Cache-hit delivery | Events queued immediately | Already complete before abort |
| Downloads | Separate job table | Abort does not inspect or cancel jobs |
| Event queue | Session ring without removal API | Existing events remain queued |
| Terminal event | Aborted kind exists | Never emitted by abort |
| Audit | RequestAborted is recorded | Records intent, not confirmed cancellation |

The code comment promising that a session will see no more events after AbortRequest is not enforced. do_abort does not touch the queue, fetch state, transport, downloads, cache, navigation history, or origin state. It also returns success for arbitrary RequestIds, including zero, future identifiers, completed requests, requests owned by another session, and identifiers that wrapped into reuse.

Cancellation should become a first-class lifecycle transition. Navigation must register a request before starting work, return control to the dispatcher, and advance through bounded asynchronous steps. Abort should mark that exact request generation as cancellation-requested, wake or close any blocking transport operation, and let the owning worker perform idempotent cleanup. The client-facing acknowledgement must distinguish a cancellation request from confirmed terminal cancellation.

**Cancellation request:** The authorized caller asked the service to stop a known nonterminal request.

**Cancellation observation:** A worker reached a defined cancellation point and stopped initiating new side effects.

**Cancellation completion:** Transport, temporary files, download work, queued future events, request slots, and policy mutations reached a terminal cleaned state.

**Cancellation evidence:** The service emitted one terminal event and one correlated audit outcome that describe what was actually cancelled.

### Abort request validation

The current validation checks only that the supplied SessionId and capability identify a live session. That prevents a caller without the session capability from invoking its abort path, but it does not prove that request_id belongs to the session because sessions retain no request table. RequestId is merely a wrapping per-session counter used when navigation begins.

This produces ambiguous success semantics. A valid session can “abort” an unknown, already completed, never allocated, or future request and receive Ok. The service cannot distinguish repeated aborts from first attempts, nor can it report that completion won the race. It records all such calls as RequestAborted, making the audit log overstate cancellation.

Request identifiers wrap without collision checks. Once asynchronous requests exist, an old abort message could target a newer request that reused the same numeric id. Session identifiers and capabilities can also be restored through temporal state, so request authority must include a session generation and request generation rather than relying on two reusable integers.

Production validation needs a bounded active-request table owned by the service. Each record should bind an unforgeable or generation-bearing request handle to the authenticated caller, live session generation, request kind, current state, cancellation token, transport resources, related download or cache operation, and terminal-delivery state. Abort lookup must require all relevant ownership fields before changing state.

The response should distinguish accepted cancellation, already cancelling, already terminal, unknown request, wrong owner, and non-cancellable phase. For privacy, wrong-owner and unknown may share an external error while retaining different protected audit evidence. Repeated abort must be idempotent and must not generate multiple terminal events or cleanup attempts.

Validation must happen before recording a successful cancellation audit event. Rejected attempts may be audited separately with bounded metadata, especially for repeated cross-session guesses or stale capabilities. An audit record named RequestAborted should mean the request actually reached the aborted terminal state, not merely that a caller supplied an identifier.

### Current best-effort abort behavior

The current behavior is an acknowledgement marker rather than best-effort cancellation. The service verifies capability, writes one audit entry, and returns Ok. No layer reads abort state because no abort state exists. FetchErrorKind::Aborted is defined but unreachable from fetch_request, stream_body, transport, or service dispatch.

Synchronous execution also changes the meaning of RequestAccepted. For network requests, the method returns that response only after fetch_request has completed and all generated events have been enqueued. Cache hits are likewise fully queued before return. The API appears asynchronous to callers, but the implementation performs the expensive operation inline under the global mutex.

This model blocks more than abort. PollEvents, CloseSession, timer tick updates, and requests from unrelated sessions must wait behind the active fetch. A stalled network operation can therefore prevent the control action intended to stop it. It can also delay timeout epochs and cleanup requests, making service-level cancellation and deadline enforcement impossible without restructuring ownership.

The event collector inside fetch_request has a fixed capacity of 64. Body streaming pushes events into that local array, silently discarding later events when full. Cancellation cannot reduce that work because the body read continues even after event capacity is exhausted. Once fetch_request returns, service enqueue can silently drop additional events if the session queue is full. A later abort cannot reconstruct which events were generated, dropped, or delivered.

Until asynchronous cancellation exists, the accurate contract is that AbortRequest records an unverified abort intention after any synchronous fetch holding the service lock has returned. It does not stop network traffic, suppress queued events, prevent completion, or clean associated resources. Returning Ok under those semantics is misleading and should be replaced with an explicit unsupported or no-active-request result if the API remains exposed during scaffolding.

### Transport-level cancellation goals

TransportHandle owns either a TLS session handle or TCP connection identifier and provides an explicit close method. That gives cancellation a concrete release operation once the worker and control plane can coordinate safely. The current handle remains a stack-local value inside fetch_request, inaccessible to service dispatch while the request runs.

Cancellation must be observable at every potentially blocking or repeated operation. DNS resolution is a single synchronous call. TCP connection creation is synchronous at this layer. TLS handshake loops for a fixed number of ticks. send_all loops until the request is transmitted. Header reads, identity body reads, and chunked decoding continue until framing or EOF. None receives a deadline or cancellation token.

Closing a connection from another context is not enough by itself. Resource handles can be reused, so an abort command must target the generation of the exact transport object. The worker must tolerate close racing with read, write, TLS tick, parser progress, and normal completion. Cleanup should be idempotent because timeout, session close, process death, network error, and user abort may converge on the same request.

The preferred architecture is a request worker or reactor-owned state machine. The service table holds request metadata and a cancellation flag, while the network reactor owns transport handles and advances work in bounded steps. Abort changes the request state and signals the reactor. Each transition checks cancellation before initiating DNS, connect, TLS, sending, redirect follow, header processing, body delivery, cache insertion, download publication, and final completion.

| Phase | Cancellation action | Cleanup requirement |
|---|---|---|
| Before DNS | Skip resolution | Release request slot |
| DNS or connect | Cancel or invalidate operation generation | Ignore stale completion callbacks |
| TLS handshake | Close and free exact TLS generation | Emit no established state afterward |
| Request send | Close transport | Record whether remote side may have received bytes |
| Response headers | Stop parser and close | Prevent redirect, cookie, cache, or download commits |
| Response body | Stop reads and downstream delivery | Discard partial cache and inline state |
| Download write | Cancel writer and quarantine partial file | Never publish final destination |
| Finalization | Resolve race by atomic terminal transition | Emit exactly one terminal result |

HTTP methods complicate cancellation evidence. Aborting a POST after bytes were sent does not prove that the server ignored it. The terminal event should distinguish local transfer cancellation from remote side-effect rollback. Oreulius must not imply that closing the connection undid a request that may already have reached the origin.

Transport cancellation also needs bounded deadlines. An abort that depends on a blocked worker eventually noticing a flag is not prompt cancellation. DNS, TCP, TLS, reads, writes, and close handshakes need wakeup or deadline mechanisms, with escalation to forced resource release where safe.

### Queued event cleanup after abort

BrowserSession stores events in a fixed ring and can only enqueue or drain from the head. It has no operation to inspect request ownership, remove matching entries, insert a terminal event ahead of body data, or reserve terminal capacity. enqueue silently discards events when the queue is full.

Because fetch completion precedes abort dispatch, Headers, BodyChunk, Complete, FetchError, Redirect, or policy events may already be queued for the request. do_abort leaves all of them untouched. Clients can receive Complete after a successful abort response, directly contradicting the intended semantics. Events for unrelated requests share the same queue, so clearing the whole queue would also be incorrect.

A production queue needs request-aware cancellation semantics. One viable rule is that events committed before cancellation remain observable, but every event carries sequence information and the final Aborted event establishes the terminal boundary. Another rule removes undelivered nonterminal events for the cancelled request. Either policy can work, but it must be deterministic across polling, push delivery, retries, and queue pressure.

Removing matching events from a bounded ring requires compaction or per-request queues. More importantly, event publication and terminal state changes must share synchronization. A worker must not pass a cancellation check, race with abort completion, and enqueue BodyChunk or Complete afterward. Publication should verify the request generation and nonterminal state while committing the event.

Terminal events need reserved capacity or a separate reliable control channel. Silent queue overflow cannot be allowed to erase Aborted, Complete, or final error because the client then cannot know whether more work will occur. Backpressure should stop body production before terminal evidence becomes impossible, or the service should retain terminal status in the request table until the client acknowledges it.

Abort must also clean secondary side effects that are not ordinary events. Partial cache entries must be invalidated, pending cookie or navigation commits must not occur, redirect chains must stop, download offers or writers must be cancelled according to their lifecycle, and audit completion must reflect cleanup success. The current fetch path performs some commits after fetch_request returns, so the terminal-state gate must cover service-level finalization as well as transport work.

### Final aborted event semantics

FetchErrorKind already includes Aborted, and FetchEvent::FetchError can carry it, so the protocol has a usable provisional terminal representation. The service never emits it. There is also no request-state record that prevents both Complete and Aborted from becoming visible for the same request.

The terminal contract should state that exactly one of Complete, PolicyBlocked, terminal FetchError, redirect handoff under the chosen redirect model, or download transfer ownership completes a request generation. Abort should become a terminal FetchError with Aborted once cleanup reaches the guaranteed boundary. A synchronous AbortRequest response should only report whether the cancellation request was accepted; it should not substitute for the asynchronous terminal event.

The event needs enough semantics to avoid false guarantees. It should identify the request generation, cancellation initiator class, phase observed, whether request bytes may have reached the server, whether response bytes were delivered, whether local side effects were committed, and whether cleanup encountered errors. Sensitive details can remain in protected audit evidence while the client receives a bounded status.

Ordering must be defined. No nonterminal event for that request may be committed after Aborted. Complete and Aborted must be mutually exclusive through one atomic compare-and-transition. Repeated aborts should return the existing state and never emit another terminal event. If normal completion wins before cancellation is accepted, abort should report already terminal rather than rewriting history.

Session close and process death may prevent delivery to the original client, but the service still needs internal terminalization and audit. Closing a session should cancel all owned requests, drain or discard their client events according to policy, release transports and temporary resources, and record aggregate cleanup failures before reusing the session slot. Temporal snapshot should exclude live network requests unless a durable resumable protocol exists; restore must never resurrect a request as in flight from a stale identifier.

Tests must control every race: abort before work starts, during each transport phase, between the last body byte and completion, during event enqueue, after completion but before polling, concurrent repeated abort, session close, process death, queue saturation, RequestId wraparound, stale callbacks, cache and download side effects, and remote methods whose effects cannot be rolled back.

## Fetch timeout and slow-response policy

The fetch service has no coherent timeout policy of its own. Several lower network components contain hard-coded deadlines, but fetch_request does not receive a clock, deadline budget, cancellation token, or timeout profile. It maps lower failures into broad DNS, connection, TLS, reset, or protocol errors and cannot tell the client which phase exceeded its limit.

The existing limits also use incompatible semantics. DNS performs multiple response-deadline attempts. TCP connect waits about five seconds. TCP receive waits about two seconds, then returns a zero-length successful read rather than a timeout error. TLS handshake loops 512 iterations without measuring elapsed time. Header and body loops have no independent deadlines and interpret zero as end of stream. The network reactor request wrapper adds another approximately five-second limit around individual reactor calls.

| Phase | Existing bound | Fetch-visible result |
|---|---|---|
| DNS response | Per-attempt PIT deadline with retries | Every DNS error becomes DnsFailure |
| Reactor request | Approximately five seconds | Usually flattened by the caller |
| TCP connect | Approximately five seconds | ConnectionFailed |
| TLS handshake | 512 loop iterations | TlsHandshakeFailed |
| TCP receive | Approximately two seconds per call | Zero bytes, indistinguishable from EOF |
| Response headers | No fetch-level elapsed or rate deadline | Partial data may proceed |
| Response body | No idle, total, or rate deadline | Timeout-like zero read becomes completion |
| Whole request | None | One phase can consume the entire service indefinitely |

This fragmentation does not provide defense in depth because the layers disagree about what expiration means. A timeout must be a typed terminal condition, not a synthetic EOF. An EOF says the peer ended the byte stream normally; a timeout says the service stopped waiting before protocol completion. Treating them as equivalent can turn incomplete framing into successful completion and hide slow-response attacks as ordinary short responses.

Oreulius should define one monotonic timing contract and pass an absolute request deadline plus phase-specific budgets through the reactor, transport, HTTP parser, cache, and download path. Each lower layer may impose a stricter safety ceiling, but it must report which ceiling fired and preserve enough phase evidence for cleanup and audit. Relative counters should derive from the platform clock frequency rather than assume that one loop or one service tick equals a stable duration.

**Connect budget:** DNS, route and neighbor discovery, TCP establishment, proxy work if introduced, and TLS handshake.

**First-byte budget:** Time from request transmission to the first response byte.

**Header budget:** Maximum elapsed time and minimum useful progress until a complete validated header block arrives.

**Body idle budget:** Maximum interval without decoded-body or framing progress.

**Total budget:** Maximum lifetime of the complete request across redirects, retries, authentication, downloads, and cleanup.

Timeout handling must converge with cancellation. The request should atomically enter a timeout terminal path, stop new side effects, close the exact transport generation, discard partial cache or response state, quarantine partial downloads, suppress Complete, emit one typed terminal event, and record cleanup outcome. Because current navigation holds the global service mutex, the asynchronous request restructuring described in the abort audit is also a prerequisite for reliable deadline enforcement.

### DNS resolution timeout

DNS resolution does have a real bounded wait in the network stack. For each attempt, dns_resolve_with_progress calculates a deadline from the PIT frequency and DNS_RESPONSE_TIMEOUT_SECS, polls until that deadline, and retries up to DNS_QUERY_MAX_ATTEMPTS. After exhausting attempts, it inserts the domain into a negative cache and returns the string DNS timeout. The network reactor request wrapper also has its own outer deadline.

The fetch transport discards this specificity. TransportHandle::connect maps every dns_resolve error, including not configured, invalid readiness, negative-cache hit, malformed domain conditions, send failure, parser failure, and timeout, to TransportError::DnsFailure. fetch_request then emits the same DnsFailure and message for all of them. Operators and clients cannot distinguish configuration failure, authoritative negative answers, cached failure, malformed names, and elapsed timeout.

The effective total DNS time is not represented in fetch policy. Multiple per-attempt waits can consume substantially more than one response timeout, while the outer reactor request may expire first and reset its shared request state. The interaction between the inner DNS operation and outer caller timeout needs a clear ownership rule so a late resolver completion cannot write into a reused request slot or update caches after the fetch has terminalized.

Negative caching after timeout also changes later timing behavior. A later request can fail immediately with DNS negative cache, yet fetch reports the same generic failure as a live timeout. The cache lifetime is expressed in ticks and is not tied to the request’s policy, network change generation, DNS server generation, or temporal restore model.

Production DNS should accept the request’s absolute deadline and derive retry count and per-attempt windows from the remaining budget. Results need typed categories for timeout, no configured resolver, network unavailable, negative answer, malformed response, validation failure, and internal resource pressure. The final event should include bounded attempt and cache evidence without exposing unnecessary query data.

DNS cleanup must invalidate the operation generation, ignore late packets, release staged request state, and prevent timed-out answers from being committed to the wrong request. Tests should vary PIT frequency, retry timing, late and mismatched transaction responses, network reconfiguration, negative-cache expiry, outer-deadline races, cancellation, and concurrent lookups.

### TCP connection timeout

The network reactor starts TCP establishment and waits until the connection reaches one of two accepted states, disappears, or exceeds a PIT-derived five-second deadline. TransportHandle maps every tcp_connect failure to TcpConnectFailed, and fetch_request maps that together with most other transport errors to ConnectionFailed.

This supplies a lower safety ceiling but not a fetch connection policy. The request cannot choose a shorter deadline, share one remaining budget with DNS and TLS, or identify whether timeout, refusal, route failure, connection-table exhaustion, network-not-ready, or reactor contention caused the result. The outer reactor request timeout is also approximately five seconds, so two independently measured limits can race and report whichever layer happens to fire first.

Failed connection attempts need explicit cleanup. The reactor’s timeout branch returns an error but the visible code does not close the allocated connection identifier before returning. If the underlying stack does not reclaim that attempt independently, repeated unreachable destinations can consume connection slots. A late state transition after the caller has timed out also needs generation checking before any handle is returned or reused.

Connection timing should include route readiness, neighbor discovery, retransmission policy, and proxy or tunnel establishment where applicable. A five-second TCP state wait alone does not describe the whole path. Production policy should define per-origin concurrency, retry restrictions, address fallback, and whether multiple candidate addresses share or each receive the same budget.

The fetch layer needs a typed ConnectTimeout distinct from refusal, reset, unreachable, local resource exhaustion, and policy denial. Timeout terminalization must close the exact connection generation, remove pending callbacks, and free request and reactor slots. Tests must cover immediate refusal, blackholed SYNs, delayed success at the boundary, connection-table exhaustion, outer and inner deadline races, address fallback, cancellation, and stale handle reuse.

### TLS handshake timeout

TLS connection setup uses a fixed loop of 512 calls to tick_all. It succeeds when handshake_done becomes true, fails early when the session exposes an error string, and otherwise frees the session after the loop. This is bounded by iteration count but not by elapsed time. The duration depends on scheduler progress, network driver behavior, CPU speed, and how much work one tick performs.

The loop does not derive from the PIT clock or the request’s remaining budget. It can expire almost immediately while packets are legitimately in flight, or consume unpredictable wall time if tick work blocks. It also advances every active TLS session through tick_all rather than only the session belonging to this request, coupling one fetch’s handshake loop to unrelated TLS work.

Every allocation failure, protocol failure, certificate failure, transport failure, and loop exhaustion becomes TlsHandshakeFailed. The service cannot report timeout separately from trust rejection. It emits a failed TLS state and a generic fetch error but carries no elapsed time, handshake phase, alert, peer identity, or cleanup evidence.

Production TLS should advance through reactor-owned bounded steps under an absolute handshake deadline. The state machine should report timeout with the last handshake phase and preserve certificate or protocol failures as distinct typed reasons. Cancellation, timeout, network error, and normal close must converge on generation-safe session release.

Handshake time should remain inside the whole-request budget and may have separate first-flight and idle-progress limits. Receiving irrelevant packets or repeatedly executing a state without cryptographic or protocol progress must not reset the deadline. Tests should cover delayed server hello, stalled certificate and finished phases, certificate failure near the deadline, session-pool exhaustion, PIT frequency changes, unrelated active sessions, timeout and completion races, and proof that the TLS slot is reclaimed.

### Response header timeout

read_until_headers has no explicit deadline. It repeatedly calls read_raw into a 256-byte buffer until it sees the header terminator, receives zero, encounters an error, or fills 16 KiB. For plaintext TCP, each read can wait about two seconds in the network reactor. For TLS, read_raw performs one session tick and returns whatever bytes are immediately available, including zero.

The reactor returns zero both for true EOF and for a receive wait that exceeded its two-second limit. read_until_headers treats either as the end of header collection. If no bytes arrived, fetch emits a generic protocol error. If some bytes arrived, fetch parses them even when the terminating empty line never arrived. It sets block_end to raw_len, allowing an incomplete header block to influence status and header processing.

This behavior is vulnerable to slow or strategically partial headers. A server can send enough bytes to produce a valid-looking status line and selected headers, then stall. The parser may accept that prefix as the complete response. The 16 KiB capacity is a size ceiling, not a time or completeness guarantee, and reaching it without a terminator is likewise not rejected explicitly.

A production header reader must retain a distinct state for progress, EOF, timeout, capacity exhaustion, malformed framing, and complete terminator. Only complete framing may advance to semantic parsing. It needs an absolute header deadline, an idle-progress deadline, and optionally a minimum sustained byte rate after a grace interval. Progress should mean accepted new bytes toward one bounded header block, not repeated zero reads or irrelevant network activity.

First-byte and complete-header deadlines should be separately observable because they diagnose different failure patterns. On timeout, the service must close the transport, discard all partial fields, prohibit redirects, cookies, cache insertion, content classification, downloads, and navigation commits, and emit a typed HeaderTimeout. Tests must trickle one byte below each boundary, split the terminator across reads, fill the buffer without termination, send a valid status prefix then stall, and distinguish EOF from timeout.

### Body idle and total request timeout

stream_body has no fetch-level idle deadline, total deadline, byte-rate floor, or total decoded-body ceiling. Identity bodies read until Content-Length bytes have been observed, until read_raw returns zero, or indefinitely for unknown length. Chunked bodies read until the decoder reports done or read_raw returns zero.

For plaintext TCP, a two-second receive timeout becomes zero and therefore ends the loop. For TLS, a temporarily empty read can end the loop immediately. Both paths then call push_complete and return success. Identity responses do not verify that total_received equals Content-Length, and chunked responses do not require a terminating zero chunk before completion. A stalled or truncated body can therefore become Complete.

The policy module has a body-size limit helper, but fetch_request does not call body_too_large and stream_body does not enforce MAX_BODY_BYTES lazily. Unknown-length or chunked responses can continue until connection closure, local buffer behavior, or event capacity intervenes. The local event array silently fills after 64 events while network reading continues, so the service can spend time and bandwidth on bytes it can no longer report.

Idle and total timing need different clocks. The idle deadline should reset only on meaningful framing or decoded-body progress. The total deadline should never reset and should include redirects and retries. A minimum-rate policy can prevent a peer from sending one byte just before each idle deadline forever, but it should use a grace period and rolling window suitable for constrained networks.

Content-Length, chunk terminators, connection-close framing, and method/status body rules must determine whether EOF is successful. A receive timeout is never successful framing. On body timeout or truncation, the service must emit a terminal error instead of Complete, invalidate partial cache state, stop inline delivery according to the documented partial-response policy, and quarantine or remove partial downloads.

Production limits should be policy-profile values with hard kernel ceilings. They should account separately for encoded bytes, decoded bytes, decompressed bytes when content coding is added, event-queue backpressure, and local write time. Tests must cover exact Content-Length completion, one-byte-short EOF, chunked stalls, missing terminators, endless unknown-length bodies, periodic trickles, queue saturation, size-limit crossing, cancellation, download writes, and total deadline expiry despite continuing progress.

### Slowloris-style response handling

The current receive behavior limits how long one plaintext tcp_recv call waits, but it does not defend against slowloris behavior across many successful small reads. Every arriving byte starts another receive call with a fresh lower-layer wait. There is no total header deadline, total request deadline, rolling rate calculation, per-origin slow-connection quota, or global budget for stalled fetches.

The synchronous service model magnifies the impact. One slow request holds the global fetch-service mutex, delaying event polling, session close, abort, timer-driven service epoch updates, and all requests from other sessions. A peer does not need many connections to deny service; one sufficiently slow response can monopolize the control plane until a lower-layer read returns.

TLS is even less consistent because read_raw may return zero when no decrypted bytes are immediately ready, causing premature EOF-like completion rather than a measured idle timeout. This can avoid prolonged blocking but weakens protocol correctness and produces different behavior for equivalent HTTP and HTTPS peers.

Slow-response defense should combine absolute deadlines, idle deadlines, rolling minimum progress, bounded header and body sizes, per-session and per-origin concurrency, and a global stalled-resource budget. The scheduler must keep control operations responsive while network work waits. Backpressure from a full event queue or slow client should pause or cancel the remote read under its own local-consumer deadline rather than consume and discard data.

Rate policy should operate on protocol progress. During headers, accepted header bytes count; during chunked framing, valid framing and decoded data count; during downloads, durable quarantine writes may also constrain progress. Invalid bytes, retransmissions, TLS housekeeping, and repeated callbacks without application data must not keep a request alive.

Detection needs careful evidence to avoid misclassifying ordinary high-latency links. Record the phase, elapsed time, idle duration, bytes received, progress-window rate, configured thresholds, and whether local backpressure contributed. Apply escalating controls such as request termination, origin concurrency reduction, and rate-limited audit rather than permanent origin blocking from one event.

Tests should use deterministic clocks and scripted transports to model one-byte trickles, header fragmentation, long pauses, TLS records without application data, chunk extensions, slow consumers, event saturation, many origins, many sessions, and recovery after timed-out resources are reclaimed.

## Fetch audit event schema and evidence guarantees

The fetch service owns a fixed 128-entry in-memory audit ring. Each record contains a wrapping 32-bit sequence number, SessionId, RequestId, AuditKind, and a 32-byte free-form note. The design is allocation-free and cheap to append while the service mutex is held, which matches Oreulius’s bounded kernel-service model. It is useful as a diagnostic trace, but it is not yet a security-grade evidence channel.

The schema mixes typed event identity with untyped annotation bytes. AuditKind provides eighteen named categories, while note carries truncated context whose meaning changes by call site. There is no timestamp, authenticated caller identity, session generation, request generation, origin identity, URL digest, network phase, outcome field, policy generation, severity, note length, truncation marker, or causal parent. A reader cannot reliably distinguish unused trailing zeros from note content or reconstruct the conditions under which a decision was made.

| Property | Current implementation | Evidence consequence |
|---|---|---|
| Capacity | 128 records | Older evidence is overwritten |
| Ordering | Wrapping u32 sequence | Ambiguous after wraparound |
| Time | No timestamp | Duration and chronology across systems are unavailable |
| Correlation | SessionId and RequestId | Reused identifiers can alias later work |
| Context | 32 raw note bytes | Truncated and event-specific |
| Overflow | Silent overwrite | Loss is not represented |
| Access | Internal iter and drain helpers only | No authorized service export exists |
| Durability | None | Reboot, crash, and temporal transitions lose evidence |
| Integrity | None | Records are not authenticated or tamper-evident |

The live emission surface is smaller than the enum suggests. Service code emits session open and close, cache hit and miss, navigation start, fetch complete, selected policy blocks, redirect followed, internal errors, and RequestAborted. It does not call the helpers for NavigateCommit, FetchStart, TLS established or failed, download offered or complete, cookie set, or content filtered. Many critical rejection paths return without audit, including invalid capabilities, invalid sessions, malformed URLs, unsupported schemes, duplicate session attempts, quotas, download ownership failures, and event loss.

Audit must describe outcomes that actually occurred. RequestAborted currently records an abort request even though no request is cancelled. FetchComplete is recorded from FetchOutcome::Complete even when event delivery may have silently dropped Complete or body data. CacheMiss is emitted for every non-hit before network work, but cache admission is absent. An event name should not overstate stronger guarantees than the underlying subsystem provides.

Oreulius should separate operational telemetry from security evidence. High-volume cache and progress events can use lossy counters or telemetry. Authority changes, policy denials, trust decisions, persistence operations, cross-boundary writes, and terminal request outcomes need a reliable structured audit path with explicit loss behavior. The fetch-local ring can remain a fast recent-history cache, but production evidence should flow into the kernel’s broader protected audit system.

**Subject:** Authenticated process, delegated principal, session generation, and request generation.

**Action:** Typed operation and phase, such as session open, redirect decision, TLS validation, cookie mutation, download commit, or temporal restore.

**Object:** Canonical origin, bounded URL or path digest, download identifier, cache partition, or persistence generation.

**Decision:** Allowed, denied, failed, cancelled, timed out, committed, or partially cleaned, with a typed reason.

**Evidence:** Monotonic time, policy and trust generations, byte counts, integrity digests, previous-event linkage, and explicit truncation or omission flags.

### Audit ring ownership and capacity

AuditLog is embedded directly in the singleton FetchServiceService and mutated while that service is locked. This gives one clear writer and avoids a second synchronization primitive. AUDIT_LOG_SIZE fixes memory use at 128 records, and push always succeeds by replacing the entry at head before advancing the ring.

The ring does not track how many entries are valid. iter always returns 128 records beginning at head, including untouched AuditEntry::EMPTY values. Empty entries use InternalError as their kind and sequence zero, so a raw iterator can present uninitialized slots as apparent internal errors unless the reader knows to apply additional filtering.

Sequence zero is also the first value assigned to a real event. drain_since explicitly excludes every entry whose sequence equals zero, so the first audit event is never drained. After u32 wraparound, the same sentinel collision recurs and the comparison e.seq greater than after_seq no longer defines chronological order. A long-running or noisy system can therefore lose both ordering and visibility without an overflow.

The module comment says AuditEntry fits in a 64-byte cache line, but repr C and the declared fields do not establish an exact portable 64-byte record contract. If binary export, persistence, hashing, or shared-memory reading depends on layout, the wire schema must be defined independently from Rust structure layout and verified with explicit size assertions.

No public fetch request exposes audit reading, no authorized subscriber receives records, and no service method exports ring state. The internal iter and drain_since methods have no call sites. Evidence that cannot leave the private service object is useful only during future internal diagnostics, not for incident response or policy monitoring.

A production ring needs a valid count, 64-bit nonzero sequence or epoch-plus-sequence identity, monotonic timestamp, overwritten-count watermark, and cursor protocol that reports gaps. Readers need explicit authority and stable snapshots so they cannot observe partially related records or infer another session’s sensitive activity. High-value events should be forwarded durably before local overwrite where the threat model requires post-crash evidence.

### Session and request correlation fields

Every entry carries SessionId and RequestId, with zero documented as not applicable. The convenience methods generally use both identifiers for request-scoped events and request zero for session events. This gives a basic local join key across navigation, cache, policy, and completion records.

The identifiers are not globally or temporally unique. SessionId is derived from a reusable session-table slot, and RequestId is a wrapping counter scoped to that session. Neither field carries a generation. After close and reopen, temporal restore, or counter wrap, unrelated activity can produce the same pair. Sequence order may reduce ambiguity while the relevant records remain in the ring, but silent overwrite and wrap remove that protection.

Correlation is also inconsistently populated. cookie_set forces RequestId zero even though a response request would cause the mutation. DownloadComplete accepts a request argument in its helper despite the event protocol identifying completion primarily by DownloadId. Restored downloads reset their request to zero. Early policy blocks before request allocation use RequestId zero, which conflates session-level and attempted-request evidence.

The audit record omits authenticated caller identity. A valid session and capability are checked for many operations, but the log cannot show who presented them, whether authority was delegated, or whether a wrong caller attempted access. It also cannot distinguish the original top-level request from redirects, cache work, download continuation, or asynchronous callbacks.

Production correlation should use generation-bearing identifiers for principal, session, request, redirect hop, download transfer, cache transaction, and temporal generation where applicable. One trace identifier should follow the logical operation, while child operation identifiers distinguish network attempts and side effects. Failed operations that never receive a request id still need an attempt identifier assigned before security-relevant validation.

Sensitive object correlation should use keyed digests or protected internal identifiers rather than truncated raw URLs, hosts, and paths. The digest scheme and key generation must be versioned so records remain comparable within the intended evidence window without becoming a durable tracking or disclosure mechanism.

### Security-relevant event kinds

AuditKind names several important lifecycle events, but it does not define a complete or consistently used security taxonomy. Start and completion variants exist for navigation and fetch, yet service code emits NavigateStart and FetchComplete without FetchStart or NavigateCommit. TLS, cookie, download, and content-filter helpers exist but have no live emission call sites. InternalError is used as a generic sink for heterogeneous failures.

Important authority failures are absent from the enum or call sites. Invalid capability, invalid session, wrong owner, caller identity mismatch, quota exhaustion, malformed input, unsupported scheme, cookie rejection, storage denial, download destination rejection, timeout, event overflow, audit overflow, snapshot authentication, rollback detection, cleanup failure, and process-death revocation need typed representation.

Success events also need stricter definitions. SessionOpened should mean all mandatory subsystem registration committed, which is not currently true for storage. FetchComplete should mean protocol framing, delivery, and terminal publication succeeded, which current event dropping can violate. RequestAborted should mean cancellation completed, not merely requested. DownloadComplete should require verified atomic publication and quarantine evidence.

A production taxonomy should encode action, outcome, and reason separately rather than creating an enum variant for every combination or placing the reason in free-form bytes. Stable numeric reason codes are easier to query and test. Schema versioning must preserve interpretation across upgrades, and unknown future values must remain parseable without being reclassified.

Security events should cover authority acquisition and revocation, validation failures, network trust decisions, cross-origin transitions, state mutation, persistence and restore, local filesystem publication, terminal cleanup, and evidence loss. Repetitive low-risk telemetry should be aggregated or rate-limited without suppressing the first occurrence, transition, recovery, or final count.

### Audit overflow behavior

push always overwrites the oldest slot and records no overflow marker, overwritten count, oldest retained sequence, or reader lag. Once more than 128 events are written, evidence disappears silently. A noisy origin, repeated cache misses, or deliberate invalid activity can evict the event needed to explain a later security decision.

drain_since cannot reliably detect the loss. It returns entries whose nonzero sequence is numerically greater than the supplied cursor, but provides no ring generation, earliest retained sequence, or gap result. If the reader falls behind by more than the ring capacity, it receives only recent entries and cannot prove that anything was omitted. Sequence wrap makes numerical comparison invalid even without overwrite.

The overwrite policy also gives all event classes equal eviction power. High-volume operational records such as CacheMiss can displace session authority changes, policy violations, TLS failures, download commits, and restore events. An attacker should not be able to erase scarce high-value evidence by generating cheap low-value events.

Production overflow behavior must be explicit and observable. The ring should track total appended, total overwritten, earliest retained cursor, and overflow epochs. A reader request should return records plus a gap indicator. The durable audit sink should receive a loss event before or as part of degradation, with reserved capacity or out-of-band counters preventing the loss marker itself from being silently erased.

Backpressure is appropriate only if audit reliability is allowed to affect the operation. For high-risk actions, Oreulius may fail closed when protected evidence cannot be committed. For routine telemetry, it may aggregate, sample, or drop while incrementing typed counters. The policy must state which class each event belongs to and avoid deadlocking the fetch service on an unavailable sink.

### Evidence guarantees and known gaps

The implementation currently guarantees only that a call to AuditLog::push writes one bounded in-memory record into the current ring slot while the fetch service object is exclusively locked. The record receives the current wrapping sequence value, copies at most 32 note bytes, and remains available until overwritten or the service state is lost.

It does not guarantee that every security-relevant operation calls push, that event names reflect completed outcomes, that the first event is drainable, that records are distinguishable from empty slots, that overflow is detectable, that chronology survives wrap, that notes are complete, that terminal events reached clients, or that evidence survives crash, reboot, temporal restore, memory corruption, or privileged tampering.

The note field is particularly weak as evidence. AuditEntry::new silently truncates without recording original length or truncation. It accepts arbitrary bytes despite the ASCII comment. redirect_followed copies the beginning of an untrusted Location value, cookie_set copies a host, and internal_error copies ad hoc messages. Prefix truncation can make distinct targets identical, leak sensitive URL data, split multibyte text, or preserve attacker-controlled control bytes.

There is no cryptographic integrity chain, trusted timestamp, persistence binding, boot identity, schema version, signer identity, or export acknowledgement. The ring is not included in fetch temporal snapshots, which avoids resurrecting stale log state but also means temporal transitions can separate restored authority from the evidence that created it.

Production guarantees should be stated by event class. A protected evidence event should have an authenticated source, stable schema, complete typed fields or explicit omission flags, trusted monotonic ordering, detectable loss, integrity protection, bounded privacy exposure, and retention appropriate to its threat model. Delivery to an external sink should use acknowledgement and replay-safe cursors.

Tests should assert both presence and absence. Every security decision needs a test for its exact event, fields, reason, and correlation. Failed operations must not emit success evidence. Overflow tests must prove gap reporting and preservation of high-value loss evidence. Wrap, reboot, restore, concurrent readers, malformed note inputs, sink failure, rate limiting, and privacy redaction all need deterministic coverage.

## Fetch temporal restore authenticity and rollback policy

The fetch service contains a standalone version-two snapshot encoder and restore parser for sessions, navigation history, cookies, and download jobs. The format is bounded and uses explicit little-endian fields rather than serializing Rust memory directly. That is a sound starting point for a kernel persistence boundary. The implementation is not connected to FetchServiceService or the broader temporal object system, however, so no live service path currently invokes snapshot, validation, or restore.

If connected as written, restore would import authority-bearing state from any byte slice with the expected magic and version. It restores process identifiers, capability tokens, session identifiers, request counters, cookies, download destinations, byte counters, and terminal labels without authentication, freshness, generation, caller binding, or transactional validation. A forged or stale payload could therefore create live sessions and resurrect credentials.

| State class | Included | Important exclusions or lost context |
|---|---|---|
| Sessions | Identifier, process id, capability, alive flag, next request id | Policy profile, subscription state, generation, authenticated owner |
| Navigation | Ring position, count, URL bytes | Canonical parsed URL, origin decisions, redirect provenance |
| Cookies | Session, expiry, flags, name, value, domain, path | Host-only flag, creation time, partition key, policy provenance |
| Downloads | Identifier, session, state, name, MIME, size, destination, bytes written | Request correlation, source URL, digest, writer, file identity, quarantine |
| Cache | Excluded | Metadata, bodies, validators, policy bindings |
| Storage | Excluded | Registry mapping, origin partition, VFS generation |
| Network work | Excluded | Transports, requests, cancellation, deadlines |
| Audit | Excluded | Evidence explaining the restored authority |

The main security requirement is not merely adding a checksum. Restore changes who can issue fetch operations, which credentials future requests can carry, and which local download destinations appear active. The accepted snapshot must be authenticated, fresh, bound to the current kernel and profile identity, compatible with current policy, and validated completely before any live object changes.

Oreulius should model restore as a staged transaction. Decode into bounded temporary records, validate the complete payload and cross-record relationships, authorize the snapshot and requested restore mode, derive new live authority, reconcile external state, then atomically publish the new generation. Any failure before commit should leave the existing service unchanged.

**Authenticity:** The payload came from the trusted persistence authority for this kernel, profile, and device context.

**Integrity:** Every byte, count, field, and external reference is covered by authenticated metadata.

**Freshness:** The snapshot generation is permitted by the current rollback policy.

**Compatibility:** Schema, feature set, policy generations, and trust generations can be safely migrated.

**Reconciliation:** Restored sessions, cookies, downloads, storage, process identities, and external files agree before activation.

### Snapshot contents and excluded state

snapshot iterates the eight live session slots, every active cookie, and every active download job. It writes into a caller-provided buffer and returns zero if capacity would be exceeded. The header records magic, version, three record counts, and a reserved field. Navigation serializes all 32 ring slots for every session, while cookie and download records use explicit variable lengths.

The session record preserves the exact capability token and request counter. It also writes an alive byte that is always one because only live sessions are iterated. Restore loads policy as PolicyProfile::DEFAULT rather than persisting the session’s actual policy. It does not restore event subscription or queued events. A restored session can therefore retain old authority while silently receiving a different policy and losing its observable event history.

Navigation entries preserve reconstructed URL bytes, not the authoritative parsed representation or the decisions associated with those URLs. They do not carry canonical origin, TLS identity, redirect chain, policy generation, or commit evidence. Historical URLs may also contain sensitive query data in plaintext.

All active cookies are serialized, including session cookies with expiry zero. Values are stored in plaintext in the payload. Restore bypasses normal cookie acceptance and does not check owning-session existence, expiration, Domain safety, Secure origin, prefixes, public suffix policy, or current time. The existing cookie audit identifies further metadata that the current record cannot represent.

All active download jobs are serialized regardless of state. Active and Complete labels survive without a network stream, writer, temporary file identity, destination capability, source URL, digest, or quarantine metadata. Restore deliberately sets RequestId to zero. A state label therefore cannot prove that any transfer can continue or that any final file exists.

Exclusions are not automatically safe. Cache exclusion avoids stale response reuse, but storage exclusion leaves persistent VFS files without restored registry mappings. Network exclusion means no in-flight request can resume. Audit exclusion means restored authority is separated from the evidence that originally granted it. Production documentation must define the result of each mismatch rather than merely listing excluded data.

### Snapshot structure validation

validate_snapshot checks only that the payload is at least 24 bytes and that the magic and version match. It does not validate counts, reserved bits, record boundaries, full consumption, canonical encodings, cross-record references, duplicate identifiers, field semantics, or trailing bytes.

restore validates and mutates in one pass. It writes sessions directly into SessionTable, then inserts cookies and downloads into their live managers. When a field is missing or invalid, most loops break rather than failing the restore. The function returns the number of sessions restored, so a malformed snapshot can produce partial live state and a nonzero success result.

The session count is capped with min rather than rejected. If session_count exceeds eight, restore parses only eight session records and immediately begins cookie parsing at the ninth session record. The remaining session bytes are reinterpreted as cookie fields. Cookie and download counts are not bounded against their table capacities before iteration.

Navigation length handling can also desynchronize parsing. A declared URL length above URL_MAX is reduced with min, and restore consumes only the reduced number of bytes rather than rejecting or skipping the full encoded field. Later bytes are then interpreted as the next record. Snapshot-generated records do not exceed the limit, but a hostile payload can.

Several semantic values are accepted too broadly. The reserved header is ignored. Any nonzero alive byte is true. Invalid SameSite bits become Lax. Unknown download states become Error. Zero session, capability, download, and request-related values are not comprehensively rejected. Duplicate sessions can overwrite prior restored slots, and duplicate cookies or jobs can create ambiguous state.

Restore does not require exact payload consumption, so appended data is accepted. It does not clear or stage existing state, which means restored objects can overwrite some live sessions while cookies and downloads append into available slots. Capacity failures from restore_entry and restore_job are ignored. The result cannot tell whether cookies or downloads were dropped.

Production validation must be two-pass or decode-first. The decoder should use checked arithmetic, reject impossible counts before loops, require every declared length to fit without coercion, reject duplicates and invalid enum values, validate references to accepted sessions, require exact end-of-payload, and return a typed error with no live mutations. Fuzzing should target record-count interactions and parser alignment, not only individual field bounds.

### Snapshot authentication requirements

The format contains no MAC, signature, authenticated digest, encryption, key identifier, boot identity, device identity, profile identity, creation time, nonce, or generation. Magic and version identify syntax only. Anyone able to supply or replace the byte slice can forge every restored field.

Because the payload contains capability tokens, cookie values, URLs, and destination paths, confidentiality may also be required. Authentication without encryption would prevent undetected modification but still expose credentials and browsing history to the persistence medium or diagnostic tooling. The threat model should determine whether encryption is device-bound, profile-bound, sealed to measured boot state, or protected by a broader temporal store.

Authentication must cover the complete canonical envelope, including schema version, object type, payload length, generation, device and profile bindings, creation context, and migration metadata. Verifying a digest stored beside an untrusted payload is insufficient unless the digest itself is keyed or signed by trusted authority.

Key lifecycle needs explicit behavior for rotation, revocation, recovery, cloning, and migration. A snapshot authenticated under a revoked trust generation should not silently restore because its MAC remains mathematically valid. Restoring onto another device or profile should require an explicit export and import authority rather than reusing ordinary resume credentials.

Verification should occur before detailed parsing where feasible and always before state mutation. Failure must clear temporary plaintext buffers containing cookies and capabilities, produce protected audit evidence, and reveal only bounded diagnostics to untrusted callers. The parser should still remain memory-safe under unauthenticated input because authentication cannot substitute for structural validation.

### Restored capability policy

Session records serialize Cap values and SessionTable::restore installs them unchanged. A caller that retained an old session and capability pair could regain access after rollback or reboot. A forged snapshot could choose any nonzero or zero capability value. restore performs no check against the capability manager, current process table, session owner, revocation state, or duplicate live authority.

ProcessId is restored from the payload as if it still identifies the same principal. Process identifiers can be reused across lifecycle events, and the current fetch boundary already treats caller-supplied process identity as scaffolding. Binding a historical capability to a historical numeric process id does not authenticate a present process.

Restored sessions also receive DEFAULT policy rather than their prior profile, while origin-table registration and storage registration are not recreated. The service could therefore contain a live session token with no matching origin or storage state and with policy different from the state under which the token was issued.

The conservative production policy is to treat snapshot capabilities as references, not live bearer tokens. After authentication and owner reconciliation, issue new session and capability generations, invalidate historical tokens, rebuild origin and storage registrations transactionally, and notify the restored principal through a trusted channel. Persisted identifiers may remain as audit correlation but should not remain directly usable.

If exact capability restoration is required for a narrow suspend-and-resume model, it needs a sealed execution context that proves no concurrent or later generation used the same authority, no revocation occurred, and no process identity changed. That is a stronger condition than ordinary snapshot authenticity.

Restore must also decide what happens to next_request_id. Reusing a historical counter can collide with stale events, callbacks, abort messages, and external traces. New request generations should be allocated independently even if navigation history is retained.

### Persistence generation and rollback detection

The snapshot header has a reserved field but no persistence generation, parent generation, creation epoch, boot nonce, temporal object version, policy generation, trust-store generation, or latest-accepted marker. The restore function accepts any authenticated-looking version-two payload repeatedly and cannot distinguish current state from rollback.

Rollback is an authority attack in this subsystem. It can resurrect closed sessions, revoked capabilities, expired or deleted cookies, rejected downloads, old destination paths, earlier navigation state, and request counters. Even a valid snapshot created by the kernel becomes unsafe after later revocations or policy changes.

The broader Oreulius temporal system has object versions and persistence machinery, but this fetch snapshot is not integrated with it. No fetch-specific temporal object key, event hook, restore mode, generation comparison, or rollback callback appears in the code surface. Integration must use the broader system’s trusted generation rather than inventing an unrelated local counter.

Production snapshots should carry a monotonically advancing generation protected by authenticated storage and tied to the principal and boot or resume domain. The system must remember the highest accepted generation in rollback-resistant state. Parent linkage or a hash chain can make branching and replay visible, while explicit administrative rollback can use a different restore mode with stronger authority and forced credential rotation.

Policy and trust generations need reconciliation even when the snapshot itself is fresh. Cookies accepted under old public-suffix policy, sessions created under old origin rules, or TLS-derived state from an old trust store may need rejection or migration. Restore should never allow historical state to bypass current enforcement merely because it was valid when captured.

Snapshots and external VFS state need a consistency generation. A rolled-back fetch snapshot paired with newer storage or download files can expose data under old authority, while a newer snapshot paired with older files can assert completion that never occurred. Exact global transactions may be impractical, but mismatches must fail closed or enter explicit recovery.

### Restore audit records

The fetch AuditKind enum has no snapshot, restore, authentication, rollback, migration, partial-restore, capability-reissue, or reconciliation event. Neither snapshot nor restore accepts an AuditLog, and neither function emits into the kernel-wide audit system. Successful, rejected, malformed, forged, stale, and partial restore attempts are invisible.

This omission is especially important because restore mutates authority directly. A session can become live, a cookie can become active, or a download can reappear without any audit record showing the source snapshot, generation, owner, decision, or dropped records. The local audit ring itself is excluded from the snapshot, so there is no inherited evidence either.

Production restore should emit a protected begin record after authenticating the caller and snapshot envelope, then a terminal committed or rejected record after the transaction resolves. The terminal record should include the snapshot object identity, schema version, generation, restore mode, principal, counts accepted and rejected by class, capability disposition, external-state reconciliation result, policy migrations, and reason code.

Authentication failure and rollback detection need rate-limited but durable evidence. Avoid copying snapshot payload bytes, cookie values, capabilities, URLs, or destination paths into audit notes. Use keyed digests or protected object identifiers. Parser failures should record bounded offset and field class only where that information does not become an oracle.

Partial restore should not exist in the normal mode. If an administrative recovery mode intentionally salvages selected non-authority data, every omitted or transformed record must be counted and the resulting session must receive new authority. The audit event should distinguish recovery from transparent resume.

Tests should verify that failed authentication, malformed structure, stale generation, migration rejection, owner mismatch, capability reissue, successful commit, external-state mismatch, and cleanup failure each produce exactly the documented audit outcome. Failed restore must never emit committed evidence, and committed evidence must correspond to one atomic published generation.

## Fetch service security test matrix

The fetch service currently has no dedicated unit tests, integration tests, boot self-tests, fuzz targets, or regression corpus. That absence is a release-blocking gap because the service parses attacker-controlled network data, creates authority-bearing sessions, persists cross-request state, writes remote content into local storage, and restores security state across temporal boundaries. The implementation contains many bounded structures and explicit policy checks, but those properties are not yet supported by repeatable evidence.

The test program should follow the Oreulius design philosophy by proving boundedness, explicit authority, deterministic failure, isolation, and auditable state transitions. Tests should assert security invariants rather than mirror private implementation details. Every accepted operation must remain within declared memory and state limits; every rejected operation must fail closed without publishing partial state; authority must never cross a session, caller, generation, or capability boundary; and every security-relevant terminal outcome must produce the documented event and audit evidence.

The service needs deterministic test seams before this matrix can be implemented well. A scripted transport should control DNS, TCP, TLS, response bytes, partial reads, resets, and stalls. An injectable monotonic clock should advance without wall-clock sleeps. A fault-injecting VFS should model short reads, short writes, capacity exhaustion, path races, rename failure, and cleanup failure. Deterministic capability and identifier sources should make collision, wraparound, stale-authority, and slot-reuse cases reproducible. Event and audit sinks should expose queue occupancy, ordering, loss, and terminal delivery without depending on a live browser process.

| Test layer | Primary purpose | Required execution model |
|---|---|---|
| Pure unit tests | Parsers, matchers, canonicalization, bounds, and small state transitions | Fast host execution with exhaustive boundary values |
| Stateful property tests | Session lifecycles, allocators, redirect chains, cookie jars, cache transitions, and restore transactions | Generated operation sequences with invariant checks after every step |
| Fault-injection integration tests | Transport, VFS, event, audit, and cleanup behavior under partial failure | Deterministic substitutes for every external dependency |
| Kernel self-tests | Dispatcher wiring, caller identity binding, capability checks, queues, and service ownership | Boot-time tests following the existing self-test reporting model |
| Fuzz and regression tests | Hostile URL, HTTP, chunked, cookie, and snapshot byte streams | Seed corpora in continuous integration plus longer scheduled campaigns |
| System interoperability tests | Real resolver, network stack, TLS provider, VFS, and browser-service integration | Emulator or controlled network fixtures, never the primary parser oracle |

Native unit and property tests should run on every change. Seed-corpus fuzz regression, kernel self-tests, and deterministic integration tests should gate merges that touch the fetch service. Longer fuzzing, concurrency stress, and system interoperability suites can run on a schedule, but every discovered failure must become a permanent minimized regression case. Production readiness requires all critical invariants to have both a positive test and a negative test that proves the corresponding bypass fails.

### Session and capability tests

Session tests must establish that authority comes from the authenticated caller context and cannot be manufactured from request fields. Once the dispatcher is bound to IPC identity, opening a session should ignore or reject caller-supplied ownership claims, enforce the intended per-principal quota, and associate every capability with the actual caller, session generation, and service instance. Tests should cover successful open, duplicate open, full session table, storage-registration failure, close, repeated close, forced process death, reopen, and physical slot reuse.

Capability tests should exercise zero values, random values, altered bits, capabilities from another session, capabilities from another caller, capabilities issued before close, and capabilities restored from an older generation. Closing a session must revoke all of its request, download, storage, cookie, cache, event, and audit authority before the slot becomes reusable. Reopening the same slot must produce an unrelated capability and generation even when deterministic collision tests force the identifier source through wraparound.

Stateful tests should generate interleaved operations from several callers and verify after every operation that no caller can observe, mutate, abort, download, poll, snapshot, or restore another caller’s state. Failure during session creation must roll back every subordinate registration. Process termination and service restart tests must prove that cleanup is complete, idempotent, and unable to revoke a newer session that reused the same numeric slot.

### URL parser and redirect tests

URL tests should use a conformance corpus that covers schemes, empty and malformed authorities, user information, IPv4 and IPv6 literals, ports, fragments, percent encoding, dot segments, repeated separators, Unicode input, embedded control bytes, and every fixed-buffer boundary. Exact-limit, one-byte-over, and multi-field aggregate cases matter because silent truncation can make the URL that policy evaluates differ from the URL that transport requests. An accepted URL must have one unambiguous canonical representation; an input that cannot be represented without loss must be rejected before DNS, cache, cookie, audit, or transport state changes.

Property tests should verify idempotent canonicalization, stable origin derivation, preservation of meaningful path and query distinctions, and rejection of forbidden schemes or malformed encodings. Equivalent spellings should produce the same origin and cache identity only when the protocol defines them as equivalent. Distinct URLs must not collide because a field was truncated, omitted from serialization, decoded at the wrong layer, or normalized differently by policy and transport.

Redirect tests should drive complete scripted chains through every recognized redirect status. They should cover absent, empty, duplicated, malformed, relative, network-path, and oversized Location fields; same-origin and cross-origin transitions; HTTPS downgrade attempts; loops; exact and excessive hop counts; fragments; port changes; and redirect targets that resolve to newly forbidden addresses. Each hop must rerun URL validation, network policy, origin policy, cookie selection, credential stripping, method and body transformation, timeout accounting, and audit recording. A rejected hop must not contact the target or publish a success event.

### Header and chunked-decoder tests

The response parser must be tested against fragmented input at every byte boundary, not only complete header blocks. Status tests should cover unsupported protocol versions, missing separators, nondecimal and out-of-range status values, reason phrases at their limit, informational responses, premature EOF, and bytes following the header terminator. Header tests should cover empty names, invalid name characters, control bytes, obsolete folding, whitespace variants, exact and oversized names and values, maximum and excessive counts, and blocks whose aggregate size exceeds policy.

Duplicate-field tests need field-specific expectations. Conflicting Content-Length values, Content-Length combined with Transfer-Encoding, ambiguous Transfer-Encoding sequences, duplicated Location, and malformed framing fields must fail closed. Set-Cookie must remain independently enumerable rather than collapse into a generic duplicate rule. Parser failure must discard the partial response, release the transport, and emit one typed terminal failure without exposing unvalidated metadata.

Chunked-decoder tests should vary chunk-size case, leading zeros, extensions, delimiters, integer overflow, encoded size, decoded size, zero chunks, multiple chunks, split boundaries, premature EOF, extra bytes, and trailers. Generated tests should feed identical messages in every practical segmentation and require the same decoded result and evidence. Malformed input must always make progress toward a bounded failure; it must never panic, loop, read beyond supplied bytes, treat EOF as completion, or emit bytes beyond the declared decoded-body limit.

Dedicated fuzz targets should cover status and header parsing, framing selection, chunk-size parsing, complete chunk streams, and parser composition. The fuzz oracle should assert memory safety, bounded work, deterministic classification, complete-input accounting, and agreement between one-shot and incrementally segmented parsing. Minimized failures should join a versioned regression corpus run in continuous integration.

### Cookie, cache, and storage isolation tests

These tests should model several simultaneous sessions with overlapping hosts, paths, cache entries, and storage keys. Randomized operation sequences should set, expire, replace, retrieve, delete, snapshot, restore, close, and reopen state while asserting that observations remain confined to the owning session and current generation. Reusing an allocator slot must not reveal stale cookie bytes, cached body bytes, validators, storage roots, or metadata from its previous owner.

Cookie tests should cover host-only and Domain cookies, canonical host comparison, path matching boundaries, default paths, Secure attachment, HttpOnly script exclusion, SameSite context, Max-Age and Expires precedence, replacement identity, deletion, clock advancement, and purge behavior. Public-suffix and registrable-domain cases need a maintained conformance corpus once the service adopts an authoritative suffix source. End-to-end request tests must prove that cookie selection is rerun after redirects and that cookies never attach merely because a string suffix matches.

Cache tests should prove that the key contains every policy-relevant input and cannot collide through truncation or ambiguous serialization. They should cover freshness boundaries, malformed directives, age calculation, ETag and Last-Modified revalidation, 304 merging, authorization and cookie-sensitive responses, Vary behavior, no-store and private directives, body-pool reuse, failed writes, and policy changes after insertion. A cache hit must still pass current authority and network policy; cached content must never become a bypass around a newly denied origin, capability, or session.

Storage tests should exercise empty keys, separators, dot components, encoded traversal, control bytes, invalid text, exact path limits, root creation failure, duplicate registration, quota exhaustion, short I/O, deletion, cleanup, and generation mismatch. The VFS fixture must verify resolved object authority rather than only string shape. Failed registration or mutation must leave no partially published mapping, and temporal restore must reconcile fetch metadata with the actual storage generation before exposing it.

### Download destination tests

Download tests should treat each offer as a state machine with explicit legal transitions. They should cover offer creation, acceptance, rejection, repeated decisions, cancellation, completion, session close, process death, identifier wraparound, wrong-session identifiers, stale identifiers after slot reuse, and restore. Every illegal transition must fail without modifying destination state or emitting evidence that implies success.

Destination tests need a fault-injecting VFS and adversarial namespace fixtures. They should cover empty and overlong paths, relative paths, traversal, encoded separators, reserved names, symbolic-link substitution, mount crossing, parent replacement between validation and open, existing files, permission denial, capacity exhaustion, short writes, rename failure, and cleanup failure. Production behavior should write through an authority-checked handle to a private temporary object and publish by atomic rename; tests must prove that failure never exposes a partially trusted final file.

Filename tests should exercise Content-Disposition filename and filename-star forms, invalid encodings, path components, control characters, bidi controls, leading and trailing separators, reserved device names, extension confusion, normalization collisions, empty results, and deterministic fallback. MIME, source URL, redirect chain, content length, digest, scan or quarantine state, and final disposition should remain attached to the same download identity. Completion evidence must only appear after durable publication and required quarantine policy have succeeded.

### TLS, timeout, and transport failure tests

Transport tests require a scripted resolver, connection, and TLS provider plus an injectable clock. Live network tests are useful for interoperability but cannot establish exact timeout or cleanup behavior. Every phase should be independently configurable to succeed, fail immediately, return partial progress, stall until a deadline, or complete at the exact boundary.

DNS tests should distinguish malformed names, no records, policy-denied addresses, temporary resolver failure, and deadline expiry. TCP tests should cover refusal, reset, unreachable routes, partial connection state, exact-deadline success, timeout, and resource reclamation. TLS tests should cover protocol alerts, unsupported versions, chain failure, hostname mismatch, expiry, not-yet-valid certificates, trust-anchor changes, incomplete handshakes, and elapsed-time timeout across repeated progress iterations. The emitted failure reason and certificate evidence must match the actual decision without leaking unbounded peer data.

Response timing tests should separately exercise first-byte, complete-header, body-idle, and total-request deadlines. Slowloris fixtures should send bytes just below and just above each threshold, vary header and chunk boundaries, and continue making tiny progress past the total deadline. EOF, timeout, cancellation, and reset must remain distinct terminal states. Incomplete Content-Length or chunked framing must never become Complete merely because the peer closed or the clock expired.

Race tests should interleave abort, timeout, transport completion, event-queue pressure, and session closure. Exactly one terminal outcome may win, all transport and buffer ownership must be reclaimed once, and no body event may appear after the terminal event. Repeated fault campaigns should verify that failed requests do not consume permanent slots, poison later connections, or retain credentials.

### Temporal restore and rollback tests

Snapshot tests should first prove a canonical round trip for every included state class and explicit exclusion of in-flight transport, ephemeral buffers, local audit storage, and other nonrestorable resources. Structural tests should mutate every length, count, tag, version, identifier, and boundary field; append trailing bytes; truncate at every offset; duplicate identities; reorder records; and exceed each fixed capacity. A failed parse must leave the live service byte-for-byte equivalent to its pre-restore state.

Authentication tests should cover valid envelopes, altered payloads, altered metadata, wrong keys, wrong principals, wrong devices or boot domains, expired credentials, unsupported algorithms, and replayed envelopes. Rollback tests should exercise stale generations, branching histories, lost generation storage, newer external VFS state, older policy or trust generations, concurrent snapshot creation, and explicitly authorized recovery. Normal restore must reject stale or inconsistent authority before mutating live state.

Restored session tests should verify capability rotation, caller rebinding, request-identifier safety, cookie expiry under the restored clock model, cache-policy revalidation, download reconciliation, storage generation matching, and revocation that occurred after the snapshot. No serialized capability should become directly usable merely because its containing snapshot authenticated. Publication should be transactional: either the entire validated generation becomes visible with one committed audit record, or no restored state becomes visible and one typed rejection record explains why.

Property-based snapshot generation and a dedicated byte-stream fuzz target should share the production decoder. The oracle should require bounded parsing, no panic, no partial publication, deterministic rejection, and canonical reserialization of accepted state. Corpus cases should include every previously discovered parser desynchronization and capacity edge.

### Event overflow and audit evidence tests

Event tests should fill the session queue, local staging queue, and downstream IPC path at controlled points in a request. They should verify ordering, per-request correlation, body-before-terminal sequencing, terminal-event uniqueness, and behavior when capacity is exhausted before headers, during body delivery, or at completion. Silent loss is not an acceptable oracle. Once loss signaling exists, tests must prove that the marker reports the affected sequence range and that the client can distinguish an incomplete stream from a successful response.

Audit tests should assert both presence and absence. Identity rejection, capability failure, URL rejection, redirect denial, TLS failure, timeout, abort, download decision, storage denial, snapshot rejection, rollback detection, restore commit, event loss, and audit overflow each need a typed record with the correct session, request, generation, actor, outcome, and bounded reason. Conversely, failed operations must not emit success records, secrets must not appear in notes, and duplicate terminal evidence must not arise from retries or races.

Ring tests should cover empty iteration, first sequence values, wraparound, overwrite, readers that lag by more than capacity, concurrent writers, and recovery after overflow. Audit loss must create durable, monotonic evidence rather than disappear when the overwritten slot is reused. Correlation tests should follow one request across redirects, cache decisions, cookie attachment, transport phases, body delivery, abort or completion, and temporal operations, while distinguishing a reused numeric request identifier by its session and generation.

The final evidence suite should derive expected records from the externally observed state transition, not from calls to the logging helper. This prevents tests from passing when implementation and audit code repeat the same incorrect assumption. For every security-critical operation, the suite should establish a three-way correspondence between authorized state change, client-visible terminal result, and durable audit outcome.

## Current maturity level

The fetch service is implementation-started and structurally meaningful. It has fixed-size state, a service dispatcher, session capabilities, a transport wrapper, an HTTP/1.1 pipeline, response events, cookie state, cache state, download jobs, storage registration, temporal snapshot and restore, and audit hooks.

It is not production-ready as a browser security boundary yet. The foundation is strong, but several critical areas still need hardening before this can be treated as a fully trusted internet subsystem.

**Already strong**

**Bounded memory:** Most state uses fixed arrays and caller-provided buffers.

**Service shape:** Clients use requests and responses instead of direct transport internals.

**Session containment:** Cookies, cache, downloads, storage, and events are session-scoped.

**Event streaming:** Large responses are emitted as chunks instead of one large allocation.

**Temporal structure:** Snapshot and restore have a versioned wire format with length checks.

**Policy placement:** Scheme, redirect, origin, mixed-content, body-size, and denylist checks have defined places in the service.

**Still scaffolded**

**Caller identity:** Session open still accepts a process id from request data.

**Abort behavior:** Abort records an audit event, but transport-level cancellation is best effort.

**Download writing:** Download acceptance records destination state, but full VFS write policy and quarantine behavior need deeper integration.

**Cache behavior:** Cache lookup exists, but full revalidation and freshness policy are not complete browser-grade behavior.

**Origin model:** Same-site logic is approximate and does not use a full public suffix list.

**Event queue overflow:** Full queues silently drop events.

**Snapshot trust:** Temporal payloads are structurally checked but not cryptographically authenticated in this layer.

**TLS policy:** TLS handshake success or failure is surfaced, but richer certificate identity and policy evidence still need to be carried.

## Todos and known limitations

### Known issues/TODOS in Caller Identity

Issue: OpenSession currently accepts a process id in the request. That is useful for scaffolding because it gives the fetch service a simple way to record a session owner, enforce one live session per supplied process id, and group fetch state under a caller context. However, this is not a secure identity boundary by itself. The process id is request-provided data at the fetch boundary, not authenticated caller identity supplied by IPC, the scheduler, or the execution layer.

The current implementation records caller identity, but it does not yet authenticate it. Session creation stores the supplied process id in the browser session record, and duplicate-session enforcement searches existing sessions by that stored process id. Later operations validate the session id and local capability token, but the stored process id is not yet checked against an authenticated caller identity for navigation, close, subscribe, unsubscribe, abort, download accept, download reject, or event polling.

The broader IPC layer already has the concepts needed for stronger binding: messages carry source process identity, channel capabilities carry ownership and rights, and channel creation can grant authority through the capability manager. The missing fetch-side integration is a service dispatch path that receives caller identity out-of-band and treats that identity as the real owner of the fetch session.

Required fixes:

1. Bind session creation to authenticated IPC or execution-layer caller identity. The fetch service should receive the real caller identity from the service invocation boundary instead of trusting the process id inside OpenSession.

2. Treat request-provided process identity as untrusted input. Until the fetch dispatcher receives authenticated caller metadata, the process id in OpenSession should be documented as alpha scaffolding only.

3. Remove trusted ownership from the OpenSession request payload. OpenSession can still carry profile, policy, or session configuration fields, but the authoritative owner should come from the caller context attached to the service call.

4. Reject attempts to open sessions on behalf of another process. Once authenticated caller identity is available, the service should either ignore any caller-supplied process id entirely or reject the request when it does not match the authenticated caller.

5. Ensure one-session-per-caller enforcement uses authenticated identity. The duplicate-session check should search by the trusted caller identity supplied by IPC or the execution layer, not by a process id supplied inside the fetch request.

6. Extend capability validation so later operations check both token possession and caller ownership. A valid session id and local capability token should not be enough if the caller presenting them is not the session owner or a deliberately delegated holder of fetch authority.

7. Add typed validation failures for caller identity problems. The service should eventually distinguish invalid session, invalid capability, wrong caller, forged identity, stale generation, and revoked authority.

8. Tie session cleanup to authenticated process lifecycle. When a process exits, crashes, is killed, or loses policy authority, the fetch service should close or revoke sessions belonging to that authenticated process identity.

9. Define cleanup behavior for active fetch state. Forced cleanup should handle in-flight requests, queued events, pending downloads, accepted downloads, cookies, cache entries, origin policy, storage registration, and temporal session state.

10. Add audit records for normal session open, normal session close, forged identity attempts, wrong-caller attempts, duplicate-session rejection, policy-driven cleanup, process-exit cleanup, crash cleanup, and kill cleanup.

11. Review temporal restore behavior for stored process ids. Restored sessions should not blindly trust historical process ids unless the restored process identity is valid under the current process table, persistence generation, and snapshot trust policy.

12. Add tests for forged process ids, duplicate sessions under authenticated caller identity, wrong-caller operation attempts, close and reopen behavior, process-exit cleanup, crash cleanup, kill cleanup, policy revoke, restored process ids, and delegated fetch authority once delegation exists.

### Known issues/TODOS in Fetch Policy

Issue: The current policy model is bounded and readable, but it is not full browser-grade policy. It handles important early checks, but not the full complexity of web security.

Required fixes:

1. Expand origin policy for subresource types and navigation contexts.
2. Add stronger redirect policy with typed denial reasons.
3. Make same-site classification production-grade or explicitly document the approximation.
4. Carry richer TLS certificate identity and failure evidence.
5. Add tests for mixed content, redirect downgrade, blocked schemes, denylist hits, and origin allowlist behavior.

### Known issues/TODOS in Event Delivery

Issue: Sessions queue events in fixed-size rings, and full queues silently drop new events. That is safe for memory, but weak for observability and correctness.

Required fixes:

1. Define queue overflow behavior as drop-new, drop-old, disconnect, or backpressure.
2. Add an explicit event loss marker.
3. Audit overflow in production policy.
4. Add client wakeup or blocking poll semantics where needed.
5. Add tests for queue exhaustion and event ordering.

### Known issues/TODOS in Downloads

Issue: Downloads have a good job model, but the write path needs stronger security policy before remote content can safely become local files.

Required fixes:

1. Validate destination paths against filesystem capabilities.
2. Normalize and sanitize suggested filenames.
3. Define overwrite, partial-write, and resume behavior.
4. Attach MIME and source URL evidence to completed downloads.
5. Add quarantine or untrusted-origin metadata where needed.
6. Add tests for wrong-session download ids, rejected downloads, invalid paths, and partial writes.

### Known issues/TODOS in Temporal Restore

Issue: Temporal snapshots can restore sessions, capabilities, cookies, navigation history, and download jobs. That makes snapshot trust a security boundary.

Required fixes:

1. Authenticate snapshot payloads before restore.
2. Bind snapshots to persistence generation and rollback state.
3. Decide whether restored capabilities should remain valid or be reissued.
4. Audit snapshot restore, partial restore, malformed restore, and rejected restore.
5. Add tests for malformed counts, truncated records, stale capabilities, rollback attempts, and cookie restore behavior.

### Known issues/TODOS in Transport

Issue: The current transport path is a minimal HTTP/1.1 client over TCP or TLS. It works as a scaffold, but it is not yet a complete browser transport layer.

Required fixes:

1. Add clearer timeout and cancellation behavior.
2. Carry TLS certificate identity into events and audit.
3. Decide whether connection pooling is allowed.
4. Add stronger handling for very large headers and slow responses.
5. Add tests for DNS failure, TCP failure, TLS failure, timeout, header overflow, chunked decoding, and connection reset.

### Known issues/TODOS in Cache and Cookies

Issue: Cookie and cache state is bounded and session-scoped, but production web compatibility and privacy require more detail.

Required fixes:

1. Add stronger cookie domain matching and public-suffix awareness.
2. Enforce Secure, HttpOnly, SameSite, path, and expiry behavior in every request path.
3. Finish cache revalidation behavior for ETag and Last-Modified.
4. Add privacy policy for cache partitioning and cookie isolation.
5. Add tests for cookie scope, expiry, secure-only cookies, SameSite behavior, cache freshness, and stale entries.

## Todos and known limitations

### Known issues/TODOS in Fetch Session Capabilities

Issue: Fetch sessions currently use a local session id and capability pair as the authority token for later operations. This gives the service an explicit authority shape, but it is still an alpha bearer-token model. Production maturity needs fetch capabilities to be tied to authenticated caller identity, a revocation generation, and the broader Oreulius capability subsystem.

Required fixes:

1. Replace local-only capability authority with kernel capability subsystem integration or a boot-secret-backed authority mechanism.
2. Bind fetch capabilities to authenticated caller identity, session id, authority class, and revocation generation.
3. Stop describing the current local token as a cryptographic MAC unless the implementation actually provides that guarantee.
4. Add tests for wrong capability, stale capability, zero capability, wrong session, closed session, and slot-reuse behavior.
5. Add audit records for invalid capability attempts, stale authority attempts, and capability revocation events.

### Known issues/TODOS in Current Alpha Capability Flow

Issue: The current alpha flow opens a fetch session from request-provided process identity, creates a session table entry, returns a session id and capability, and relies on that pair for later operations. The flow is readable and useful for scaffolding, but the identity source is not strong enough for a production authority boundary.

Required fixes:

1. Treat the current flow as alpha-local session authority in documentation.
2. Replace caller-supplied process identity with authenticated IPC caller identity.
3. Ensure session ownership is established outside the client-controlled request body.
4. Add tests showing that a caller cannot open a session on behalf of another process.
5. Add audit records for session open, rejected duplicate sessions, and rejected forged identity attempts.

### Known issues/TODOS in Session Capability Issuance

Issue: Session capabilities are currently issued locally by the fetch session table. The generator is deterministic and starts from a fixed seed, so it should not be treated as a production-grade unguessable authority source. Session ids are also slot-derived, which makes capability strength and generation tracking more important.

Required fixes:

1. Replace deterministic local token generation with kernel-issued capability authority or a boot-secret-backed construction.
2. Add an explicit session generation or revocation generation.
3. Bind issued capabilities to the authenticated caller and the session lifetime.
4. Define whether temporal restore reuses old capabilities, reissues fresh capabilities, or rejects restored capability authority.
5. Add tests for slot reuse, repeated open and close cycles, restored capabilities, zero capability restore, and capability uniqueness across sessions.

### Known issues/TODOS in Capability Validation

Issue: Capability validation currently checks whether the supplied session id resolves to a live session and whether the supplied capability matches the stored capability. That keeps the validation path centralized, but it proves token possession rather than full process-bound authority.

Required fixes:

1. Pass authenticated IPC caller identity into the fetch service validation path.
2. Check that the authenticated caller matches the process bound to the session.
3. Replace boolean validation with typed validation failures such as invalid session, invalid capability, wrong caller, stale generation, and revoked authority.
4. Add generation checks so old capabilities fail after close, reopen, or restore decisions.
5. Add audit records for wrong-caller attempts, stale-generation attempts, and repeated invalid capability attempts.

### Known issues/TODOS in Capability Revocation on Session Close

Issue: Closing a session resets the session slot and purges related fetch-owned state, including origin policy, cookies, cache entries, downloads, and storage registration. This is a useful local revocation behavior, but revocation is still represented mainly by slot clearing and token mismatch rather than an explicit generation model.

Required fixes:

1. Add explicit revocation generation tracking to session state.
2. Ensure closed-session capabilities fail even when a session slot is later reused.
3. Audit close-session revocation as an authority event, not only as lifecycle cleanup.
4. Define how close interacts with active requests, pending downloads, queued events, and temporal snapshots.
5. Add tests for stale requests after close, slot reuse after close, restored closed sessions, and purged per-session state.

### Known issues/TODOS in Future Capability-Subsystem Integration

Issue: The fetch service currently uses a local session capability token rather than a fully integrated Oreulius capability object. This keeps the alpha implementation simple, but it leaves fetch authority outside the same capability lifecycle used by the rest of the kernel. The main capability subsystem already has typed capability classes, rights, object ids, signed token payloads, per-task capability tables, revocation paths, attenuation, provenance, IPC transfer staging, remote leases, and audit events. Fetch authority is still represented as a session id and local token stored inside the fetch session table.

The important limitation is not just that fetch has its own token. It is that fetch authority is not yet visible to the kernel capability manager as a normal capability. A fetch session cannot yet be listed as a capability in the caller’s capability table, revoked by capability type, attenuated into narrower rights, transferred through the ticketed IPC capability path, connected to parent capability provenance, or evaluated through the same signed-token verification path used by the broader capability model.

The capability taxonomy also does not yet define a fetch-specific authority class. The current capability types cover channels, tasks, spawners, console, clock, store, filesystem, service pointers, and cross-language links. Fetch therefore needs either a dedicated Fetch capability type or a constrained service-pointer authority class with fetch-specific rights. Without that, fetch remains capability-shaped but not capability-subsystem-native.

Required fixes:

1. Define a first-class fetch capability authority class in the kernel capability taxonomy, either as a dedicated Fetch capability type or as a constrained service-pointer capability class for the fetch service.

2. Define fetch-specific rights instead of treating one session token as all-purpose session authority. The rights model should separate session lifecycle control, navigation, event polling, abort, download acceptance, storage access, introspection, and delegation.

3. Replace raw local token checks with capability table validation where possible. Fetch operations should validate a capability object owned by the authenticated caller, not only compare a numeric token stored inside the fetch session table.

4. Bind fetch session capabilities to authenticated process identity, fetch session object id, session lifetime, authority class, rights bitset, origin process, grant timestamp, and revocation generation.

5. Add an object id model for fetch sessions so a capability can point to a specific fetch session object rather than only carrying a local session id.

6. Add a session generation or revocation generation so stale fetch capabilities fail after close, slot reuse, process cleanup, policy revoke, or temporal restore.

7. Add policy revoke support so fetch authority can be invalidated outside normal session close. This should cover process exit, process crash, kill, caller policy revoke, forced cleanup, and future security policy decisions.

8. Store fetch authority in the caller’s per-task capability table so it can be listed, inspected, revoked, transferred, attenuated, and audited through the same path as other kernel capabilities.

9. Add capability-manager revocation on fetch session close. Closing a fetch session should purge fetch-owned state and also retire the corresponding kernel capability authority.

10. Add forced revoke behavior for process cleanup. When a task exits or crashes, its fetch capabilities should be revoked through the capability manager and the fetch service should purge the matching sessions, cookies, cache entries, downloads, event queues, storage registration, and origin policy.

11. Add attenuation support for fetch capabilities. A caller should be able to delegate narrower fetch authority, such as poll-only authority, abort-only authority, download-decision authority, or storage-limited authority, without handing over complete session control.

12. Add provenance tracking for delegated fetch authority. If a fetch capability is derived from another fetch capability, the child authority should preserve parent capability information so the delegation chain remains inspectable.

13. Decide whether fetch capabilities are transferable over IPC. If they are transferable, transfers should use the existing ticketed IPC capability transfer path, require delegation rights, support rollback on failed transfer, and install the received authority into the target task’s capability table.

14. Define how fetch capabilities interact with remote capability leases and CapNet. Remote fetch authority should not automatically imply full local session control. The model should define whether a remote lease can open a session, use an existing session, poll events, accept downloads, or only invoke a constrained fetch service pointer.

15. Move fetch validation toward typed authority failures instead of a single boolean result. The validation path should distinguish invalid session, invalid capability, wrong capability type, missing right, wrong caller, stale generation, revoked authority, expired lease, and transfer constraint failure.

16. Connect fetch authority failures to the existing security and observability paths. Invalid fetch capability use, wrong-caller attempts, rights escalation attempts, transfer constraint failures, stale-generation attempts, and revoked-capability use should become structured audit or security events.

17. Add tests for capability revoke, cross-process misuse, stale handles, restored handles, authority-class mismatch, missing rights, wrong object id, wrong owner, revoked session generation, attenuated authority, IPC transfer, remote lease denial, process cleanup, and close-session revocation.

18. Add tests proving that cache access, cookie access, event polling, download decisions, storage access, abort requests, and navigation requests each require the correct fetch capability right once the rights model is introduced.

19. Add tests proving that a fetch capability cannot be reused after session close, slot reuse, temporal restore rejection, process cleanup, policy revoke, or capability-manager revocation.

20. Document the migration boundary clearly: the current alpha model is a local session-token model, while the mature model should be typed, signed, rights-bearing, owner-bound, generation-bound, attenuatable, revocable, transferable, auditable, and compatible with remote leases where policy allows it.

### Known issues/TODOS in Fetch Caller Identity and IPC Session Binding

Issue: Fetch session ownership currently depends on process identity supplied through the request model. Production maturity needs the fetch service to receive caller identity from the IPC or execution layer, not from client-controlled request fields.

Required fixes:

1. Remove trusted process identity from the OpenSession request body.
2. Pass authenticated IPC caller identity into fetch service dispatch.
3. Bind new sessions to the real caller identity from the IPC layer.
4. Reject attempts to create or operate sessions for another process.
5. Add audit records for forged identity attempts and rejected caller/session mismatches.

### Known issues/TODOS in Current Caller-Supplied Process ID Model

Issue: The current protocol allows the caller to provide a process id when opening a fetch session. That process id is then passed through the fetch dispatcher into the session table and stored as the session owner. This is useful for early development because it lets the fetch service build a session ownership model, enforce a one-session-per-process rule, and keep session state grouped around a recorded owner. However, the process id is still request-provided data at the fetch boundary, not authenticated caller identity supplied by IPC or the scheduler.

The result is an alpha identity model rather than a secure identity boundary. The fetch service records the supplied process id and uses it during session creation, but it does not independently prove that the caller is the process named in the request. After the session is opened, later operations are authorized by the session id and local capability token. The stored process id is not yet used as part of the validation path for navigation, close, subscribe, unsubscribe, abort, download acceptance, download rejection, or event polling.

Required fixes:

1. Document caller-supplied process ids as alpha scaffolding only. The README should be explicit that the current model records a process id for development-time session ownership, but does not yet treat that value as authenticated process identity.

2. Treat request-provided process identity as untrusted input. The fetch service should not assume that the process id inside OpenSession is authoritative unless it has been supplied or rewritten by a trusted service boundary.

3. Introduce a dispatcher path that receives authenticated caller identity out-of-band. Fetch dispatch should receive caller identity from IPC, the scheduler, or the service invocation layer, rather than deriving authority from the request body.

4. Remove trusted ownership from the OpenSession request payload. OpenSession can still carry profile, policy, or session configuration fields, but the authoritative owner should come from the caller context attached to the service invocation.

5. Bind new fetch sessions to authenticated caller identity. Session creation should store the real caller identity, not a caller-declared process id.

6. Ensure one-session-per-caller enforcement uses authenticated identity. Duplicate-session checks should search by the trusted caller identity supplied by the kernel, not by a process id supplied inside the fetch request.

7. Extend capability validation so later operations check both token possession and caller ownership. A valid session id and capability token should not be enough if the caller presenting them is not the session owner or an explicitly delegated holder of fetch authority.

8. Add typed validation failures for caller identity problems. The service should eventually distinguish invalid session, invalid capability, wrong caller, stale generation, revoked authority, and forged identity instead of collapsing all authority failures into a generic invalid-capability path.

9. Add audit records for identity mismatches. Once authenticated caller identity is available, the service should audit attempts to open a session under another process id, operate a session owned by another caller, or reuse a session token from the wrong caller context.

10. Tie forced cleanup to authenticated process lifecycle. When a process exits, crashes, is killed, or loses policy authority, the fetch service should be able to close or revoke sessions belonging to that authenticated process identity.

11. Review temporal restore behavior for stored process ids. Restored sessions should not blindly trust historical process ids unless the restored identity is valid under the current process table, persistence generation, and snapshot trust policy.

12. Add tests for forged process ids, duplicate sessions under authenticated caller identity, wrong-caller operation attempts, close and reopen behavior, process cleanup, restored process ids, and delegated fetch authority once delegation exists.

### Known issues/TODOS in Authenticated IPC Caller Identity

Issue: The fetch service does not yet show a mature path where the IPC layer supplies authenticated caller identity to the service dispatcher. Without this, capability validation cannot prove that the token holder is the process that opened the session.

Required fixes:

1. Extend the fetch service dispatch interface to accept authenticated caller metadata.
2. Bind OpenSession to the caller identity supplied by IPC.
3. Bind later operations to the same caller identity during validation.
4. Ensure caller identity survives through service wrappers, queues, and request dispatch.
5. Add tests for valid caller, wrong caller, dead caller, and caller identity mismatch.

### Known issues/TODOS in One-Session-Per-Caller Enforcement

Issue: The service intends to enforce one fetch session per caller context, but the current enforcement is only as strong as the process identity source. The implementation currently checks for an existing live session by comparing the process id stored in each session against the process id supplied through `OpenSession`. That creates a useful alpha quota rule, but it is more accurately one session per supplied process id, not one session per authenticated caller.

The current enforcement point is placed correctly in the session-open path. The service checks for an existing session before allocating a new slot, before registering origin policy, and before registering storage. That prevents duplicate state from being created for the same recorded process id. The limitation is that the recorded process id still comes from the request body, so the duplicate-session rule depends on a caller-provided identity value rather than authenticated IPC or execution-layer caller identity.

There is also a design decision that needs to be made before this rule is treated as final. The protocol describes opening a session as one per tab or navigation context, while the implementation enforces one live session per process id. Those are not necessarily the same model. If each tab or navigation context maps to a separate process, then one session per process may be enough. If a single process is expected to own multiple fetch contexts, the current rule will be too strict and should eventually become one session per authenticated caller plus explicit context id, profile id, or session class.

Required fixes:

1. Enforce one session per authenticated caller, not one session per request-provided process id. The duplicate-session check should use caller identity supplied by IPC, the scheduler, or the execution layer.

2. Treat the current process-id lookup as alpha scaffolding. The README should describe the current behavior as a local session quota mechanism, not a complete process-bound identity guarantee.

3. Remove request-provided process id from the trusted duplicate-session key. `OpenSession` can still carry profile or configuration data, but the authoritative caller should come from the service invocation boundary.

4. Decide whether the final model is one session per process, one session per caller context, or one session per caller/profile pair. The documentation should align the “tab / navigation context” language with the actual enforcement rule.

5. If multiple sessions per process are allowed later, introduce explicit context ids, profile ids, or session classes. The duplicate-session key should then become authenticated caller plus explicit context, not just caller identity alone.

6. Use the existing `profile` field or replace it with a clearer context field if profile-aware or multi-context session ownership is intended. The current session-open path does not use the profile field as part of duplicate-session enforcement.

7. Extend session validation so later operations enforce caller ownership, not only session id and local capability possession. A caller should not be able to operate another caller’s session merely by presenting a valid session id and token unless authority was explicitly delegated.

8. Tie one-session-per-caller enforcement to process lifecycle cleanup. When a process exits, crashes, is killed, or loses policy authority, its fetch session should be closed or revoked so a stale session does not permanently occupy the caller slot.

9. Define restore behavior for one-session enforcement. Temporal restore should not blindly recreate a session for a stale process id, conflict with a live authenticated caller, or block a real caller because of restored historical identity.

10. Add audit records for rejected duplicate opens, forged duplicate identity attempts, caller/session mismatches, stale restored sessions, and forced cleanup of sessions that occupy a caller slot.

11. Add tests for duplicate opens under authenticated caller identity, close and reopen behavior, forged process ids, forged duplicate identity, multi-context policy, profile-aware sessions if supported, process-exit cleanup, crash cleanup, kill cleanup, and restored sessions that conflict with live caller identity.

12. Add tests proving that duplicate-session rejection occurs before origin policy registration, storage registration, and any other session-owned state allocation.

### Known issues/TODOS in Session Cleanup on Process Exit or Crash

Issue: Session cleanup currently happens through explicit `CloseSession`. That path validates the session id and local capability, resets the session slot, unregisters origin policy, purges cookies, purges cache entries, purges downloads, unregisters storage, and records a session-closed audit event. This gives the fetch service a useful local cleanup path, but it is still caller-driven. Production maturity needs a kernel-driven cleanup path that runs when the owning process exits, crashes, is killed, or loses policy authority.

The session table already stores a process id in each browser session, so the fetch service has enough local state to identify which sessions belong to a recorded process owner. The missing piece is lifecycle integration. A dead or crashed process should not need to send one final `CloseSession` request for its fetch state to be removed. Process lifecycle, scheduler cleanup, kill handling, and policy revocation should be able to force cleanup from inside the kernel.

Required fixes:

1. Tie session cleanup to authenticated process lifecycle events. The fetch service should receive cleanup notifications when a process exits normally, crashes, is killed, or loses authority through policy revoke.

2. Add a kernel-internal forced cleanup path that does not require the dead process to present its session capability. Explicit `CloseSession` should remain caller-driven, while process-exit cleanup should be kernel-driven.

3. Reuse the same cleanup semantics as explicit close where possible. Forced cleanup should reset the session slot, unregister origin policy, purge cookies, purge cache entries, purge downloads, unregister storage, clear queued events, and remove session-owned runtime state.

4. Ensure one-session-per-caller enforcement cannot be blocked by stale sessions. If a process dies and its fetch session remains live, future opens for that caller identity can fail incorrectly with a session quota error.

5. Cancel or mark active requests when the owning process dies. The service should define whether in-flight DNS, TCP, TLS, header parsing, body streaming, and cache writes are aborted immediately or converted into terminal error state before cleanup.

6. Define queued event behavior during forced cleanup. Events already queued for a dead owner should either be discarded with the session or preserved only if a trusted supervisor or audit path is supposed to observe them.

7. Define pending download behavior during forced cleanup. Pending download offers should be rejected or purged. Active downloads should be cancelled or marked failed. Completed downloads should keep whatever evidence policy requires, but session control authority should be revoked.

8. Tie forced cleanup into capability revocation. When fetch capabilities become integrated with the kernel capability subsystem, process cleanup should revoke the corresponding fetch capability authority, not only clear local fetch session state.

9. Add process-generation awareness where needed. A restored or stale session should not be treated as owned by a new process that happens to reuse the same numeric process id.

10. Review temporal restore behavior for process-owned sessions. Restored sessions should not blindly recreate live fetch authority for process ids that no longer exist, belong to a different process generation, or conflict with an active authenticated caller.

11. Distinguish normal close from forced cleanup in audit records. A user-initiated session close, process-exit cleanup, crash cleanup, kill cleanup, and policy-revoke cleanup should be separate audit-visible events.

12. Add audit records for stale-session cleanup, active-request cancellation, pending-download purge, process-exit cleanup, crash cleanup, kill cleanup, and policy-driven revocation.

13. Add tests for normal process exit, crash cleanup, kill cleanup, policy revoke, active request cleanup, queued event cleanup, pending download cleanup, active download cancellation, close and reopen after forced cleanup, and stale session removal.

14. Add tests proving that forced cleanup purges cookies, cache entries, downloads, storage registration, origin policy, queued events, and session table entries for the affected process.

15. Add tests proving that a dead process cannot leave behind a live fetch session that blocks a later authenticated caller from opening a new session.

### Known issues/TODOS in Forged Identity Audit Records

Issue: The current fetch service has audit hooks for normal lifecycle and fetch events, but forged identity attempts and caller/session mismatches are not yet represented as their own audit class. This is mostly because the fetch service does not yet receive authenticated caller identity at the dispatch boundary. `OpenSession` still accepts a process id from the request body, so the service cannot compare a trusted caller identity against a claimed process id. Until that comparison exists, a forged identity attempt cannot be reliably distinguished from an ordinary session-open request.

Once authenticated IPC or execution-layer caller identity is available, identity failures should become audit-visible events. A request that tries to open a session under another process id, operate a session owned by another caller, reuse a valid session token from the wrong caller context, or restore authority for a stale process identity should produce a typed audit record. These records should be distinct from ordinary invalid-capability failures because they describe a caller identity problem, not only a bad token problem.

Required fixes:

1. Add audit records for forged `OpenSession` identity attempts. When the authenticated caller identity does not match a requested or implied target identity, the service should record the real caller, the claimed identity, and the rejected operation family.

2. Add audit records for valid session id with wrong caller identity. Once session validation receives authenticated caller metadata, the service should detect when a caller presents a session id that belongs to another process or caller context.

3. Add audit records for valid local capability token used from the wrong caller context. This is important because the mature model should not treat token possession alone as enough authority when caller ownership is supposed to be enforced.

4. Add audit records for repeated invalid capability attempts. The service should distinguish wrong session, wrong capability, zero capability, stale generation, revoked authority, and wrong caller where possible.

5. Add audit records for restored identity mismatches. Temporal restore should not silently recreate sessions for stale process ids, missing process owners, wrong process generations, or caller identities that conflict with live sessions.

6. Add audit records for duplicate-session identity conflicts. A rejected duplicate open should record whether it was a normal duplicate under the same authenticated caller or a suspicious attempt involving a mismatched identity.

7. Rate-limit or coalesce repeated failure records to protect the audit ring. Forged identity attempts should be visible, but repeated identical failures should not be able to flood the audit log and evict more useful evidence.

8. Preserve counters for coalesced identity failures. If repeated forged identity attempts are compressed into one audit record, the record should retain enough count or summary information to show that repeated failures occurred.

9. Include useful correlation fields in identity audit records. Where possible, records should include authenticated caller id, claimed process id, stored session owner, session id, request id, operation family, and typed failure reason.

10. Keep sensitive request data out of identity audit records. Audit entries should identify the authority failure without storing unnecessary URLs, request bodies, cookies, download paths, or other sensitive fetch data.

11. Add tests confirming that forged `OpenSession` attempts generate audit evidence once authenticated caller identity is available.

12. Add tests confirming that a valid session id presented by the wrong caller generates a caller/session mismatch audit record.

13. Add tests confirming that repeated invalid capability attempts are counted, rate-limited, or coalesced instead of flooding the audit ring.

14. Add tests confirming that restored stale process ids, restored wrong-generation identities, and restored caller/session conflicts produce restore-related identity audit records.

15. Add tests confirming that normal session open and normal session close audit records remain distinct from forged identity, wrong-caller, and forced-cleanup audit records.
### Known issues/TODOS in Fetch Event Delivery, Queue Overflow, and Loss Markers

Issue: Fetch sessions use bounded event queues. That is appropriate for kernel memory control, but full queues currently risk silent event loss. Since events carry headers, body chunks, TLS state, redirects, policy blocks, download offers, completion, and errors, silent loss weakens correctness and auditability.

Required fixes:

1. Define queue overflow behavior as drop-new, drop-old, disconnect, or backpressure.
2. Add an explicit event-loss marker to the event stream.
3. Track per-session lost-event counts.
4. Audit event queue overflow.
5. Add tests for queue exhaustion, event ordering, event loss markers, and client recovery behavior.

### Known issues/TODOS in Event Queue Ownership and Depth

Issue: Each fetch session owns a fixed-depth event queue. This is the right basic shape for a kernel service because event delivery stays bounded, session-local, and predictable. The current queue is owned by the browser session, has a fixed depth of 64 events, and is drained in small batches through polling. That keeps one fetch session from growing memory without limit, but it also means the service must define what happens when a session produces events faster than the caller drains them.

The queue is session-owned, but the final authority model still needs to clarify the relationship between session ownership and caller ownership. Today, polling requires the session id and local capability token. Later, once authenticated IPC caller identity is wired into fetch dispatch, polling should also prove that the caller is the session owner or holds delegated event-read authority. Without that, the queue is session-scoped internally, but not yet fully caller-bound at the authority boundary.

The biggest practical concern is queue pressure. Headers, body chunks, redirects, TLS state, policy blocks, download offers, errors, and completion events all share the same fixed queue. Body chunks can be high-volume, especially for larger responses, and they can fill the queue before the caller drains it. If that happens, security-relevant or terminal events can be lost behind ordinary body data. A policy block, TLS failure, redirect denial, fetch error, or completion event should not silently disappear because body streaming exhausted the queue.

Required fixes:

1. Document event queue ownership clearly. The README should state that each fetch session owns its own event queue and that events are scoped to the session that produced them.

2. Document the queue depth and polling batch size. The README should explain that the queue is fixed-depth and that polling drains only a bounded number of events at a time.

3. Define whether the queue is only session-owned or also caller-owned. The current implementation scopes events to the session, but the mature model should bind event access to authenticated caller identity or delegated event-read authority.

4. Ensure event polling eventually checks authenticated caller identity. A caller should not be able to drain another caller’s event queue merely by possessing a copied session id and token unless event authority was explicitly delegated.

5. Define the consequences of queue exhaustion. The service should not silently lose events without documenting what happened and how the caller is expected to respond.

6. Add a per-session event-loss counter. If the queue fills, the session should remember that event loss occurred instead of dropping the information completely.

7. Add an explicit event-loss marker. The next poll after overflow should be able to tell the caller that the event stream is incomplete.

8. Decide whether all events are equally droppable. Body chunks, completion events, policy blocks, TLS failures, redirect denials, and fetch errors do not have the same importance.

9. Reserve space or priority for terminal and security-relevant events where needed. Completion, error, policy block, TLS failure, redirect denial, and download decision events should not be starved by body chunks.

10. Consider treating body chunks as lower priority under queue pressure. If the service must drop something, losing ordinary body data is usually easier to explain than losing the event that says the request failed, completed, or was blocked by policy.

11. Decide whether event overflow should fail the request. If the service cannot honestly represent the event stream anymore, one valid policy is to emit a terminal error and stop the request.

12. Add audit records for event queue overflow. Overflow affects the reliability of the fetch history and should be visible in audit evidence, not only client-facing events.

13. Include session and request correlation where possible. If overflow can be tied to a specific request, the loss marker and audit record should include that request. If not, the loss should still be recorded at the session level.

14. Define queue behavior during session close and forced cleanup. Closing a session or cleaning up a dead process should clear queued events deliberately, not leave ambiguous pending state.

15. Define queue behavior during temporal restore. Restored sessions should not accidentally revive stale event queues without a clear policy for whether queued events are persisted, discarded, or marked as restored.

16. Add tests for body-heavy responses that fill or nearly fill the queue.

17. Add tests for policy blocks during near-full queues.

18. Add tests for TLS failure, fetch error, redirect denial, and completion events under queue pressure.

19. Add tests proving that overflow produces a loss marker or audit evidence once loss tracking is added.

20. Add tests proving that one session cannot drain another session’s event queue.

21. Add tests for polling after close, polling after forced cleanup, and polling after temporal restore.

### Known issues/TODOS in Polling Model and Event Batches

Issue: Event polling returns a bounded batch of events. The current model is simple and predictable: PollEvents validates the session id and local capability token, finds the live session, drains up to 8 queued events, and returns those events with a count. The underlying session queue is fixed at 64 events, so the service has a bounded memory shape both at the session level and at the response level.

This is a useful alpha model, but the behavior needs clearer semantics before it becomes a mature event delivery contract. Polling currently reports only the events still present in the queue. If the queue overflowed earlier, PollEvents does not tell the caller that events were lost. An empty poll only proves that the queue is empty at that moment, not that the event stream was complete. The service also has Subscribe and Unsubscribe operations, but PollEvents does not currently require the session to be subscribed before draining events. That may be correct if subscription is intended for future push or wakeup behavior, but it should be documented directly.

Required fixes:

1. Define whether PollEvents requires an active subscription. If subscription is only for future push or wakeup behavior, the README should say that polling is controlled by session authority rather than subscription state. If subscription is meant to control event access, PollEvents should reject polling while the session is unsubscribed.

2. Document the maximum events returned per poll. The current response shape returns up to 8 events, and the README should describe that as part of the fetch event contract.

3. Document the session queue depth. The current session queue holds 64 events, which matters because one poll cannot drain a full queue in a single request.

4. Preserve event ordering across partial drains. Polling should continue to behave as a first-in, first-out drain unless the service deliberately introduces priority handling for terminal or security-relevant events.

5. Define what an empty poll means. An empty poll should be documented as “no events are currently queued,” not as proof that no events were dropped or that the request is complete.

6. Add event-loss reporting before relying on polling as a complete stream. If overflow happened before the poll, the caller should receive a loss marker or other evidence that the event history is incomplete.

7. Decide whether terminal events should receive priority. Completion, errors, policy blocks, TLS failures, and redirect denials may need stronger delivery guarantees than ordinary body chunks.

8. Decide whether body chunks can delay terminal state visibility. Since polling returns only a small batch, a long sequence of body events can keep completion or error events behind earlier queued events unless the service introduces priority or terminal-event reservation.

9. Define whether blocking poll or wakeup semantics are needed. The current model is caller-driven polling. If the service later supports blocking waits, scheduler wakeups, or push-style event notification, that behavior should be separate from basic polling semantics.

10. Bind polling to authenticated caller identity once IPC caller identity is available. The current poll path validates session id and local capability token, but mature fetch event access should also confirm that the caller owns the session or holds delegated event-read authority.

11. Add tests for empty polls. The tests should confirm that polling an empty queue returns zero events without changing session state.

12. Add tests for repeated polls. The tests should confirm that multiple polls drain the queue in order and that already-drained events do not reappear.

13. Add tests for partial drains. The tests should fill the queue with more than 8 events and confirm that each poll returns the next batch without skipping or reordering events.

14. Add tests for subscribed versus unsubscribed polling. The tests should match whichever semantic decision is chosen: either polling is independent of subscription, or unsubscribed sessions cannot poll.

15. Add tests for overflow followed by polling once loss markers are added. The caller should be able to detect that the event stream was incomplete.

16. Add tests for terminal events under batch pressure. Completion, error, policy block, TLS failure, and redirect denial events should remain visible according to the chosen event priority or loss policy.

17. Add tests for polling after session close, process cleanup, and temporal restore. These cases should not leave ambiguous event delivery state.

### Known issues/TODOS in Current Overflow Behavior

Issue: The current overflow behavior is not explicit enough for a security-sensitive fetch service. Each session has a fixed event queue, and the current queue policy drops new events when the queue is full. That keeps memory bounded, but it also allows the event stream to become incomplete without telling the caller or recording the loss in audit history.

The current behavior is best understood as alpha best-effort delivery. Existing queued events are preserved, but any event that arrives after the queue reaches capacity can be discarded silently. This matters because fetch events are not only body updates. They also carry completion, errors, policy blocks, TLS state, redirects, download offers, and other state that explains what happened to a request. Losing one of those events can make a blocked, failed, redirected, or completed request look incomplete or unclear to the caller.

The overflow is also hidden from higher-level service code. The enqueue operation does not return a delivery result, so the navigation path, cache-hit path, redirect path, and policy-block path cannot tell whether their events actually entered the session queue. A cache hit can enqueue headers, body, and completion, but any one of those can be dropped if the queue is already near capacity. Redirect-disabled and cross-origin redirect-block paths can enqueue explanatory error or policy events, but those events can also disappear if the queue is full.

The audit path has the same gap. The fetch audit log records many lifecycle and fetch events, including session open and close, navigation, fetch completion, policy blocks, TLS events, download events, cache hits and misses, aborts, redirects, content filtering, and internal errors. It does not yet define a specific event queue overflow record. That means a session can lose caller-facing events without leaving clear evidence that the event stream became incomplete.

Required fixes:

1. Replace silent drops with explicit loss accounting. The session should record that overflow occurred instead of discarding the fact along with the event.

2. Make enqueue report whether the event was stored. The service should not call enqueue blindly when the result matters. A returned delivery status would let higher-level code respond to overflow.

3. Add a per-session dropped-event counter. When the queue is full, the session should count lost events so the next poll can report that the event stream is incomplete.

4. Emit an event-loss marker when the client next polls. A caller should be able to tell the difference between a complete event stream and a stream that lost events under pressure.

5. Include dropped-event count in the loss marker where possible. If the service knows how many events were discarded, that number should be exposed to the caller.

6. Include request correlation where possible. If overflow can be tied to a specific request, the loss marker and audit record should carry that request id. If attribution is not possible, the loss should still be reported at the session level.

7. Add a dedicated audit record for event queue overflow. Overflow affects the reliability of the fetch history and should be visible in audit evidence.

8. Decide whether loss of terminal events should force request failure. Completion, fetch error, policy block, TLS failure, redirect denial, and download offer events may need stronger handling than ordinary body chunks.

9. Define whether all event kinds are equally droppable. Body chunks can be frequent and may deserve lower priority than security-relevant or terminal events.

10. Reserve queue space or priority for terminal and security-relevant events where needed. A body-heavy response should not be able to starve completion, error, policy, TLS, redirect, or download-decision events.

11. Define cache-hit overflow behavior. If headers, body, or completion from a cached response cannot be queued, the service should either report loss, fail the request, or use a documented partial-delivery policy.

12. Define redirect overflow behavior. If a redirect-disabled error or cross-origin redirect policy block cannot be queued, the caller should still receive loss evidence or a terminal failure state.

13. Define whether overflow should stop the request. If the service can no longer represent the event stream honestly, one acceptable policy is to fail the request and emit an overflow-related terminal event.

14. Protect the caller from clean-looking partial streams. PollEvents should not make an overflowed request look normal simply because the queue currently contains some events.

15. Protect the audit trail from silent incompleteness. Audit records should show when the caller-facing event stream lost information.

16. Add tests proving that overflow increments a loss counter instead of silently disappearing.

17. Add tests proving that overflow produces an event-loss marker on a later poll.

18. Add tests proving that body-heavy responses cannot hide completion or failure without loss evidence.

19. Add tests proving that policy blocks, TLS failures, redirect denials, fetch errors, and download offers remain visible or produce explicit loss evidence under queue pressure.

20. Add tests proving that cache-hit event sequences cannot appear clean when headers, body, or completion were dropped.

21. Add tests proving that blocked or failed requests cannot appear successful or merely quiet because the explanatory event was lost.

22. Add tests proving that event queue overflow creates an audit record with session and request correlation where possible.

### Known issues/TODOS in Explicit Event-Loss Markers

Issue: The protocol does not yet define a dedicated event-loss marker. The current event stream can report headers, body chunks, redirects, policy blocks, TLS state, download offers, download completion, request completion, and fetch errors, but it cannot report that the stream itself became incomplete. Without a loss marker, clients cannot reliably distinguish a quiet request from a request whose events were dropped before polling.

The missing marker matters because the queue already has a silent overflow path. Each session owns a bounded event queue, and when that queue is full, new events are discarded. The caller only sees events that successfully entered the queue. PollEvents can return a normal-looking batch, or even an empty batch, without explaining that earlier events were lost. For a fetch service, that is too ambiguous because event loss can hide body data, completion, errors, policy blocks, TLS state, redirects, or download offers.

The loss marker should not be treated as an ordinary event that gets enqueued only after overflow occurs. If the queue is already full, trying to enqueue a loss marker into the same full queue can fail for the same reason the original event failed. The service needs a small out-of-band loss state in the session, such as a dropped-event counter or pending-loss flag. When the caller polls next, the service can synthesize the loss marker before draining normal events.

Required fixes:

1. Add a dedicated event variant for lost events. The event stream should have an explicit marker that tells the caller the session event queue overflowed and the delivered stream is incomplete.

2. Track loss outside the normal event queue. The service should not depend on successfully enqueueing the loss marker at the moment overflow happens, because the queue may already be full.

3. Add a per-session dropped-event counter. When enqueue fails because the queue is full, the session should increment a counter instead of losing all evidence of the failed delivery.

4. Include the number of lost events where possible. The loss marker should report how many events were dropped since the last reported loss marker.

5. Include request correlation when loss can be attributed to one request. If the service knows which request produced the dropped event, the marker should include that request id or an equivalent request-scoped reference.

6. Support session-level loss when request correlation is not possible. If multiple requests share a session queue or attribution is unclear, the marker should still report that the session stream lost events.

7. Emit the loss marker on the next poll before ordinary queued events. The caller should learn that the stream is incomplete before processing the rest of the returned batch.

8. Reset or reduce the loss counter only after the loss marker is delivered. The service should not clear loss evidence before the caller has received it.

9. Define how clients should respond to event loss. The README should state whether clients should refetch, close the session, treat the request as failed, ignore missing body data, or surface the session as degraded.

10. Define whether event loss affects request success. Losing ordinary body chunks, losing completion, and losing a policy block do not have the same impact. The service should decide whether some lost event classes force a terminal error.

11. Add an audit record for event-loss marker emission. The client-visible marker explains the stream to the caller, while the audit record preserves evidence for later inspection.

12. Add an audit record for queue overflow even if the client never polls again. If overflow happens and the session is later closed or cleaned up, the audit log should still show that event loss occurred.

13. Decide whether terminal and security-relevant events receive priority before relying only on loss markers. A loss marker makes event loss honest, but it does not recover the lost policy block, TLS failure, redirect denial, error, completion, or download offer.

14. Document the difference between an empty poll and a complete stream. An empty poll should mean no events are currently queued, not that no events were lost and not that the request is complete.

15. Add tests for loss marker emission after queue overflow.

16. Add tests for loss counter reset after the marker is delivered.

17. Add tests for repeated overflow before polling. The marker should report the accumulated loss count rather than only one lost event.

18. Add tests for overflow followed by multiple polls. The marker should appear once for the recorded loss and should not repeat after the loss state is cleared.

19. Add tests for request-correlated loss where attribution is possible.

20. Add tests for session-level loss where attribution is not possible.

21. Add tests proving the loss marker cannot be silently dropped by the same full queue that caused the overflow.

22. Add tests proving that an empty poll after overflow does not hide the fact that loss occurred.

23. Add tests proving that terminal or security-relevant event loss either produces a loss marker, audit evidence, or a documented request-failure behavior.

### Known issues/TODOS in Overflow Audit and Recovery Expectations

Issue: Queue overflow should be part of the audit story because it affects observability. The current event queue is bounded, which is necessary for a kernel service, but overflow currently behaves like silent loss. When the queue fills, new events can fail to enter the session event stream without producing a caller-visible marker or an audit-visible record. That makes the delivered event history less trustworthy than it appears.

The service also needs to define what recovery means after event loss. Polling can drain the events that survived, but it cannot reconstruct events that were dropped. Once overflow happens, the caller needs a clear signal that the stream is incomplete and a defined response path. Depending on what was lost, recovery might mean refetching the resource, treating the request as failed, closing the session, marking the session degraded, or continuing with an explicit warning that the response stream is incomplete.

Required fixes:

1. Add audit records for event queue overflow. Overflow should produce durable evidence because it changes the reliability of the caller-facing event stream.

2. Add session and request correlation where possible. If the dropped event belongs to a known request, the audit record should include that request. If attribution is unclear, the service should still record session-level overflow.

3. Add a dedicated overflow audit kind instead of folding queue loss into a generic internal error. Overflow is a specific event delivery failure and should be searchable as its own class of evidence.

4. Add a per-session overflow counter. The service should track how often each session has experienced event loss, not only whether the most recent overflow happened.

5. Add a dropped-event counter. A caller and auditor should be able to tell whether one event was lost or whether the stream lost many events under pressure.

6. Define whether clients should refetch after event loss. If body chunks were lost, refetching may be the cleanest recovery path because the response stream can no longer be trusted as complete.

7. Define whether clients should close the session after event loss. If overflow indicates the caller cannot keep up with event delivery, closing and reopening the session may be safer than continuing with ambiguous state.

8. Define whether clients should treat the request as failed after event loss. If the service loses completion, fetch error, policy block, TLS failure, redirect denial, or download-decision events, the request should not appear clean or quietly incomplete.

9. Decide whether overflow should trigger session degradation. A session that repeatedly overflows may need to enter a degraded state where new navigations are rejected until the client drains events or resets the session.

10. Decide whether overflow should trigger backpressure. The service may need a way to slow event production, pause body streaming, stop accepting new requests, or force the caller to drain events before more work is accepted.

11. Define whether terminal and security-relevant event loss has stricter recovery behavior than body chunk loss. Losing ordinary body data is not the same as losing a TLS failure, policy block, redirect denial, error, completion event, or download offer.

12. Add a client-facing recovery rule for event-loss markers. The README should say what a frontend client is expected to do when it receives a loss marker.

13. Add an audit record when overflow forces a request failure. If the service fails a request because it cannot represent the event stream honestly, that failure should be distinct from network, TLS, parser, and policy failures.

14. Add metrics for overflow frequency. The service should expose or preserve enough counters to identify sessions, workloads, or request patterns that repeatedly overflow the event queue.

15. Add metrics for overflow severity. A single lost event and a large burst of lost events should not look the same during debugging.

16. Add tests proving that event queue overflow creates an audit record.

17. Add tests proving that dropped-event counters increase when enqueue fails because the queue is full.

18. Add tests proving that overflow recovery behavior matches the documented policy.

19. Add tests for body chunk overflow followed by refetch, failure, or degraded-session behavior, depending on the chosen policy.

20. Add tests for terminal event loss. Completion, fetch error, policy block, TLS failure, redirect denial, and download offer loss should produce explicit loss evidence or visible request failure.

21. Add tests proving that a blocked or failed request cannot appear clean because the event explaining it was dropped.

22. Add tests proving that repeated overflow does not flood the audit ring while still preserving useful evidence, counters, or coalesced records.

23. Add tests proving that a session can recover from overflow when the chosen policy allows recovery.

24. Add tests proving that a session is blocked, degraded, or closed after overflow when the chosen policy requires stricter handling.

### Known issues/TODOS in Fetch URL Parsing, Normalization, and Size Limits

Issue: URL parsing uses fixed-size fields, which is appropriate for the kernel, but the README needs to define exact parser limits and fail-closed behavior. The current parser accepts HTTP and HTTPS URLs, stores host, path, and query in bounded arrays, and rejects empty or oversized hosts. That gives the fetch service a predictable memory shape. The weaker part is that oversized path and query values are currently shortened to fit the fixed buffers, and malformed explicit ports can fall back to the scheme default. For a security-sensitive fetch boundary, malformed or oversized input should not silently become a different effective URL.

The parser should make a clear distinction between omission and malformed input. A missing port can safely use the default port for the scheme. An explicit bad port is different. If the caller supplied a port and that port is empty, nonnumeric, or outside the valid range, the parser should reject the URL. The same principle applies to size limits. If the host is too large, the parser already fails. Path and query should follow the same rule because they influence routing, cache keys, audit records, request identity, and policy decisions.

Required fixes:

1. Document supported URL forms. The README should state that the current parser accepts HTTP and HTTPS URLs with a host, optional explicit port, optional path, and optional query.

2. Document unsupported URL forms. The README should say whether fragments, userinfo, IPv6 literals, relative URLs, scheme-relative URLs, non-HTTP schemes, empty authorities, and unusual authority forms are rejected or intentionally out of scope.

3. Document exact field limits. The README should define the maximum raw URL size, host length, path length, and query length.

4. Reject oversized host, path, and query fields rather than silently truncating security-relevant data. A parsed URL should not represent a shortened version of a longer caller-provided URL unless that behavior is explicitly intended and safely documented.

5. Keep the existing empty-host rejection. Empty hosts should continue to fail because the host participates in origin identity, TLS validation, cache scope, cookie scope, and audit meaning.

6. Reject malformed explicit ports instead of falling back to defaults. A missing port can use the scheme default, but an invalid explicit port should fail parsing.

7. Reject empty explicit ports. A URL that includes a colon but no port bytes should not be treated as if the port was omitted.

8. Reject nonnumeric explicit ports. Port parsing should not convert malformed authority text into port 80 or port 443.

9. Reject out-of-range explicit ports. Values above the valid 16-bit port range should fail instead of falling back to the scheme default.

10. Define host normalization rules. The README should state whether hosts are case-preserved, lowercased, ASCII-only, punycode-normalized, or treated as raw bytes.

11. Define scheme case handling. The current parser recognizes lowercase HTTP and HTTPS prefixes. The README should state whether uppercase or mixed-case schemes are rejected or normalized.

12. Define path normalization rules. The service should state whether dot segments are preserved, normalized, or rejected.

13. Define query normalization rules. The service should state whether query bytes are preserved exactly, percent-decoded, normalized, or compared as raw bytes.

14. Define percent-encoding behavior. The README should state whether percent-encoded bytes are decoded, preserved, rejected when malformed, or left to higher layers.

15. Define fragment behavior. If fragments are unsupported, the parser should reject or strip them according to a documented rule. Silent inclusion in the path or query would make request identity ambiguous.

16. Ensure one authoritative parsed representation is used across subsystems. Origin checks, cache keys, cookie scope, redirect handling, navigation history, audit records, and transport should all rely on the same accepted URL representation.

17. Add tests for exact boundary lengths. Tests should cover host, path, query, and full URL inputs at the allowed limit and one byte beyond the limit.

18. Add tests for empty hosts. URLs with missing host authority should fail.

19. Add tests for overlong fields. Oversized host, path, and query values should fail rather than truncate.

20. Add tests for invalid ports. Empty, nonnumeric, negative-looking, oversized, and out-of-range explicit ports should fail.

21. Add tests for default ports. URLs with no explicit port should use the correct default for HTTP and HTTPS.

22. Add tests for unsupported schemes. Non-HTTP schemes should fail before policy and transport handling.

23. Add tests for malformed authority sections. Inputs with userinfo, extra separators, IPv6-style brackets if unsupported, and ambiguous colon placement should follow the documented behavior.

24. Add tests for case handling. Lowercase schemes should pass, while uppercase or mixed-case schemes should either normalize or fail according to the documented rule.

25. Add tests proving that malformed or oversized URLs cannot be silently converted into a different effective request.

### Known issues/TODOS in Supported URL Forms

Issue: The fetch service supports a limited URL model, but the README should clearly define which URL forms are accepted and which are rejected. The current parser is intentionally narrow: it accepts absolute HTTP and HTTPS URLs with a host, optional port, optional path, and optional query string. That is a reasonable kernel-side starting point because every accepted URL form becomes part of origin identity, policy enforcement, cache behavior, cookie scope, transport routing, audit records, and navigation history.

The supported surface should stay explicit. The fetch service should not accidentally behave like a full browser URL parser if it only intends to accept a smaller kernel-safe subset. Relative URLs, scheme-relative URLs, fragments, userinfo, IPv6 literals, percent-encoded authority fields, and non-HTTP schemes all need defined behavior. If they are unsupported, they should fail early before the request reaches origin policy, cache lookup, transport, or audit handling.

The parser also needs a clearer distinction between missing fields and malformed fields. A missing path can safely become slash. A missing port can safely use the default port for HTTP or HTTPS. A malformed explicit port should not become the default port. An oversized or malformed input should not silently become a different effective request.

Required fixes:

1. Document support for absolute HTTP and HTTPS URL forms. The README should state that navigation requests currently expect a full URL with a scheme and host.

2. Document the accepted shape of a URL. The supported form should be described as scheme, host, optional explicit port, optional path, and optional query string.

3. Document default path behavior. If no path is supplied, the parser currently treats the path as slash.

4. Document default port behavior. If no explicit port is supplied, HTTP should default to port 80 and HTTPS should default to port 443.

5. Explicitly reject unsupported schemes such as file, data, javascript, ftp, ws, wss, blob, about, and custom schemes unless they are deliberately added later.

6. Define whether relative URLs are supported in navigation requests. If navigation requires absolute URLs, relative navigation inputs should fail before policy and transport handling.

7. Define whether relative URLs are supported in redirects. Redirect handling may eventually need a separate rule because real HTTP Location headers can be relative even when navigation requests are absolute.

8. Define whether scheme-relative URLs are supported. Inputs beginning with a host but no explicit scheme should either fail or be normalized under a documented rule.

9. Define whether IPv6 literals are supported. If bracketed IPv6 hosts are not currently supported, the README should say so and tests should reject them.

10. Define whether userinfo is supported. URLs containing username or password authority fields should be rejected unless the service intentionally supports them with strict handling.

11. Define fragment behavior. Fragments are not sent to servers in normal HTTP request semantics, so the service should decide whether to reject them, strip them, or treat them as unsupported input.

12. Define percent-encoded authority behavior. The service should state whether encoded bytes in the host or port area are rejected, preserved, or normalized.

13. Define case handling for schemes. The current parser accepts lowercase HTTP and HTTPS prefixes. The README should state whether uppercase or mixed-case schemes are rejected or normalized.

14. Define case handling for hosts. Host comparison affects origin identity, cookies, cache, TLS hostname validation, and audit meaning, so the service should document whether hosts are lowercased or preserved as raw bytes.

15. Reject malformed explicit ports. A missing port can use the scheme default, but empty, nonnumeric, or out-of-range explicit ports should fail parsing.

16. Reject malformed authority sections. Inputs with ambiguous colon placement, empty authority, unsupported userinfo, unsupported IPv6 brackets, or malformed host data should fail clearly.

17. Keep unsupported URL forms out of downstream subsystems. Origin policy, cache lookup, cookie handling, audit records, and transport should only receive URLs that passed the documented parser contract.

18. Add tests for accepted HTTP and HTTPS URLs with host only, host plus path, host plus query, host plus explicit port, and host plus path and query.

19. Add tests for rejected schemes, including file, data, javascript, ftp, blob, about, and custom schemes.

20. Add tests for relative URLs, scheme-relative URLs, empty hosts, userinfo, fragments, IPv6 literals if unsupported, and percent-encoded authority fields.

21. Add tests for default path and default port behavior.

22. Add tests for invalid explicit ports, including empty port, nonnumeric port, oversized port, and out-of-range port.

23. Add tests proving that unsupported or malformed URL forms cannot be silently converted into accepted HTTP or HTTPS requests.

### Known issues/TODOS in Scheme, Host, Port, Path, and Query Parsing

Issue: The parser breaks URLs into fixed fields, which is the right memory model for the kernel, but security maturity requires precise behavior for every field. The current parser already rejects empty hosts and oversized hosts, which is the correct fail-closed behavior. The weaker areas are explicit port handling, path length handling, query length handling, and normalization. A URL should not be accepted if parsing changes its effective meaning.

The most important distinction is between a missing field and a malformed field. A missing port can use the default for HTTP or HTTPS. A malformed explicit port should fail. A missing path can become slash. An overlong path or query should fail rather than being shortened to fit the buffer. The fetch service should only accept URLs it can represent accurately.

Required fixes:

1. Keep empty-host rejection. Empty hosts should fail because the host is part of origin identity, TLS validation, cache scope, cookie scope, transport routing, and audit meaning.

2. Keep oversized-host rejection. The current fail-closed host behavior should remain the model for the other URL fields.

3. Reject invalid explicit ports. Empty, nonnumeric, and out-of-range explicit ports should fail instead of falling back to the default port.

4. Preserve default port behavior only for omitted ports. A missing port should use port 80 for HTTP and port 443 for HTTPS, but a malformed supplied port should not be treated as missing.

5. Reject overlong path fields. Path values that exceed the fixed path limit should fail rather than being silently truncated.

6. Reject overlong query fields. Query values that exceed the fixed query limit should fail rather than being silently truncated.

7. Define whether host case is normalized. Host comparison affects origin checks, cookie scope, cache identity, TLS hostname handling, and audit records, so the README should state whether hosts are lowercased or preserved exactly.

8. Define whether scheme case is normalized. The current parser accepts lowercase HTTP and HTTPS prefixes. Uppercase or mixed-case schemes should either be rejected or normalized under an explicit rule.

9. Define path normalization behavior. The README should state whether dot segments are preserved, normalized, or rejected.

10. Define query normalization behavior. The service should state whether query bytes are preserved exactly, normalized, percent-decoded, or compared as raw bytes.

11. Define percent-encoding behavior for every field. Percent encoding in the host, path, and query can affect identity and routing, so the parser should document whether encoded bytes are preserved, decoded, normalized, or rejected when malformed.

12. Define malformed authority behavior. Ambiguous colon placement, unsupported userinfo, unsupported IPv6 bracket syntax, empty authority, and unusual separators should fail under a documented rule.

13. Ensure every downstream subsystem uses the same parsed representation. Origin checks, redirects, cache keys, cookies, navigation history, audit records, and transport should not reinterpret the raw URL differently.

14. Add tests for host boundaries. Tests should cover empty hosts, valid maximum-length hosts, and hosts that exceed the limit by one byte.

15. Add tests for port boundaries. Tests should cover omitted ports, valid explicit ports, port zero if allowed or rejected by policy, maximum valid port, empty ports, nonnumeric ports, and out-of-range ports.

16. Add tests for path boundaries. Tests should cover empty path defaulting, valid maximum-length paths, and paths that exceed the limit by one byte.

17. Add tests for query boundaries. Tests should cover empty queries, valid maximum-length queries, and queries that exceed the limit by one byte.

18. Add tests for malformed separators. Inputs with extra colons, missing authority, unsupported userinfo, unsupported IPv6 bracket forms, and misplaced question marks should follow the documented behavior.

19. Add tests proving that malformed or oversized fields cannot be silently converted into a different effective URL.

### Known issues/TODOS in Fixed-Size URL Field Limits

Issue: Fixed-size URL fields are good for bounded memory, but truncating important fields can alter the meaning of a URL. The fetch service defines fixed limits for the raw URL, host, path, and query, which fits the kernel’s memory model. The problem is not the existence of limits. The problem is inconsistent overflow behavior. Host overflow already fails, while overlong path and query fields can be shortened to fit their buffers. For a fetch boundary, that is not strict enough.

The parsed URL becomes the representation used by origin checks, cache lookup, cookie scope, transport routing, audit records, navigation history, and redirect decisions. If the parser silently shortens a path or query, those subsystems may act on a different request than the caller supplied. That can make policy decisions, cache keys, and audit history describe the shortened URL instead of the real input that crossed the boundary.

Required fixes:

1. Document HOST_MAX, PATH_MAX, QUERY_MAX, and URL_MAX behavior. The README should state the maximum accepted size for each field and explain that these are part of the fetch service security contract.

2. Define whether URL_MAX applies to the raw input before parsing. The service should reject raw URLs that exceed the documented maximum before any field-level parsing occurs.

3. Reject host overflow. The current host behavior already fails when the host is too large, and that should remain the model for every security-relevant URL field.

4. Reject path overflow rather than silently shortening the effective URL. A path that exceeds PATH_MAX should fail parsing before origin checks, cache lookup, audit logging, or transport setup.

5. Reject query overflow rather than silently shortening the effective URL. A query string that exceeds QUERY_MAX should fail parsing instead of becoming a different request.

6. Treat fixed-size field limits as validation rules, not formatting rules. The parser should not use limits to reshape caller input into something acceptable.

7. Ensure audit records use the same accepted URL representation as the fetch request. If a URL is accepted, the audit trail should describe the exact parsed representation that the service used for policy and transport.

8. Ensure rejected oversized URLs produce clear failure behavior. Oversized raw URLs, hosts, paths, and queries should fail with a predictable parse or invalid URL result, not with later policy or transport errors.

9. Ensure cache keys cannot be built from truncated URLs. A cache entry should never represent a shortened version of an overlong caller-provided path or query.

10. Ensure cookie and origin logic cannot receive truncated URL fields. Cookie scope and origin checks should only operate on URLs that passed exact field-size validation.

11. Ensure navigation history cannot store a shortened URL as if it were the requested URL. If the service cannot represent the full URL, it should reject the request before navigation state is updated.

12. Ensure redirect targets follow the same size rules. Redirect Location values should not be accepted if they exceed the same field limits or cannot be represented exactly.

13. Add tests for one-byte-under limits. Host, path, query, and full URL inputs one byte under the limit should parse correctly when otherwise valid.

14. Add tests for exact-limit values. Fields exactly at the supported limit should either parse or fail according to the documented rule, with no ambiguity.

15. Add tests for one-byte-over values. Host, path, query, and full URL inputs one byte beyond the limit should fail rather than truncate.

16. Add tests proving that cache keys are never created from truncated path or query data.

17. Add tests proving that audit records and navigation history only use accepted parsed URLs, never silently shortened rejected inputs.

18. Add tests proving that oversized redirect targets fail under the same field-limit rules as navigation inputs.

19. Add tests proving that malformed or oversized URL fields cannot be converted into a different effective request.

### Known issues/TODOS in Invalid Port and Malformed Authority Handling

Issue: Invalid explicit ports and malformed authority sections can create confusing request behavior if they are accepted or normalized too aggressively.

Required fixes:

1. Reject non-numeric explicit ports.
2. Reject out-of-range ports.
3. Reject empty explicit port fields.
4. Define behavior for multiple colons, userinfo, IPv6 literals, and malformed authority fields.
5. Add tests for invalid ports and malformed authorities.

### Known issues/TODOS in URL Normalization and Fail-Closed Behavior

Issue: URL parsing is bounded but not yet meaning-preserving or consistently fail-closed. The parser preserves host case even though DNS identity is case-insensitive, truncates oversized paths and queries, defaults malformed explicit ports, does not enforce the raw URL maximum, and leaves authority grammar, control bytes, percent encoding, dot segments, fragments, internationalized hostnames, IPv6 literals, and relative references without a complete acceptance rule. These gaps allow malformed or textually different inputs to produce ambiguous origin, cache, transport, history, redirect, and audit behavior.

Required fixes:

The parser must enforce the raw URL, host, path, and query limits before producing a usable URL. It must reject every component that cannot be represented exactly rather than truncating it. Missing ports may use scheme defaults, but empty, nondecimal, and out-of-range explicit ports must fail. Unsupported authority forms, control bytes, malformed percent triplets, fragments, and relative references must either receive a deliberately implemented interpretation or fail before policy and transport.

The service must define a conservative normalization contract. DNS hostnames should use one lowercase validated ASCII form across origin comparison, denylist checks, DNS, TLS hostname validation, cache identity, history, and audit. Path normalization should remove only transformations whose equivalence is well-defined, while preserving encoded reserved delimiters and path case. Query bytes should remain application-sensitive and should not be reordered or broadly decoded. Internationalized names, IPv6 literals, userinfo, and relative references should remain rejected until their parsing and canonicalization rules are implemented end to end.

The accepted parsed URL must become the sole authority for scheme checks, origin policy, redirect transitions, cache keys, cookie scope, request construction, TLS peer naming, navigation history, and success audit records. Raw caller input may be retained only as bounded diagnostic evidence. Redirect targets must pass through the same parser, normalization, size checks, downgrade checks, origin checks, denylist checks, and canonical serialization as initial navigation requests before the service emits a followed redirect or opens a connection.

Parser failure must be atomic and typed. A rejected URL must not allocate a request id when avoidable, mutate top-origin state, populate cache or history, create cookies, emit success-like redirect evidence, or reach DNS and transport. Internal errors should distinguish malformed authority, invalid port, oversized input, invalid encoding, forbidden bytes, unsupported form, and unsupported scheme, with bounded audit evidence that cannot inject arbitrary text into logs.

Production verification must include exact-limit and one-byte-over tests for every field, adversarial authority and encoding cases, host-case and default-port canonical-origin tests, path and query distinction tests, fragment and control-byte rejection, and redirect-target parity tests. Cross-module tests must prove that origin, cache, TLS, transport, history, redirect events, and audit all consume the same accepted representation. Fuzzing should assert that parsing never panics, never truncates accepted input, never emits an invalid canonical serialization, and never allows a failed parse to produce observable fetch state.

### Known issues/TODOS in Fetch Redirect Handling and Cross-Origin Transition Policy

Issue: The redirect surface contains response detection, policy types, event types, and audit support, but it does not implement a complete redirect state machine. One fetch call stops at the first usable Location header. The service can reject redirects when the request maximum is zero and can perform one optional exact-origin comparison, but it does not issue the next request, retain chain state, count hops, call the redirect policy checker, or clearly transfer responsibility to the client. Comments and audit names currently describe redirects as followed even though the implementation only emits the target.

Required fixes:

The service must choose and document one owner for redirect chains. A kernel-owned loop should preserve the request identity, effective redirect limit, canonical source and target URLs, method state, body replay state, origin transition history, TLS state, and visited-target evidence across every hop. A client-mediated design would require a kernel-authenticated continuation that prevents the client from resetting hop counts or discarding security provenance. The current types and ownership boundaries favor the kernel-owned model.

Every hop must parse or resolve the target into the same canonical URL type used by initial navigation and then repeat scheme, downgrade, origin, allowlist, denylist, credential, cookie, cache, and transport checks. Intermediate redirects must not update the session top origin or commit navigation history. The final response may commit those states only after the chain succeeds.

Redirect outcomes need typed terminal states for disabled following, malformed target, unsupported target, downgrade denial, cross-origin denial, loop detection, limit exhaustion, body replay refusal, transport failure, and final completion. Event and audit wording must reflect whether a redirect was merely observed, allowed, attempted, or successfully followed.

Production tests must exercise complete chains rather than isolated parser helpers. They should cover same-origin and cross-origin chains, mixed upgrade and downgrade chains, loops, exact-limit and over-limit behavior, relative targets, method changes, nonreplayable bodies, target-specific cookie and cache behavior, event ordering, audit ordering, and failure cleanup.

### Known issues/TODOS in Redirect Response Detection

Issue: Redirect detection recognizes 301, 302, 303, 307, and 308 and returns a redirect outcome when the first parsed Location value is nonempty. The Location path is not a real parser. Header parsing and Location copying can both truncate values, duplicate Location headers are not rejected, and malformed or missing targets cause a redirect status to fall through as an ordinary body-bearing response without a typed redirect error.

Required fixes:

The response parser must reject an oversized Location value rather than shortening it. It should reject conflicting duplicate Location fields, forbidden control bytes, incomplete header blocks, and values that cannot be represented by the redirect-target parser. A recognized redirect status without a usable Location should produce a typed protocol or redirect error instead of silently becoming an ordinary final response.

Detection should return structured evidence containing the status, complete bounded Location value, original request method, and body replay context. That object should remain distinct from the later policy verdict so events and audit records can show both what the server requested and what the kernel decided.

The implementation must define status-specific method behavior. A 303 requires an explicit conversion rule, 307 and 308 require method and body preservation, and 301 and 302 need a documented compatibility policy. No body may be replayed merely because a redirect status was detected.

Tests must cover every recognized status, nonredirect three-hundred statuses, missing and empty Location values, duplicate equal and conflicting values, exact-limit and oversized values, malformed header lines, incomplete header termination, and method-specific redirect outcomes.

### Known issues/TODOS in Redirect Limit Enforcement

Issue: Redirect limits are represented but not enforced. The service computes an effective maximum from the session and request policies, yet the fetch pipeline never reads it and no redirect count exists. Only a request maximum of zero changes behavior. The standalone redirect checker compares a supplied count with the global ceiling of ten, ignores the effective per-session value, returns an unrelated scheme denial on exhaustion, and has no caller.

Required fixes:

Each in-flight request needs a hop counter and immutable effective maximum calculated once from kernel, session, and request policy. The initial request should not count as a redirect hop. The first accepted transition should be hop one, and the service must reject before opening a connection that would exceed the maximum.

Zero redirects must produce a redirects-disabled result rather than too-many-redirects. Exhaustion must produce its own typed terminal error and audit kind. The checker should accept the effective maximum or operate on a redirect-chain state object instead of consulting only the global constant.

A bounded visited-target digest set should supplement the numeric ceiling so the service can identify direct and indirect loops early. Loop detection and limit exhaustion must close the chain, preserve final evidence, prevent navigation commit, and leave the caller with an unambiguous terminal event.

Tests must cover zero, one, exact-limit, and over-limit chains; request policy narrower than session policy; attempted request policy broader than session policy; repeated targets; alternating loops; and exhaustion under event-queue and audit-ring pressure.

### Known issues/TODOS in Cross-Origin Redirect Policy

Issue: Cross-origin checking occurs only when the request flag disables cross-origin following. The service parses the target as an absolute URL and compares exact source and target origins. If parsing fails, the check is skipped and the redirect receives success-like audit and event treatment. When cross-origin following is enabled, the session origin table, allowlist, same-site classification, and opaque-origin rejection are not consulted.

Required fixes:

Target resolution and canonicalization must succeed before origin comparison. Parse failure must block the transition. Relative references must either resolve against the canonical source or receive a typed unsupported-relative result; they must not bypass policy.

The effective redirect decision must intersect request preference with session authority. A request may disable cross-origin following, but enabling it must not override a session same-origin rule or allowlist. Every target should pass through the registered origin policy, including opaque-origin rejection and any future same-site rule.

Credentials, cookies, authorization state, cache entries, host headers, and TLS identity must be recomputed for the new target. Cross-origin transitions should not inherit host-bound state from the source request. Sensitive bodies should require explicit replay policy and should be denied by default when crossing origins.

Events and audit records should distinguish same-origin, same-site, allowlisted cross-origin, and denied cross-origin transitions. Tests must cover case-normalized hosts, default ports, scheme changes, relative references, allowlisted targets, malformed targets, opaque targets, and chains that leave and later return to the original origin.

### Known issues/TODOS in HTTPS-to-HTTP Downgrade Blocking

Issue: A downgrade checker exists but is unused. It correctly tests for HTTPS as the source and HTTP as the target, despite a contradictory comment, and maps the denial to the general mixed-content reason. The active service path can emit and audit an HTTPS-to-HTTP target without applying this checker. Cross-origin-disabled requests may be blocked incidentally by origin inequality, but they do not receive a transport-security-specific result.

Required fixes:

The redirect transition must run a downgrade check on every resolved canonical target before DNS, cookie selection, cache lookup, credential forwarding, or connection setup. The policy must remain active across the entire chain so an earlier upgrade does not permit a later downgrade.

The protocol and audit model need a dedicated redirect-downgrade reason rather than mixed content or generic origin denial. A same-host downgrade and a cross-origin downgrade should both preserve the transport-security verdict even if another policy would also block the transition.

Any development exception must require privileged session authority and must be visible in both events and audit records. An ordinary request field must not weaken the secure default. Production policy should have no silent fallback from failed HTTPS to HTTP.

Tests must cover direct and multi-hop downgrades, upgrades, secure same-origin redirects, host case variations, explicit and default ports, relative references resolved from secure origins, malformed targets, and attempts to bypass the check through unsupported schemes or parser failure.

### Known issues/TODOS in Invalid or Unsupported Redirect Targets

Issue: Any nonempty Location bytes can become a redirect outcome. The Location helper trims whitespace and copies up to its buffer size, while the service validates the target only during the optional cross-origin check. Unsupported schemes, malformed absolute URLs, relative references, fragments, invalid ports, control bytes, and oversized components can therefore receive a RedirectFollowed audit record and Redirect event when parsing fails or is skipped.

Required fixes:

The service must reject truncation at both the response-header and redirect-target boundaries. A target must fit the raw URL and component limits exactly, contain no forbidden controls, use a supported scheme, and produce a canonical URL before any policy or success-like event occurs.

Relative-reference support must be intentional. If implemented, a bounded resolver should handle absolute-path, relative-path, query-only, and network-path forms against the canonical source before reparsing the result. Until then, all nonabsolute forms should fail with a typed unsupported-relative-redirect result.

Conflicting Location headers, malformed authority, unsupported IPv6 and internationalized host forms, userinfo, fragments, malformed percent encoding, empty targets, and unknown schemes need explicit denial reasons. Parse failure must never fall through to followed treatment.

Target acceptance must also decide the next method, body replay, and forwarded headers. The service should not resend credentials or request bodies to a new authority without a specific rule derived from the status and transition classification.

Tests must include every supported reference form, every rejected scheme, exact-limit and oversized targets, duplicate Location headers, malformed authority and encoding, controls and whitespace, fragments, invalid ports, body-bearing methods, and proof that rejected targets never reach DNS, transport, cache, cookies, history, or followed audit records.

### Known issues/TODOS in Redirect Audit Events

Issue: Redirect auditing currently has one dedicated kind named RedirectFollowed, even though the service does not perform the next request. Its record stores only the first 32 target bytes. Cross-origin denial uses a general policy record, redirect-disabled uses an internal-error record, and malformed targets, downgrade attempts, loops, limit exhaustion, method changes, event loss, and final chain commit have no dedicated audit representation.

Required fixes:

The audit vocabulary should distinguish redirect observed, allowed, attempted, followed, blocked, malformed, downgrade denied, loop detected, limit exhausted, and chain committed. Names must describe completed actions accurately. The current followed record should not be emitted until the service actually commits a next-hop request.

Each transition record should bind the request id, hop number, status, source-origin digest, target-origin digest, canonical-target digest, method decision, and policy verdict. A short printable note may supplement those fields, but a truncated raw prefix cannot serve as target identity. Attacker-controlled bytes need a defined encoding or hashing rule.

Record ordering should mirror the state machine. Observation follows response parsing, verdict precedes the next connection, follow records the committed transition, and chain commit follows the successful terminal response. Failures in event delivery should be correlated so the audit trail can explain when the caller missed redirect evidence.

The bounded ring needs redirect-chain summarization or counters so a hostile chain cannot erase all useful context merely by generating many records. Tests must verify typed kinds, ordering, hop attribution, source and target identity, blocked outcomes, limit and loop records, final commit, ring wraparound, and event-queue overflow interaction.

### Known issues/TODOS in Fetch Request Body Handling and Upload Limits

Issue: Navigate carries a fixed 4096-byte body and a separate length, but the dispatcher slices with the untrusted length before validation. A value above the array capacity can panic instead of returning an error. Accepted body bytes are then forwarded for every HTTP method, no request-upload policy is applied, and the transport cannot report whether a send failure occurred before or during body delivery.

Required fixes:

The protocol boundary must validate body length before slicing and construct an immutable accepted request descriptor containing method, exact body slice, upload limit, content metadata, and replay policy. Malformed representation, method rejection, and quota denial need distinct typed errors and bounded audit evidence.

Admission must complete before request-id allocation, cache lookup, DNS, TLS, header construction, or network output. The service should define per-request, per-session, and aggregate upload limits independently from response-body limits. Rejected bodies must never be truncated or partially forwarded.

Transport outcomes should distinguish request-construction failure, header-send failure, partial body send, complete body send, timeout, and peer reset. Events and audit records must communicate when a remote endpoint may have received a prefix, especially for non-idempotent methods.

Redirect, retry, abort, and timeout handling must carry body replay state. The service should deny automatic replay when delivery may have started, when the body is not rewindable, or when a transition crosses an authority boundary without explicit policy.

Verification must include malformed lengths, every method-body combination, policy limits, exact request bytes, partial writes, redirect method rules, aborts, timeouts, and proof that rejected requests create no network side effects.

### Known issues/TODOS in Supported Methods With Request Bodies

Issue: The method helper identifies POST and PUT as body-bearing, and the protocol comment says request bodies are for those methods and ignored for GET and HEAD. The executed path never calls the helper. Any nonempty body is sent for GET, HEAD, DELETE, and OPTIONS as well as POST and PUT.

Required fixes:

The service should adopt a narrow initial contract that permits bounded bodies for POST and PUT, requires empty bodies for GET and HEAD, and rejects DELETE and OPTIONS bodies until their semantics are deliberately supported. Rejection should be explicit rather than silently discarding caller data.

Method validation must occur before cache lookup and transport. GET cache behavior must never ignore a supplied body while returning a cached bodyless response. HEAD handling must also avoid sending payload bytes and should eventually enforce response-body suppression independently.

Redirect logic must define the next method and body state for every supported redirect status. A 303 should apply the chosen conversion-to-GET rule, 307 and 308 should preserve a body only when replay is safe, and 301 and 302 need a documented compatibility policy. Cross-origin body replay should default to denial.

Errors and audit records should identify the method and denial class without exposing body contents. Tests must cover empty and nonempty bodies for all six methods, cache interactions, exact transmitted bytes, and redirect transitions from body-bearing methods.

### Known issues/TODOS in Fixed Request Body Buffer Limit

Issue: The 4096-byte array bounds storage but does not safely bound the declared body. The caller-provided length is used directly as a slice endpoint, so an oversized value can panic. There is no named request-body limit, checked accessor, typed invalid-length result, or independent session upload quota.

Required fixes:

Define one shared request-body maximum used by the protocol type, decoder, service admission, documentation, and tests. Validate the length before any slice is constructed, preferably through a checked constructor that prevents invalid body state from crossing the protocol boundary.

Separate representation validity from policy. A length above the backing array is malformed input. A representable body above a session or operation quota is a policy denial. Both must fail before network activity and neither may be clamped to the nearest accepted value.

Review stack and IPC-copy costs for the complete Navigate envelope. The fixed array exists in every request value whether the body is empty or full, so future increases affect kernel memory pressure even when uploads remain small.

Tests and fuzzing must cover zero, exact capacity, one byte over capacity, extreme integer values, decoder behavior, and repeated malformed requests. The required invariant is that no body length can panic, read outside storage, create a shortened request, or reach transport after rejection.

### Known issues/TODOS in Content-Length Generation

Issue: Transport generates Content-Length from the nonempty body slice and sends that same slice, which is locally consistent after admission. However, admission is unchecked, generation is independent of method policy, empty POST and PUT requests omit Content-Length, and request-construction failures are collapsed into a general connection-failed result.

Required fixes:

Generate the header only from a validated immutable request descriptor. The service must decide whether accepted empty body-bearing methods emit Content-Length zero and apply that decision consistently. Forbidden method-body combinations must fail before header construction.

Preserve the current structured-header advantage: callers should not be able to inject Content-Length or Transfer-Encoding through raw header bytes. Chunked uploads, request trailers, and Expect handling should remain unsupported until they have dedicated bounded state machines.

Introduce typed request-build errors for insufficient header scratch space, invalid request target, invalid host field, and length-format failure. These are not connection failures and should not imply that bytes reached the peer.

Transport reporting must track how many header and body bytes were sent when failure occurs. That evidence is required before retries or redirect replay can be safe.

Tests should capture the exact wire request for empty and nonempty accepted methods, maximum bodies, long paths and hosts, and forced partial writes. They should prove one correct Content-Length field, no Transfer-Encoding, and exact agreement between declared and transmitted body length.

### Known issues/TODOS in Rejected Oversized Body Declarations

Issue: Oversized body declarations are not currently rejected. The body length field is used directly to create the slice, so values above 4096 can panic. Values within the array are accepted regardless of method or upload policy. The response-body maximum in the policy profile does not constrain requests.

Required fixes:

Validate all length-bearing protocol fields during decode or immediately at dispatch entry, before borrowing their arrays. Return malformed-request for impossible representation and upload-quota-exceeded for otherwise valid bodies outside granted policy.

Define a dedicated request-upload limit in the session policy. Do not reuse the response-body maximum because inbound resource protection and outbound authority are different controls with different expected sizes and consequences.

Rejection must be atomic. It should not allocate a request id when avoidable, consult or populate cache state, record navigation start, perform DNS, allocate TLS, or send headers. Audit evidence should contain method, declared length, effective limit, and denial class, not body data.

Never truncate an oversized body. The caller’s payload may be signed, structured, or side-effecting, and a prefix can have different semantics from the complete message.

Tests must prove typed rejection for malformed and policy-oversized lengths, exact-limit acceptance, no panic for extreme values, no transport calls after rejection, and no misleading success or navigation events.

### Known issues/TODOS in Future Streaming Upload Model

Issue: The fixed 4096-byte body is appropriate for small requests but cannot support large uploads without inflating the IPC envelope and trusted memory footprint. The existing service lacks the partial-send reporting, cancellation, timeout, redirect replay, and backpressure semantics required for safe streaming.

Required fixes:

Streaming should use a separate capability-gated lifecycle rather than a larger Navigate array. Opening an upload should bind session, canonical destination, origin policy, method, content type, maximum total size, expiry, replay policy, and use budget. Ordered chunks should carry sequence state and an explicit final marker.

The kernel must enforce bounded staging, transport backpressure, per-upload and aggregate quotas, idle and total timeouts, cancellation, and deterministic cleanup. It must report admitted, sent, and acknowledged state precisely enough to tell whether a peer may have received a prefix.

Automatic retry and redirect replay should be denied after transmission begins unless the source is demonstrably rewindable, the method permits replay, and policy authorizes the destination. Cross-origin replay should remain disabled by default.

Incremental integrity evidence should support an expected or computed digest without storing payloads in audit records. Sensitive staging memory should be cleared on release where required by the allocator and threat model.

Implementation should wait until abort, timeout, event-loss, and transport-write semantics are mature. Tests need simulated slow, resetting, redirecting, and partially accepting peers, plus quota exhaustion, sequence gaps, duplicate chunks, revocation, process death, and cleanup across every upload state.

### Known issues/TODOS in Fetch Response Header Parsing and Size Limits

Issue: Response headers are bounded but not parsed transactionally. The reader can return incomplete bytes after buffer exhaustion, EOF, or transport error; the field parser truncates names and values, drops fields after the thirty-second entry, and skips malformed lines; downstream helpers then make framing, redirect, MIME, and body decisions from the surviving first-match view. Bytes received after the header terminator in the same read are also discarded instead of becoming the initial body prefix.

Required fixes:

The transport reader must return a typed complete-header result containing the terminator offset and any already-read body prefix. Buffer exhaustion, premature EOF, timeout, and transport failure before termination must be distinct failures and must never pass collected prefixes into semantic parsing.

The field parser must return either a complete validated collection or a typed syntax or capacity error. It must reject name overflow, value overflow, field-count overflow, invalid controls, malformed lines, and unsupported folding. Silent truncation, skipping, and omission must disappear from security decisions.

Semantic extraction must be field-specific. Framing, redirects, cookies, content type, content disposition, and cache metadata require different duplicate and combination rules. A generic first-match helper may remain for noncritical presentation fields but should not control protocol behavior.

The internal validated collection and the client-facing header projection should be separate concepts. If the event format intentionally exposes fewer fields or shorter values, it must state that the projection is incomplete while all security decisions continue to use complete validated evidence.

Tests and fuzzing must cover fragmented reads, block boundaries, body-prefix preservation, malformed syntax, every field capacity, count overflow, duplicates, framing conflicts, and proof that rejected headers never reach redirect, body, cache, cookie, or completion paths.

### Known issues/TODOS in Status Line Parsing

Issue: The status parser checks for an HTTP/1. prefix, line termination, and three digits at fixed offsets, but it does not validate the minor version, required separators, status range, control bytes, or an independent line-length limit. It also treats the first informational response as the final response.

Required fixes:

Accept only explicitly supported HTTP versions and exact status-line grammar. Validate the separator after the version, the three-digit status, the separator or end after the status, the range from 100 through 599, permitted reason-phrase bytes, carriage-return and line-feed termination, and a small dedicated maximum line length.

Replace the zero sentinel with a typed result that distinguishes malformed syntax, unsupported version, invalid status, oversized line, informational response handling, and unsupported protocol switch. Audit and event code should receive only validated status evidence.

Handle informational responses as a bounded sequence until a final response arrives, or reject them explicitly. Switching protocols and other upgraded connections should remain outside the fetch path unless a separate state machine owns them.

Tests must include HTTP/1.0 and HTTP/1.1, unsupported versions, malformed separators, every status boundary, undefined but in-range codes according to policy, long reason phrases, controls, line-ending variants, partial reads, multiple informational responses, and protocol upgrades.

### Known issues/TODOS in Header Name and Value Limits

Issue: Header names are stored in sixty-four bytes and values in 256 bytes, but both are silently truncated. Name truncation can change field identity, value truncation can change field semantics, and a colon-first line is accepted as an empty-name field because empty input passes the token-character predicate.

Required fixes:

Reject any field whose complete name or value cannot be represented under the accepted parser contract. Do not truncate before lookup or semantic parsing. Require a nonempty token-valid name and reject prohibited controls, bare line breaks, and unsupported folding in values.

Define exact inclusive limits and apply them to complete received fields before lowercase normalization or whitespace trimming. Boundary failures should return typed protocol errors with field position and failure class, not attacker-controlled field contents.

Consider dedicated capacities for fields whose legitimate values exceed the generic event projection, including Location, Set-Cookie, ETag, and Content-Disposition. Internal semantic parsing must use complete accepted bytes even when the client-facing event exposes a smaller redacted or summarized representation.

Tests must cover empty names, exact-limit and one-byte-over names and values, common-prefix name collisions, long security-sensitive fields, controls, whitespace normalization, mixed-case names, and proof that overflow never creates a different stored field.

### Known issues/TODOS in Maximum Response Header Count

Issue: The parser stores at most thirty-two valid fields and silently stops. It returns no overflow marker and does not count malformed lines, so downstream code cannot distinguish a complete collection from a partial one. Remote field ordering can determine whether framing, redirect, cookie, cache, or content-classification fields remain visible.

Required fixes:

Reject a response that exceeds the accepted field count before using any field. The parser result should report total received lines, accepted fields, and complete termination, but successful semantic processing should require that no overflow or malformed line occurred.

If the implementation later validates a larger bounded block while emitting only a thirty-two-field event projection, it must keep the complete semantic collection separate and mark the event projection as partial. Security decisions may not depend on which fields fit the event.

Repeated fields with legitimate multiplicity need dedicated handling. Set-Cookie entries should be extracted individually under their own quota, while comma-combinable fields should use field-specific aggregation after full validation.

Tests must position critical fields and conflicting duplicates around the exact count boundary, mix malformed and valid lines, exceed the limit by one and by many, and prove that overflow causes atomic rejection rather than order-dependent semantics.

### Known issues/TODOS in Duplicate and Malformed Header Behavior

Issue: Malformed lines are skipped and duplicate lookup returns the first stored match. Conflicting Content-Length, Transfer-Encoding, Location, and Content-Type fields are not rejected. Repeated Set-Cookie fields are not preserved through first-match lookup. Content-Length overflow saturates to the maximum integer and invalid framing can become an absent length. Transfer-Encoding detection searches for the word chunked as a substring inside one value.

Required fixes:

Reject malformed lines rather than continuing with a partial collection. Return typed syntax errors for missing colons, empty or invalid names, prohibited controls, obsolete folding, malformed line endings, and incomplete final lines.

Implement field-specific duplicate rules. Content-Length duplicates must be valid and identical if accepted at all. Conflicting lengths must fail. Transfer-Encoding must be parsed as an ordered token list, unsupported codings must fail, and coexistence with Content-Length must follow a strict anti-smuggling policy. Location and Content-Type ambiguity should fail. Set-Cookie must preserve separate records.

Change numeric parsing to detect overflow rather than saturating. Distinguish absent metadata from invalid metadata so malformed framing cannot fall back to connection-close body handling.

Remove generic substring detection for transfer codings. Parse complete comma-separated tokens, parameters where permitted, duplicate fields, ordering, and the requirement that chunked be final under the supported HTTP policy.

Tests must cover equal and conflicting Content-Length fields, decimal overflow, signed and malformed numbers, Transfer-Encoding combinations, Content-Length conflicts, duplicate redirects and MIME fields, repeated cookies, malformed lines, and duplicate fields beyond the count boundary.

### Known issues/TODOS in Oversized Header Failure Policy

Issue: The 16 KiB raw block, sixty-four-byte names, 256-byte values, and thirty-two-field collection all fail open through partial interpretation. Reaching the block limit, losing the connection before the terminator, or encountering a read error can still return nonzero bytes for parsing. Per-field and count overflow are silent and produce no event or audit evidence.

Required fixes:

Make every header limit atomic and observable. Missing termination within the raw block limit, status-line overflow, field-name overflow, field-value overflow, field-count overflow, and premature transport termination must reject the response before any semantic field is consumed.

Return typed reader and parser failures so the event stream and audit log can distinguish too-large blocks, oversized lines, too many fields, malformed syntax, premature EOF, timeout, and transport error. These failures should not emit successful Headers or Complete events.

Preserve body bytes received alongside the completed header block. On failure, discard untrusted partial state and close transport. On success, pass the body prefix into the body decoder exactly once.

No rejected or partial response may trigger redirect handling, content classification, cookie mutation, cache insertion, download offers, navigation commit, or body relay. Audit records should contain bounded failure metadata and request correlation without copying hostile header contents.

Tests must place the terminator at every relevant boundary, split it across reads, exceed the block by one byte, force EOF and read errors before completion, overflow individual fields and counts, combine multiple overflow conditions, and verify complete absence of downstream side effects.

### Known issues/TODOS in Fetch Chunked Transfer Decoding

Issue: Chunked decoding is bounded but not integrity-preserving or fail-closed. Transfer-Encoding detection uses a first-value substring match. Size parsing converts malformed input into partial values or a zero terminator. The decoder can consume payload bytes it did not emit, the staging loop can discard transport bytes when full, EOF before the terminal chunk still produces Complete, and trailers are neither parsed nor rejected.

Required fixes:

Replace the tuple decoder with an explicit incremental state machine for size line, chunk data, data terminator, trailers, complete, and failed. Every transition must distinguish need-more-input, output-ready, valid completion, and typed protocol failure.

Enforce the invariant that no payload source byte is consumed unless it was emitted or retained in decoder state. Output-buffer and event-queue pressure must stop source and transport consumption rather than discard data.

Require a valid terminal zero-size chunk and a complete trailer terminator. EOF, timeout, staging overflow, malformed syntax, or unsupported trailers before that point must suppress Complete and produce a typed terminal error.

Integrate chunk framing with complete header validation, Content-Length conflict policy, response-body quotas, cache admission, cancellation, timeout, event loss, and audit evidence. Partial decoded events preceding a later error must remain marked as an invalid stream.

Add deterministic state-machine tests and fuzzing for arbitrary read boundaries, output capacities, event capacities, architecture targets, malformed syntax, overflow, trailers, and proof that decoded output exactly equals the valid encoded payload.

### Known issues/TODOS in Chunked Response Detection

Issue: Detection reads only the first stored Transfer-Encoding field and searches for chunked as an arbitrary case-insensitive byte substring. It can accept invalid larger tokens, ignores coding order and later fields, does not support or reject preceding codings correctly, and does not reject coexistence with Content-Length.

Required fixes:

Parse all complete Transfer-Encoding fields as one ordered token list under field-specific duplicate rules. Match complete tokens rather than substrings, reject invalid syntax and parameters, and require chunked to be final.

Reject every unsupported transfer coding until its decoder is implemented. Do not remove chunk framing from a representation that still requires another coding such as gzip and then expose the encoded bytes as ordinary content.

Adopt a strict anti-smuggling rule for responses containing both Transfer-Encoding and Content-Length. The framing decision should fail before body processing rather than prefer one field while retaining ambiguous evidence.

Return a typed framing mode that distinguishes identity, valid chunked, unsupported coding, malformed coding, duplicate ambiguity, and Content-Length conflict. A boolean does not carry enough evidence for safe failure handling.

Tests must cover exact tokens, mixed case, comma-separated lists, multiple fields, invalid larger tokens, unsupported codings before and after chunked, parameters, whitespace, truncation, duplicates, and every Content-Length conflict.

### Known issues/TODOS in Chunk-Size Parsing

Issue: The hexadecimal parser returns the accumulated prefix when it encounters an invalid digit, returns zero for an empty size, ignores unvalidated extension bytes, and saturates numeric overflow to the maximum machine-sized integer. The decoder interprets zero as the terminal chunk, so malformed size lines can terminate the response successfully.

Required fixes:

Return a typed parse result and require at least one hexadecimal digit. Reject every nonhexadecimal byte before the extension delimiter, detect arithmetic overflow, and use a fixed-width protocol integer so behavior does not vary across architectures.

Bound the complete size line and extension section. If extensions remain unsupported, validate a minimal safe grammar and ignore their semantics only after successful syntax validation. Prohibited controls and excessive extension data must fail.

Compare the declared size with the remaining response-body quota before waiting for payload bytes. Large valid chunks should be streamed through bounded output events using a remaining-byte counter rather than requiring equivalent staging memory.

Never use zero as both a valid terminal size and a parse-error fallback. The terminal transition should occur only after an explicitly valid zero size line.

Tests must cover empty lines, invalid first and later digits, leading zeros, uppercase and lowercase input, fixed-width overflow, architecture consistency, extension boundaries, controls, line-length limits, and chunk sizes above the body quota.

### Known issues/TODOS in Body Chunk Emission

Issue: One decoder call writes into a single 4096-byte output buffer. When a chunk or group of chunks exceeds the remaining output capacity, the decoder advances over the full source payload but copies only the prefix that fits. The body loop emits at most one event per transport read and does not drain complete frames already buffered. Local and session event overflow can then discard additional body events and completion.

Required fixes:

Consume only the payload bytes actually written into the current output event. Retain the chunk’s remaining byte count and emit as many ordered events as required. Never advance across un-emitted payload.

Drain all processable buffered input before reading more transport data. If output or event capacity is unavailable, apply backpressure or terminate visibly; do not continue reading and discard either encoded or decoded bytes.

Make event enqueue operations report success. The decoder must not consume additional input unless the produced event was retained or another bounded output sink accepted it. Event-loss evidence alone is insufficient after payload has already vanished.

Define terminal signaling independently from data availability. Complete should be authoritative after the zero chunk and trailers. The is_last flag should follow a documented rule for cases where the terminal marker arrives in a later read with no new payload.

Tests must use chunks smaller than, equal to, and larger than 4096 bytes; multiple chunks in one read; chunks split across every boundary; full local and session queues; zero-length bodies; and byte-for-byte comparison of emitted output against the source payload.

### Known issues/TODOS in Malformed Chunk Handling

Issue: The decoder has no malformed result. Missing size termination appears incomplete, invalid sizes become prefixes or zero, missing carriage return and line feed after payload is tolerated, staging overflow discards later reads, and EOF before the zero chunk exits the loop and emits Complete. Malformed framing can therefore become a successful truncated response.

Required fixes:

Introduce typed errors for invalid size, size overflow, excessive size line, missing data terminator, premature EOF, timeout, staging capacity exhaustion, body quota exhaustion, malformed trailer, unsupported trailer, and unexpected bytes after completion.

Require the exact carriage return and line feed after every nonzero chunk. Do not continue parsing later bytes when the terminator is absent, and do not treat transport closure as the end of a chunked body.

On framing failure, close transport, emit a terminal protocol error, suppress Complete, prevent cache or navigation commit, and record bounded audit evidence. Earlier body events must be considered part of an invalid stream and must not be treated as a usable successful resource.

Buffer-capacity exhaustion should be impossible under normal state-machine flow because transport reads stop when input cannot be consumed. If an invariant still fails, return a visible internal or protocol error rather than dropping bytes.

Tests and fuzzing must cover every malformed delimiter and read split, long unterminated lines, incomplete chunks, missing zero terminators, full buffers, read failures, EOF at every byte position, and proof that no malformed stream emits successful completion.

### Known issues/TODOS in Trailer Support or Rejection Policy

Issue: The decoder reports completion immediately after parsing a zero size and optionally consuming one immediate carriage return and line feed. It does not require the complete trailer terminator, parse trailer fields, preserve split trailer bytes, reject forbidden fields, or expose trailer evidence. Nonempty trailers are silently discarded when the body loop breaks.

Required fixes:

Adopt an explicit initial policy. The smallest safe contract is to parse through the final empty trailer line, accept only an empty trailer section, and reject nonempty trailers with a typed unsupported-trailer result.

Keep trailer parsing as a distinct decoder state so termination split across transport reads remains incomplete rather than successful. Completion may occur only after the trailer section’s final carriage return and line feed is consumed.

If trailer support is added later, use a strict allowlist and independent quotas. Framing, routing, authentication, cookie, redirect, and content-classification fields must not revise decisions made from the initial headers. Integrity fields need explicit binding to the complete decoded body.

Define how accepted trailer evidence reaches clients and audit without exposing unbounded values. Generic silent omission is not sufficient when trailers affect integrity or provenance.

Tests must cover empty trailers, one and multiple nonempty fields, forbidden fields, duplicate fields, malformed syntax, oversized names and values, field-count overflow, split final termination, missing termination, and extra bytes after completion.

### Known issues/TODOS in Fetch TLS Identity, Certificate Evidence, and Failure Reporting

Issue: The fetch service treats the underlying TLS Connected state as Established, but the TLS implementation does not parse or validate the certificate chain, verify CertificateVerify, check validity periods, match the requested hostname, apply revocation policy, or select a trust anchor. It verifies encrypted records and the server Finished transcript, which protects the cryptographic handshake but does not authenticate the URL’s server identity. The general network surface already recognizes this gap and defines fail-closed validation-unavailable behavior, while fetch bypasses it.

Required fixes:

Block production HTTPS until a reviewed certificate and hostname validation path is integrated. If an explicit development policy permits encryption without identity, expose and audit that state as unauthenticated or validation-unavailable rather than Established.

Implement bounded certificate-message parsing, CertificateVerify signature verification, chain construction, trust-anchor selection, certificate-signature checks, validity-time policy, constraints and key-usage enforcement, hostname matching, unsupported-critical-extension rejection, and revocation or freshness policy.

Replace scheduler-tick-derived TLS randomness with a kernel cryptographic random generator and define entropy health, reseed, snapshot, and failure behavior. Cryptographic randomness failure must block the handshake.

Return an evidence-bearing TLS verdict bound to canonical hostname, port, resolved endpoint, negotiated parameters, chain result, hostname result, trust anchor, leaf fingerprint, policy generation, and request identity.

Harden handshake parsing so malformed or unexpected messages, missing key shares, decryption failures, fragmentation problems, and invalid state transitions fail visibly instead of being ignored. Add cross-architecture conformance, negative, interoperability, and adversarial tests before treating the custom TLS stack as production trust code.

### Known issues/TODOS in TLS Handshake State Event

Issue: The event exposes Established, Failed, and Plaintext. Established means only that the custom TLS state reached Connected. It implies certificate and hostname security that the implementation does not provide. Failed collapses allocation, timeout, malformed-handshake, alert, and cryptographic failures. Events use lossy queues, so dependent response events may survive after the TLS verdict is dropped.

Required fixes:

Separate transport mode, cryptographic handshake state, and authenticated identity verdict. Production HTTP transmission must begin only after an authenticated verdict. Validation-unavailable development mode needs a distinct value and may not reuse Established.

Carry negotiated TLS version, cipher suite, identity-validation status, and typed failure class in a bounded event or linked evidence record. Plaintext should be represented as transport mode rather than a handshake outcome.

Guarantee ordering and visibility for trust decisions. If the TLS state event cannot be delivered, the service must not continue delivering headers and body as though the caller received the security context. Reserve event capacity, apply backpressure, or fail the request.

Emit failure before the terminal fetch error and authenticated success before request bytes are sent. Correlate every transition with session, request, connection generation, and redirect hop.

Tests must cover success and every failure phase, event ordering, event-queue pressure, redirects, session reuse, closure, post-handshake record failure, and proof that no response data appears without its required TLS verdict.

### Known issues/TODOS in Certificate Identity Evidence

Issue: Certificate and CertificateVerify messages only advance handshake state. No certificate is parsed, no signature is checked, and no identity evidence reaches fetch events or audit. Operators cannot identify which certificate was presented, which chain was accepted, or which key allegedly authenticated the peer.

Required fixes:

Parse the bounded certificate list and retain the exact leaf and chain evidence needed for validation. Verify CertificateVerify using the leaf public key, advertised signature scheme, TLS 1.3 context string, and transcript.

Produce a compact validated identity summary containing leaf SHA-256 fingerprint, matched subject alternative name, issuer or trust-anchor identifier, serial digest, validity interval, public-key and signature algorithms, chain depth, and policy generation.

Bind evidence to the canonical request hostname, endpoint, handshake transcript, session, request, and connection generation. Evidence from a reused or freed TLS slot must never be mistaken for a later session.

Keep complete certificate material behind a separately authorized diagnostic surface if needed. Events and audit should prefer fixed digests and typed identifiers over truncated attacker-controlled subject strings.

Tests must cover chain lengths and capacity limits, malformed DER, signature-algorithm mismatches, fingerprint stability, SAN selection, evidence redaction, slot reuse, and proof that evidence always describes the chain actually validated.

### Known issues/TODOS in Hostname and Chain Validation Result

Issue: The requested hostname is sent through Server Name Indication but never compared with certificate names. Certificate chains are not parsed or validated. There is no trust store, trusted-time policy, wildcard rule, IP-address rule, name-constraint enforcement, key-usage enforcement, critical-extension handling, or revocation result.

Required fixes:

Define one canonical DNS identity shared with URL parsing, DNS, Server Name Indication, hostname validation, origin policy, cache identity, and audit. Reject unsupported internationalized names and literal-address forms until their exact rules are implemented.

Match only accepted subject alternative name types under a strict wildcard policy. Common-name fallback should remain disabled unless a deliberate compatibility policy requires it. IP literals must match IP-address SAN entries rather than DNS names.

Build and validate a bounded path to a policy-authorized trust anchor. Check certificate signatures, validity periods using trusted time, basic constraints, path length, key usage, extended key usage, name constraints, algorithm policy, and unsupported critical extensions.

Return separate typed hostname, chain, time, and revocation verdicts, then combine them through session policy. Unknown time, unknown issuer, unsupported validation feature, and stale revocation evidence should fail closed in production.

Partition trust anchors by authority domain, such as public web, enterprise, update infrastructure, pinned services, and development. Trust-store changes need generation tracking, revocation, persistence integrity, and audit. Tests must cover valid chains and every major failure class, including cross-signed paths and policy partitioning.

### Known issues/TODOS in Typed TLS Failure Reasons

Issue: The TLS session keeps short free-form errors, transport exposes only allocation and handshake failure, and fetch emits one Failed state and one TlsHandshakeFailed error. Pool exhaustion, timeout, missing session state, peer alert, malformed messages, decryption failure, bad Finished, and internal errors collapse together. Certificate and hostname reasons do not exist because validation is absent.

Required fixes:

Introduce stable phase and cause enums across TLS, transport, fetch events, policy, and audit. Preserve distinctions when mapping between layers rather than reducing every failure to handshake failed.

Cover resource exhaustion, timeout, TCP failure, malformed record, record overflow, unsupported version, unsupported cipher or group, invalid key share, handshake decryption failure, unexpected message, certificate parse failure, bad CertificateVerify, unknown issuer, validity failure, hostname mismatch, revocation, bad Finished, peer alert, application-record authentication failure, closure, and internal invariant failure.

Report timeout as timeout and pool exhaustion as resource exhaustion. Distinguish failures before any request bytes were sent from failures after application transmission began so retry policy remains correct.

Expose a bounded public reason while retaining richer internal audit evidence. Never include complete certificates, raw alerts, or attacker-controlled handshake bytes in unescaped audit notes.

Tests must assert exact error mapping and phase preservation for every failure injection point, including queue pressure and audit ordering. No failure should silently become EOF, ordinary connection reset, or successful completion.

### Known issues/TODOS in TLS Audit Records

Issue: The audit schema defines TlsEstablished and TlsFailed helpers, but fetch never calls them. Success exists only as a lossy client event, and failure is later recorded as a generic internal error. The current Established audit name would also be misleading because certificate and hostname validation are absent.

Required fixes:

Record TLS validation start where timeout evidence is required, typed failure before returning the fetch error, and authenticated success before sending HTTP request bytes. Associate every record with session, request, redirect hop, and connection generation.

Add structured evidence or linked records for canonical hostname digest, endpoint, negotiated version and cipher, validation policy generation, trust-anchor identifier, leaf fingerprint, hostname verdict, chain verdict, time and revocation verdicts, failure phase, and failure reason.

Do not emit TlsEstablished under the current validation model. Record validation-unavailable and block production HTTPS. Any development exception must have a separate audit kind that clearly states encryption without authenticated identity.

Record downgrade denials, trust-store changes relevant to decisions, post-handshake record-integrity failures, abnormal closure, and event-delivery loss affecting TLS evidence.

Tests must verify record presence, ordering, typed content, identity binding, ring wraparound, slot reuse, queue overflow interaction, development-policy labeling, and proof that an authenticated-success record cannot exist without successful chain and hostname validation.

### Known issues/TODOS in Fetch Cache Keys, Freshness, and Revalidation

Issue: The cache implementation exists, but the fetch service never stores completed responses, so normal operation produces only misses. Before activation, several correctness defects must be resolved: URL keys silently truncate, max-age zero becomes indefinitely fresh, tick epochs are compared with HTTP seconds, validators are not revalidated and can survive slot reuse, the body ring can overwrite active entries without invalidating them, and hits emit only one 4096-byte body prefix before Complete.

Required fixes:

Implement cache admission only after complete validated network responses can be committed transactionally. Do not store malformed, partial, unauthenticated, policy-blocked, event-incomplete, noncacheable, or oversized responses.

Replace the body allocator with ownership-safe range management. Every allocation must invalidate or relocate all overlapping active ranges, not only ranges at wrap. Entry publication must occur after body and metadata writes complete.

Stream complete cached bodies through observable backpressure. A hit must emit every byte in order, then one terminal completion. Queue failure must not turn a prefix into a successful response.

Define canonical collision-resistant keys, HTTP-compatible freshness units, directive parsing, validator handling, 304 merge behavior, replacement semantics, and policy-generation binding before connecting store to fetch completion.

Add unit, integration, model, and fuzz tests for key uniqueness, allocator overlap, slot reuse, freshness boundaries, full-body delivery, revalidation, policy changes, session lifecycle, and proof that no cache hit can produce bytes or authority from another entry.

### Known issues/TODOS in Session-Scoped Cache Ownership

Issue: Lookup and replacement compare session identifiers, and close purges matching entries. This prevents direct active-session sharing, but entries are not bound to a session generation, top-level site, cookie or authorization state, policy generation, or trust generation. Inactive body bytes are not cleared.

Required fixes:

Bind entries to a nonreusable session generation or capability identity in addition to the numeric session id. Cleanup, process death, restore, and identifier reuse must not permit stale ownership.

Decide which request contexts further partition a private session cache, including top-level site, canonical origin, cookie generation, authorization state, client profile, and content-policy generation. Reject cache eligibility when required context cannot be represented.

Keep temporal restore exclusion explicit. Restored sessions should begin with no inherited cache state unless a future authenticated cache snapshot binds every entry to restored identity and policy generations.

Define zeroization policy for sensitive cached bodies, validators, and metadata on purge and eviction. Inactive ranges must remain unreachable even before physical clearing.

Tests must cover simultaneous sessions, close and reopen with reused identifiers, process death, restore, policy changes, cookie changes, allocator reuse, and direct proof that one session cannot observe another session’s metadata or body bytes.

### Known issues/TODOS in URL Digest and Cache Key Inputs

Issue: The so-called digest is a 512-byte serialization that silently stops copying. Long paths and queries can collide, the query can be omitted when it does not entirely fit, and the serialization has its own component-boundary and default-port rules. The key excludes request context such as method, cookies, authorization, headers, Vary, top-level site, policy generation, and TLS identity.

Required fixes:

Build keys from the authoritative canonical URL using length-delimited components. Reject any input that cannot be represented exactly. Hash the complete representation with a collision-resistant digest and retain sufficient canonical evidence to confirm equality where required.

Enforce GET-only storage and lookup initially or include method explicitly. Responses to body-bearing or otherwise unsupported request forms must not enter the cache accidentally.

Implement Vary-aware request selection before caching negotiated responses. Include or partition on every supported varying request field. Responses depending on cookies, authorization, or unmodeled request state should bypass cache unless a safe private-key strategy exists.

Bind keys or entry metadata to session generation, top-level partition, policy generation, trust-store generation, and relevant TLS verdict. Invalidation must occur when those authorities change.

Tests must construct long common-prefix URLs, exact capacity boundaries, default and explicit ports, host case variants, path and query differences, hash collisions through test doubles, Vary combinations, cookie and authorization changes, and policy-sensitive reuse.

### Known issues/TODOS in Max-Age Freshness Checks

Issue: Freshness compares service tick epochs with a max-age documented as seconds. A positive max-age is stale only when age is greater than the value. A zero max-age skips the check entirely and makes the entry perpetually fresh despite the comment saying zero requires revalidation. No fetch code parses Cache-Control, Age, Date, no-cache, or no-store.

Required fixes:

Use a trusted monotonic duration source with explicit conversion to seconds. Define how boot, suspend, temporal restore, tick-rate changes, and counter wrap affect freshness. Unknown or discontinuous time should invalidate or require revalidation.

Parse a deliberately supported Cache-Control subset from complete validated headers. Enforce no-store, no-cache, private or public policy as applicable, max-age, must-revalidate, and Age handling. Unknown directives should follow a documented conservative rule.

Treat max-age zero as immediately requiring validation. Until conditional revalidation is implemented, zero, stale, unknown, and no-cache entries must miss. No-store responses must never be admitted.

Define the exact boundary calculation using response time, corrected age, resident time, and rounding policy appropriate to the supported subset. Use checked arithmetic and reject nonsensical or overflowing values.

Tests must cover zero, exact expiry, one unit before and after expiry, Age greater than max-age, clock discontinuities, saturation attempts, boot and restore, directive combinations, and proof that no stale entry becomes fresh through tick-unit mismatch.

### Known issues/TODOS in ETag and Last-Modified Revalidation

Issue: ETag and Last-Modified byte fields and copy helpers exist, but no conditional request uses them and no 304 path exists. Values are silently truncated. Reused entry slots retain old validator lengths when the replacement response omits validators, allowing stale metadata to attach to a new resource if revalidation is activated.

Required fixes:

Clear all entry metadata before filling a reused slot, including validator bytes and lengths. Publish the new entry only after every field is initialized.

Reject validator overflow rather than truncating identity-bearing values. Parse ETag syntax, weak versus strong semantics, duplicate fields, and Last-Modified HTTP dates under bounded field-specific rules.

Build conditional headers through the structured request builder. Prefer If-None-Match when an eligible ETag exists and use If-Modified-Since according to explicit fallback policy. Caller-controlled raw header injection should remain unavailable.

Handle 304 as a validated revalidation transaction. Retain the existing body only if the request key and entry generation still match, merge only permitted response metadata, recompute freshness, and preserve policy and TLS evidence from the new exchange.

On network, TLS, header, policy, or 304 validation failure, leave the stale entry stale or invalidate it according to policy. Never silently refresh it. Tests must cover strong and weak tags, malformed and oversized validators, stale slot metadata, 304 merges, changed validators, full 200 replacement, concurrent eviction, and failed revalidation.

### Known issues/TODOS in Cache Isolation and Policy Bypass Prevention

Issue: Scheme and navigation-origin checks run before lookup, but hit delivery bypasses network-pipeline denylist checks, TLS decisions, mixed-content checks, content filtering, download classification, and policy-generation changes. Hits synthesize empty response headers and can present a cached response differently from the original. Body-pool overlap can also return one entry’s bytes under another entry’s metadata.

Required fixes:

Define all policy and trust decisions required on a hit. At minimum, re-evaluate current session authority, origin, scheme, mixed-content context, denylist, content disposition, MIME classification, download rules, and transport-security requirements.

Store policy-relevant response metadata in a complete typed form or rerun classification from retained evidence. Do not synthesize an empty-header response when those headers control client behavior or security decisions.

Bind entries to policy, content-filter, cookie, and trust-store generations. Invalidate or bypass entries when a relevant generation changes. A prior TLS success must not authorize reuse after trust revocation or hostname-policy changes.

Repair body-range ownership before activation. Every hit must verify that the entry owns a valid pool range and that body integrity metadata matches. A digest over cached content can detect corruption but does not replace correct allocation.

Stream hits through the same event-delivery guarantees as network responses. Tests must change every policy after admission, exercise denylist and TLS revocation, alter cookies and origins, force allocator overlap, fill event queues, and prove that cache cannot bypass or misrepresent the equivalent fresh-fetch decision.

### Known issues/TODOS in Fetch Cookie Matching, Isolation, and Request Attachment Rules

Issue: The cookie jar is not connected to live fetches. Response processing never extracts and stores Set-Cookie fields, the transport request builder cannot accept a Cookie field, and redirects do not recompute cookie selection. Existing attribute checks therefore provide no end-to-end behavior.

Required fixes:

Connect cookie processing only after response header parsing preserves every validated Set-Cookie field independently. Parse and commit each cookie transactionally with bounded failure reporting, then pass a caller-supplied cookie value into request construction without allowing header injection or silent truncation.

Run selection after URL normalization and again for every redirect target. Supply the full request context needed by SameSite, including top-level site, navigation status, method safety, redirect history, and trusted time. Make cache admission and lookup aware of cookie-dependent request state.

Add cookie-specific audit records for accepted, rejected, replaced, deleted, expired, restored, and attached state without recording secret values. Conformance and adversarial tests must cover complete response-to-request round trips, repeated Set-Cookie fields, quota exhaustion, redirects, malformed bytes, cache interaction, and event or audit backpressure.

### Known issues/TODOS in Session-Scoped Cookie Storage

Issue: Entries compare SessionId, but they are not bound to a session generation. The jar has one global 128-entry quota, inactive slots retain secret bytes, oversized fields are truncated, and replacement identity omits Path.

Required fixes:

Bind entries to an unambiguous session lifetime or generation and guarantee cleanup on process death as well as explicit close. Partition or fairly allocate capacity so one session cannot exhaust cookie storage for all others.

Reject oversized or syntactically invalid names, values, domains, and paths before mutation. Use the full cookie key of name, domain, path, and partition context for replacement and deletion, preserve the correct case-sensitive name semantics, and clear sensitive bytes when records become inactive.

Restore only cookies whose owning session was successfully restored and whose persisted authority is authenticated and fresh. Define whether session cookies survive temporal restore; the conservative default is to discard them. Tests must exercise reused identifiers, partial restore, hostile snapshots, full-jar contention, duplicate path variants, and cross-session non-observability.

### Known issues/TODOS in Domain and Path Matching

Issue: The jar does not distinguish host-only cookies from Domain cookies, accepts unrelated Domain attributes, silently truncates scope fields, does not derive the default path, and has an incorrect boundary case for stored paths ending in a slash.

Required fixes:

Record a host-only flag and require exact host equality for those entries. For Domain cookies, canonicalize the attribute and require it to domain-match the response host before storage. Reject IP widening, invalid labels, empty domains, unrelated parents, public suffixes, and any field that exceeds capacity.

Implement the standard default-path algorithm from the response request path. Apply the path-match rule exactly, including the case where the cookie path itself ends in a slash. Retain creation ordering and serialize matching cookies by descending path length followed by creation time.

Tests must cover host-only subdomain exclusion, valid parent domains, sibling and lookalike domains, trailing dots, IP literals, absent and malformed Path values, slash boundaries, equal names at different paths, ordering, and every fixed-buffer boundary.

### Known issues/TODOS in Secure, HttpOnly, and SameSite Enforcement

Issue: Secure and SameSite checks exist only in unused helpers. HttpOnly is metadata without an access-control surface, insecure responses can overwrite Secure cookies, cookie prefixes are unsupported, and one cross-site boolean cannot express SameSite semantics.

Required fixes:

Enforce Secure at acceptance, overwrite protection, redirect selection, and final attachment. Implement the Secure and Host prefix invariants before committing a record. Reject SameSite=None without Secure.

Define every API that may inspect or mutate cookie state and enforce HttpOnly there. Debug and audit interfaces must expose metadata without values unless a stronger authority explicitly permits disclosure.

Replace is_cross_site with a typed request context derived from the canonical top-level site, target site, request method, navigation kind, and redirect chain. Test Strict, Lax, None, defaulted and malformed values across same-site, cross-site, safe and unsafe methods, scheme changes, redirects, and insecure overwrite attempts.

### Known issues/TODOS in Expiry and Purge Behavior

Issue: Only Max-Age is recognized, expiry uses an undefined tick-based epoch, equality does not expire a cookie, expired entries are not reclaimed before insertion, and temporal snapshots preserve session cookies.

Required fixes:

Introduce a trusted cookie time source with second-level semantics and explicit behavior across suspend, reboot, and temporal restore. Parse Expires with strict HTTP-date handling, apply Max-Age precedence, reject malformed numeric input and unsafe overflow, and expire records when current time reaches the deadline.

Purge expired entries before capacity checks, during selection, and through bounded maintenance. Delete every record matching the complete cookie key and clear deactivated values. Define whether session cookies survive service restart, session restore, process death, and kernel temporal operations.

Tests must cover exact-deadline expiry, negative and zero Max-Age, numeric overflow, malformed dates, Max-Age and Expires conflicts, full jars containing expired records, restored deadlines, rollback attempts, and session-cookie destruction.

### Known issues/TODOS in Public Suffix and Registrable-Domain Limitations

Issue: No public suffix or registrable-domain implementation exists. Domain cookies can be accepted for shared suffixes, and the service cannot compute schemeful sites for SameSite decisions.

Required fixes:

Provide a versioned, updateable, rollback-resistant public suffix policy with a deterministic failure mode. Reject Domain cookies when safe widening cannot be established; continue to permit host-only cookies when the exact canonical host is valid.

Build one canonical host and site-identity service used by cookie acceptance, SameSite classification, redirect credential policy, cache partitioning, and audit. Keep host matching and site comparison as distinct operations over the same normalized input.

Test pinned public and private suffix cases, multi-label country suffixes, internationalized domains, trailing dots, localhost-style hosts, IP literals, unknown suffix data, policy updates, rollback, and tenant isolation on shared hosting domains.

### Known issues/TODOS in Fetch Storage Authority and Per-Session VFS Mapping

Issue: The module is dormant, session-scoped rather than origin-scoped, and mapped to persistent directories named by reusable SessionIds. Registration failure is ignored, live IPC exposes no storage operation, and VFS authority is not explicitly bound to the requesting fetch principal.

Required fixes:

Choose and document separate semantics for ephemeral session storage and durable origin storage. Bind every partition to a stable principal, canonical origin or storage key, policy generation, and explicit VFS delegation rather than a bare reusable session number.

Add typed protocol operations only after registration, authorization, quotas, complete-value behavior, cleanup, and auditing are defined. Keep operation failure atomic and ensure storage errors cannot leave a granted session in a falsely healthy state.

Test the complete IPC-to-VFS path under wrong capabilities, wrong sessions, cross-origin navigation, identifier reuse, process death, quota pressure, malformed keys, temporal transitions, and hostile filesystem state.

### Known issues/TODOS in Session Storage Registration

Issue: register ignores ensure_dir failure, do_open_session ignores register failure, duplicate session registration is not rejected, and restored sessions are never registered.

Required fixes:

Make session opening transactional across the session table, origin policy, storage registry, and filesystem initialization. Return a typed failure or an explicit storage-disabled session state; never silently grant partial initialization.

Create and verify the storage root during service initialization. Reject duplicate registrations, propagate directory errors, and roll back every earlier allocation when a later step fails. Rebuild authorized mappings after restore through the same validated registration path.

Audit registration, rollback, duplicate attempts, capacity exhaustion, VFS denial, and recovery. Tests must inject each failure point and prove that no capability, registry slot, directory, or origin entry remains partially committed.

### Known issues/TODOS in Browser Storage Root Layout

Issue: The root constant is unused by path construction, the root is not created or verified, and persistent directories use allocator-derived session numbers that can be reassigned to unrelated principals.

Required fixes:

Use one versioned root-layout implementation and verify its inode, ownership, mount, and no-follow properties before serving storage. Derive durable partitions from stable profile and canonical origin identity, with collision detection metadata; derive ephemeral partitions from non-reusable session generations.

Constrain every resolved path to the verified root and immediate partition. Define mount replacement, corruption, migration, and read-only behavior. Do not let raw origins, caller keys, or transient numeric handles become trusted directory names.

Tests must cover clean initialization, pre-existing roots, wrong inode types, symlinks, digest collisions, identifier reuse, origin variants, mount changes, layout migration, and power-loss remnants.

### Known issues/TODOS in Storage Key Validation

Issue: Validation permits dot and double-dot components, bytes that are not UTF-8, broad printable metacharacters, and values that can change meaning during downstream VFS normalization. PathTooLong is also used for UTF-8 conversion failure.

Required fixes:

Adopt a strict one-component grammar and reject dot, double dot, non-canonical whitespace, non-ASCII bytes unless encoded, reserved forms, and every value altered by normalization. Verify the normalized full path remains an immediate child of the expected partition.

Separate web-visible key bytes from internal filenames if arbitrary keys are required. Use a reversible safe encoding or bounded record store, retain collision evidence, and report validation, encoding, capacity, and path failures through distinct errors.

Test every accepted character class, exact length boundaries, dot forms, separators, control bytes, high bytes, invalid UTF-8, normalization changes, encoded-key collisions, and containment after VFS resolution.

### Known issues/TODOS in Read, Write, and Delete Authority

Issue: Helpers perform path-based VFS operations without receiving fetch capabilities, origin context, partition identity, quotas, or an explicit delegated VFS subject. VALUE_MAX is declared but unenforced, and reads can silently return prefixes.

Required fixes:

Authorize each operation with a live session generation, valid capability, requesting and top-level origins, partition policy, and scoped VFS rights. Ensure the VFS evaluates the intended client delegation rather than broader ambient service authority.

Enforce per-value, per-partition, per-principal, and global quotas before mutation. Require complete reads or return the required size, use atomic replacement for durable writes, define concurrency semantics, and return typed errors for absence, denial, capacity, truncation, and backend failure.

Audit metadata without values and test confused-authority attempts, cross-origin access, stale handles, concurrent operations, oversized writes, short reads, lost updates, VFS denials, and failure atomicity.

### Known issues/TODOS in Storage Cleanup and Temporal Interaction

Issue: unregister revokes only one table entry, cloned storage handles remain usable, files persist under reusable identifiers, process-death cleanup is absent here, and temporal restore neither recreates mappings nor reconciles VFS generations.

Required fixes:

Use revocable generation-bearing handles and integrate forced teardown with process lifecycle. Revoke access before cancelling operations and applying retention. Ephemeral partitions should be deleted; durable partitions should lose session bindings while retaining stable origin ownership.

Coordinate VFS persistence and temporal restore through authenticated generations. Restored sessions must reauthorize durable partitions from stable identity, while stale, newer, missing, or rolled-back storage states produce explicit policy decisions and audit evidence.

Test close and write races, process death, leaked clones, deletion failure, stale directories, restored sessions, missing partitions, snapshots older and newer than VFS state, rollback attempts, and identifier reuse without cross-principal disclosure.

### Known issues/TODOS in Fetch Download Destination, Filename, and Quarantine Policy

Issue: The live fetch path never creates offers or diverts response bodies. Accept only changes job metadata, no VFS writer exists, and completed files have no quarantine or provenance model.

Required fixes:

Implement one transactional pipeline from response classification through bounded quarantine, user consent, delegated destination authority, verified writing, metadata attachment, and atomic publication. Keep remote evidence, local write authority, and commit evidence as separate typed objects.

Do not activate destination writing until header completeness, body framing, redirect policy, TLS evidence, resource quotas, cancellation, event delivery, and audit failure semantics are trustworthy. A download must never be considered complete solely because the remote connection ended.

Test the entire flow with attachment headers, MIME mismatches, executables, archives, unknown lengths, redirects, cache responses, malformed framing, user rejection, process death, storage failure, policy changes, and audit or event saturation.

### Known issues/TODOS in Download Offer Lifecycle

Issue: Offer creation and DownloadOffered emission have no call sites. Internal transition methods do not enforce prior state or ownership, terminal retention is inconsistent, and DownloadIds can wrap into collisions.

Required fixes:

Define and enforce a typed transition graph covering classified, pending, accepted, active, complete, rejected, cancelled, expired, blocked, and failed states. Require a generation-bearing transfer token and expected prior state for every mutation.

Choose a bounded content-retention strategy for the consent interval. Apply deadlines and quotas to pending offers, retain terminal reason evidence for a bounded observation period, and reclaim slots deterministically without identifier ambiguity.

Tests must cover illegal transitions, duplicate decisions, identifier wraparound, queue-full events, timeout, close, abort, restore, classification after sniff buffering, and proof that no body is delivered inline after a download decision.

### Known issues/TODOS in Session Ownership Checks for Downloads

Issue: Accept and reject verify session ownership, but progress, completion, error, lookup, and destination retrieval use DownloadId alone. Jobs are not bound to session generations or authenticated principals, and restore can insert orphaned jobs.

Required fixes:

Bind every job and transfer token to the session generation, authenticated process or profile, originating request, source object, and destination transaction. Require those bindings on internal callbacks as well as IPC actions.

On close or process death, revoke tokens, cancel writers, suppress stale events, clean temporary files, and prevent callbacks from targeting a reused session queue. Restore only jobs whose owner and durable transfer journal can be authenticated.

Test wrong-session actions, stale capabilities, reused identifiers, collided download identifiers, forged callbacks, owner death during every state, orphaned restore records, and completed-file ownership distinct from session status ownership.

### Known issues/TODOS in Destination Path Validation

Issue: dest_len is sliced before validation, accept silently truncates paths, and every path form is accepted as metadata. No VFS capability, root constraint, no-follow resolution, overwrite reservation, or time-of-check protection exists.

Required fixes:

Validate protocol lengths before slicing and reject rather than truncate. Treat the path only as a selector within delegated VFS authority. Resolve and reserve the destination transaction under the intended principal with approved-root, mount, inode, no-follow, quota, and overwrite checks.

Write to a private temporary file in the destination directory, bind the resolved identities to the transaction, revalidate before commit, attach quarantine metadata, and publish through atomic rename. Existing targets should remain unchanged unless explicit replacement authority was granted.

Test oversized lengths, empty and malformed paths, NUL, invalid encoding, traversal, symlink races, mount substitution, directory targets, existing files, quota and free-space failures, revoked capabilities, and commit-time identity changes.

### Known issues/TODOS in Suggested Filename Normalization

Issue: Filename parsing treats filename and filename-star as equivalent raw bytes, returns the first match, and silently truncates without sanitizing path syntax, controls, Unicode hazards, reserved names, or misleading extensions.

Required fixes:

Implement a bounded Content-Disposition parameter parser with explicit duplicate policy, quoted-string escapes, supported filename-star decoding, precedence, and malformed-input handling. Preserve raw evidence separately from the normalized suggestion.

Produce distinct safe display, canonical internal, and reserved VFS names. Remove path semantics and dangerous controls, handle normalization and reserved forms, provide a neutral fallback, and surface extension and MIME mismatches rather than trusting the suffix.

Test separators from multiple platforms, dot names, controls, bidirectional text, confusables, invalid encodings, duplicate parameters, quoted escapes, percent encoding, very long values, hidden extensions, reserved names, and names that normalize to empty.

### Known issues/TODOS in Overwrite, Partial-Write, and Resume Policy

Issue: No writer exists. Active is set before destination setup, progress is unverified, size zero conflates unknown and empty, completion ignores expected size and digest, and temporal restore can resurrect interrupted states.

Required fixes:

Default to no overwrite and require explicit replacement authority. Reserve names atomically, write only to quarantined temporary files, track source and durable destination byte counts separately, and publish only after framing, size, digest, scan, metadata, sync, and rename succeed.

Disable resume until strong validators, correct Range handling, durable partial journals, hash-state recovery, unchanged destination authority, and representation identity are implemented. Interrupted transfers should restart into a new transaction or remain quarantined under an explicit recovery policy.

Test zero-length and unknown-length responses, short and oversized bodies, disk full, mid-write failure, cancellation, reboot, existing targets, atomic-replace failure, cleanup failure, server validator changes, ignored Range requests, restore, and digest mismatch.

### Known issues/TODOS in MIME, Source URL, and Quarantine Evidence

Issue: Jobs retain only declared MIME and basic counters. Source and final URLs, redirects, TLS evidence, sniffed type, digest, timestamps, scanner result, policy generation, and quarantine state are absent; restore does not verify files against records.

Required fixes:

Capture canonical initial and final URLs, bounded redirect evidence, response status, TLS verdict, declared and sniffed media types, disposition evidence, expected and actual sizes, content digest, acquisition time, scanner outcome, and relevant policy generations.

Attach protected quarantine metadata before publication and make release a separately authorized, audited transition. Preserve declared, sniffed, extension-derived, and signature classifications independently so disagreement remains visible.

On restore, reconcile records with authenticated owners, durable transfer journals, temporary files, final file identity, size, digest, and quarantine metadata. Convert unverifiable Active or Complete records to safe terminal states rather than trusting serialized labels.

### Known issues/TODOS in Fetch Abort, Cancellation, and In-Flight Request Cleanup

Issue: Abort performs no cancellation. Synchronous navigation holds the global service mutex until fetch completion, so AbortRequest cannot be dispatched while network work is running. No active-request table, cancellation state, transport signal, queue cleanup, or aborted terminal event exists.

Required fixes:

Move fetch execution out of the global dispatch critical section and represent every request as a bounded generation-bearing lifecycle record. Return request acceptance before network completion, then advance work asynchronously through cancellable steps.

Make cancellation a transaction across transport, parser, event delivery, cache, cookies, redirects, navigation, downloads, temporary files, and audit. Separate cancellation requested from cancellation completed, and expose one reliable terminal result.

Test scheduling and cleanup under every phase, queue pressure, unrelated concurrent sessions, repeated abort, close, process death, timeout, stale callbacks, and normal-completion races.

### Known issues/TODOS in Abort Request Validation

Issue: Capability validation proves only that the session is live. The service does not verify request existence, ownership, generation, state, or cancellability and returns success for arbitrary identifiers.

Required fixes:

Add a bounded active-request registry binding request generation, session generation, authenticated principal, operation type, state, resources, and terminal-delivery status. Resolve abort only through this registry.

Return typed outcomes for cancellation accepted, already cancelling, already terminal, unknown, wrong owner, and non-cancellable state. Make retries idempotent and prevent wrapped identifiers or restored stale messages from targeting new work.

Record successful cancellation only after terminal cleanup. Audit rejected, stale, and cross-owner attempts separately without leaking request existence to unauthorized callers.

### Known issues/TODOS in Current Best-Effort Abort Behavior

Issue: The implementation only records abort intent after synchronous work can finish. No component observes abort state, and the comment promising no later events is unenforced.

Required fixes:

Until real cancellation lands, return an explicit unsupported or no-active-request result instead of Ok and name audit records as abort requests rather than confirmed aborts. Remove behavioral claims the implementation cannot guarantee.

Restructure RequestAccepted so it precedes asynchronous execution. Ensure PollEvents, CloseSession, timer progress, and other sessions remain serviceable while one request waits on network work.

Add instrumentation proving cancellation latency, work stopped, bytes delivered, events suppressed, resources released, and terminal state reached. Tests must demonstrate that an abort response is never mistaken for completed cleanup.

### Known issues/TODOS in Transport-Level Cancellation Goals

Issue: Transport handles are stack-local to synchronous fetch_request, and DNS, connect, TLS, send, header, and body loops receive no cancellation token or externally addressable operation generation.

Required fixes:

Move transport ownership into a reactor or request worker that advances bounded states and accepts generation-checked cancellation signals. Observe cancellation before every side effect and after every wakeup.

Make close, timeout, network error, session teardown, and user abort converge on idempotent resource cleanup. Ignore stale callbacks and prevent reused TCP or TLS handles from being closed by old cancellation messages.

Report whether request bytes may have reached the server and never imply rollback of remote side effects. Test abort races around DNS, connect, TLS, send, redirects, headers, chunk framing, body reads, EOF, and handle reuse.

### Known issues/TODOS in Queued Event Cleanup After Abort

Issue: The session ring cannot remove events by request, publication is not gated by request state, queue overflow is silent, and currently queued Complete or body events remain after abort.

Required fixes:

Choose a deterministic policy for pre-cancellation events and implement request-aware removal or sequence boundaries. Commit event publication and lifecycle checks atomically so no nonterminal event can follow Aborted.

Reserve reliable terminal capacity or retain terminal state until acknowledged. Body backpressure and overflow must fail visibly before Complete or Aborted evidence can be lost.

Cancel secondary effects, including partial cache state, navigation commits, redirects, cookie mutations, download jobs, and temporary files. Test mixed-request queues, polling races, full queues, stale workers, and exactly which events remain observable.

### Known issues/TODOS in Final Aborted Event Semantics

Issue: FetchErrorKind::Aborted exists but is never emitted. There is no atomic terminal state preventing both Complete and Aborted, and audit currently records abort before confirming any cleanup.

Required fixes:

Use FetchError with Aborted as the provisional terminal event, enriched or paired with bounded phase and side-effect evidence. Treat the synchronous abort response only as acknowledgement that cancellation was accepted.

Resolve Complete, Aborted, policy failure, network failure, and other terminal outcomes through one atomic transition. Repeated aborts and stale callbacks must observe the existing result without emitting duplicates.

Define delivery and audit behavior for session close and process death, when the client may no longer receive events. Test exact ordering, completion races, cleanup failure, undeliverable terminals, RequestId reuse, and proof that no later event or side effect commits after terminal abort.

### Known issues/TODOS in Fetch Timeout and Slow-Response Policy

Issue: Timeout behavior is fragmented across hard-coded lower-layer limits. Fetch has no request-wide budget or typed timeout errors, and receive timeout is often returned as zero bytes and misinterpreted as EOF or successful completion.

Required fixes:

Define one monotonic deadline model with request-wide, phase, idle, and progress-rate budgets. Pass absolute deadlines and cancellation state through the reactor, transport, parser, cache, and download layers.

Represent timeout separately from EOF, reset, refusal, malformed framing, and policy failure. Every timeout must atomically terminalize the request, close generation-matched resources, prevent partial-state commits, and emit reliable event and audit evidence.

Use deterministic clock and scripted transport tests across all phases, redirect and retry budget consumption, scheduler delays, PIT frequency changes, queue backpressure, cancellation races, and cleanup failure.

### Known issues/TODOS in DNS Resolution Timeout

Issue: DNS has per-attempt PIT deadlines and retries, but fetch flattens timeout, configuration, negative cache, malformed responses, and network failures into DnsFailure. Inner DNS and outer reactor deadlines can race.

Required fixes:

Derive attempt and retry windows from the request’s remaining absolute deadline. Define which layer owns terminalization and invalidate operation generations so late DNS responses cannot update reused requests.

Expose typed timeout, negative answer, cached negative, not configured, network unavailable, malformed response, and resource failure results. Bind negative caching to network and resolver generations with explicit expiry semantics.

Test late responses, transaction mismatches, retry exhaustion, outer-deadline races, network changes, negative-cache behavior, cancellation, concurrent queries, and clock-frequency boundaries.

### Known issues/TODOS in TCP Connection Timeout

Issue: The reactor waits about five seconds, but fetch reports every failure as ConnectionFailed. The reactor request wrapper has a competing deadline, and timed-out allocated connection slots are not visibly reclaimed in this path.

Required fixes:

Share the remaining connect budget across route readiness, address selection, neighbor discovery, TCP establishment, and any future proxy work. Return typed timeout, refusal, unreachable, local exhaustion, and policy outcomes.

Close or invalidate timed-out connection generations before returning. Ignore late state changes and prevent stale callbacks or identifiers from attaching to new requests.

Test blackholes, refusal, delayed boundary success, connection-table exhaustion, address fallback, cancellation, cleanup failure, and races between reactor and request deadlines.

### Known issues/TODOS in TLS Handshake Timeout

Issue: TLS uses 512 tick_all iterations rather than elapsed time, advances unrelated sessions, and reports loop exhaustion, certificate rejection, protocol failure, and transport failure as one generic handshake error.

Required fixes:

Advance only the request’s generation-owned TLS state through bounded reactor steps under an absolute handshake deadline and idle-progress policy. Preserve the last handshake phase.

Separate timeout, certificate, hostname, protocol, alert, transport, and session-pool failures. Make timeout, cancellation, and error cleanup idempotently free the exact TLS slot.

Test stalls at every handshake phase, unrelated active sessions, near-deadline success, certificate failure races, pool exhaustion, clock changes, cancellation, and slot reclamation.

### Known issues/TODOS in Response Header Timeout

Issue: Header reading has no elapsed deadline and treats receive timeout or temporary zero read as EOF. A partial status and header prefix can be parsed without the terminating empty line.

Required fixes:

Require a complete header terminator before semantic parsing. Track first-byte, idle-progress, total-header, and capacity outcomes separately, and never convert timeout into EOF.

On timeout or incomplete EOF, discard all partial fields and prohibit redirects, cookies, cache, classification, downloads, and navigation commits. Emit a typed header terminal error with bounded phase evidence.

Test byte trickles, split terminators, valid prefixes followed by stalls, exact deadline boundaries, capacity exhaustion, TLS temporary-empty reads, cancellation, and EOF versus timeout.

### Known issues/TODOS in Body Idle and Total Request Timeout

Issue: Body streaming has no idle or total deadline, does not enforce the policy body-size ceiling, treats timeout-like zero reads as successful termination, and emits Complete without proving Content-Length or chunk completion.

Required fixes:

Track encoded, decoded, and future decompressed byte counts under hard limits. Reset idle time only on meaningful protocol progress, enforce a non-resetting total deadline, and optionally apply a rolling minimum-rate policy.

Require framing completion before success. Timeout, premature EOF, missing chunk terminators, and short Content-Length bodies must emit terminal errors, invalidate cache state, and quarantine or remove partial downloads.

Test exact and short lengths, chunk stalls, unknown-length streams, periodic trickles, size boundaries, queue backpressure, slow local writes, cancellation, redirects, and total expiry during continuous progress.

### Known issues/TODOS in Slowloris-Style Response Handling

Issue: Per-call receive waits do not stop a peer from sending tiny periodic fragments indefinitely. Synchronous fetch execution lets one slow response hold the global service lock and block control operations for every session.

Required fixes:

Combine header and body total deadlines, idle limits, rolling progress floors, bounded sizes, per-origin and per-session concurrency, and a global stalled-resource budget. Move network waiting outside the global dispatch lock.

Count valid protocol progress rather than callbacks, retransmissions, TLS housekeeping, or invalid framing. Treat local event or storage backpressure as a separate bounded condition and stop reading before data is silently discarded.

Test deterministic slow headers and bodies, TLS records without application bytes, chunk-framing trickles, slow consumers, full event queues, cross-session fairness, resource reclamation, and recovery after repeated timeouts.

### Known issues/TODOS in Fetch Audit Event Schema and Evidence Guarantees

Issue: The fetch-local audit log is a private lossy diagnostic ring, not a complete evidence system. Most defined event kinds are unused, critical failures are unaudited, annotations are untyped and silently truncated, and event names can overstate outcomes.

Required fixes:

Define a versioned structured schema with authenticated subject, generation-bearing correlation, typed action, object identity, decision, reason, monotonic time, policy generations, and explicit omission flags. Separate security evidence from high-volume telemetry.

Connect every authority, trust, mutation, persistence, filesystem, timeout, cancellation, and cleanup path to the schema. Emit success only after the promised state transition commits.

Forward protected events into the kernel-wide audit facility with detectable loss and durable retention policy. Test exact event semantics, privacy redaction, failure atomicity, and synchronization with client-visible terminal outcomes.

### Known issues/TODOS in Audit Ring Ownership and Capacity

Issue: The 128-entry ring has no valid count or export surface. iter returns empty slots, sequence zero represents both the first real event and emptiness, drain_since drops that first event, and u32 wrap breaks ordering.

Required fixes:

Track valid count, 64-bit nonzero cursor identity, monotonic time, earliest retained cursor, and overwritten totals. Define a portable wire record rather than relying on Rust structure layout.

Provide an authorized snapshot or streaming reader with gap reporting and privacy filtering. Preserve or forward high-value evidence before local overwrite, while keeping the local ring bounded.

Test empty and partially filled rings, first sequence, exact capacity, multiple wraps, sequence overflow, concurrent export, unauthorized reads, reboot, and durable-sink failure.

### Known issues/TODOS in Session and Request Correlation Fields

Issue: SessionId and RequestId are reusable and generationless. Correlation is inconsistently populated, early failures use zero, restored work loses request identity, and authenticated caller or delegation identity is absent.

Required fixes:

Use principal, session, request, redirect-hop, download, and temporal generations. Assign an attempt or trace identifier before security-relevant validation so rejected operations can be correlated without reusing zero.

Carry authenticated caller and delegation provenance through service dispatch. Use keyed object digests or protected identifiers for origins, URLs, paths, and cache partitions.

Test close and reopen, counter wrap, temporal restore, redirects, asynchronous callbacks, early validation failures, delegated callers, and proof that unrelated operations never share one effective correlation identity.

### Known issues/TODOS in Security-Relevant Event Kinds

Issue: The enum contains unused start, commit, TLS, download, cookie, and filter events, while identity, capability, quota, parser, timeout, overflow, restore, storage, cleanup, and process-lifecycle failures lack complete typed coverage.

Required fixes:

Model action, outcome, and reason as separate stable fields. Define exact commit conditions for success events and reserve distinct states for requested, accepted, completed, failed, and partially cleaned operations.

Cover authority issuance and revocation, validation, policy, TLS identity, redirects, cookie and cache mutation, storage, downloads, timeout, cancellation, queue and audit loss, temporal restore, rollback, and cleanup.

Classify events by evidence criticality and rate-limit only with aggregate counts and recovery markers. Test every variant and reject orphaned or semantically impossible event combinations.

### Known issues/TODOS in Audit Overflow Behavior

Issue: Every append silently overwrites the oldest record. Readers receive no loss marker or cursor gap, and cheap CacheMiss traffic can evict high-value authority or policy evidence.

Required fixes:

Track append, overwrite, earliest-retained, and per-class drop counters. Return explicit gaps to readers and preserve a loss epoch through reserved or out-of-band state.

Separate high-value evidence from lossy telemetry. Define which operations fail closed when protected audit commit is unavailable and ensure sink backpressure cannot deadlock the service.

Test hostile flooding, class prioritization, repeated overflow, loss-marker preservation, reader lag, sink outage, recovery, and sequence wrap.

### Known issues/TODOS in Evidence Guarantees and Known Gaps

Issue: Current guarantees stop at one in-memory bounded write. Completeness, truthful outcome naming, drainability, chronology, loss detection, privacy, durability, integrity, and synchronization with client-visible events are not guaranteed.

Required fixes:

Publish guarantees per event class, including source authentication, schema stability, ordering, retention, integrity, loss behavior, redaction, and export acknowledgement. Mark every partial or omitted field explicitly.

Replace free-form remote-input prefixes with typed bounded fields and keyed digests. Record original length and truncation where bounded text remains necessary, and reject unsafe control content.

Test positive and negative evidence assertions, tamper detection, crash and reboot retention, temporal transitions, malformed annotations, privacy boundaries, sink replay, duplicate delivery, and exact agreement between terminal operation state and audit outcome.

### Known issues/TODOS in Fetch Temporal Restore Authenticity and Rollback Policy

Issue: The standalone restore parser accepts unauthenticated version-two bytes, mutates live state incrementally, restores bearer capabilities unchanged, and has no freshness, generation, reconciliation, or audit policy. It is currently disconnected from the live service.

Required fixes:

Integrate fetch state with the trusted temporal object and persistence framework through a versioned, authenticated, encrypted where required, generation-bound envelope. Define resume, migration, recovery, and administrative rollback as separate authorized modes.

Decode and validate into temporary bounded state, reconcile current process, policy, trust, storage, and download state, rotate authority as required, then atomically publish one new service generation. Failure must leave live state unchanged.

Test malicious payloads, stale valid snapshots, concurrent state changes, policy migration, capability rotation, external-state mismatches, crash during commit, and exact audit evidence.

### Known issues/TODOS in Snapshot Contents and Excluded State

Issue: Sessions, raw capabilities, navigation URLs, cookie secrets, and download labels are included, while policy, origin registration, storage mapping, request state, source evidence, audit, and external file identity are excluded. Restored state can therefore be internally inconsistent.

Required fixes:

Define a field-level persistence contract with confidentiality, authority, lifetime, and migration classification for every record. Do not persist session cookies, active transfers, or bearer capabilities by default.

Persist stable references and evidence needed for reconciliation rather than unsupported live labels. Rebuild derived policy, origin, storage, cache, and request state under current rules.

Test each included and excluded field, secret redaction, policy changes, missing external resources, restored defaults, and proof that exclusions cannot silently broaden authority.

### Known issues/TODOS in Snapshot Structure Validation

Issue: Header validation checks only length, magic, and version. Restore accepts partial parsing, coerces overlong navigation lengths, caps session count without skipping excess records, ignores insertion failures and trailing data, and can return partial success after mutating live state.

Required fixes:

Reject counts above capacities before parsing and use checked arithmetic for complete size validation. Require exact lengths, canonical enums and flags, unique identifiers, valid cross-record ownership, reserved-field rules, and exact payload consumption.

Decode without mutation and return typed all-or-nothing errors. Never clamp hostile lengths or reinterpret excess records as another record class. Report every capacity failure rather than dropping records.

Fuzz the whole grammar with count interactions, alignment shifts, duplicates, trailing data, maximum records, truncated fields, integer boundaries, and existing-live-state rollback assertions.

### Known issues/TODOS in Snapshot Authentication Requirements

Issue: The format has no keyed authentication, encryption, identity binding, creation context, key generation, or protected envelope. Magic and version provide no trust.

Required fixes:

Authenticate the complete canonical envelope with a device, kernel, profile, and temporal-object binding. Encrypt capability tokens, cookie values, URLs, and paths when the persistence threat model requires confidentiality.

Define key rotation, revocation, migration, cloning, and recovery. Verify before state mutation and clear temporary secret buffers on every exit.

Test bit tampering, truncation, envelope substitution, wrong device and profile, revoked keys, old trust generations, replay, ciphertext modification, and parser safety before authentication.

### Known issues/TODOS in Restored Capability Policy

Issue: Session capability and process identifiers are restored unchanged without checking current principal identity, revocation, duplication, policy, origin registration, or storage registration.

Required fixes:

Treat persisted capabilities as references and issue fresh session and capability generations after authenticated owner reconciliation. Invalidate old tokens and rebuild all dependent registrations transactionally.

Permit exact token continuation only for a sealed suspend context that proves no intervening use, revocation, identity reuse, or concurrent generation. Allocate new request generations regardless.

Test retained old tokens, process-id reuse, revoked authority, duplicate sessions, restored zero values, wrong owners, policy changes, reissue notification, and stale external messages.

### Known issues/TODOS in Persistence Generation and Rollback Detection

Issue: No snapshot generation or latest-accepted marker exists. Any valid version-two payload can be replayed repeatedly, and fetch state is not integrated with the broader temporal generation model.

Required fixes:

Bind each snapshot to a monotonically advancing rollback-resistant generation, parent lineage, principal, policy generation, trust generation, and explicit restore mode. Remember the highest accepted state outside the rollbackable payload.

Use administrative rollback only through stronger authority and rotate all resurrectable credentials. Reconcile snapshot generation with VFS storage, download files, process lifecycle, and current policy.

Test replay, branching, stale but authentic snapshots, generation-store loss, newer external files, old policy state, trust revocation, concurrent snapshots, and authorized recovery.

### Known issues/TODOS in Restore Audit Records

Issue: Snapshot and restore emit no local or kernel-wide audit records, and the audit schema has no temporal restore event kinds. Partial authority resurrection is therefore invisible.

Required fixes:

Emit protected begin and terminal records with snapshot identity, schema and generation, restore mode, authenticated principal, accepted and rejected counts, capability disposition, migrations, reconciliation result, and typed reason.

Do not log payload secrets. Use protected identifiers and bounded parser location evidence. Rate-limit repeated attacks while preserving totals and first, transition, and recovery events.

Disallow partial normal restore. If explicit recovery salvages non-authority data, rotate authority and audit every omitted or transformed class. Test exact correspondence between transactional commit and committed audit evidence.

### Known issues/TODOS in Fetch Service Security Test Matrix

Issue: The fetch service has no dedicated automated test surface despite operating across identity, capability, network, parser, storage, download, temporal, and audit trust boundaries. Current behavior therefore has no repeatable proof of fail-closed handling, boundary safety, isolation, failure atomicity, or evidence delivery.

Required fixes:

Build a layered harness with host unit tests, stateful property tests, deterministic transport and VFS fault injection, kernel boot self-tests, fuzz targets, regression corpora, and controlled system interoperability tests. Introduce injectable clocks, scripted external dependencies, deterministic identifier sources, and observable event and audit sinks.

Make security invariants the release criteria. Every bounded field needs exact-limit and overflow tests; every authority check needs wrong-caller, wrong-session, stale-generation, and slot-reuse tests; every transactional operation needs partial-failure tests; and every security-relevant terminal state needs client-visible and audit-visible evidence.

Run fast deterministic suites on every change and gate fetch-service merges on the relevant regression corpus and kernel self-tests. Convert every fuzzing, stress, or production failure into a minimized permanent regression case.

### Known issues/TODOS in Session and Capability Tests

Issue: Session ownership still depends on request-supplied identity, capability generation is not supported by adversarial collision evidence, and no tests prove revocation across close, process death, restore, or physical slot reuse.

Required fixes:

Bind tests to authenticated IPC identity and cover open, duplicate open, capacity exhaustion, subordinate-registration failure, close, repeated close, process death, reopen, and cleanup. Verify rollback of every partially created state class.

Exercise zero, malformed, random, cross-session, cross-caller, stale, restored, collided, and wrapped capabilities. Generate interleaved multi-caller operation sequences and prove that no authority or state survives into a reused slot or newer session generation.

### Known issues/TODOS in URL Parser and Redirect Tests

Issue: URL and redirect parsing accepts hostile variable-length input through fixed buffers, but no conformance, property, segmentation, or chain-level tests prove that policy, canonicalization, cache identity, and transport use the same lossless URL.

Required fixes:

Create a corpus for malformed authorities, ports, address literals, encodings, dot segments, Unicode, control bytes, and every component boundary. Assert lossless representation, canonicalization idempotence, stable origin derivation, collision resistance, and zero side effects on rejection.

Drive complete redirect chains through absent, duplicate, relative, malformed, oversized, cross-origin, downgrade, loop, and hop-limit cases. Require policy, credential, cookie, method, timeout, and audit recomputation at every hop before transport contact.

### Known issues/TODOS in Header and Chunked-Decoder Tests

Issue: Response framing and chunked decoding have no fragmented-input, ambiguity, progress, or fuzz coverage even though malformed framing can cause response smuggling, premature completion, unbounded work, or body-boundary confusion.

Required fixes:

Test status lines and headers at every size and segmentation boundary, including aggregate limits, invalid syntax, conflicting Content-Length, Transfer-Encoding combinations, duplicate Location, and independently preserved Set-Cookie fields. Rejection must discard partial metadata and produce one typed failure.

Test chunk sizes, extensions, overflow, delimiters, multiple chunks, zero chunks, trailers, premature EOF, extra bytes, and encoded and decoded limits under every practical input split. Add compositional fuzz targets whose oracles enforce bounded work, progress, deterministic classification, and equivalence between one-shot and incremental parsing.

### Known issues/TODOS in Cookie, Cache, and Storage Isolation Tests

Issue: Cookie, cache, and storage state can influence later requests, yet no tests prove standards-correct matching, complete cache identity, VFS authority, policy reapplication, generation handling, or isolation after allocator reuse and temporal restore.

Required fixes:

Use multi-session stateful tests for cookie replacement, expiry, redirects, domain and path matching, Secure, HttpOnly, SameSite, public suffixes, and purge behavior. Assert that no request receives a cookie through string-suffix confusion or stale state.

Cover cache-key serialization, freshness boundaries, validators, 304 merging, Vary, authorization, cookies, no-store, body-pool reuse, and current-policy enforcement on hits. Test storage traversal, key boundaries, registration and I/O failures, quotas, cleanup, resolved VFS authority, and snapshot-to-storage generation mismatch.

### Known issues/TODOS in Download Destination Tests

Issue: Download lifecycle, destination authority, filename normalization, atomic publication, quarantine, and evidence are not covered by state-machine or fault-injection tests.

Required fixes:

Model all legal and illegal offer transitions, including wrong-session and stale identifiers, repeated decisions, cancellation, process death, restore, and identifier wraparound. No rejected transition may alter destination state.

Use an adversarial VFS to test traversal, symlink and parent replacement races, mount crossing, existing files, short writes, capacity exhaustion, rename and cleanup failure. Verify private temporary writes, atomic publication, deterministic filename normalization, metadata continuity, quarantine disposition, and completion evidence only after durable success.

### Known issues/TODOS in TLS, Timeout, and Transport Failure Tests

Issue: The service lacks a deterministic transport and clock harness, so exact DNS, TCP, TLS, timeout, slow-response, cancellation, cleanup, and terminal-state behavior cannot be reproduced or proven.

Required fixes:

Provide scripted resolver, TCP, and TLS implementations plus a manually advanced monotonic clock. Cover immediate failure, partial progress, exact-deadline completion, stalls, resets, certificate and hostname failures, trust changes, and resource cleanup for every phase.

Test first-byte, header, body-idle, and total deadlines independently and in combination with slowloris input. Race abort, timeout, completion, queue pressure, and session close; require one terminal outcome, no post-terminal body events, distinct EOF and timeout semantics, and exactly-once reclamation.

### Known issues/TODOS in Temporal Restore and Rollback Tests

Issue: Restore mutates authority from unauthenticated, structurally fragile state, and there are no transactional, authenticity, rollback, reconciliation, fuzz, or audit tests.

Required fixes:

Mutate every snapshot field and truncate at every offset while asserting bounded parsing and byte-identical live state after failure. Add property and fuzz tests for counts, capacities, duplicate identities, trailing data, parser desynchronization, and canonical round trips.

Test authenticated envelopes, wrong principals and keys, tampering, replay, stale and branching generations, policy and trust changes, external VFS mismatch, and authorized recovery. Require capability rotation, current-policy reconciliation, atomic publication, and exact correspondence between committed state and restore audit evidence.

### Known issues/TODOS in Event Overflow and Audit Evidence Tests

Issue: Event queues and audit rings can overflow without sufficient loss evidence, and no tests prove terminal delivery, ordering, privacy, correlation, sequence behavior, or recovery under pressure.

Required fixes:

Fill every queue at each request phase and verify ordering, correlation, body and terminal sequencing, exactly one terminal outcome, and explicit sequence-range loss evidence. A client must never interpret a truncated event stream as a complete response.

Test empty rings, overwrite, lagging readers, sequence wraparound, concurrent writers, durable overflow records, privacy redaction, and reused request identifiers across generations. Derive expected evidence from externally observed state transitions so logging tests cannot repeat the implementation’s own incorrect assumptions.
