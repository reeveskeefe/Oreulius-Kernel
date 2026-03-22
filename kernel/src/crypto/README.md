# `crypto` — Cryptographic Primitives

This module provides every cryptographic primitive used by the Oreulia kernel:
symmetric encryption and authentication (AES-128-GCM), hash functions (SHA-256,
SHA-512), a MAC (HMAC-SHA256), key derivation (HKDF), an asymmetric key-exchange
primitive (X25519), a digital signature verifier (Ed25519), domain-separated
hashing (Merkle-Damgård), and signed-artifact helpers.  The implementation is
`no_std` with no external crates, and every primitive is derived rigorously from
its formal specification.

---

## File Map

| File | Lines | Primitive |
|---|---|---|
| `mod.rs` | 597 | SHA-256, HMAC-SHA256, AES-128 core, AES-128-CTR, `ct_eq`, pub re-exports |
| `sha512.rs` | 298 | SHA-512 (FIPS 180-4 §6.4) |
| `ghash_gf128.rs` | 61 | GHASH over $\text{GF}(2^{128})$ |
| `aes_gcm_nist_sp800_38d.rs` | 146 | AES-128-GCM (NIST SP 800-38D) |
| `hkdf_rfc5869.rs` | 106 | HKDF-SHA256 (RFC 5869) |
| `ed25519_twisted_edwards.rs` | 481 | Ed25519 signature verification (RFC 8032) |
| `x25519_montgomery.rs` | 257 | X25519 Diffie-Hellman (RFC 7748) |
| `merkle_damgard_domain.rs` | 31 | Domain-separated leaf/node hashing |
| `signing_formats.rs` | 197 | Canonical signed-message builders + detached-signature verifier |

---

## SHA-256 — FIPS 180-4

### 1. The Merkle-Damgård Construction

SHA-256 is built on the Merkle-Damgård iterative compression scheme.

**Padding.**  Given a message $m$ of length $\ell$ bits, append bit $1$, then
enough zero bits so that the total length is $\equiv 448 \pmod{512}$, then
appended the 64-bit big-endian encoding of $\ell$.  The padded message $m'$
has length that is a multiple of 512 bits (64 bytes), yielding blocks
$m'_1, m'_2, \ldots, m'_n$.

**Iteration.** Let $f : \{0,1\}^{256} \times \{0,1\}^{512} \to \{0,1\}^{256}$
be the SHA-256 compression function.  Then

$$H_0 = \mathrm{IV}_{256}, \quad H_i = f(H_{i-1},\, m'_i), \quad \text{SHA-256}(m) = H_n.$$

The initial vector is derived from the first 32 bits of the fractional parts of
the square roots of the first eight primes:

$$\mathrm{IV}_{256} = \left(\lfloor\sqrt{2}\rfloor_{32},\, \lfloor\sqrt{3}\rfloor_{32},\, \ldots,\, \lfloor\sqrt{19}\rfloor_{32}\right)$$

where $\lfloor x \rfloor_{32}$ denotes the first 32 fractional bits of $x$.

**Length-extension resistance.** The padding includes the message length, so
$\text{SHA-256}(m) = \text{SHA-256}(m')$ implies $m = m'$ (equal padded messages).

---

### 2. The SHA-256 Compression Function

**Word schedule.**  The 512-bit block is parsed into sixteen 32-bit words
$W_0,\ldots,W_{15}$ (big-endian).  The schedule is extended to 64 words:

$$W_t = \sigma_1(W_{t-2}) \oplus W_{t-7} \oplus \sigma_0(W_{t-15}) \oplus W_{t-16}, \quad 16 \leq t \leq 63$$

with the lower-case sigma functions

$$\sigma_0(x) = \mathrm{ROTR}^7(x) \oplus \mathrm{ROTR}^{18}(x) \oplus \mathrm{SHR}^3(x)$$

$$\sigma_1(x) = \mathrm{ROTR}^{17}(x) \oplus \mathrm{ROTR}^{19}(x) \oplus \mathrm{SHR}^{10}(x)$$

and $\mathrm{ROTR}^n(x) = (x \gg n) \mid (x \ll 32{-}n)$ for 32-bit words.

**Working variables.** The 256-bit state $H_{i-1}$ is unpacked into eight
32-bit words $a,b,c,d,e,f,g,h$.

**Round function.** For $t = 0,\ldots,63$:

$$T_1 = h + \Sigma_1(e) + \mathrm{Ch}(e,f,g) + K_t + W_t$$

$$T_2 = \Sigma_0(a) + \mathrm{Maj}(a,b,c)$$

$$h \leftarrow g; \; g \leftarrow f; \; f \leftarrow e; \; e \leftarrow d + T_1; \; d \leftarrow c; \; c \leftarrow b; \; b \leftarrow a; \; a \leftarrow T_1 + T_2$$

where arithmetic is $\bmod 2^{32}$ throughout, and

$$\Sigma_0(x) = \mathrm{ROTR}^{2}(x) \oplus \mathrm{ROTR}^{13}(x) \oplus \mathrm{ROTR}^{22}(x)$$

$$\Sigma_1(x) = \mathrm{ROTR}^{6}(x) \oplus \mathrm{ROTR}^{11}(x) \oplus \mathrm{ROTR}^{25}(x)$$

$$\mathrm{Ch}(x,y,z) = (x \mathbin{\&} y) \oplus (\lnot x \mathbin{\&} z)$$

$$\mathrm{Maj}(x,y,z) = (x \mathbin{\&} y) \oplus (x \mathbin{\&} z) \oplus (y \mathbin{\&} z)$$

**Ch** selects bit-by-bit from $y$ when $x = 1$ and from $z$ when $x = 0$.
**Maj** outputs the majority bit of $(x, y, z)$.

**Round constants.** The 64 constants $K_t$ are the first 32 fractional bits of
the cube roots of the first 64 primes.  They break algebraic symmetry and ensure
every round key is distinct.

**Feed-forward.** After 64 rounds:

$$H_i[j] = H_{i-1}[j] + v[j] \pmod{2^{32}}, \quad j = 0,\ldots,7$$

where $v = (a,b,c,d,e,f,g,h)$ after the 64-round loop.

---

### 3. SHA-512 — The 64-bit Analogue

SHA-512 (FIPS 180-4 §6.4) follows the same template but lifts everything from
32-bit to 64-bit words and uses 80 rounds.

**Padding target:** $\ell \equiv 896 \pmod{1024}$; 128-bit length appended.

**Working register width:** 64 bits; arithmetic $\bmod 2^{64}$.

**Word-schedule rotation distances:**

$$\sigma_0(x) = \mathrm{ROTR}^1(x) \oplus \mathrm{ROTR}^8(x) \oplus \mathrm{SHR}^7(x)$$

$$\sigma_1(x) = \mathrm{ROTR}^{19}(x) \oplus \mathrm{ROTR}^{61}(x) \oplus \mathrm{SHR}^6(x)$$

$$\Sigma_0(x) = \mathrm{ROTR}^{28}(x) \oplus \mathrm{ROTR}^{34}(x) \oplus \mathrm{ROTR}^{39}(x)$$

$$\Sigma_1(x) = \mathrm{ROTR}^{14}(x) \oplus \mathrm{ROTR}^{18}(x) \oplus \mathrm{ROTR}^{41}(x)$$

The rotation constants are chosen so that the diffusion from a single bit change
propagates through every output bit within a small number of rounds.

SHA-512 is used internally by Ed25519 to compute $H(R \| A \| M)$ — the hash
challenge scalar — because Ed25519 is specified to use SHA-512.

---

## AES-128 — Over $\text{GF}(2^8)$

### 1. The Finite Field $\text{GF}(2^8)$

AES arithmetic is defined over the field

$$\text{GF}(2^8) = \text{GF}(2)[x] \mathbin{/} \langle x^8 + x^4 + x^3 + x + 1 \rangle.$$

Elements are 8-bit polynomials over $\text{GF}(2)$.  Addition is bitwise XOR
(coefficient addition mod 2).  Multiplication is polynomial multiplication
followed by reduction modulo the irreducible polynomial
$p(x) = x^8 + x^4 + x^3 + x + 1$ (the FIPS-197 choice).

**gf_mul2 — multiply by $x$.**  In `mod.rs`:

```rust
fn gf_mul2(b: u8) -> u8 {
    let hi = b & 0x80;
    let out = b << 1;
    if hi != 0 { out ^ 0x1B } else { out }
}
```

This is correct because shifting left by 1 multiplies by $x$, and if the degree
exceeds 7 (the `hi` bit was set) we subtract $x^8 = x^4+x^3+x+1 =
\texttt{0x1B}$ to remain below degree 8.  Precisely:

$$x \cdot f(x) \pmod{p(x)} = \begin{cases} f(x) \ll 1 & \text{if } [x^7]f = 0 \\ (f(x) \ll 1) \oplus \texttt{0x1B} & \text{if } [x^7]f = 1 \end{cases}$$

### 2. AES State and Key Schedule

**State.** A 128-bit block is arranged as a $4 \times 4$ column-major byte array:

$$S = \begin{pmatrix} s_{0,0} & s_{0,1} & s_{0,2} & s_{0,3} \\ s_{1,0} & s_{1,1} & \cdots & \cdots \\ s_{2,0} & \cdots & & \vdots \\ s_{3,0} & \cdots & \cdots & s_{3,3} \end{pmatrix}, \quad s_{r,c} \in \text{GF}(2^8)$$

Linear indexing in the implementation: byte $i$ in a flat 16-byte array
represents row $r = i \bmod 4$, column $c = \lfloor i / 4 \rfloor$.

**Key expansion.** AES-128 has a 128-bit key, expanded to $(10+1) \times 16 = 176$
bytes of round key material.  The expansion uses:

- **RotWord**: cyclic left rotation of a 4-byte word $(a_0,a_1,a_2,a_3) \to (a_1,a_2,a_3,a_0)$
- **SubWord**: apply the S-box to each of the 4 bytes
- **Rcon**: the round constant $\text{Rcon}[i] = (x^{i-1}, 0, 0, 0)$ in $\text{GF}(2^8)^4$

For each group of 16 bytes after the original key:

$$W[i] = W[i-4] \oplus g(W[i-1])$$

where $g$ applies RotWord + SubWord + Rcon⊕ on the previous word when $4 \mid i$.

### 3. SubBytes — The S-box

The S-box $S : \text{GF}(2^8) \to \text{GF}(2^8)$ is defined as:

1. **Inversion**: $b = a^{-1}$ in $\text{GF}(2^8)$ (map $0 \mapsto 0$).
2. **Affine map over $\text{GF}(2)$**:

$$S(a) = M \cdot b \oplus c$$

where $M$ is the $8 \times 8$ binary circulant matrix with first row
`10001111` and $c = \texttt{0x63}$.

The S-box is a bijection.  Its nonlinearity (maximum cross-correlation with any
linear function) is $2^6 = 64$, which is optimal for an 8-bit bijection.  The
algebraic degree over $\text{GF}(2)$ is 7, making algebraic attacks computationally
infeasible.

### 4. ShiftRows

Row $r$ of the state is rotated left by $r$ positions:

$$s'_{r,c} = s_{r,\,(c+r)\bmod 4}, \quad r = 0,1,2,3$$

This ensures that after MixColumns, each column of the output depends on all
four rows — producing the inter-column diffusion necessary for the avalanche
effect.

### 5. MixColumns

Each column $(a_0, a_1, a_2, a_3)^T \in \text{GF}(2^8)^4$ is multiplied by the
fixed MDS matrix over $\text{GF}(2^8)$:

$$\begin{pmatrix} 2 & 3 & 1 & 1 \\ 1 & 2 & 3 & 1 \\ 1 & 1 & 2 & 3 \\ 3 & 1 & 1 & 2 \end{pmatrix} \begin{pmatrix} a_0 \\ a_1 \\ a_2 \\ a_3 \end{pmatrix}$$

where numerals denote elements of $\text{GF}(2^8)$: $2 = x$, $3 = x+1$.

**The implementation** in `aes_mix_columns` avoids the matrix multiply by expanding
directly.  For column $c$ with entries $a_0,a_1,a_2,a_3$ and sum
$t = a_0 \oplus a_1 \oplus a_2 \oplus a_3$:

$$b_i = a_i \oplus t \oplus \text{gf\_mul2}(a_i \oplus a_{(i+1)\bmod 4}), \quad i = 0,1,2,3$$

**Proof of correctness.** The desired output for row $i$ is
$(x+1)a_i \oplus x a_{(i+1)} \oplus a_{(i+2)} \oplus a_{(i+3)}$.  Expanding
$(x+1)a_i = \text{gf\_mul2}(a_i) \oplus a_i$ and collecting:

$$b_i = a_i \oplus (a_0 \oplus a_1 \oplus a_2 \oplus a_3) \oplus \text{gf\_mul2}(a_i \oplus a_{i+1}) = \text{matrix row } i$$

The matrix is an MDS (Maximum Distance Separable) matrix: any $4 \times 4$
submatrix formed by selecting rows and columns has full rank over $\text{GF}(2^8)$,
guaranteeing that any non-zero input column produces an output with maximum Hamming
weight.  This is the "wide-trail strategy" — every difference in one round forces
a high active-S-box count in subsequent rounds.

### 6. AddRoundKey and Cipher Structure

$$\mathrm{ARK}(S, K) = S \oplus K$$

AES-128 applies: ARK → (SubBytes → ShiftRows → MixColumns → ARK) ×9 → SubBytes → ShiftRows → ARK.
The final round omits MixColumns to make decryption symmetric.

### 7. AES-128 CTR Mode

CTR mode turns AES into a stream cipher:

$$C_i = P_i \oplus E_K(\mathrm{IV} \| i), \quad i = 0, 1, 2, \ldots$$

where the counter block layout in `aes128_ctr_xor` is:

- Bytes 0–7: the 64-bit `nonce` (little-endian)
- Bytes 8–15: the 64-bit `counter` (little-endian)

**Security.** CTR mode is IND-CPA secure under the PRF assumption on AES provided
the nonce is never reused with the same key.  CTR mode provides **no** authentication.

---

## HMAC-SHA256 — RFC 2104

### Construction

$$\mathrm{HMAC}(K, m) = H\!\left[(K_0 \oplus \text{opad}) \;\|\; H\!\left[(K_0 \oplus \text{ipad}) \;\|\; m\right]\right]$$

where $K_0$ is $K$ zero-padded to a full block width (64 bytes for SHA-256),
$\text{ipad} = \texttt{0x36}^{64}$, $\text{opad} = \texttt{0x5C}^{64}$.

**Why $\text{ipad} \oplus \text{opad} = \texttt{0x6A}^{64} \neq 0$.** The two
padded keys are never equal, so the inner and outer hash computations are seeded
with different values.

### Security Arguments

**Lemma (HMAC security).** If $H$ is a PRF with block length $B$ and output
length $L$, then HMAC is a PRF for messages of length at most $2^{64}B$ bits.
Formally, any PPT adversary making $q$ queries achieves advantage

$$\mathrm{Adv}^{\mathrm{PRF}}_{\mathrm{HMAC}}(\mathcal{A}) \leq \mathrm{Adv}^{\mathrm{PRF}}_{H}(\mathcal{B}_1) + \mathrm{Adv}^{\mathrm{PRF}}_{H}(\mathcal{B}_2) + \frac{q^2}{2^L}$$

The reduction works by replacing the inner hash with a random function and bounding
the birthday term.  The implementation achieves this bound because:

1. `ipad` and `opad` XOR with $K_0$ to produce two distinct block-length keys,
   seeding the inner and outer SHA-256 computations from different initial states.
2. The output $H(\text{outer\_block}\|H(\text{inner\_block}\|m))$ is a
   length-second-preimage-resistant function of $m$.

### Streaming API (`HmacSha256`)

The stateful `HmacSha256` struct stores only the partially-hashed inner state
and the $\text{opad}$-keyed outer state — no plaintext key bytes are held after
construction.

---

## AES-128-GCM — NIST SP 800-38D

AES-128-GCM is an AEAD (Authenticated Encryption with Associated Data) scheme
combining AES-128-CTR confidentiality with GHASH authentication.

### Initialisation

Given key $K$ and IV of exactly 96 bits:

$$H = E_K(0^{128}), \quad J_0 = \mathrm{IV} \| 0^{31}1$$

$H$ is the GHASH authentication subkey.  $J_0$ is the pre-counter block.

### Encryption

$$C_i = P_i \oplus E_K(\mathrm{IV} \| \langle i+1 \rangle_{32}), \quad i = 1, 2, \ldots, \lceil |P|/128 \rceil$$

Counters start at 2 (not 1) because $\mathrm{ctr}=1$ is reserved for the
authentication mask:

$$T = \mathrm{GHASH}(H, A, C) \oplus E_K(J_0)$$

In the implementation (`ctr_block` starts at `ctr=1` for the $J_0$ keystream
block, and the cipher loop starts at `ctr=2`).

### Decryption and Tag Verification

Decryption recomputes $\mathrm{GHASH}(H, A, C)$ **before** decrypting.  The
`aes128_gcm_decrypt` function uses `ct_eq` to compare expected and received tags
in constant time.  Crucially, plaintext bytes are written to `out` **only after
the tag check passes** — this prevents an attacker from observing partial plaintext
via padding-oracle-style timing.

### Authenticated Encryption Security

AES-128-GCM achieves indistinguishability under chosen-ciphertext attack (IND-CCA2)
under the assumption that AES is a pseudorandom permutation and that GHASH is a
$\Delta$-universal hash family:

$$\mathrm{Adv}^{\mathrm{AE}}(\mathcal{A}) \leq \frac{q \cdot \sigma}{2^{128}} + \frac{q^2}{2^{32}}$$

for $q$ encrypt queries covering $\sigma$ total 128-bit blocks.  The second term
reflects the GCM nonce collision bound: with probability $q^2/2^{32}$, a repeating
the same nonce under the same key completely breaks authentication.  **Nonces must
therefore be unique per (key, nonce) pair.**

---

## GHASH over $\text{GF}(2^{128})$

### The Field

$$\text{GF}(2^{128}) = \text{GF}(2)[x] \mathbin{/} \langle x^{128} + x^7 + x^2 + x + 1 \rangle$$

Elements are 128-bit strings interpreted as polynomials over $\text{GF}(2)$.
Addition is bitwise XOR.  Multiplication is polynomial multiplication reduced
by the NIST reduction polynomial $r(x) = x^{128} + x^7 + x^2 + x + 1$.

### The GHASH Function

Given authentication subkey $H \in \text{GF}(2^{128})$ and the concatenated input
$X = A_1 \| \cdots \| A_{\lceil|A|/128\rceil} \| C_1 \| \cdots \| C_{\lceil|C|/128\rceil} \| L$

where $L$ encodes the bit-lengths of $A$ and $C$ as two big-endian 64-bit integers,
the GHASH is computed as the final state $Y_m$ of:

$$Y_0 = 0^{128}, \quad Y_i = (Y_{i-1} \oplus X_i) \cdot H$$

with multiplication in $\text{GF}(2^{128})$.  Expanding:

$$\mathrm{GHASH}(H, X) = X_1 H^m \oplus X_2 H^{m-1} \oplus \cdots \oplus X_m H$$

This is evaluation of the polynomial $P_X \in \text{GF}(2^{128})[z]$ at $H$, where
the coefficients are the $X_i$ blocks.  **GHASH is a polynomial hash family.**

### Security: $\Delta$-Universality

**Claim.** For any two distinct inputs $X \neq X'$ and a uniformly random
$H \in \text{GF}(2^{128})$:

$$\Pr[\mathrm{GHASH}(H, X) = \mathrm{GHASH}(H, X')] = \frac{d}{2^{128}}$$

where $d = \deg(P_X - P_{X'}) \leq m$ (the number of differing blocks).

**Proof sketch.** $\mathrm{GHASH}(H, X) - \mathrm{GHASH}(H, X') = (P_X - P_{X'})(H)$.
This is a non-zero polynomial of degree at most $m$ evaluated at a random
point.  A non-zero polynomial of degree $d$ over $\text{GF}(2^{128})$ has
at most $d$ roots, so the probability that $H$ is one of them is $\leq d / 2^{128}$.
For single-block AAD and ciphertext, $d \leq 3$, giving a forgery probability
bounded by $3/2^{128}$. $\square$

### gf_mul Implementation

`gf_mul(x, y)` uses the right-to-left binary method (comb multiplication).
For each bit of $y$ (MSB first, within each byte), it conditionally XORs $v = x$
into the accumulator $z$, then right-shifts $v$ by 1 in $\text{GF}(2^{128})$
(polynomial division by $x$), applying the reduction $v[0] \;\mathbin{^=}\;
\texttt{0xE1}$ if the shifted-out bit was 1.

**Why `0xE1`?** Dividing by $x$ in $\text{GF}(2^{128})$ is: if the LSB
(coefficient of $x^0$) was 1, then $x \cdot v/x = x^0 + \text{reduction}$.
The GCM reduction polynomial is $x^{128} + x^7 + x^2 + x + 1$, so
$x^{128} \equiv x^7 + x^2 + x + 1$ and the feedback polynomial for a 1-shift-right
with carry is $x^{127} + x^6 + x^1 + x^0$, whose low byte in big-endian bit-order
is $\texttt{0xE1} = 1110\,0001_2$.

---

## HKDF-SHA256 — RFC 5869

### Extract–Expand Paradigm

**Goal.** Given possibly non-uniform input keying material (IKM), produce $N$
pseudorandom bytes suitable as cryptographic keys.

**Extract.** Compress the IKM into a uniformly distributed pseudorandom key (PRK):

$$\mathrm{PRK} = \mathrm{HMAC\text{-}SHA256}(\mathrm{salt},\, \mathrm{IKM})$$

If `salt` is empty, a string of 32 zero bytes is used (the hash-function block
length).  This step "extracts" the entropy from the IKM into a uniform form.

**Expand.** Generate keying material of arbitrary length from PRK and a
context label `info`:

$$T(0) = \varepsilon$$

$$T(i) = \mathrm{HMAC\text{-}SHA256}(\mathrm{PRK},\; T(i-1) \;\|\; \mathrm{info} \;\|\; i), \quad i = 1, 2, \ldots$$

$$\mathrm{OKM} = T(1) \;\|\; T(2) \;\|\; \cdots \quad [\text{first } N \text{ bytes}]$$

The limit is $N \leq 255 \times 32$ bytes.

### Security

**Theorem (informal, Krawczyk 2010).** If HMAC is a PRF, then HKDF-Extract is a
randomness extractor and HKDF-Expand produces a PRF family keyed by PRK.  An
adversary that cannot distinguish HMAC from a random oracle cannot distinguish
OKM from a uniform random string of $N$ bytes.

**Context separation.** The `info` field — present in every call to
`hkdf_expand_label_sha256` — binds the derived key to its intended purpose.
Even with the same PRK, different `info` values produce cryptographically
independent outputs.  This is the TLS 1.3 key derivation pattern: info is the
struct `HkdfLabel { length: u16, label: "tls13 " || label, context: ctx }`.

### Implementation Notes

`hkdf_expand<const N>` is const-generic over output length, resolving the target
size at compile time.  The inner message buffer is stack-allocated at
`[u8; 32 + 255 + 1]` = 288 bytes, which safely covers the maximum
`T(i-1) || info || counter` without heap allocation.

---

## X25519 — Montgomery Ladder on Curve25519

### The Curve

Curve25519 is the Montgomery curve

$$E : y^2 = x^3 + 486662 \, x^2 + x \quad \text{over } \mathbb{F}_p, \quad p = 2^{255} - 19$$

The coefficient $A = 486662$; the constant $A_{24} = (A-2)/4 = 121665$.

The X25519 function computes the scalar multiplication exclusively in the
$x$-coordinate (the Montgomery $u$-coordinate), which suffices for Diffie-Hellman.

### The Field $\mathbb{F}_p$, $p = 2^{255} - 19$

Elements are represented as four 64-bit limbs (`Fe = [u64; 4]`), storing the
255-bit value in standard unsigned little-endian form.

**Reduction identity.** Since $p = 2^{255} - 19$, we have
$2^{255} \equiv 19 \pmod{p}$.  This is exploited in the field multiplication
`fe_mul`:

1. Schoolbook multiply two 256-bit numbers into a 512-bit product stored in 8
   limbs $c[0..7]$.
2. For $i \in \{4,5,6,7\}$: each limb $c[i]$ represents $c[i] \cdot 2^{64i}$;
   since $64 \times 4 = 256 = 255 + 1$, we have $2^{256} = 2 \cdot 2^{255}
   \equiv 2 \cdot 19 = 38 \pmod{p}$.  Therefore $c[i]$ for $i \geq 4$ contributes
   $c[i] \cdot 38$ to $c[i-4]$ plus carry:

   $$c'[i-4] \leftarrow c[i-4] + 38 \cdot c[i]$$

3. A second fold propagates any remaining overflow (at most $c[4] \leq 1$ after
   the first fold), adding $c[4] \cdot 38$ to $c[0]$.
4. `fe_reduce` subtracts $p$ if the result is $\geq p$.

### Key Clamping

Per RFC 7748 §5, before use the 32-byte scalar is clamped:

$$k[0] \leftarrow k[0] \mathbin{\&} \texttt{0xF8}, \quad k[31] \leftarrow (k[31] \mathbin{\&} \texttt{0x7F}) \mathbin{|} \texttt{0x40}$$

The first operation clears the three low bits, making the scalar a multiple of 8
(the cofactor of Curve25519), ensuring small-subgroup attacks are impossible.
The second operation clears bit 255 (which is not in $\mathbb{F}_p$) and sets
bit 254, placing the scalar in the range $[2^{254}, 2^{255})$ — a canonical
representative that defeats the "e = 0" degenerate case.

### The Montgomery Ladder

The ladder computes $[k]P$ for a point $P = (u, v)$ using only $u$-coordinates.
It maintains two projective points $(R_0, R_1)$ invariant:

$$R_0 = [m]P, \quad R_1 = [m+1]P, \quad R_1 - R_0 = P$$

For bit $k_t$ of the scalar (from MSB to LSB):

1. **Conditional swap**: $\mathrm{CSWAP}(k_t, R_0, R_1)$
2. **Differential addition**: $R_1 \leftarrow R_0 + R_1$ using the Montgomery
   differential formula
3. **Doubling**: $R_0 \leftarrow 2 R_0$
4. **Swap back**: $\mathrm{CSWAP}(k_t, R_0, R_1)$

After 255 iterations (LSB to MSB loop), recover $u = X/Z$ via $u = R_0.X \cdot (R_0.Z)^{-1}$.

**Security of cswap.** The branching-free swap:

```rust
fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap & 1);  // 0xFF..FF if swap=1, 0 if swap=0
    for i in 0..4 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}
```

The mask is all-ones when `swap=1`, all-zeros when `swap=0`.  Swapping via
`a ^= t; b ^= t` never branches on the secret bit, eliminating timing sidechannels.
The instruction trace is identical regardless of the bit value.

### Field Inversion via Fermat's Little Theorem

$$a^{-1} \equiv a^{p-2} = a^{2^{255}-21} \pmod{p}$$

`fe_inv` in `x25519_montgomery.rs` uses an addition chain for $p-2$ that requires
only 255 squarings and 11 multiplications, derived from the binary representation:

$$p - 2 = 2^{255} - 21 = \underbrace{2^{255}}_{\text{250 squarings}} - 21$$

The chain exploits $p-2 = 2^{250}(2^5 - 1)(2^5 + 1) - 21$ — see the source for
the exact accumulator sequence $z_2, z_9, z_{11}, z_{2^5}, z_{2^{10}}, z_{2^{20}},
z_{2^{40}}, z_{2^{50}}, z_{2^{100}}, z_{2^{200}}, z_{2^{250}}$.

---

## Ed25519 — Twisted Edwards Curve

### The Curve

Edwards25519 is the twisted Edwards curve

$$E_{-1,d} : -x^2 + y^2 = 1 + d \, x^2 y^2 \quad \text{over } \mathbb{F}_p, \quad p = 2^{255} - 19$$

$$d = \frac{-121665}{121666} \pmod{p}$$

computed in the implementation via `fe_neg(&fe_from_u64(121_665))` multiplied by
`fe_inv(&fe_from_u64(121_666))`.  The "twist" coefficient $a = -1$ (vs. $a = 1$
for standard Edwards curves) enables a faster unified addition law.

### Extended (Projective) Coordinates

Points are represented as $\mathbf{P} = (X : Y : Z : T)$ where

$$x = X/Z, \quad y = Y/Z, \quad T = XY/Z \quad (T/Z = xy)$$

This uses 5 field elements per point and enables a unified addition formula free
of special cases (no point-at-infinity edge case).

### The Complete Addition Law

For $\mathbf{P} = (X_1, Y_1, Z_1, T_1)$ and $\mathbf{Q} = (X_2, Y_2, Z_2, T_2)$:

$$A = (Y_1 - X_1)(Y_2 - X_2), \quad B = (Y_1 + X_1)(Y_2 + X_2)$$

$$C = T_1 \cdot T_2 \cdot 2d, \quad D = Z_1 \cdot Z_2 \cdot 2$$

$$E = B - A, \quad F = D - C, \quad G = D + C, \quad H = B + A$$

$$X_3 = E \cdot F, \quad Y_3 = G \cdot H, \quad Z_3 = F \cdot G, \quad T_3 = E \cdot H$$

This requires 8 field multiplications and 8 additions.  **The formula is complete:**
it is valid for all pairs of points on the curve, including the neutral element.

### Doubling

For $\mathbf{P} = (X, Y, Z, T)$:

$$A = X^2, \quad B = Y^2, \quad C = 2Z^2, \quad D = -A$$

$$E = (X+Y)^2 - A - B, \quad G = D + B, \quad F = G - C, \quad H = D - B$$

$$X_3 = E \cdot F, \quad Y_3 = G \cdot H, \quad Z_3 = F \cdot G, \quad T_3 = E \cdot H$$

### Point Compression and Decompression

**Compression.** Compute affine $(x, y) = (X Z^{-1}, Y Z^{-1})$.  The compressed
form is the 32-byte little-endian encoding of $y$ with bit 255 set to the sign
bit of $x$ (the low bit of the canonical byte representation of $x$).

**Decompression.**  Given compressed $y$ and sign $s$:

1. Recover $y^2$.
2. Compute $u = y^2 - 1$ and $v = d y^2 + 1$.
3. Compute $x = \sqrt{u/v}$ via the Tonelli formula adapted to $\mathbb{F}_p$:

$$x^2 \equiv u/v \pmod{p} \iff x = (u/v)^{(p+3)/8} \pmod{p}$$

   If the square of the result does not equal $u/v$, multiply by $\sqrt{-1}$
   (precomputed as $2^{(p-1)/4} \bmod p$).  If still no square root, the point
   is not on the curve.

4. Negate $x$ if its sign does not match $s$.

**Canonical encoding check.**  After decompression, the implementation re-encodes
the point and uses `ct_eq` to verify that the encoding round-trips.  This catches
non-canonical byte representations (e.g., $y \geq p$) which must be rejected per
RFC 8032.

### The Scalar Field

The group order of Edwards25519 is

$$\ell = 2^{252} + 27742317777372353535851937790883648493$$

$$= \texttt{7fffffffffffffffffffffffffffffffffffffffffffffffffffffed} + 1 \quad (\text{big-endian})$$

Scalars must satisfy $0 \leq s < \ell$.  `scalar_is_canonical` performs a
big-endian byte comparison against $\ell$ to reject non-canonical scalars, which
is required to prevent signature-malleability attacks.

### 51-bit Limb Arithmetic

The field arithmetic in `ed25519_twisted_edwards.rs` uses five 51-bit limbs
(`Fe = [u64; 5]`; `MASK51 = 2^{51} - 1`), representing $x \in \mathbb{F}_p$ as

$$x = h_0 + h_1 \cdot 2^{51} + h_2 \cdot 2^{102} + h_3 \cdot 2^{153} + h_4 \cdot 2^{204}$$

**Why 51 bits?** Since $p = 2^{255} - 19$, five limbs of 51 bits cover
$5 \times 51 = 255$ bits.  The word size is 64 bits, leaving $64 - 51 = 13$ spare
bits per limb — enough headroom to absorb carries during multiplication without
overflow.

**fe_mul and the factor 19.** In the multiplication `h0 = f0·g0 + f1·g4·19 + …`:
the cross-term $f_i \cdot g_j$ contributes to limb $i+j \bmod 5$ with a weight
of $2^{51(i+j \bmod 5)} \cdot 2^{255 \lfloor (i+j)/5 \rfloor}$.  Since
$2^{255} \equiv 19 \pmod{p}$, each limb whose index would exceed 4 is folded
back multiplied by 19.  Explicitly, for $i + j \geq 5$:

$$f_i \cdot g_j \cdot 2^{51\cdot 5} \equiv f_i \cdot g_j \cdot 2^{255} \equiv 19 \cdot f_i \cdot g_j \pmod{p}$$

This gives the schoolbook-mod-reduction formula for 51-bit limbs with free
coefficient $19$, matching what's in source as `g1_19 = g1 * 19`, etc.

### Ed25519 Signature Verification

Given public key $A$, message $m$, and signature $(R, s)$ where
$R \in E(\mathbb{F}_p)$ (compressed point), $s \in \mathbb{Z}_{<\ell}$:

1. Decode $A$ and $R$ as curve points.
2. Reject if $A$ or $R$ is a low-order point: check $[8]A \neq \mathcal{O}$ and
   $[8]R \neq \mathcal{O}$.
3. Compute the challenge scalar

$$k = \mathrm{SHA\text{-}512}(R_{\mathrm{enc}} \;\|\; A_{\mathrm{enc}} \;\|\; m) \pmod{\ell}$$

4. Accept if and only if

$$8 [s] B = 8 (R + [k] A)$$

where $B$ is the standard base point and $8$ is the cofactor multiplication.

**Why cofactor multiplication?** Curve25519 has cofactor $h = 8$.  Any low-order
component of $A$ or $R$ would cause the equation $[s]B = R + [k]A$ to admit
multiple passing scalars for a single signature, enabling existential forgery.
Multiplying both sides by 8 cancels the 8-torsion subgroup, ensuring the
check is over the prime-order subgroup.

**Verification equation derivation.** The signing equation is $s = r + k \cdot a$
where $r$ is the secret nonce (chosen so $R = [r]B$) and $a$ is the private key
($A = [a]B$).  Substituting:

$$[s]B = [r + ka]B = [r]B + [k][a]B = R + [k]A \qquad \square$$

**Constant-time final comparison.** The implementation compresses both $[8s]B$
and $[8(R + kA)]$ and uses `ct_eq` to compare the two 32-byte encodings, so
the comparison itself does not branch on the result.

---

## Merkle-Damgård Domain Separation

### Motivation

Domain separation prevents cross-context collisions.  Without it:

$$H(\text{``leaf''} \| d) = H(\text{``node''} \| d')$$

might be achievable by a birthday attack that conflates leaf and node hashes.

### Construction

`merkle_damgard_domain_hash(domain, payload)` computes:

$$\mathrm{DH}(D, P) = \mathrm{SHA\text{-}256}\!\left(\texttt{0xA5} \;\|\; |D|_8 \;\|\; D \;\|\; |P|_{64} \;\|\; P\right)$$

where $|D|_8$ is the one-byte length of the domain label and $|P|_{64}$ is the
eight-byte big-endian length of the payload.

**Prefix-free encoding.** The two-byte header $(\texttt{0xA5}, |D|)$ before the
domain label ensures that no domain $D_1$ is a prefix of $(\texttt{0xA5} \| |D_2|
\| D_2)$ for any $D_2 \neq D_1$.  This makes the input encoding **injective**,
so collisions in domain-separated hashes require collisions in SHA-256 itself.

### Leaf and Node Hashes

**Leaf:**
$$\mathrm{leaf}(D, \ell) = \mathrm{DH}(D,\; \texttt{0x00} \;\|\; \mathrm{SHA\text{-}256}(\ell))$$

**Node:**
$$\mathrm{node}(D, L, R) = \mathrm{DH}(D,\; \texttt{0x01} \;\|\; L \;\|\; R)$$

The leading byte $\texttt{0x00}$ (leaf) vs $\texttt{0x01}$ (node) prevents
**second-preimage attacks** where a crafted interior node compresses to the same
value as a leaf.  This is the RFC 6962 transparency-tree pattern.

---

## Constant-Time Equality (`ct_eq`)

```rust
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for i in 0..a.len() { diff |= a[i] ^ b[i]; }
    diff == 0
}
```

**Correctness.**  $\forall i: a_i \oplus b_i = 0 \iff a_i = b_i$.  Therefore
$\texttt{diff} = \bigvee_i (a_i \oplus b_i) = 0 \iff a = b$.

**Timing-safety argument.**  The loop body `diff |= a[i] ^ b[i]` has no branch
dependent on the values of $a_i, b_i$.  The accumulator `diff` is widened to
`u8` so that `|=` cannot cause an early-exit trap in the compiled code.
The single branch is on `diff == 0` **after** the loop, at which point the only
observable timing difference is the cost of `==` on a register — independent of
which bytes differed.

Under the standard model of a timing adversary who can observe per-instruction
execution time (but not micro-architectural side-channels like cache), this
function's execution trace has length exactly $O(n)$ with no dependence on
whether $a = b$.

`ct_eq` is called in:
- `aes128_gcm_decrypt` — tag comparison
- `fe_eq` (Ed25519) — field element comparison
- `point_decompress` (Ed25519) — canonical-encoding round-trip check
- `ed25519_verify` — final point comparison

---

## Signing Formats (`signing_formats.rs`)

### Detached Signature Pattern

`verify_detached_ed25519(pubkey_path, sig_path, message)` loads public key and
signature from VFS-backed hex files, then calls `ed25519_verify`.  The status
hierarchy:

| Public key file | Signature file | Outcome |
|---|---|---|
| Absent | Absent | `Unsigned` — no trust assertion |
| Present | Absent | Error — key configured but no sig |
| Absent | Present | Error — orphaned signature |
| Present | Present | `Verified` or error |

This three-way policy enforces the invariant that a partial attestation (public
key without a signature file, or vice versa) is always an error, preventing a
downgrade from "verified" to "unsigned" by removing only one file.

### Canonical Message Formats

**OTA manifest:**

```
oreulia-ota-manifest:v1\n
hash=<hex32>\n
version=<str>\n
```

**Fleet attestation:**

```
oreulia-fleet-attestation:v1\n
boot_session=<u32>\n
crash_count=<u32>\n
boot_tick=<u64>\n
measurement=<hex32>\n
active_slot_hash=<hex32>\n
sched_switches=<u64>\n
```

**Canonical encoding rationale.** The message is text-line encoded (not binary)
so it is human-readable and unambiguous across platforms: no endianness
ambiguity, no struct padding.  The `append_hex` and `append_decimal_*` helpers
are deterministic — same inputs always produce identical byte strings — which is
the necessary condition for a signing-then-verifying pair to pass.

---

## Public API Summary

```rust
// Hashing
pub fn sha256(data: &[u8]) -> [u8; 32]
pub fn sha512(data: &[u8]) -> [u8; 64]
pub struct Sha256  { fn new() -> Self; fn update(&mut self, data); fn finalize(self) -> [u8; 32] }
pub struct Sha512  { fn new() -> Self; fn update(&mut self, data); fn finalize(self) -> [u8; 64] }

// MAC
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32]
pub fn hmac_sha256_trunc16(key: &[u8], data: &[u8]) -> [u8; 16]
pub struct HmacSha256 { fn new(key); fn update(&mut self, data); fn finalize(self) -> [u8; 32] }

// Symmetric encryption + authentication
pub fn aes128_gcm_encrypt(key, iv, aad, pt, out) -> [u8; 16]    // returns tag
pub fn aes128_gcm_decrypt(key, iv, aad, ct, tag, out) -> Result<(), ()>

// AES building blocks
pub fn aes128_expand_key(key: &[u8; 16]) -> [u8; 176]
pub fn aes128_encrypt_block_in_place(block: &mut [u8; 16], rk: &[u8; 176])
pub fn aes128_ctr_xor(key: &[u8; 16], nonce: u64, data: &mut [u8])

// Key derivation
pub fn hkdf_extract(salt, ikm) -> [u8; 32]
pub fn hkdf_expand<const N: usize>(prk, info) -> [u8; N]
pub fn hkdf_expand_label_sha256<const N: usize>(secret, label, ctx) -> [u8; N]

// Asymmetric
pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32]
pub fn x25519_public_key(priv_key: &[u8; 32]) -> [u8; 32]
pub fn x25519_shared_secret(priv_key: &[u8; 32], peer: &[u8; 32]) -> [u8; 32]
pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool

// Domain-separated hashing
pub fn merkle_damgard_domain_hash(domain, payload) -> [u8; 32]
pub fn merkle_damgard_leaf_hash(domain, leaf) -> [u8; 32]
pub fn merkle_damgard_node_hash(domain, left: &[u8;32], right: &[u8;32]) -> [u8; 32]

// Constant time
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool

// Signed-artifact helpers
pub fn verify_detached_ed25519(pubkey_path, sig_path, message)
    -> Result<DetachedSignatureStatus, &'static str>
pub fn build_ota_manifest_signed_message(hash, version) -> Vec<u8>
pub fn build_fleet_attestation_signed_message(...) -> Vec<u8>
```

---

## Security Guarantees and Design Constraints

### Constraint Table

| Constraint | Mechanism |
|---|---|
| No heap allocation in crypto primitives | All buffers stack-allocated; `Fe`, `Point`, `Sha256`, etc. are fixed-size |
| No secret-dependent branches in comparison | `ct_eq` OR-accumulation pattern |
| No secret-dependent branches in scalar multiplication | `cswap` mask pattern in `x25519` |
| Key material zeroed after use | `aes128_ctr_xor` calls `round_keys.fill(0)` |
| GCM tag checked before plaintext release | `aes128_gcm_decrypt` verifies tag before writing `out` |
| Non-canonical point encodings rejected | `point_decompress` round-trip check via `ct_eq` |
| Non-canonical scalars rejected in Ed25519 | `scalar_is_canonical` checked before use |
| Low-order point injection rejected in Ed25519 | Cofactor mul check: $[8]A \neq \mathcal{O}$ and $[8]R \neq \mathcal{O}$ |
| Field arithmetic avoids timing from carry chains | 13-bit headroom in 51-bit limbs absorbs intermediate products without conditional branches |

### Primitive Composition in the Kernel

```
TLS 1.3 handshake
    X25519 ──────────────────────► shared secret
        │
        └─► HKDF-Extract (HMAC-SHA256, salt=0)
                │
                └─► HKDF-Expand-Label (traffic secret)
                        │
                        └─► AES-128-GCM ◄── per-record key/IV

OTA firmware update
    SHA-256 ──────────────────────► firmware hash
        │
        └─► build_ota_manifest_signed_message
                │
                └─► verify_detached_ed25519 (Ed25519 + SHA-512)

Capability attestation
    merkle_damgard_leaf_hash ──────► leaf digest
    merkle_damgard_node_hash ──────► tree root
        │
        └─► build_fleet_attestation_signed_message
                │
                └─► verify_detached_ed25519
```

### Known Limitations

- **AES-128 only.** The GCM nonce space is 96 bits.  The collision bound
  $q^2/2^{32}$ becomes significant at $q \approx 2^{16}$ encryptions under the
  same key.  Applications must rotate keys or use random nonces with low-volume
  traffic.
- **Software AES.** No hardware AES-NI intrinsics.  The implementation is
  correct but slower than an `aesenc`-based implementation.
- **No constant-time guarantee for field inversion.** `fe_pow` and `fe_inv`
  iterate over bits of the exponent, which is always a public constant
  ($p - 2$ or the Ed25519 inversion exponent), so no timing leak arises from a
  secret-dependent bit scan.
- **Ed25519 verification only.** Signing is not needed inside the kernel —
  attestations are signed externally and verified at boot.
