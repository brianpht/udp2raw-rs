# Copilot Instructions

> **Wire-compatible C++ port. Every byte on the wire must be identical.**
>
> ⚠️ If a change alters packet layout, key derivation output, encryption result, or handshake sequence → **REJECT**.

---

## Critical Rules (Auto-Reject)

```
❌ Reorder fields in #[repr(C, packed)] structs
❌ Add padding/alignment to wire-format structs
❌ Use PKCS7 padding for AES-CBC → custom padding (last byte = padded_len - original_len)
❌ Swap encrypt/decrypt key direction without matching C++
❌ Global mutable state → Config is &Config, mutable state owned by event loop
❌ Wrapper crates for raw socket I/O → use libc:: directly
❌ unwrap() on network data / decryption results
❌ Host-endian assumptions in wire format → explicit to_be_bytes/from_be_bytes
❌ Change HKDF info strings → "cipher_key client-->server" etc. are wire-critical
❌ Modify handshake marker bytes → b'b' (bare), b'h' (heartbeat), b'd' (data)
```

---

## Wire Format Invariants

`send_bare` `recv_bare` `send_safer` `recv_safer_multi` `send_handshake`

**Bare packet**: `[iv:8B][padding:8B][marker='b':1B][data:NB]` → encrypt

**Safer packet**: `[my_id:4B][opp_id:4B][seq:8B][type:1B][roller:1B][data:NB]` → encrypt

**Handshake IDs**: `numbers_to_bytes(id1, id2, id3)` → 12 bytes, big-endian `u32`s

> Verify with `cargo test --test wire_protocol` and `cargo test --test encrypt_cross`.

---

## Encryption Pipeline

```rust
// ✅ HMAC path (Encrypt-then-MAC)
encrypt: data → cipher_encrypt() → auth_cal() → output
decrypt: data → auth_verify() → cipher_decrypt() → output

// ✅ Non-HMAC path (MAC-then-Encrypt, legacy)
encrypt: data → auth_cal() → cipher_encrypt() → output
decrypt: data → cipher_decrypt() → auth_verify() → output

// ❌ NEVER mix the two paths
```

---

## Key Derivation Direction

```rust
// ✅ Client encrypts with client→server, decrypts with server→client
// ✅ Server encrypts with server→client, decrypts with client→server
// The info strings are SWAPPED in EncryptionKeys::derive(password, is_client)

// ❌ NEVER: both sides using same direction
```

---

## #[repr(C, packed)] Structs

```rust
// ✅ Exact C struct layout — verified by tests/packet_headers.rs
IpHeader     // 20 bytes — version_ihl uses bitwise ops, NOT bitfields
TcpHeader    // 20 bytes — off_flags: network-byte-order u16
UdpHeader    // 8 bytes
IcmpHeader   // 8 bytes
PseudoHeader // 12 bytes

// ❌ NEVER reorder fields, add derives that require alignment, or use #[repr(Rust)]
```

---

## State & Ownership

```rust
// ✅ Config built once from CLI, passed as &Config everywhere
// ✅ Mutable state owned by event loop function, passed as &mut
// ✅ Encryptor passed as &Encryptor (immutable after init)
// ✅ RawSocketState passed as &mut to event loop

// ❌ NEVER: static mut, lazy_static for runtime state, Arc<Mutex<>>
```

---

## unsafe Policy

Allowed **only** for:
- `libc::` FFI calls (`socket`, `bind`, `sendto`, `recvfrom`, `setsockopt`, `ioctl`, `clock_gettime`)
- `#[repr(C, packed)]` struct → `&[u8]` casting via `std::slice::from_raw_parts`
- `timerfd_create` / `timerfd_settime` for mio timer integration

All `unsafe` blocks must be **minimal** (single FFI call) with error checking on return value.

---

## Event Loop Pattern

```rust
// ✅ mio::Poll with SourceFd wrapper around raw FDs
// ✅ MioFdSource struct implementing mio::event::Source (see client.rs, server.rs)
// ✅ Tokens: fixed constants for known FDs, DYNAMIC_BASE+ for server UDP FDs
// ✅ Timer via Linux timerfd_create → registered with mio as READABLE

// ❌ NEVER: tokio, async/await, std threads for I/O
```

---

## Checksum & Byte Order

```rust
// ✅ RFC 1071 checksum: csum() and csum_with_header() in common.rs
// ✅ Wire integers: to_be_bytes() / from_be_bytes()
// ✅ IV/padding in bare packets: to_ne_bytes() (matching C++ memcpy behavior)
// ✅ Sequence numbers: big-endian on wire, native in memory

// ❌ NEVER: assume endianness, use transmute for byte conversion
```

---

## Testing

```bash
cargo test                         # All tests — no root needed
cargo test --test wire_protocol    # Byte-layout verification
cargo test --test encrypt_cross    # All cipher×auth roundtrips
cargo test --test packet_headers   # Struct size/offset assertions
cargo test --test anti_replay      # Sliding window correctness
```

> Any change to `encrypt.rs`, `connection.rs`, or `network.rs` **must** pass all integration tests.

---

## Final Rule

```
Wire Compatibility > Correctness > Simplicity > Performance
```

> If it doesn't produce byte-identical packets to the C++ version = **broken**.

