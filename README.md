# UDP2RAW-RS

A wire-compatible Rust rewrite of [udp2raw](https://github.com/wangyu-/udp2raw). A UDP tunnel that encapsulates UDP traffic into encrypted FakeTCP/UDP/ICMP packets using raw sockets.

## Overview

`udp2raw-rs` disguises UDP packets as TCP, UDP, or ICMP traffic to bypass firewalls and QoS rules that block or throttle plain UDP. It uses raw sockets to craft packets at the IP layer, with encryption and authentication to protect tunnel traffic.

This is a byte-for-byte compatible reimplementation of the original C++ [udp2raw-tunnel](https://github.com/wangyu-/udp2raw). A Rust client can talk to a C++ server, and vice versa. Every byte on the wire is identical.

## Features

- **FakeTCP/UDP/ICMP Encapsulation**: Tunnel UDP through protocol headers that firewalls typically allow
- **Wire-Compatible**: Byte-identical packets with the C++ version, full interop guaranteed
- **Encryption**: AES-128-CBC, AES-128-CFB, XOR, or no cipher
- **Authentication**: HMAC-SHA1 (Encrypt-then-MAC), MD5, CRC32, simple hash, or none
- **Anti-Replay**: Sliding window (4000 packets) to reject duplicate/replayed packets
- **Auto iptables**: Automatically manages firewall rules to prevent kernel RST interference
- **Lower-Level Mode**: Send at OSI Layer 2 via `AF_PACKET` for environments without raw socket IP access
- **AF_XDP Transport**: Optional high-performance kernel-bypass I/O via AF_XDP (compile with `--features xdp`)
- **GRO Fix**: Handle NIC Generic Receive Offload that coalesces packets
- **No async runtime**: Synchronous `mio` event loop with `libc` FFI. No tokio, no threads for I/O

## How It Works

```mermaid
flowchart LR
    A["Local App"] -->|UDP| B["udp2raw Client"]
    B -->|"Encrypted FakeTCP/UDP/ICMP"| C["udp2raw Server"]
    C -->|UDP| D["Remote App"]
    D -->|UDP| C
    C -->|"Encrypted FakeTCP/UDP/ICMP"| B
    B -->|UDP| A
```

1. Local application sends UDP to the tunnel client
2. Client encrypts the payload, wraps it in a FakeTCP/UDP/ICMP packet, sends over raw socket
3. Server receives the raw packet, decrypts it, forwards plain UDP to the target application
4. Return traffic follows the reverse path

## Installation

### From source

```bash
git clone https://github.com/brianpht/udp2raw-rs.git
cd udp2raw-rs
cargo build --release
# Binary at target/release/udp2raw

# With AF_XDP support (Linux >= 5.7):
cargo build --release --features xdp
```

### Requirements

- Linux (raw sockets via `libc` FFI)
- Root or `CAP_NET_RAW` capability
- Rust 1.70+

## Quick Start

**Server** (on the remote machine):

```bash
sudo ./udp2raw -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 -k "my_password" --raw-mode faketcp -a
```

**Client** (on the local machine):

```bash
sudo ./udp2raw -c -l 127.0.0.1:3333 -r SERVER_IP:4096 -k "my_password" --raw-mode faketcp -a
```

Now point your application at `127.0.0.1:3333`. UDP traffic is tunneled through the encrypted FakeTCP connection to `127.0.0.1:7777` on the server.

## Usage

```
udp2raw: UDP tunnel over encrypted raw sockets (FakeTCP/UDP/ICMP)

Options:
  -c, --client              Run as client
  -s, --server              Run as server
  -l <ip:port>              Local listen address
  -r <ip:port>              Remote address
  -k, --key <password>      Encryption password [default: "secret key"]
      --raw-mode <mode>     faketcp | udp | icmp [default: faketcp]
      --cipher-mode <mode>  aes128cbc | aes128cfb | xor | none [default: aes128cbc]
      --auth-mode <mode>    hmac_sha1 | md5 | crc32 | simple | none [default: md5]
  -a, --auto-rule           Auto add/delete iptables rules
  -g, --gen-rule            Print iptables rule and exit
      --log-level <0-6>     0=off, 4=info, 6=trace [default: 4]
      --seq-mode <0-4>      TCP sequence number mode [default: 3]
      --lower-level <spec>  Layer 2 mode: "if_name#dest_mac"
      --fix-gro             Fix GRO coalesced packets
      --disable-anti-replay Disable anti-replay protection
      --sock-buf <KB>       Socket buffer size [default: 1024]
      --conf-file <path>    Load options from config file
      --fifo <path>         FIFO for runtime commands (e.g. "reconnect")
      --xdp                 Use AF_XDP transport (requires --features xdp)
      --xdp-queue <N>       AF_XDP NIC queue ID [default: 0]
      --xdp-dst-mac <mac>   AF_XDP destination MAC (aa:bb:cc:dd:ee:ff)
      --xdp-if <name>       AF_XDP interface name (defaults to --dev)
```

## Wire Protocol

Every packet on the wire is byte-identical to the C++ implementation. The protocol uses two packet formats:

**Bare packet** (handshake phase):

```
[iv:8B][padding:8B][marker='b':1B][data:NB] → encrypt
```

**Safer packet** (data/heartbeat phase):

```
[my_id:4B][opp_id:4B][seq:8B][type:1B][roller:1B][data:NB] → encrypt
```

Packet types: `b'h'` = heartbeat, `b'd'` = data, `b'b'` = bare.

### Encryption Pipeline

```
HMAC mode (Encrypt-then-MAC):
  encrypt: data → cipher_encrypt() → auth_cal() → output
  decrypt: data → auth_verify() → cipher_decrypt() → output

Legacy mode (MAC-then-Encrypt):
  encrypt: data → auth_cal() → cipher_encrypt() → output
  decrypt: data → cipher_decrypt() → auth_verify() → output
```

### Key Derivation

```
password → MD5 → normal_key
password → PBKDF2-SHA256 (10000 rounds) → HKDF-SHA256 → {
    "cipher_key client-->server"
    "cipher_key server-->client"
    "hmac_key client-->server"
    "hmac_key server-->client"
}
```

Client encrypts with `client→server` key, decrypts with `server→client` key.
Server does the reverse. The HKDF info strings are wire-critical.

## Architecture

```
src/
├── main.rs        Entry point, CLI dispatch, signal handlers
├── lib.rs         Module re-exports for tests and examples
├── misc.rs        CLI parsing (clap), Config struct, iptables management
├── common.rs      Type aliases, constants, checksum, byte-order helpers
├── encrypt.rs     AES-CBC/CFB, XOR, HMAC-SHA1, MD5, CRC32, PBKDF2, HKDF
├── connection.rs  Wire protocol (send_bare, send_safer), anti-replay, conv manager
├── network.rs     Raw socket I/O, #[repr(C,packed)] IP/TCP/UDP/ICMP headers, BPF
├── transport.rs   RawTransport enum — dispatches to raw socket or AF_XDP backend
├── xdp.rs         AF_XDP (kernel-bypass) transport (feature-gated: --features xdp)
├── client.rs      Client event loop (mio::Poll + raw fd + UDP fd + timerfd)
├── server.rs      Server event loop (mio::Poll + raw fd + per-conn UDP fds)
├── fd_manager.rs  Fd64 abstraction to avoid OS fd-reuse collisions
├── mio_fd.rs      Shared MioFdSource wrapper for mio::Poll registration
└── logging.rs     Custom logger with timestamps and color
```

### Design Principles

- **Wire Compatibility > Correctness > Simplicity > Performance**: if it doesn't produce byte-identical packets to the C++ version, it's broken
- **No global mutable state**: `Config` is `&Config` everywhere, mutable state owned by the event loop
- **No async runtime**: synchronous `mio::Poll` event loop with `SourceFd` wrappers around raw fds
- **Minimal unsafe**: only for `libc::` FFI calls, `#[repr(C, packed)]` struct casting, and `timerfd` integration
- **No wrapper crates for raw socket I/O**: direct `libc::socket`, `libc::sendto`, `libc::recvfrom`

## Configuration

### Raw Modes

| Mode | Description | iptables rule |
|---|---|---|
| `faketcp` | Fake TCP with SYN/ACK handshake (default, best firewall compat) | blocks kernel RST |
| `udp` | Raw UDP encapsulation | blocks kernel ICMP port-unreachable |
| `icmp` | ICMP Echo request/reply encapsulation | blocks kernel ICMP reply |

### Cipher Modes

| Mode | Description |
|---|---|
| `aes128cbc` | AES-128-CBC with custom padding (default) |
| `aes128cfb` | AES-128-CFB streaming cipher |
| `xor` | XOR with derived key (fast, weak) |
| `none` | No encryption |

### Auth Modes

| Mode | Description |
|---|---|
| `hmac_sha1` | HMAC-SHA1 Encrypt-then-MAC (strongest) |
| `md5` | MD5 hash (default) |
| `crc32` | CRC32 checksum |
| `simple` | Simple hash |
| `none` | No authentication (disables anti-replay) |

### Config File

```bash
# /etc/udp2raw.conf
-c
-l 127.0.0.1:3333
-r server:4096
-k my_password
--raw-mode faketcp
-a
```

```bash
sudo ./udp2raw --conf-file /etc/udp2raw.conf
```

## Examples

```bash
# Run the examples
cargo run --example encrypt_decrypt    # All cipher×auth encryption roundtrips
cargo run --example key_derivation     # Inspect derived key material
cargo run --example packet_builder     # Build and hex-dump raw packet headers
```

## Testing

```bash
cargo test                         # All tests (no root needed)
cargo test --test wire_protocol    # Byte-layout verification
cargo test --test encrypt_cross    # All cipher×auth roundtrips (client↔server)
cargo test --test packet_headers   # Struct size/offset assertions
cargo test --test anti_replay      # Sliding window correctness
```

All tests verify wire compatibility with the C++ implementation.

## Comparison with C++ Version

| | C++ udp2raw | udp2raw-rs |
|---|---|---|
| Wire format | ✅ reference | ✅ byte-identical |
| Handshake | ✅ | ✅ compatible |
| Encryption | OpenSSL | RustCrypto (aes, cbc, hmac, sha2) |
| Event loop | libev | mio |
| Raw sockets | direct | libc FFI (direct) |
| Memory safety | manual | Rust ownership |
| Packet headers | C bitfields | `#[repr(C, packed)]` + bitwise ops |
| Binary size | ~300 KB | ~500 KB (static, stripped) |

## Credits

This is a Rust reimplementation of [udp2raw-tunnel](https://github.com/wangyu-/udp2raw) by wangyu.

