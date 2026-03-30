//! Example: Build and inspect raw packet headers.
//!
//! Demonstrates how IP, TCP, UDP, and ICMP headers are constructed,
//! showing their binary layout and field values.
//!
//! Run: cargo run --example packet_builder

use udp2raw::common::csum;
use udp2raw::network::*;

fn hex_dump(data: &[u8], label: &str) {
    println!("  {} ({} bytes):", label, data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: String = chunk.iter().map(|b| format!("{:02x} ", b)).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
            .collect();
        println!("    {:04x}  {:<48} {}", i * 16, hex, ascii);
    }
}

fn main() {
    println!("═══════════════════════════════════════════════════════════════════");
    println!("  udp2raw Packet Header Builder Example");
    println!("═══════════════════════════════════════════════════════════════════");

    // ── IPv4 Header ─────────────────────────────────────────────────────
    println!();
    println!("── IPv4 Header ──────────────────────────────────────────────────");
    let mut iph = IpHeader::default();
    iph.set_version_ihl(4, 5);
    iph.tos = 0;
    iph.tot_len = 60u16.to_be();
    iph.id = 0x1234u16.to_be();
    iph.frag_off = 0x4000u16.to_be(); // Don't Fragment
    iph.ttl = 64;
    iph.protocol = 6; // TCP
    iph.saddr = u32::from(std::net::Ipv4Addr::new(192, 168, 1, 100)).to_be();
    iph.daddr = u32::from(std::net::Ipv4Addr::new(93, 184, 216, 34)).to_be();
    iph.check = 0;
    let cs = csum(iph.as_bytes());
    iph.check = cs;

    println!("  Version:  {}", iph.version());
    println!("  IHL:      {} ({} bytes)", iph.ihl(), iph.ihl() as usize * 4);
    println!("  TTL:      {}", iph.ttl);
    println!("  Protocol: {} (TCP)", iph.protocol);
    println!(
        "  Src IP:   {}",
        std::net::Ipv4Addr::from(u32::from_be(iph.saddr))
    );
    println!(
        "  Dst IP:   {}",
        std::net::Ipv4Addr::from(u32::from_be(iph.daddr))
    );
    let check_val = { iph.check };
    println!("  Checksum: 0x{:04x}", check_val);

    hex_dump(iph.as_bytes(), "IP Header bytes");

    // Verify checksum
    let verify = csum(iph.as_bytes());
    println!(
        "  Checksum verify: 0x{:04x} (should be 0x0000)",
        verify
    );

    // ── TCP Header ──────────────────────────────────────────────────────
    println!();
    println!("── TCP Header (SYN) ─────────────────────────────────────────────");
    let mut tcph = TcpHeader::default();
    tcph.source = 54321u16.to_be();
    tcph.dest = 80u16.to_be();
    tcph.seq = 0x12345678u32.to_be();
    tcph.ack_seq = 0u32.to_be();
    tcph.set_doff(5);
    tcph.set_flags(false, true, false, false, false); // SYN
    tcph.window = 65535u16.to_be();

    println!("  Src Port: {}", u16::from_be(tcph.source));
    println!("  Dst Port: {}", u16::from_be(tcph.dest));
    println!("  Seq:      0x{:08x}", u32::from_be(tcph.seq));
    println!("  Ack:      0x{:08x}", u32::from_be(tcph.ack_seq));
    println!("  Doff:     {} ({} bytes)", tcph.doff(), tcph.doff() as usize * 4);
    println!(
        "  Flags:    SYN={} ACK={} FIN={} RST={} PSH={}",
        tcph.syn(),
        tcph.ack(),
        tcph.fin(),
        tcph.rst(),
        tcph.psh()
    );
    println!("  Window:   {}", u16::from_be(tcph.window));

    hex_dump(tcph.as_bytes(), "TCP Header bytes");

    // ── TCP Header (SYN+ACK) ───────────────────────────────────────────
    println!();
    println!("── TCP Header (SYN+ACK) ─────────────────────────────────────────");
    let mut tcph2 = TcpHeader::default();
    tcph2.source = 80u16.to_be();
    tcph2.dest = 54321u16.to_be();
    tcph2.seq = 0xAABBCCDDu32.to_be();
    tcph2.ack_seq = 0x12345679u32.to_be();
    tcph2.set_doff(5);
    tcph2.set_flags(false, true, false, false, true); // SYN+ACK

    println!(
        "  Flags:    SYN={} ACK={} (SYN+ACK handshake reply)",
        tcph2.syn(),
        tcph2.ack()
    );

    hex_dump(tcph2.as_bytes(), "TCP SYN+ACK bytes");

    // ── UDP Header ──────────────────────────────────────────────────────
    println!();
    println!("── UDP Header ───────────────────────────────────────────────────");
    let udph = UdpHeader {
        source: 12345u16.to_be(),
        dest: 53u16.to_be(),
        len: 20u16.to_be(), // 8 header + 12 data
        check: 0,
    };

    let udp_bytes = unsafe {
        std::slice::from_raw_parts(
            &udph as *const _ as *const u8,
            std::mem::size_of::<UdpHeader>(),
        )
    };

    println!("  Src Port:  {}", u16::from_be(udph.source));
    println!("  Dst Port:  {} (DNS)", u16::from_be(udph.dest));
    println!("  Length:    {}", u16::from_be(udph.len));

    hex_dump(udp_bytes, "UDP Header bytes");

    // ── ICMP Header ─────────────────────────────────────────────────────
    println!();
    println!("── ICMP Header (Echo Request) ─────────────────────────────────");
    let icmph = IcmpHeader {
        type_: 8, // Echo Request
        code: 0,
        check_sum: 0,
        id: 0x1234u16.to_be(),
        seq: 1u16.to_be(),
    };

    let icmp_bytes = unsafe {
        std::slice::from_raw_parts(
            &icmph as *const _ as *const u8,
            std::mem::size_of::<IcmpHeader>(),
        )
    };

    println!("  Type:      {} (Echo Request)", icmph.type_);
    println!("  Code:      {}", icmph.code);
    println!("  ID:        0x{:04x}", u16::from_be(icmph.id));
    println!("  Seq:       {}", u16::from_be(icmph.seq));

    hex_dump(icmp_bytes, "ICMP Header bytes");

    // ── Struct sizes summary ────────────────────────────────────────────
    println!();
    println!("── Struct Sizes Summary ──────────────────────────────────────────");
    println!("  IpHeader:      {} bytes", std::mem::size_of::<IpHeader>());
    println!("  TcpHeader:     {} bytes", std::mem::size_of::<TcpHeader>());
    println!("  UdpHeader:     {} bytes", std::mem::size_of::<UdpHeader>());
    println!("  IcmpHeader:    {} bytes", std::mem::size_of::<IcmpHeader>());
    println!("  PseudoHeader:  {} bytes", std::mem::size_of::<PseudoHeader>());
    println!("  Ip6Header:     {} bytes", std::mem::size_of::<Ip6Header>());
    println!("  PseudoHeader6: {} bytes", std::mem::size_of::<PseudoHeader6>());

    println!();
    println!("═══════════════════════════════════════════════════════════════════");
}

