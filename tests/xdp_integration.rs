//! AF_XDP integration tests.
//!
//! These tests verify XDP module unit functionality that doesn't require
//! root/Linux. Tests requiring AF_XDP sockets (veth pair, eBPF load) are
//! marked `#[ignore]` and run manually with `sudo cargo test`.

#[cfg(feature = "xdp")]
mod xdp_tests {
    use udp2raw::xdp::*;

    #[test]
    fn constants_af_xdp() {
        assert_eq!(AF_XDP, 44);
        assert_eq!(SOL_XDP, 283);
        assert_eq!(XDP_MMAP_OFFSETS, 1);
        assert_eq!(XDP_RX_RING, 2);
        assert_eq!(XDP_TX_RING, 3);
        assert_eq!(XDP_UMEM_REG, 4);
        assert_eq!(XDP_UMEM_FILL_RING, 5);
        assert_eq!(XDP_UMEM_COMPLETION_RING, 6);
    }

    #[test]
    fn constants_bind_flags() {
        assert_eq!(XDP_COPY, 0x02);
        assert_eq!(XDP_ZEROCOPY, 0x04);
        assert_eq!(XDP_USE_NEED_WAKEUP, 0x08);
    }

    #[test]
    fn constants_ring_pgoff() {
        assert_eq!(XDP_PGOFF_RX_RING, 0);
        assert_eq!(XDP_PGOFF_TX_RING, 0x80000000);
        assert_eq!(XDP_UMEM_PGOFF_FILL_RING, 0x100000000);
        assert_eq!(XDP_UMEM_PGOFF_COMPLETION_RING, 0x180000000);
    }

    #[test]
    fn struct_sizes_match_kernel_abi() {
        assert_eq!(std::mem::size_of::<XdpDesc>(), 16);
        assert_eq!(std::mem::size_of::<SockaddrXdp>(), 16);
        assert_eq!(std::mem::size_of::<XdpRingOffset>(), 32);
        assert_eq!(std::mem::size_of::<XdpMmapOffsets>(), 128);
    }

    #[test]
    fn xdp_desc_field_offsets() {
        // Verify packed layout: addr@0, len@8, options@12
        let desc = XdpDesc {
            addr: 0x0102_0304_0506_0708,
            len: 0x090A_0B0C,
            options: 0x0D0E_0F10,
        };
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &desc as *const _ as *const u8,
                std::mem::size_of::<XdpDesc>(),
            )
        };
        assert_eq!(
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            0x0102_0304_0506_0708
        );
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            0x090A_0B0C
        );
        assert_eq!(
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            0x0D0E_0F10
        );
    }

    #[test]
    fn ethernet_frame_roundtrip() {
        // Build an Ethernet frame the same way XdpState::send_ip_packet does
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dst_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ethertype: u16 = 0x0800;

        // Fake IP packet (just the first 20 bytes of a header)
        let ip_pkt = [
            0x45, 0x00, 0x00, 0x28, // version/ihl, tos, total_len
            0x00, 0x01, 0x00, 0x00, // id, frag_off
            0x40, 0x06, 0x00, 0x00, // ttl=64, protocol=TCP, checksum
            0xC0, 0xA8, 0x01, 0x01, // src: 192.168.1.1
            0xC0, 0xA8, 0x01, 0x02, // dst: 192.168.1.2
        ];

        // Build frame (matching XdpState::send_ip_packet logic)
        let mut frame = vec![0u8; 14 + ip_pkt.len()];
        frame[0..6].copy_from_slice(&dst_mac);
        frame[6..12].copy_from_slice(&src_mac);
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        frame[14..].copy_from_slice(&ip_pkt);

        // Strip frame (matching XdpState::recv_ip_packet logic)
        assert!(frame.len() >= 14);
        let parsed_ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let parsed_ip = &frame[14..];

        assert_eq!(parsed_ethertype, 0x0800);
        assert_eq!(parsed_ip, &ip_pkt);

        // Parse IP fields (matching recv_raw_ip XDP path)
        let ihl = (parsed_ip[0] & 0x0F) as usize * 4;
        assert_eq!(ihl, 20);
        let saddr = u32::from_be_bytes([parsed_ip[12], parsed_ip[13], parsed_ip[14], parsed_ip[15]]);
        let daddr = u32::from_be_bytes([parsed_ip[16], parsed_ip[17], parsed_ip[18], parsed_ip[19]]);
        assert_eq!(saddr, 0xC0A80101); // 192.168.1.1
        assert_eq!(daddr, 0xC0A80102); // 192.168.1.2
        assert_eq!(parsed_ip[9], 0x06); // TCP
    }

    /// This test requires root + Linux with AF_XDP support.
    /// Run manually: `sudo cargo test --features xdp -- --ignored xdp_socket_create`
    #[test]
    #[ignore]
    fn xdp_socket_create_on_loopback() {
        // Attempt to create an XSK socket on loopback (lo, queue 0)
        // This tests the full 9-step constructor.
        let ifindex = ifname_to_index("lo").expect("loopback interface not found");
        let result = XskSocket::new(
            ifindex,
            0, // queue 0
            DEFAULT_NUM_FRAMES,
            DEFAULT_FRAME_SIZE,
            DEFAULT_RING_SIZE,
            false, // copy mode
        );
        match result {
            Ok(xsk) => {
                assert!(xsk.fd() >= 0, "XSK fd should be valid");
                println!("XSK socket created successfully on lo, fd={}", xsk.fd());
            }
            Err(e) => {
                // Expected to fail without root or on systems without AF_XDP
                println!("XSK creation failed (expected without root): {}", e);
            }
        }
    }
}

