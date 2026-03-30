//! Integration tests for the anti-replay window.
//!
//! Verifies sliding window behavior: accepts new packets, rejects duplicates,
//! handles out-of-order delivery, and correctly slides the window forward.

use udp2raw::connection::AntiReplay;

#[test]
fn sequential_packets_accepted() {
    let mut ar = AntiReplay::new();
    let base = ar.get_new_seq_for_send();

    // Sequential packets should all be accepted
    for i in 0..100 {
        assert!(
            ar.is_valid(base + i, false),
            "sequential packet {} should be valid",
            i
        );
    }
}

#[test]
fn duplicate_packets_rejected() {
    let mut ar = AntiReplay::new();
    let seq = 1000;

    assert!(ar.is_valid(seq, false), "first packet should be valid");
    assert!(
        !ar.is_valid(seq, false),
        "duplicate packet should be rejected"
    );
}

#[test]
fn out_of_order_within_window() {
    let mut ar = AntiReplay::new();

    // Receive packets 1..100 in order
    for i in 1..=100 {
        assert!(ar.is_valid(i, false));
    }

    // Now receive packet 50 again — should be rejected (already seen)
    assert!(!ar.is_valid(50, false));
}

#[test]
fn out_of_order_delivery() {
    let mut ar = AntiReplay::new();

    // Receive packet 100 first
    assert!(ar.is_valid(100, false));

    // Then receive earlier packets within window
    assert!(ar.is_valid(99, false));
    assert!(ar.is_valid(50, false));
    assert!(ar.is_valid(1, false));

    // Duplicates still rejected
    assert!(!ar.is_valid(100, false));
    assert!(!ar.is_valid(50, false));
}

#[test]
fn window_slides_forward() {
    let mut ar = AntiReplay::new();

    // Send packet way ahead of current window
    assert!(ar.is_valid(10000, false));

    // Packets far behind (outside 4000-window) should be rejected
    assert!(
        !ar.is_valid(1, false),
        "packet far behind window should be rejected"
    );
    assert!(
        !ar.is_valid(5999, false),
        "packet just outside window should be rejected"
    );

    // Packets within window should be accepted
    assert!(ar.is_valid(6001, false));
    assert!(ar.is_valid(9999, false));
}

#[test]
fn max_packet_at_window_boundary() {
    let mut ar = AntiReplay::new();

    // Set max to exactly WINDOW_SIZE
    assert!(ar.is_valid(4000, false));

    // Packet at seq=0 is outside the window (4000 - 0 = 4000 >= WINDOW_SIZE)
    assert!(!ar.is_valid(0, false));

    // Packet at seq=1 is at the edge (4000 - 1 = 3999 < WINDOW_SIZE)
    assert!(ar.is_valid(1, false));
}

#[test]
fn large_gap_clears_window() {
    let mut ar = AntiReplay::new();

    // Accept some sequential packets
    for i in 1..=100 {
        ar.is_valid(i, false);
    }

    // Jump far ahead (> WINDOW_SIZE gap)
    assert!(ar.is_valid(100_000, false));

    // Old packets should be rejected
    assert!(!ar.is_valid(100, false));
    assert!(!ar.is_valid(1, false));

    // New sequential packets after the jump should work
    assert!(ar.is_valid(100_001, false));
    assert!(ar.is_valid(100_002, false));
}

#[test]
fn send_sequence_monotonic() {
    let mut ar = AntiReplay::new();

    let seq1 = ar.get_new_seq_for_send();
    let seq2 = ar.get_new_seq_for_send();
    let seq3 = ar.get_new_seq_for_send();

    assert!(seq2 > seq1);
    assert!(seq3 > seq2);
    assert_eq!(seq2, seq1 + 1);
    assert_eq!(seq3, seq2 + 1);
}

#[test]
fn re_init_resets_window() {
    let mut ar = AntiReplay::new();

    // Accept some packets
    for i in 1..=100 {
        ar.is_valid(i, false);
    }
    assert!(!ar.is_valid(50, false)); // duplicate rejected

    // Re-init
    ar.re_init();

    // After re-init, max_packet_received is 0, old seqs can be accepted again
    assert!(ar.is_valid(50, false));
}

#[test]
fn disabled_anti_replay_accepts_all() {
    let mut ar = AntiReplay::new();

    // With anti-replay disabled, everything should pass
    assert!(ar.is_valid(100, true));
    assert!(ar.is_valid(100, true)); // duplicate accepted
    assert!(ar.is_valid(1, true));   // old packet accepted
    assert!(ar.is_valid(0, true));   // zero accepted
}

#[test]
fn stress_sequential() {
    let mut ar = AntiReplay::new();

    // Accept 10000 sequential packets
    for i in 1..=10_000u64 {
        assert!(ar.is_valid(i, false), "packet {} should be valid", i);
    }

    // Re-check last 100 — all should be rejected as duplicates
    for i in 9_901..=10_000u64 {
        assert!(
            !ar.is_valid(i, false),
            "duplicate packet {} should be rejected",
            i
        );
    }

    // Packets within window but not yet seen (there are none since we sent all 1..10000)
    // But next packet should work
    assert!(ar.is_valid(10_001, false));
}

#[test]
fn interleaved_packets() {
    let mut ar = AntiReplay::new();

    // Receive even packets first
    for i in (2..=200).step_by(2) {
        assert!(ar.is_valid(i, false), "even packet {} should be valid", i);
    }

    // Then receive odd packets (within window, not yet seen)
    for i in (1..=199).step_by(2) {
        assert!(ar.is_valid(i, false), "odd packet {} should be valid", i);
    }

    // All should be rejected now as duplicates
    for i in 1..=200 {
        assert!(
            !ar.is_valid(i, false),
            "all packets 1..200 should be rejected as duplicates"
        );
    }
}

