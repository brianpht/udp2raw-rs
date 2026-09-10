use std::process::Command;

#[test]
fn worker_count_is_bounded() {
    for value in ["0", "17"] {
        let status = Command::new(env!("CARGO_BIN_EXE_udp2raw"))
            .args(["-c", "-l", "127.0.0.1:0", "-r", "127.0.0.1:9", "--workers", value])
            .output().unwrap().status;
        assert_eq!(status.code(), Some(2));
    }
}

#[test]
fn unsupported_parallel_carriers_are_rejected_before_socket_setup() {
    for extra in [vec!["--raw-mode", "udp"], vec!["--raw-mode", "icmp", "--fix-gro"]] {
        let result = Command::new(env!("CARGO_BIN_EXE_udp2raw"))
            .args(["-c", "-l", "127.0.0.1:0", "-r", "127.0.0.1:9", "--workers", "2"])
            .args(extra).output().unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&result.stderr).contains("requires IPv4 ICMP"));
    }
}
