//! Integration tests for conversation manager and connection state.
//!
//! Tests ConvManager CRUD operations, bidirectional mapping, LRU cleanup,
//! FdManager uniqueness guarantees, and ConnInfo state machine basics.

use std::net::SocketAddr;
use udp2raw::common::*;
use udp2raw::connection::{ConvManager, ConvManagerVariant, ConnInfo, Blob};

// ─── ConvManager<SocketAddr> (client-side) ──────────────────────────────────

#[test]
fn conv_manager_insert_and_lookup() {
    let mut cm = ConvManager::<SocketAddr>::new();

    let addr1: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:5001".parse().unwrap();

    let conv1 = cm.get_new_conv();
    let conv2 = cm.get_new_conv();
    assert_ne!(conv1, conv2);
    assert_ne!(conv1, 0); // get_new_conv returns non-zero
    assert_ne!(conv2, 0);

    cm.insert_conv(conv1, addr1);
    cm.insert_conv(conv2, addr2);

    assert_eq!(cm.get_size(), 2);
    assert!(cm.is_conv_used(conv1));
    assert!(cm.is_conv_used(conv2));
    assert!(cm.is_data_used(&addr1));
    assert!(cm.is_data_used(&addr2));
}

#[test]
fn conv_manager_bidirectional_mapping() {
    let mut cm = ConvManager::<SocketAddr>::new();
    let addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
    let conv = 0x12345678u32;

    cm.insert_conv(conv, addr);

    // conv → data
    assert_eq!(cm.find_data_by_conv(conv), Some(&addr));
    // data → conv
    assert_eq!(cm.find_conv_by_data(&addr), Some(conv));
}

#[test]
fn conv_manager_erase() {
    let mut cm = ConvManager::<SocketAddr>::new();
    let addr: SocketAddr = "192.168.1.1:9999".parse().unwrap();
    let conv = 0xAABBCCDDu32;

    cm.insert_conv(conv, addr);
    assert_eq!(cm.get_size(), 1);

    cm.erase_conv(conv);
    assert_eq!(cm.get_size(), 0);
    assert!(!cm.is_conv_used(conv));
    assert!(!cm.is_data_used(&addr));
    assert_eq!(cm.find_data_by_conv(conv), None);
    assert_eq!(cm.find_conv_by_data(&addr), None);
}

#[test]
fn conv_manager_clear_all() {
    let mut cm = ConvManager::<SocketAddr>::new();

    for i in 0..50 {
        let addr: SocketAddr = format!("10.0.0.{}:{}", i % 256, 5000 + i).parse().unwrap();
        let conv = cm.get_new_conv();
        cm.insert_conv(conv, addr);
    }
    assert_eq!(cm.get_size(), 50);

    cm.clear_all();
    assert_eq!(cm.get_size(), 0);
}

#[test]
fn conv_manager_erase_nonexistent() {
    let mut cm = ConvManager::<SocketAddr>::new();
    // Erasing a non-existent conv should not panic
    cm.erase_conv(0x99999999);
    assert_eq!(cm.get_size(), 0);
}

#[test]
fn conv_manager_update_active_time() {
    let mut cm = ConvManager::<SocketAddr>::new();
    let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let conv = 0x11111111u32;

    cm.insert_conv(conv, addr);
    // Should not panic
    cm.update_active_time(conv);
    assert_eq!(cm.get_size(), 1);
}

#[test]
fn conv_manager_with_clear_fn() {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let mut cm = ConvManager::<u32>::new();
    cm.clear_fn = Some(Box::new(move |_val| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
    }));

    cm.insert_conv(1, 100);
    cm.insert_conv(2, 200);
    cm.insert_conv(3, 300);

    cm.erase_conv(1);
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    cm.clear_all();
    assert_eq!(counter.load(Ordering::SeqCst), 3); // 2 more erased
}

// ─── ConvManager<Fd64> (server-side) ────────────────────────────────────────

#[test]
fn conv_manager_fd64_operations() {
    let mut cm = ConvManager::<Fd64>::new();

    let fd64_1: Fd64 = u32::MAX as Fd64 + 100;
    let fd64_2: Fd64 = u32::MAX as Fd64 + 101;

    let conv1 = 0xAAAAAAAAu32;
    let conv2 = 0xBBBBBBBBu32;

    cm.insert_conv(conv1, fd64_1);
    cm.insert_conv(conv2, fd64_2);

    assert_eq!(cm.get_size(), 2);
    assert_eq!(cm.find_data_by_conv(conv1), Some(&fd64_1));
    assert_eq!(cm.find_conv_by_data(&fd64_2), Some(conv2));

    cm.erase_conv(conv1);
    assert_eq!(cm.get_size(), 1);
    assert!(!cm.is_data_used(&fd64_1));
    assert!(cm.is_data_used(&fd64_2));
}

// ─── ConnInfo state machine ─────────────────────────────────────────────────

#[test]
fn conn_info_client_initial_state() {
    let conn = ConnInfo::new_client();
    assert_eq!(conn.state, ConnectionState::Client(ClientState::Idle));
    assert_eq!(conn.my_id, 0);
    assert_eq!(conn.opposite_id, 0);
    assert!(conn.blob.is_none());
}

#[test]
fn conn_info_server_initial_state() {
    let conn = ConnInfo::new_server();
    assert_eq!(conn.state, ConnectionState::Server(ServerState::Idle));
    assert_eq!(conn.my_id, 0);
    assert!(conn.blob.is_none());
}

#[test]
fn conn_info_prepare_client() {
    let mut conn = ConnInfo::new_client();
    conn.prepare_client();
    assert!(conn.blob.is_some());

    let blob = conn.blob.as_ref().unwrap();
    match &blob.conv_manager {
        ConvManagerVariant::Client(cm) => {
            assert_eq!(cm.get_size(), 0);
        }
        ConvManagerVariant::Server(_) => panic!("expected Client variant"),
    }
}

#[test]
fn conn_info_re_init_client() {
    let mut conn = ConnInfo::new_client();
    conn.state = ConnectionState::Client(ClientState::Ready);
    conn.my_roller = 42;
    conn.opposite_roller = 13;

    conn.re_init_client();

    assert_eq!(conn.state, ConnectionState::Client(ClientState::Idle));
    assert_eq!(conn.my_roller, 0);
    assert_eq!(conn.opposite_roller, 0);
}

#[test]
fn conn_info_recover() {
    let mut conn1 = ConnInfo::new_client();
    conn1.my_id = 0x11111111;
    conn1.opposite_id = 0x22222222;
    conn1.last_hb_recv_time = 12345;
    conn1.last_hb_sent_time = 12340;

    let mut conn2 = ConnInfo::new_client();
    conn2.prepare_client();
    conn2.recover(&conn1);

    assert_eq!(conn2.my_id, conn1.my_id);
    assert_eq!(conn2.opposite_id, conn1.opposite_id);
    assert_eq!(conn2.last_hb_recv_time, conn1.last_hb_recv_time);
    assert_eq!(conn2.raw_info.rst_received, 0);
    assert!(!conn2.raw_info.disabled);
}

// ─── Blob variant ───────────────────────────────────────────────────────────

#[test]
fn blob_client_variant() {
    let blob = Blob::new_client();
    match &blob.conv_manager {
        ConvManagerVariant::Client(_) => {}
        ConvManagerVariant::Server(_) => panic!("expected Client variant"),
    }
}

#[test]
fn blob_server_variant() {
    let blob = Blob::new_server(Box::new(|_fd64| {}));
    match &blob.conv_manager {
        ConvManagerVariant::Server(_) => {}
        ConvManagerVariant::Client(_) => panic!("expected Server variant"),
    }
}

// ─── FdManager ──────────────────────────────────────────────────────────────

use udp2raw::fd_manager::FdManager;

#[test]
fn fd_manager_create_and_lookup() {
    let mut fm = FdManager::new();

    // Use fake fd values (not real OS fds — just for testing the mapping)
    let fd64_a = fm.create(100);
    let fd64_b = fm.create(200);

    assert_ne!(fd64_a, fd64_b);
    assert!(fm.exist(fd64_a));
    assert!(fm.exist(fd64_b));
    assert!(fm.fd_exist(100));
    assert!(fm.fd_exist(200));
    assert_eq!(fm.to_fd(fd64_a), 100);
    assert_eq!(fm.to_fd(fd64_b), 200);
}

#[test]
fn fd_manager_uniqueness() {
    let mut fm = FdManager::new();

    // Each call to create() returns a unique fd64
    let ids: Vec<Fd64> = (0..100).map(|i| fm.create(1000 + i)).collect();
    let unique: std::collections::HashSet<Fd64> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len(), "all fd64 IDs should be unique");
}

#[test]
fn fd_manager_info() {
    let mut fm = FdManager::new();
    let fd64 = fm.create(42);

    let addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
    fm.set_info(
        fd64,
        udp2raw::fd_manager::FdInfo {
            conn_info_key: Some(addr),
        },
    );

    let info = fm.get_info(fd64).unwrap();
    assert_eq!(info.conn_info_key, Some(addr));
}

// ─── LruCollector ───────────────────────────────────────────────────────────

#[test]
fn lru_collector_ordering() {
    let mut lru = LruCollector::<String>::new();

    lru.new_key("first".to_string());
    lru.new_key("second".to_string());
    lru.new_key("third".to_string());

    assert_eq!(lru.size(), 3);

    // Oldest should be "first"
    let (key, _ts) = lru.peek_back().unwrap();
    assert_eq!(key, "first");
}

#[test]
fn lru_collector_update_moves_to_front() {
    let mut lru = LruCollector::<u32>::new();

    lru.new_key(1);
    // Small delay to ensure different timestamps
    std::thread::sleep(std::time::Duration::from_millis(2));
    lru.new_key(2);
    std::thread::sleep(std::time::Duration::from_millis(2));
    lru.new_key(3);

    // Update key 1 — should move it to front
    std::thread::sleep(std::time::Duration::from_millis(2));
    lru.update(&1);

    // Now oldest should be 2 (since 1 was updated)
    let (key, _) = lru.peek_back().unwrap();
    assert_eq!(key, 2);
}

#[test]
fn lru_collector_erase() {
    let mut lru = LruCollector::<u32>::new();

    lru.new_key(10);
    lru.new_key(20);
    lru.new_key(30);

    lru.erase(&10);
    assert_eq!(lru.size(), 2);

    // peek_back should skip erased entry and return next oldest
    let (key, _) = lru.peek_back().unwrap();
    assert_eq!(key, 20);
}

#[test]
fn lru_collector_clear() {
    let mut lru = LruCollector::<u32>::new();
    lru.new_key(1);
    lru.new_key(2);
    lru.clear();
    assert_eq!(lru.size(), 0);
    assert!(lru.is_empty());
    assert!(lru.peek_back().is_none());
}

