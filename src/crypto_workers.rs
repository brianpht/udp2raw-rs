//! Bounded ordered packet crypto. Connection state and sockets remain on the I/O thread.
//! No worker can mutate IDs, anti-replay windows, rollers or socket sequence state.
use crate::common::{RawMode, BUF_LEN, HUGE_BUF_LEN, MAX_DATA_LEN};
use crate::encrypt::Encryptor;
use crate::network::{RawInfo, RawSocketState};
use mio::{Token, Waker};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::{mpsc, Arc, OnceLock};
use std::thread::{self, JoinHandle};

pub const CRYPTO_TOKEN: Token = Token(usize::MAX - 1);
const CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction { Encrypt, Decrypt }

struct Job {
    direction: Direction,
    id: u64,
    info: RawInfo,
    input: Vec<u8>,
}

struct Completion {
    job: Job,
    output: Option<Vec<u8>>,
}

struct Ordered<T> {
    next: u64,
    pending: BTreeMap<u64, T>,
}

impl<T> Ordered<T> {
    fn new() -> Self { Self { next: 0, pending: BTreeMap::new() } }
    fn insert(&mut self, id: u64, item: T) {
        assert!(id >= self.next && !self.pending.contains_key(&id));
        self.pending.insert(id, item);
    }
    fn pop(&mut self) -> Option<T> {
        let item = self.pending.remove(&self.next)?;
        self.next = self.next.checked_add(1).expect("completion sequence exhausted");
        Some(item)
    }
}

struct Pool {
    queues: Vec<mpsc::SyncSender<Job>>,
    results: mpsc::Receiver<Completion>,
    handles: Vec<JoinHandle<()>>,
    waker: Arc<OnceLock<Arc<Waker>>>,
    next_worker: usize,
}

impl Pool {
    fn new(encryptor: Encryptor, workers: usize) -> io::Result<Self> {
        if !(2..=16).contains(&workers) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "workers must be 2..16"));
        }
        let (result_tx, results) = mpsc::channel();
        let waker = Arc::new(OnceLock::<Arc<Waker>>::new());
        let encryptor = Arc::new(encryptor);
        let mut pool = Self { queues: Vec::new(), results, handles: Vec::new(), waker, next_worker: 0 };
        for number in 0..workers {
            let (tx, rx) = mpsc::sync_channel::<Job>(CAPACITY);
            let output = result_tx.clone();
            let wake = pool.waker.clone();
            let crypto = encryptor.clone();
            let handle = thread::Builder::new().name(format!("crypto-{number}")).spawn(move || {
                while let Ok(job) = rx.recv() {
                    // Malformed input must never kill a worker and leave an ordering hole.
                    let transformed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let mut buffer = [0u8; BUF_LEN];
                        let result = match job.direction {
                            Direction::Encrypt => crypto.my_encrypt(&job.input, &mut buffer),
                            Direction::Decrypt => crypto.my_decrypt(&job.input, &mut buffer),
                        };
                        result.ok().map(|len| buffer[..len].to_vec())
                    })).ok().flatten();
                    if output.send(Completion { job, output: transformed }).is_err() { break; }
                    if let Some(waker) = wake.get() { let _ = waker.wake(); }
                }
            })?;
            pool.queues.push(tx);
            pool.handles.push(handle);
        }
        Ok(pool)
    }

    fn submit(&mut self, job: Job) -> io::Result<()> {
        // Total outstanding jobs is bounded by the owner. No blocking enqueue.
        let worker = self.next_worker % self.queues.len();
        self.queues[worker].try_send(job).map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "crypto queue unavailable")
        })?;
        self.next_worker = (worker + 1) % self.queues.len();
        Ok(())
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.queues.clear();
        // Results are unbounded, but at most CAPACITY jobs can be outstanding.
        // Workers therefore cannot deadlock on a full completion channel here.
        for handle in self.handles.drain(..) { let _ = handle.join(); }
    }
}

pub struct ParallelTransport {
    pub socket: RawSocketState,
    pool: Pool,
    tx_order: Ordered<Completion>,
    rx_order: Ordered<Completion>,
    ready: VecDeque<Completion>,
    last_plain: Option<(Vec<u8>, Vec<u8>)>,
    tx_id: u64,
    rx_id: u64,
    outstanding: usize,
    pub queue_drops: u64,
    pub rejected: u64,
    pub send_errors: u64,
}

impl ParallelTransport {
    pub fn new(socket: RawSocketState, encryptor: Encryptor, workers: usize) -> io::Result<Self> {
        Ok(Self { socket, pool: Pool::new(encryptor, workers)?, tx_order: Ordered::new(),
            rx_order: Ordered::new(), ready: VecDeque::new(), last_plain: None,
            tx_id: 0, rx_id: 0, outstanding: 0, queue_drops: 0, rejected: 0, send_errors: 0 })
    }

    pub fn set_waker(&mut self, waker: Arc<Waker>) {
        assert!(self.pool.waker.set(waker).is_ok(), "waker already registered");
    }

    pub fn enqueue_encrypt(&mut self, info: &RawInfo, input: &[u8]) -> io::Result<()> {
        if input.len() > MAX_DATA_LEN { return Err(io::ErrorKind::InvalidInput.into()); }
        if self.outstanding >= CAPACITY {
            self.queue_drops += 1;
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.pool.submit(Job { direction: Direction::Encrypt, id: self.tx_id,
            info: info.clone(), input: input.to_vec() })?;
        self.tx_id = self.tx_id.checked_add(1).expect("transmit sequence exhausted");
        self.outstanding += 1;
        Ok(())
    }

    /// Called only on I/O thread. Capture bounded batches; never touch connection state.
    pub fn pump(&mut self) -> io::Result<()> {
        self.collect();
        let mut input = [0u8; HUGE_BUF_LEN];
        for _ in 0..CAPACITY {
            if self.outstanding >= CAPACITY { break; }
            let mut info = RawInfo::default();
            let len = match self.socket.recv_raw0(&mut info, RawMode::Icmp, &mut input) {
                Ok(len) => len,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::InvalidData => continue,
                Err(error) => return Err(error),
            };
            if len > MAX_DATA_LEN + 200 { self.rejected += 1; continue; }
            self.pool.submit(Job { direction: Direction::Decrypt, id: self.rx_id,
                info, input: input[..len].to_vec() })?;
            self.rx_id = self.rx_id.checked_add(1).expect("receive sequence exhausted");
            self.outstanding += 1;
        }
        self.collect();
        Ok(())
    }

    fn collect(&mut self) {
        while let Ok(completion) = self.pool.results.try_recv() {
            match completion.job.direction {
                Direction::Encrypt => self.tx_order.insert(completion.job.id, completion),
                Direction::Decrypt => self.rx_order.insert(completion.job.id, completion),
            }
        }
        while let Some(mut completion) = self.tx_order.pop() {
            self.outstanding -= 1;
            if let Some(bytes) = completion.output {
                if self.socket.send_raw0(&mut completion.job.info, &bytes, RawMode::Icmp).is_err() {
                    self.send_errors += 1;
                }
            } else { self.rejected += 1; }
        }
        while let Some(completion) = self.rx_order.pop() {
            if completion.output.is_some() {
                self.ready.push_back(completion);
            } else {
                self.outstanding -= 1;
                self.rejected += 1;
            }
        }
    }

    pub fn has_ready(&self) -> bool { !self.ready.is_empty() }

    pub fn recv(&mut self, info: &mut RawInfo, output: &mut [u8]) -> io::Result<usize> {
        let head = self.ready.front().ok_or(io::ErrorKind::WouldBlock)?;
        let len = head.job.input.len();
        if output.len() < len { return Err(io::ErrorKind::InvalidInput.into()); }
        info.recv_info = head.job.info.recv_info.clone();
        output[..len].copy_from_slice(&head.job.input);
        if !info.peek {
            let head = self.ready.pop_front().expect("front checked");
            self.last_plain = Some((head.job.input, head.output.expect("authenticated packet")));
            self.outstanding -= 1;
        }
        Ok(len)
    }

    pub fn decrypt_received(&mut self, encrypted: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        let (original, plain) = self.last_plain.take().ok_or(())?;
        if original != encrypted || plain.len() > output.len() { return Err(()); }
        output[..plain.len()].copy_from_slice(&plain);
        Ok(plain.len())
    }

    pub fn discard(&mut self) {
        if self.ready.pop_front().is_some() { self.outstanding -= 1; }
        self.last_plain = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{AuthMode, CipherMode};
    use crate::encrypt::EncryptionKeys;

    fn dummy_socket() -> RawSocketState {
        RawSocketState { raw_recv_fd: -1, raw_send_fd: -1, filter_port: -1,
            seq_mode: 3, ip_id_counter: 0, g_packet_buf: Vec::new(), g_packet_buf_len: -1,
            lower_level: false, is_client: true }
    }

    #[test]
    fn pending_completions_count_towards_the_queue_limit() {
        let crypto = Encryptor::new(EncryptionKeys::derive("test", true), AuthMode::HmacSha1, CipherMode::Aes128Cbc);
        let mut transport = ParallelTransport::new(dummy_socket(), crypto, 2).unwrap();
        for _ in 0..CAPACITY { transport.enqueue_encrypt(&RawInfo::default(), &[1; 32]).unwrap(); }
        assert_eq!(transport.enqueue_encrypt(&RawInfo::default(), &[1]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(transport.outstanding, CAPACITY);
        assert_eq!(transport.queue_drops, 1);
        // Drop with a full queue must join workers without blocking on results.
        drop(transport);
    }

    #[test]
    fn authenticated_duplicates_still_require_serial_anti_replay() {
        let server = Encryptor::new(EncryptionKeys::derive("test", false), AuthMode::HmacSha1, CipherMode::Aes128Cbc);
        let client = Encryptor::new(EncryptionKeys::derive("test", true), AuthMode::HmacSha1, CipherMode::Aes128Cbc);
        let mut pool = Pool::new(server, 2).unwrap();
        let mut encrypted = [0; BUF_LEN];
        let len = client.my_encrypt(&123u64.to_be_bytes(), &mut encrypted).unwrap();
        for id in 0..2 { pool.submit(Job { direction: Direction::Decrypt, id,
            info: RawInfo::default(), input: encrypted[..len].to_vec() }).unwrap(); }
        let mut ordered = Ordered::new();
        for _ in 0..2 {
            let result = pool.results.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            ordered.insert(result.job.id, result.output.unwrap());
        }
        let mut replay = crate::connection::AntiReplay::new();
        let first = u64::from_be_bytes(ordered.pop().unwrap().try_into().unwrap());
        let second = u64::from_be_bytes(ordered.pop().unwrap().try_into().unwrap());
        assert!(replay.is_valid(first, false));
        assert!(!replay.is_valid(second, false));
    }

    #[test]
    fn parallel_encryption_remains_compatible_with_serial_receiver() {
        let client = Encryptor::new(EncryptionKeys::derive("test", true), AuthMode::HmacSha1, CipherMode::Aes128Cbc);
        let server = Encryptor::new(EncryptionKeys::derive("test", false), AuthMode::HmacSha1, CipherMode::Aes128Cbc);
        let mut pool = Pool::new(client, 2).unwrap();
        for id in 0..32 { pool.submit(Job { direction: Direction::Encrypt, id,
            info: RawInfo::default(), input: vec![id as u8; 1320] }).unwrap(); }
        for _ in 0..32 {
            let result = pool.results.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            let mut plain = [0; BUF_LEN];
            let len = server.my_decrypt(&result.output.unwrap(), &mut plain).unwrap();
            assert_eq!(&plain[..len], vec![result.job.id as u8; 1320]);
        }
    }

    #[test]
    fn reverse_completions_are_released_in_order_including_failures() {
        let mut ordered = Ordered::new();
        ordered.insert(2, Some(2));
        ordered.insert(1, None);
        assert_eq!(ordered.pop(), None);
        ordered.insert(0, Some(0));
        assert_eq!(ordered.pop(), Some(Some(0)));
        assert_eq!(ordered.pop(), Some(None));
        assert_eq!(ordered.pop(), Some(Some(2)));
    }

    #[test]
    fn workers_authenticate_independent_packets_and_reject_tampering() {
        let server = Encryptor::new(EncryptionKeys::derive("test-only", false), AuthMode::HmacSha1, CipherMode::Aes128Cbc);
        let client = Encryptor::new(EncryptionKeys::derive("test-only", true), AuthMode::HmacSha1, CipherMode::Aes128Cbc);
        let mut pool = Pool::new(server, 2).unwrap();
        for id in 0..64 {
            let mut buffer = [0u8; BUF_LEN];
            let size = client.my_encrypt(&[id as u8; 100], &mut buffer).unwrap();
            if id % 2 == 1 { buffer[5] ^= 1; }
            pool.submit(Job { direction: Direction::Decrypt, id, info: RawInfo::default(), input: buffer[..size].to_vec() }).unwrap();
        }
        let mut ordered = Ordered::new();
        for _ in 0..64 {
            let completion = pool.results.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            ordered.insert(completion.job.id, completion.output);
        }
        for id in 0..64 {
            let output = ordered.pop().unwrap();
            if id % 2 == 0 { assert_eq!(output.unwrap(), vec![id as u8; 100]); }
            else { assert!(output.is_none()); }
        }
    }
}
