//! FD manager: maps OS file descriptors to unique Fd64 IDs to avoid FD reuse collisions.
//! Corresponds to fd_manager.{h,cpp} in the C++ version.

use crate::common::Fd64;
use std::collections::HashMap;
use std::os::unix::io::RawFd;

pub struct FdInfo {
    /// Index into the server's conn_manager, if applicable.
    pub conn_info_key: Option<std::net::SocketAddr>,
}

pub struct FdManager {
    counter: Fd64,
    fd_to_fd64: HashMap<RawFd, Fd64>,
    fd64_to_fd: HashMap<Fd64, RawFd>,
    fd_info: HashMap<Fd64, FdInfo>,
}

impl Default for FdManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FdManager {
    pub fn new() -> Self {
        // Start counter above u32::MAX to distinguish from raw fds
        let counter = u32::MAX as Fd64 + 100;
        Self {
            counter,
            fd_to_fd64: HashMap::with_capacity(64),
            fd64_to_fd: HashMap::with_capacity(64),
            fd_info: HashMap::with_capacity(64),
        }
    }

    pub fn create(&mut self, fd: RawFd) -> Fd64 {
        assert!(
            !self.fd_to_fd64.contains_key(&fd),
            "fd {} already registered",
            fd
        );
        let fd64 = self.counter;
        self.counter += 1;
        self.fd_to_fd64.insert(fd, fd64);
        self.fd64_to_fd.insert(fd64, fd);
        fd64
    }

    pub fn fd_exist(&self, fd: RawFd) -> bool {
        self.fd_to_fd64.contains_key(&fd)
    }

    pub fn exist(&self, fd64: Fd64) -> bool {
        self.fd64_to_fd.contains_key(&fd64)
    }

    pub fn to_fd(&self, fd64: Fd64) -> RawFd {
        *self
            .fd64_to_fd
            .get(&fd64)
            .expect("fd64 does not exist in FdManager")
    }

    pub fn fd64_close(&mut self, fd64: Fd64) {
        if let Some(fd) = self.fd64_to_fd.remove(&fd64) {
            self.fd_to_fd64.remove(&fd);
            self.fd_info.remove(&fd64);
            unsafe {
                libc::close(fd);
            }
        }
    }

    pub fn get_info(&self, fd64: Fd64) -> Option<&FdInfo> {
        self.fd_info.get(&fd64)
    }

    pub fn get_info_mut(&mut self, fd64: Fd64) -> &mut FdInfo {
        self.fd_info.entry(fd64).or_insert(FdInfo {
            conn_info_key: None,
        })
    }

    pub fn set_info(&mut self, fd64: Fd64, info: FdInfo) {
        self.fd_info.insert(fd64, info);
    }
}

