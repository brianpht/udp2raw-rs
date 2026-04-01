//! Shared `MioFdSource` wrapper for registering raw FDs with mio::Poll.
//! Used by both client and server event loops.

use std::io;
use std::os::unix::io::RawFd;

use mio::{Interest, Token};

/// Wraps a raw file descriptor so it can be registered with `mio::Poll`.
pub struct MioFdSource {
    pub fd: RawFd,
}

impl mio::event::Source for MioFdSource {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        registry.register(&mut mio::unix::SourceFd(&self.fd), token, interests)
    }
    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        registry.reregister(&mut mio::unix::SourceFd(&self.fd), token, interests)
    }
    fn deregister(&mut self, registry: &mio::Registry) -> io::Result<()> {
        registry.deregister(&mut mio::unix::SourceFd(&self.fd))
    }
}

