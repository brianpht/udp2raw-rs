# Experimental ordered crypto workers

`--workers 1` is the default synchronous path. `--workers N` for N=2..16
starts N crypto threads in addition to the main I/O thread. Parallel mode is
currently limited to IPv4 ICMP without GRO, XDP or lower-level mode; unsupported
combinations fail before socket setup. Packet format is unchanged.

## Ownership and ordering

Workers encrypt, decrypt and authenticate complete packets using immutable key
schedules. Socket I/O, connection IDs, rollers, sequence allocation and replay
windows remain on the main thread. TX and RX completions are independently
resequenced. Authentication failures consume completion slots without updating
connection state. Authenticated duplicates still pass the serial replay check.

At most 256 packets may be outstanding, including completed packets awaiting
ordered delivery. TX enqueue is nonblocking and rejects packets when full; RX
stops draining while full. Failed crypto operations produce failed completions
so later packets are not held behind an unfilled ordering slot. Normal pool
destruction closes input queues and joins workers.

## Validation and limitations

Run `cargo test --locked` on Linux. Tests exercise ICMP payload boundaries, IPv4
DF encoding, ordering, authentication rejection, duplicate rejection, queue
limits, shutdown and CLI validation. The socket-domain regression test is
ignored by default because it requires CAP_NET_RAW.

Previous Linux validation passed 112 tests across the full-suite run and the
additional CLI run; one privileged test was ignored. A separate network trial
completed all eight TCP throughput cases. Two workers were slower than one in
that trial; this is not a performance improvement claim or a statistical study.
Queue, scheduling and wakeup costs need profiling before further optimization.
This is not a complete security audit or validation of every transport mode.

Inherited process signal handling uses `process::exit`; this change does not
redesign service lifecycle or automatic firewall cleanup. Avoid automatic
firewall mutation in isolated tests and explicitly clean up test resources.
