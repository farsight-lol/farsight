# Farsight

Farsight is a stateless SYN-based TCP scanner and banner grabber built directly on top of Linux's `AF_XDP` socket. Farsight is guided by an adaptive and self-reinforcing targeting strategy adapted from PMap's reinforcement-learning approach to Internet-wide port scanning.

Farsight fires raw SYN packets at the entire IPv4 address space (or a subset of it), verifies replies against a cookie instead of keeping per-target connection state. Completes just enough of a TCP handshake to ask a server "are you there, and what are you," and parses the answer. Session over session it gets better at knowing where to look next because it is continuously learning from its own results.

## Table of Contents
- [Key Properties](#key-properties)
- [How Farsight Works](#how-farsight-works)
    - [Why AF_XDP](#why-af_xdp)
    - [Userspace AF_XDP Plumbing](#userspace-af_xdp-plumbing)
    - [Stateless SYN Scanning](#stateless-syn-scanning)
    - [Minecraft Server List Ping](#minecraft-server-list-ping)
    - [The PMap Adaptive Targeting Engine](#the-pmap-adaptive-targeting-engine)
    - [Storage](#storage)
    - [Rate Limiting and Backpressure](#rate-limiting-and-backpressure)
- [Project Layout](#project-layout)
- [Requirements](#requirements)
- [Building](#building)
- [Configuration Reference](#configuration-reference)
- [The Outbound RST Problem](#the-outbound-rst-problem)
- [Running Farsight](#running-farsight)
- [Extending Farsight to Other Protocols](#extending-farsight-to-other-protocols)
- [Performance](#performance)
- [Limitations and Roadmap](#limitations-and-roadmap)
- [Ethical and Legal Use](#ethical-and-legal-use)
- [Further Reading](#further-reading)
- [Acknowledgments](#acknowledgments)

## Key Properties

- Kernel bypass via `AF_XDP`, packets destined for the scanner are redirected straight from the NIC driver into userspace-mapped ring buffers by a small eBPF program. This allows for skipping socket buffer allocation and most of the normal Linux networking stack. While also allowing every other packet on the box to flow through exactly as if Farsight weren't running.
- A PMap-derived strategy, seeded from and continuously rebuilt against Farsight's own ClickHouse result history. The strategy decides which ports to try on a given host and which IP prefixes deserve more attention than a flat and uniform sweep.
- Automatic honeypot detection to avoid wasting a scanning budget on hosts that answer identically on every port.
- Fully configuration-driven performance tuning.
- Application-layer parsing and payload construction sit behind two small traits.

## How Farsight Works

### Why AF_XDP

There are three broad ways to get packets into userspace faster than the ordinary socket API allows.
1. `DPDK`
2. `AF_PACKET`
3. `AF_XDP`

DPDK reserves the entire NIC for itself and throws away all the kernel's networking functionality for that device, every other process loses access to it, and ordinary tools like `ip` and `ping` stop working against it. That's an unacceptable tradeoff for a box that also needs to be reachable and administrable while it's scanning. `AF_PACKET`, even with a mapped ring buffer, still clones every matching frame into a socket buffer. `AF_XDP` requires an eBPF program installed at the earliest possible point in the receive path, inside the NIC driver itself. With driver or hardware support it decides per packet whether a frame belongs to userspace or should continue through the ordinary kernel stack. Only the packets Farsight actually wants ever leave the driver's DMA ring. Everything else is untouched, and the box remains a completely normal Linux machine for every other purpose. With driver-mode zero-copy support, matched packets are handed to userspace without ever being copied into an `skbuff` at all.

### Userspace AF_XDP Plumbing

Rather than depend on a higher-level `AF_XDP` wrapper, Farsight implements the socket, ring, and UMEM machinery directly against the raw kernel interface (`src/xdp/`):

- `Umem`, a `mmap`'d, optionally huge-page-backed arena of fixed-size frames shared between the kernel and userspace. Every packet Farsight sends or receives lives in one of these frames; there are no separate buffer copies once a frame is written.
- `Socket`, thin wrappers around `socket(AF_XDP, ...)`, the `XDP_UMEM_REG`/`XDP_RX_RING`/`XDP_TX_RING`/`XDP_UMEM_FILL_RING`/`XDP_UMEM_COMPLETION_RING` socket options, `bind(2)` with a `sockaddr_xdp`, and the busy-polling socket options (`SO_PREFER_BUSY_POLL`, `SO_BUSY_POLL`, `SO_BUSY_POLL_BUDGET`).
- `Ring`, the four `mmap`'d ring buffers (Fill, Completion, RX, TX) that every `AF_XDP` socket exposes, each a single-producer/single-consumer lock-free queue of frame descriptors, built on the kernel-provided offset layout returned by `XDP_MMAP_OFFSETS`.

At startup, Farsight determines the NIC's combined queue count via an `ETHTOOL_GCHANNELS` ioctl and clamps it against `available_parallelism() - 2` (one core is always reserved for the target-generation feeder/main thread, one for the async housekeeping and database-writer task). If those two numbers disagree, Farsight refuses to start and prints the exact `ethtool -L <iface> combined <n>` command needed to fix it, rather than silently scanning with fewer queues than the hardware actually has.

For each usable queue, Farsight allocates its own `Umem` and two `AF_XDP` sockets sharing that UMEM via `XDP_SHARED_UMEM`:

- A scanner socket, whose only job is to drain a lock-free work-stealing deque of freshly generated `(source port, ip, destination port)` targets and blast SYNs onto the wire as fast as the TX ring and rate limiter allow.
- A responder socket, pairing an RX ring (for reading whatever comes back) with its own TX ring (for the follow-up ACKs, data pushes, and RSTs that a completed exchange needs).

Target generation is fanned out to all of them through a work-stealing deque, so an idle queue can steal work from a busier one instead of starving. Notably, the async Tokio runtimes run in single-threaded mode. Tokio is used purely for lightweight orchestration, never for the hot packet path, which is entirely hand-parallelized across real OS threads instead.

### Stateless SYN Scanning

Farsight belongs to the same lineage as classic SYN-stealth scanners, it never calls `connect(2)`. Hence, an ordinary OS-level TCP socket is never registered for a target host, so scanned connections are invisible to tools like `ss`. Every finished exchange is torn down with a raw RST rather than a graceful FIN close.

The mechanism that makes this safe without keeping millions of pending connection records in memory is the initial TCP sequence number being a cookie. This was popularized by ZMap. For every outgoing SYN, the sequence number is computed as a cheap multiplicative hash over the target's IP address, the target port, and a random 64-bit seed chosen once per scanning session.

```
cookie(ip, port, seed) = ((ip  K + port)  K + seed)  K   (mod 2^32)
```

When a SYN-ACK comes back, its acknowledgment number is checked against a freshly recomputed cookie for that ip-port-pair. Only a match proves the reply corresponds to a SYN Farsight actually sent, a mismatch is rejected for the cost of one multiplication, with zero state ever having been allocated for it. Because the seed changes every session, a slow or delayed reply that arrives after a session boundary simply fails the cookie check and is silently dropped rather than being incorrectly matched to a new session's bookkeeping.

Only once a SYN-ACK passes cookie verification does Farsight allocate a small per-ip-port-pair connection-tracking entry, and the exchange proceeds efficiently:

1. SYN is sent.
2. SYN-ACK received.
3. PSH+ACK carrying the protocol payload is sent immediately, piggybacked onto the acknowledgment of the SYN-ACK, skipping the usual "bare ACK, then a separate data segment" round trip that a normal socket-based client would perform.
4. The response is read back. A small bounded reorder buffer (`tcp.max_reorder_segments` / `tcp.max_reorder_bytes`) reassembles shuffled segments up to a fixed memory ceiling; a segment that would exceed that ceiling is simply dropped rather than buffered. This trades the small chance of a missed banner for some memory use.
5. As soon as a complete, valid application-layer response has been parsed, Farsight immediately RSTs the connection, there is no clean four-way FIN teardown, since nothing is gained by one here.

Every packet's IPv4 and TCP checksums are computed incrementally rather than by resumming the whole frame on every send: a baseline checksum over the parts of the packet template that never change (the fixed TCP options, the scanner's own source address) is computed once when a sender starts, and only the per-packet-varying terms, destination address, ports, sequence number, are folded in per send. When `xdp.checksum_offload` is enabled, even that is skipped in favor of the NIC computing the checksum itself, using `AF_XDP`'s TX metadata mechanism.

Connections that never get a reply, or that stall mid-handshake, are reclaimed through an expiry queue processed in bounded batches (`strategy.timeout_batch`), so memory use stays bounded even against packet loss or targets that never respond at all.

### Minecraft Server List Ping

Once a session with a live server is open, Farsight sends the two packets that make up a modern Minecraft "Server List Ping": a handshake packet (declaring a protocol version, a, freely spoofable, virtual hostname and port the client claims to be connecting through, and "status" as the next protocol state) immediately followed by a status request packet with no body.

The server responds with a single VarInt-length-prefixed JSON payload. Farsight parses the length prefix, waits for the full declared length to arrive, and validates that the payload actually deserializes as JSON before accepting it as a hit. This filters out non-Minecraft TCP services that happen to be listening on a probed port and reply with something else entirely.

The status query is deliberately not version-gated on the wire: vanilla Minecraft servers, and effectively all third-party implementations, answer a status request regardless of whether the declared protocol version matches their own (only the login sequence is version-sensitive). The default `[ping]` configuration is therefore mostly cosmetic, with one caveat: proxy software that does hostname-based virtual-host routing (BungeeCord- and Velocity-style "forced hosts") can branch on the declared hostname, so it's worth customizing when specifically probing a proxied server network.

### The PMap Adaptive Targeting Engine

The paper this is adapted from, PMap: Reinforcement Learning-Based Internet-Wide Port Scanning (Song, He, Chen, Lin, Fan, Wen, Wang, and Yang; IEEE/ACM Transactions on Networking, vol. 32, no. 6, December 2024), starts from two empirical observations: hosts within the same network tend to have similar sets of open ports, and open ports show measurable correlation with each other (a host with UDP/443 open is far more likely to also have TCP/443 and TCP/80 open than the reverse). The paper builds a directed correlation graph of ports from a batch of pre-scanned "seed" addresses per network that greedily walks that graph to recommend which port to try next for every other address in the same network. The problem is modeled as a multi-armed bandit.

Farsight implements the same underlying idea as two independent, continuously running instances of it, one for ports and one for IP prefixes. The dataset is sourced entirely from its own accumulated ClickHouse history and updated in real-time rather than in the paper's discrete scan-then-batch-update phases.

Port-level (`controller/strategy/port/pmap.rs`). Before each scanning session, a `PortGraph` is rebuilt from ClickHouse: for every port ever seen open, how often, and for every pair of ports, how often they were seen open on the same address together, exactly the paper's single- and co-occurrence counts, computed over Farsight's own findings instead of a Censys snapshot. For a freshly discovered address, the first port tried is either the single globally best-known port (with probability `1 - strategy.epsilon.port`) or a uniformly random port (otherwise), plus, before any history exists at all, `strategy.seed_ports` lets an operator hand-seed candidate ports. As results for that address come back, a small per-host max-heap is kept up to date: whenever a port is found open, every port correlated with it gets its candidate probability bumped to the larger of its historical prior and the freshly computed conditional probability given what's now known about that specific host, the same "take the max of the seed-derived prior and the posterior" rule the paper uses when propagating information through its graph. The next port tried is whichever of "top of this host's personal heap" or "next unvisited entry in the global ranking" currently looks more promising, mirroring the paper's greedy walk. `strategy.budget_per_address` caps the total number of ports tried per host, the direct analogue of the paper's intrusiveness metric.

Farsight also folds in automatic honeypot / catch-all detection, something the underlying paper doesn't need to worry about but which matters a great deal when the target population includes generic cloud instances and security appliances that answer every port identically: every banner Farsight receives is hashed, and if the same exact hash comes back `strategy.catchall_threshold` times from a single host, Farsight assumes it's talking to a device that fakes a response on every port and abandons the rest of that host's port budget rather than wasting probes on what is almost certainly not a real, distinct server per port.

Prefix-level (`controller/strategy/ip/pmap.rs`). The complementary observation, hosts in the same network tend to look alike, is applied one level up, at the granularity of /24 prefixes. A `PrefixGraph` built from ClickHouse gives every /24 a historical hit-density prior; during a session, a live, concurrent max-heap tracks which /24s are actually paying off right now, bumped every time a hit (a fully parsed banner, not merely an open port) lands inside a given /24. New target addresses are drawn from a perfect, repeat-free pseudorandom permutation of the entire scan scope with probability `strategy.epsilon.ip`. Farsight instead exploits the current hottest /24, drawing a still-unscanned address from it directly rather than waiting for the sequential sweep to get there. Both selection paths write into the same per-prefix scanned bitmap, so any address the exploit path picks early is automatically skipped when the sequential sweep later reaches it. The whole in-scope address space is still covered exactly once per session, regardless of how much front-loaded exploitation happens along the way.

Both graphs are rebuilt from scratch at the start of every session, so a run's findings directly sharpen the very next run's targeting, a closed loop with no external dependency beyond Farsight's own result table.

Sessions run for a fixed `session.duration` and alternate ranges with probability `session.rescan.epsilon`, between a full sweep of the entire in-scope IPv4 space and a rescan pass over a batch of up to `session.rescan.max_count` previously-seen IPs pulled straight from the database. This is done to catch server churn, MOTD changes, player count drift, servers going up or down, without re-sweeping the entire address space every time.

### Storage

Results ("scanlings": timestamp, IP, port, raw response body) are written to [ClickHouse](https://clickhouse.com/) using its official async Rust client. Writes are batched and flushed either once `database.flush_capacity` rows have accumulated or `database.flush_interval` seconds have elapsed since the last flush, on a dedicated task that never blocks the packet-processing hot loop, the exact `CREATE TABLE` statement Farsight expects is documented directly in `config.example.toml`. ClickHouse isn't just an output sink here, either: it's the single source of truth the PMap engine rebuilds its correlation graphs from at the start of every session, so it needs to already contain whatever history you want the next session to learn from.

### Rate Limiting and Backpressure

`controller.max_rate` sets a global packets-per-second ceiling, implemented as a token bucket that's split evenly across every queue's completion reclaimer and applied at TX-ring completion time rather than at SYN issuance.

## Project Layout

```
.
├── Cargo.toml                  # workspace root
├── config.example.toml         # fully documented, safe-defaults starting config
├── config.toml                 # your local config (copy from the example, gitignored)
├── exclude.conf                # CIDR / IP-range / single-IP exclusion list, one per line
├── rust-toolchain.toml         # pins the nightly toolchain this project builds against
├── farsight/                   # the userspace controller (the actual binary)
│   ├── build.rs                #   builds farsight-ebpf as a build dependency via aya-build
│   └── src/
│       ├── main.rs             #   entry point: loads the XDP program, drives the session loop
│       ├── config.rs           #   config.toml deserialization
│       ├── exclude.rs          #   exclude.conf parsing
│       ├── database/           #   ClickHouse client + graph-building queries
│       ├── net/                #   MAC/gateway/interface/IP discovery, TCP header + checksum
│       │                       #   helpers, IPv4 range compilation and exclusion
│       ├── xdp/                #   hand-rolled AF_XDP socket, ring, and UMEM primitives
│       └── controller/
│           ├── session.rs      #     spins up one bounded scanning session
│           ├── feeder.rs       #     draws targets from the strategy, rate-limits generation
│           ├── scanner.rs      #     drains the work-stealing deque, blasts SYNs
│           ├── responder.rs    #     handles SYN-ACK/ACK/FIN/RST, TCP reassembly, parsing
│           ├── sender.rs       #     raw packet construction + incremental checksums
│           ├── receiver.rs     #     AF_XDP RX ring / fill ring bookkeeping
│           ├── completer.rs    #     TX completion reclaiming + rate limiting
│           ├── deque/          #     the work-stealing deque implementation
│           ├── protocol/       #     Parser/Payload traits + the Minecraft SLP implementation
│           └── strategy/       #     the PMap targeting engine (ip/, port/, pmap/)
├── farsight-common/             # tiny #![no_std] crate shared between farsight and farsight-ebpf
└── farsight-ebpf/                # the kernel-side XDP program (compiled to BPF, not run directly)
    └── src/xdp.rs
```

`farsight-common` is presently minimal, effectively a `#![no_std]` marker crate with an optional `user` feature that pulls in `aya`, reserved as the shared vocabulary between the eBPF program and the userspace controller (map value types, and the like) as more eBPF-side functionality gets added.

## Requirements

- Linux, with `AF_XDP` support (present since kernel 4.18, though driver-mode zero-copy support and the specific TX metadata / checksum offload path Farsight can use are considerably newer, a recent 6.x kernel is recommended).
- A NIC and driver combination that supports XDP. Native/driver-mode XDP (`attach_mode = "driver"`) needs driver support; hardware/offloaded mode needs NIC support; generic mode (`attach_mode = "skb"`) works everywhere as a slower fallback that emulates `AF_XDP` in software.
- Rust nightly, pinned via `rust-toolchain.toml`. `rustup` will pick this up automatically once you're inside the repository.
- The `rust-src` rustup component for that nightly toolchain (needed by `aya`'s eBPF build path to build `core`/`alloc` for the BPF target).
- `bpf-linker`, used to link the compiled eBPF object.
- Root, or the equivalent capability set, at runtime: `CAP_SYS_RESOURCE` (to raise `RLIMIT_MEMLOCK` to unlimited, required for the eBPF maps and `AF_XDP` ring memory), `CAP_NET_ADMIN`/`CAP_BPF` (to load and attach the XDP program), and `CAP_NET_RAW` (for the `AF_XDP` socket family itself).
- A reachable ClickHouse server (self-hosted or managed) to write results to and to seed the PMap graphs from.
- `ethtool`, `ip`/`nft` (or equivalent), for interface queue tuning and the outbound-RST workaround described below.

## Building

```bash
# Pin and install the nightly toolchain this project expects
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# The linker aya needs to turn the eBPF crate into loadable bytecode
cargo install bpf-linker

# Builds the userspace controller; farsight/build.rs transparently cross-compiles
# farsight-ebpf to BPF and embeds it into the resulting binary, there is no
# separate .o file to manage or load at runtime.
cargo build --release
```

The resulting binary lives at `target/release/farsight`.

## Configuration Reference

Farsight is entirely configuration-driven, there is no command-line flag parsing in `main.rs`. Copy `config.example.toml` to `config.toml` (the program will tell you to do exactly this if it can't find `config.toml`) and edit it; every field below is documented inline in the shipped example as well.

### `[database]`

| Key                                   | Meaning                                                                                                                |
|---------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `url`, `user`, `password`, `database` | ClickHouse connection details.                                                                                         |
| `table`                               | Table name to read from and write to; must already exist (`CREATE TABLE` statement provided in `config.example.toml`). |
| `flush_interval`                      | Flush the write batch if it's been at least this many seconds since the last flush.                                    |
| `flush_capacity`                      | Flush immediately once this many rows have accumulated, whichever comes first.                                         |

### `[controller]`

| Key           | Meaning                                                                                                                                                                                                             |
|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `source_port` | The ephemeral TCP source-port range (or single port) Farsight's outgoing SYNs use. This is also the range the XDP program filters incoming traffic against, and the range that needs the nftables workaround below. |
| `interface`   | The network interface to attach to (`ip addr` or `nmcli d` to find the right name, it almost certainly isn't `lo`).                                                                                                 |
| `print_every` | How often (seconds) TX/RX throughput is logged.                                                                                                                                                                     |
| `max_rate`    | Global packets-per-second ceiling.                                                                                                                                                                                  |

### `[tcp]`

| Key                    | Meaning                                                                                                                                                                 |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `max_reorder_segments` | Maximum number of out-of-order TCP segments buffered per connection while waiting to reassemble a response. Higher costs more memory but drops fewer partial responses. |
| `max_reorder_bytes`    | Maximum total bytes buffered per connection for the same purpose.                                                                                                       |

### `[strategy]`

| Key                           | Meaning                                                                                                                                                                                  |
|-------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `max_in_flight`               | How many concurrent per-host PMap states are tracked at once. Higher uses more memory but loses fewer in-progress hosts under load.                                                      |
| `epsilon.ip` / `epsilon.port` | Exploration probability for the IP-level and port-level strategies respectively, the chance of trying something outside the current model's top recommendation instead of exploiting it. |
| `budget_per_address`          | Maximum distinct ports tried per address within one session, the primary intrusiveness control.                                                                                          |
| `seed_ports`                  | Ports to hint into the port-recommendation list before any history exists, as `[[start, end], ...]` ranges.                                                                              |
| `timeout_batch`               | Maximum number of expired per-host states reclaimed per housekeeping tick.                                                                                                               |
| `catchall_threshold`          | Number of identical banner hashes from one host before it's flagged as a likely honeypot and its remaining budget is abandoned.                                                          |

### `[session]`

| Key                | Meaning                                                                           |
|--------------------|-----------------------------------------------------------------------------------|
| `duration`         | Length of one scanning session, in seconds.                                       |
| `batch_size`       | Number of targets generated and handed off to the work-stealing deque at a time.  |
| `rescan.max_count` | Maximum number of previously-seen IPs queued for a rescan session.                |
| `rescan.epsilon`   | Probability that a given session is a rescan pass rather than a fresh full sweep. |

### `[ping]`

| Key                | Meaning                                                                                                                                                           |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `host`             | The virtual hostname announced in the Minecraft handshake. Cosmetic for most servers; relevant for proxies doing hostname-based routing.                          |
| `port`             | The virtual port announced alongside `host`.                                                                                                                      |
| `protocol_version` | The protocol version declared in the handshake. Status queries aren't version-gated on the server side, so this mostly doesn't need to match any specific target. |

### `[xdp]`

| Key                                                  | Meaning                                                                                                                                                                                                           |
|------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `mode`                                               | `"zero-copy"` (fastest, driver-dependent stability), `"copy"` (fast, broadly compatible), or `"fallback"` (defer to the driver's own preference).                                                                 |
| `attach_mode`                                        | `"hardware"` (fastest, needs NIC support), `"driver"` (faster, needs driver support), or `"skb"` (slower, always available, emulates `AF_XDP` generically).                                                       |
| `checksum_offload`                                   | Offload TCP checksum computation to the NIC. Faster when it works; some drivers don't support it in combination with zero-copy mode, in which case you'll see no throughput and should turn this off.             |
| `huge_pages`                                         | Back the UMEM arena with huge pages, if the system has them configured (see the enabling commands in `config.example.toml`).                                                                                      |
| `ring_size`                                          | Size of each of the four `AF_XDP` rings (Fill, Completion, RX, TX). Higher uses more memory but can improve throughput.                                                                                           |
| `busy_polling.enabled` / `.microseconds` / `.budget` | Enables kernel-level socket busy-polling (`SO_PREFER_BUSY_POLL`/`SO_BUSY_POLL`/`SO_BUSY_POLL_BUDGET`) to trade CPU for lower, more consistent latency by avoiding interrupt- and softirq-driven scheduling delay. |
| `batches.completion` / `.rx`                         | Maximum packets processed per batch on the completion and receive paths respectively. Must not exceed `ring_size`, and shouldn't be set too close to it.                                                          |

Two starting points are shipped: `config.example.toml` is heavily commented and defaults to the broadly-compatible, conservative end of every knob (`skb` attach mode, `copy` mode, no huge pages, busy polling off); `config.toml` in this repository reflects a tuned, high-throughput profile (`driver` attach mode, `zero-copy`, huge pages on, busy polling on) suitable for hardware and drivers known to support it well. Start from the example, and move toward the tuned profile once you've confirmed your NIC and driver support each step.

## The Outbound RST Problem

This part is not optional, and skipping it is the single most common reason a raw-socket or `AF_XDP`-based scanner appears to send traffic but never receives anything back.

Because Farsight's "connections" never go through `connect(2)`, the kernel's own TCP/IP stack has no record of them. When a SYN-ACK arrives on one of Farsight's chosen ephemeral source ports, the kernel will detect is as a foreign packet and immediately kill the connection before Farsight's userspace code ever gets a chance to process the reply. This affects every scanner built this way, including ZMap and Masscan, and the fix is the same one all of them document: tell the kernel's own firewall to drop its own outgoing RSTs for the port range Farsight uses, so only Farsight's `AF_XDP`-delivered replies are ever seen.

```bash
sudo nft add table inet filter
sudo nft add chain inet filter output '{ type filter hook output priority 0; policy accept; }'
sudo nft add rule inet filter output ip protocol tcp tcp flags rst tcp sport <port_range_start>-<port_range_end> drop
```

To persist this across reboots:

```bash
sudo nft list ruleset | sudo tee /etc/nftables.conf
sudo systemctl enable --now nftables
```

Replace `<port_range_start>-<port_range_end>` with whatever you set `[controller].source_port` to.

## Running Farsight

```bash
cp config.example.toml config.toml
$EDITOR config.toml        # set [controller].interface and [database] connection details at minimum
touch exclude.conf         # populate with CIDR ranges, IP ranges (a.b.c.d-a.b.c.d), or single IPs to skip
sudo RUST_LOG=info ./target/release/farsight
```

`exclude.conf` accepts one entry per line, either CIDR notation (`10.0.0.0/8`) or a hyphenated range (`10.0.0.1-10.0.0.255`), `#` for comments (inline comments are stripped too), and blank lines are ignored.

Farsight is a long-running daemon, not a one-shot CLI tool: `main.rs` loops forever, alternating full sweeps and rescans according to `session.rescan.epsilon`, retrying (after logging) if an individual session hits an error rather than exiting. Logging is standard `env_logger`; set `RUST_LOG` to control verbosity (`RUST_LOG=farsight=debug` for a much more detailed view of individual packet-level decisions, `RUST_LOG=info` for the periodic throughput summaries and hit notifications, which is a reasonable default for normal operation). Every `controller.print_every` seconds, current transmit and receive rates are logged in packets, kilopackets, or megapackets per second depending on magnitude.

## Extending Farsight to Other Protocols

Application-layer behavior is isolated behind two traits in `controller/protocol/mod.rs`:

```rust
pub trait Parser: Send + Sync + Debug {
    type Output: Sized + Send + Sync + Serialize + Hash + Debug;

    fn parse(&self, data: &[u8]) -> Result<Self::Output, ParseError>;
}

pub trait Payload: Send + Sync {
    fn build(&self, ip: Ipv4Addr, port: u16) -> Result<&[u8], anyhow::Error>;
}
```

`Parser::parse` receives whatever bytes have been reassembled so far and returns either a parsed value, `ParseError::Invalid` (tear the connection down, this isn't the expected protocol), or `ParseError::Incomplete` (wait for more data). `Payload::build` constructs whatever needs to be sent to a specific `(ip, port)` once a SYN-ACK has been verified, for protocols with a fixed request body, any `Deref<Target = [u8]>` (a `Vec<u8>`, a `&[u8]`) already implements `Payload` for free.

`controller/protocol/minecraft.rs`'s `SLPParser` and `build_latest_request` are a complete example of both. Wiring a new protocol in means writing the equivalent pair and swapping the generic type parameters used in `main.rs`'s call into `Controller::session`.

## Performance

Farsight is designed around the idea that the bottleneck for an adaptive scanner like this should be the target-generation and correlation logic, not the packet path underneath it. `AF_XDP` with driver-mode zero-copy and one core per hardware queue is capable of packet rates that a purely userspace-socket-based implementation of the same targeting strategy could not sustain. As tested against an Intel I225-V (`igc` driver), Farsight is reported to fully saturate a 1 Gbps link. The practical ceiling in any given deployment will depend heavily on NIC/driver zero-copy support, core count, and how aggressively `[xdp]` is tuned per the reference above.

Two of the resources this project draws on are worth knowing about if you're chasing latency rather than raw throughput. Understanding Delays in AF_XDP-based Applications (Castillon du Perron, Lopez Pacheco, and Huet, 2024) found, across both Mellanox and Intel NICs, that the lowest and most stable per-packet latencies came from configurations with busy polling enabled and both `need_wakeup` and application-level `poll()` disabled. While enabling polling on the receive side consistently hurt latency regardless of driver, directly informing which of `[xdp]`'s knobs matter most if you go tuning for latency rather than throughput.

## Limitations and Roadmap

- IPv4 only. Every address type in the codebase is `Ipv4Addr`, and the XDP program only inspects `EtherType::Ipv4` frames. IPv6 support would need its own address-generation, range-compilation, and prefix-graph logic (the PMap paper this project draws from does cover IPv6, with somewhat different prefix-pattern-driven targeting, as a starting point).
- Minecraft SLP implemented only.
- Requires Linux, root, and cooperative hardware. There's no fallback path for platforms without `AF_XDP`.

## Ethical and Legal Use

Farsight is, functionally, in the same category of software as ZMap, Masscan, Shodan, and Censys's own scanning infrastructure: a general-purpose Internet measurement tool, not something built to target or harm any specific system. That said, sending unsolicited packets at scale carries real responsibilities, and the fact that it's technically easy to point this at "the entire IPv4 address space" doesn't mean every use of it is appropriate, welcome, or legal in your jurisdiction.

Some concrete practices, most of which Farsight already gives you the tools for:

- Maintain and honor an exclusion list. `exclude.conf` exists specifically so that networks that have asked not to be scanned, or that you simply know shouldn't be, never receive a packet. Keep it current, and act promptly on abuse complaints or opt-out requests.
- Keep your rate reasonable and stay within a single, identifiable network path so that operators who do investigate unexpected traffic can trace it back to a real point of contact rather than something that looks like a distributed attack.
- Prefer status/banner-only interactions over anything resembling exploitation. Farsight's Minecraft handling only ever performs the same unauthenticated status query any Minecraft client performs before connecting; it does not attempt to log in, authenticate, or interact with a server beyond that.
- Know your local law before scanning networks you don't own or have permission to probe. Rules around unsolicited network scanning vary significantly by country and, in some places, by network operator terms of service.
- Consult an established ethical framework for network measurement research if you're operating this at any real scale. The Menlo Report and Partridge and Allman's "Ethical Considerations in Network Measurement Papers" (Communications of the ACM, 2016) are the two most widely cited starting points in the networking research community.

## Further Reading

- Song, G., He, L., Chen, T., Lin, J., Fan, L., Wen, K., Wang, Z., & Yang, J. "PMap: Reinforcement Learning-Based Internet-Wide Port Scanning." IEEE/ACM Transactions on Networking, vol. 32, no. 6, Dec. 2024, pp. 5524–5538. The paper this project's targeting strategy is adapted from; the reference implementation released alongside it lives at [`github.com/AddrMiner/Pmap`](https://github.com/AddrMiner/Pmap).
- Castillon du Perron, K., Lopez Pacheco, D., & Huet, F. "Understanding Delays in AF_XDP-based Applications." 2024 (arXiv:2402.10513). A focused experimental study of exactly which `AF_XDP` socket and NIC driver parameters matter for latency, directly relevant to tuning `[xdp]` above.
- The Linux kernel's [`AF_XDP` documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html).

## Acknowledgments

- [`aya`](https://github.com/aya-rs/aya) and `aya-log`, for eBPF program loading, and the eBPF-side logging macros used in `farsight-ebpf`.
- [`craftping`](https://github.com/kiwiyou/craftping), for the Minecraft Server List Ping handshake and varint routines adapted into `controller/protocol/minecraft.rs`.
- [`hugepage-rs`](https://github.com/cppcoffee/hugepage-rs), which `xdp/page.rs`'s huge page size discovery is forked from.
- [`matdoesdev`](https://matdoes.dev/) for the `exclude.conf`, and its parser (`src/exclude.rs`)
