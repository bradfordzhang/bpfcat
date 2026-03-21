# bpfcat (eBPF-powered socat) 

`bpfcat` is a high-performance networking tool leveraging eBPF technology to act as a "next-generation network Swiss Army knife" for Linux. By redirecting data streams directly within the kernel, it eliminates the overhead of user-space/kernel-space context switching, providing extreme forwarding performance and deep observability.

## 🌟 Vision
To provide a zero-copy forwarding mechanism at the Socket layer using eBPF, accompanied by a real-time traffic analysis dashboard, compatible with various Linux environments ranging from bare metal to WSL2.

## ✨ Key Features

- **Extreme Performance (Kernel Zero-copy)**: For TCP-to-TCP scenarios, `bpfcat` utilizes `sock_map` and `sk_skb` to achieve kernel-level redirection, ensuring data never touches user-space.
- **Multi-Protocol Support**: Seamlessly supports and proxies between TCP, UDP, and Unix Domain Sockets (UDS).
- **Smart Concurrency Management**: Dynamically manages up to 65,535 concurrent connections using eBPF Hash Maps.
- **Real-time Monitoring Dashboard**: 
  - **Throughput (Mbps)**: Live bandwidth monitoring.
  - **QPS (Packets/s)**: Real-time packet processing rate.
  - **Active Connections**: Distinct counters for native eBPF zero-copy vs. user-space fallback connections.
- **Adaptive Environment Awareness**: 
  - Automatically switches to `SK_SKB` driver mode for restricted kernels (like WSL2) missing `STREAM_PARSER`.
  - Transparently falls back to safe User-space copying for cross-protocol scenarios (e.g., Unix to TCP).

## 🏗️ Technical Architecture

- **Control Plane (Go)**:
  - Manages eBPF program loading, attachment, and lifecycle.
  - Handles session indexing and dynamic map updates for concurrent connections.
  - Periodically aggregates `PERCPU_ARRAY` map data for live statistics.
- **Data Plane (eBPF C)**:
  - **SockMap**: Stores active socket file descriptors for kernel-level lookup.
  - **Stream Verdict**: Real-time peer lookup via Socket Cookie and instant redirection.
  - **Stats Accumulator**: Lock-less accumulation of bytes and packets per CPU for maximum efficiency.

## 🚀 Getting Started

### Prerequisites
- Linux Kernel 4.17+ (5.4+ recommended)
- Go 1.21+
- Clang & LLVM (for compiling eBPF bytecode)

### Build
```bash
# Generate eBPF bindings and build the binary
go generate
go build -o bpfcat .
```

### Usage Examples

#### 1. High-Performance TCP Forwarding (eBPF Zero-copy)
```bash
# Listen on 8888, forward to 8080
sudo ./bpfcat 8888 127.0.0.1:8080
```

#### 2. Unix Domain Socket Proxy
```bash
# Expose a local Unix Socket (e.g., Docker) as a TCP port
sudo ./bpfcat 8888 unix:/var/run/docker.sock
```

#### 3. Stateful UDP Forwarding
```bash
# Forward UDP traffic with session tracking
sudo ./bpfcat udp:9999 udp:127.0.0.1:9090
```

## 📊 Live Stats Display
The dashboard provides a real-time status line:
```text
[Stats] Throughput: 450.25 Mbps | QPS: 12540 | Active: 5 (eBPF: 4, User: 1) | Total: 1.2 GB
```

## 🛠️ Roadmap (TODO)

### Phase 3: Advanced Observability & Protocol Optimization
- [ ] **QUIC Acceleration**: 
  - Implement kernel-level routing based on QUIC Connection IDs (CID).
  - Optimize `SO_REUSEPORT` distribution for QUIC packets across multiple CPU cores.
- [ ] **XDP / TC Interception**: 
  - Introduce lower-level interception to bypass the networking stack entirely for even higher throughput.
  - Support stateless UDP redirection at the NIC level (XDP_TX).
- [ ] **Traffic Mirroring**: Clone traffic to a monitoring port without affecting the primary forwarding path.

### Phase 4: Engineering & Security
- [ ] **Prometheus Integration**: Export metrics for visualization in Grafana.
- [ ] **Dynamic Filtering (eBPF grep)**: Support dropping or modifying packets based on payload patterns in the kernel.
- [ ] **ACL Access Control**: Kernel-level IP/CIDR whitelisting/blacklisting.

## 📄 License
Licensed under the [GNU Affero General Public License v3 (AGPLv3)](LICENSE).
