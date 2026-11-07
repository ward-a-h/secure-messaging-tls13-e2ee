# Secure Messaging over TLS 1.3 with End-to-End Encryption

> 🚧 Work in progress. Computer Networks (CS3001) project at FAST NUCES Karachi, Fall 2026.

A socket-based messaging relay secured with TLS 1.3, with an extra end-to-end encryption layer so the relay server cannot read the messages it forwards. The project then measures how much handshake time, byte overhead and latency this security adds under controlled network delay and loss.

## Why

TLS only protects each hop (client to server, server to client). A relay server that relies on TLS alone can still read every message. Adding end-to-end encryption between the clients means the server only ever handles ciphertext.

## Planned architecture

```
Client 1 ── R1 ══ (tc netem: delay / loss) ══ R2 ── Relay server
                                              └──── Client 2
```

- Runs on one Ubuntu machine using Linux network namespaces and veth pairs
- Two software routers and three subnets, with static routing (OSPF via FRRouting if time permits)
- Both clients connect to the relay over TLS 1.3, and exchange public keys through it to set up end-to-end encryption

## Tech

| Layer | Tools |
|---|---|
| Transport security | TCP, TLS 1.3 (RFC 8446), Python `ssl`, self-signed X.509 certificate |
| End-to-end encryption | PyNaCl (libsodium) public-key authenticated encryption |
| Network emulation | Linux namespaces, iproute2, `tc netem` / `tc tbf` |
| Packet analysis | Wireshark, tcpdump |

## Measurements

- TLS 1.3 handshake time
- TCP vs TLS round-trip breakdown
- Per-message byte overhead of TLS and the end-to-end layer
- End-to-end message latency under different RTT and loss settings

## Status

- [x] Proposal
- [ ] Network topology
- [ ] TLS relay server and clients
- [ ] End-to-end encryption layer
- [ ] Measurements and analysis
- [ ] Final report

## Author

Wardah Ahmed, BS Computer Science, FAST NUCES Karachi

