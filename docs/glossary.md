<!--
SPDX-FileCopyrightText: 2026 skunkie

SPDX-License-Identifier: MIT
-->

# Glossary

| Term | Meaning |
| --- | --- |
| Networking service | Privileged supervised `warperd` process owning the network engine, instance lock, journal, reconnects, and session lifecycle |
| Desktop client | Ordinary-user Tauri application controlling/observing the service; its lifetime does not own routing |
| Managed configuration | Approved protected service snapshot and credential material, distinct from a source/import YAML file in a user's home |
| Control readiness | Local API can report state; distinct from OS service approval and a session being Connected |
| Session readiness | Backends, packet handlers, exemptions, routes, and DNS have passed the network startup barrier |
| Backend | One configured SSH, SOCKS5, or WireGuard instance with an ID and explicit transport/address-family capabilities |
| Captured flow | Host TCP connection or UDP association accepted from the TUN with original source/destination metadata |
| UDP association | Bounded ownership of UDP datagrams sharing an original source/destination tuple and selected backend; expiry ends that ownership without implying a wire-level connection |
| Capture route | Owned kernel route that directs destination packets to the TUN; distinct from backend-selection policy |
| Route lease | Time-bounded routing ownership derived from a released DNS address; its retention covers dependency TTL or connection grace, independently of DNS cache freshness |
| Logical lease key | Backend, normalized DNS question/type/class, and endpoint IP identifying one budgeted routing lease; renewals of that key coalesce |
| Retained DNS state | Lease/cache records, names, provenance, indexes, and expiry storage, with global count/byte admission independent of kernel route count |
| Route grace | Configurable minimum capture-route retention after DNS response handoff, including for zero-TTL answers; it never raises a wire/cache TTL |
| Pending-response reference | Temporary ownership pin keeping all required routes available until response handoff or cancellation |
| Service-binding endpoint | Effective HTTPS/SVCB target and its client-usable addresses, including hints and related address records, assigned to the original selected backend |
| Static route | Configured CIDR assignment installed independently of DNS discovery |
| Dynamic route | Destination assignment discovered from a selected backend's DNS answer |
| Physical transport exemption | Verified routing/socket mechanism keeping backend endpoints and direct DNS outside capture loops |
| Direct upstream | Real physical-network DNS resolver used for bootstrap and unmatched forwarding, never a selected-backend failure fallback |
| Split DNS | System resolver policy sending only configured domains to warper |
| Global DNS forwarding | System resolver catch-all policy sending unmatched DNS to warper; more-specific external policies may still apply |
| Host-facing stack | Userspace adapter accepting captured flows and returning packets to the host |
| Active tunnel stack | Userspace IP stack creating outbound TCP/UDP sockets inside WireGuard |
| Path MTU (PMTU) | Smallest link MTU along a packet's path; distinct from the configured host-facing or tunnel interface MTU |
| Commit | Handler publication, verified kernel acknowledgement, and recorded ownership completed before releasing a dynamic positive DNS answer |
| Recovery journal | Durable intent/ownership state used to reconcile partial mutations after startup failure, crash, or restart |
| Stub / fake / mock | Fixed-answer trait implementation / working in-memory implementation / verifier of programmed expectations |

Domain discovery selects IP destinations. It does not retain hostname
identity in later packets or cover every cached/application-managed DNS path.
