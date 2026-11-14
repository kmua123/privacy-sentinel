# Privacy Guard native core

The native core uses Mihomo v1.19.33, commit
`3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`. The `mihomo` directory contains
that upstream source and the small ingress-guard extension in
`listener/sing_tun/admission.go` and `dns.go`. Its GPL-3.0 license is retained.

`guardcore.aar` is generated for Android arm64-v8a and x86_64. It exposes
`guardcore.Guardcore` and `guardcore.Callbacks` to the host APK. The APK supplies
its VpnService TUN descriptor. The core duplicates it and owns only the duplicate.

Every TCP connection and UDP packet/session enters the host's admission callback
before Mihomo DNS hijacking, sniffing, rules, DIRECT, proxy, or ZeroTier paths.
The original source/destination addresses are retained for Android UID lookup.
Blocked and pending attempts are closed/dropped, and the APK handles approval
notifications asynchronously. The originating application must retry after an
approval. Android socket protection failure is fatal to that outbound socket.

The host calls `CloseConnections()` when a restrictive decision changes or a temporary
grant expires. This closes active TCP and UDP sessions conservatively, including
other applications' sessions. TCP/UDP ingress cannot finish an admission across
a concurrent invalidation. The core disables external listeners, remote control
ports, NTP, and automatic geodata updates. Subscription processing is performed
by the APK and is limited to selected proxy/routing fields.

Build requirements are Go 1.27.4, Android NDK r27d, Android SDK, and JDK 17+.
The original downloaded Go Windows archive has SHA-256
`178ab98950ac69ab25069307dc6ade79f3816e414cce95b4da166a115cde1e7e`.
The toolchain lives under `.tools`, outside Go's package traversal.
Run `build.ps1 -JavaHome ...` to run host regression tests and build the AAR.
Dependencies are pinned by `go.mod` and `go.sum`. Build tags keep gVisor,
Mihomo proxy protocols, WireGuard, and native ZeroTier. EasyTier and Tailscale
are disabled in this build because the user's existing ZeroTier is the home
network.

The tests exercise admission before actual DNS-handler entry points, denied
TCP/UDP/UDP sessions with IPv4/IPv6, UID metadata, session revocation, a racing
admission, changed UDP destinations, and refused socket protection. Host tests
do not establish real-phone network, proxy subscription, or ZeroTier reachability.

`TrafficSnapshot()` reports aligned UID/payload counters from the active core,
including open and closed forwarded flows without settling them twice. A fresh
epoch on each start prevents comparison with a previous VPN session. It excludes
blocked attempts, the guardian itself, nested proxy overhead and traffic outside
this VPN. `HomeStatus()` returns public node/network status, addresses and path
counts only. A ready network is not proof a home service is reachable. The APK
uses an explicit gVisor home IP stack in 0.2.1.

In 0.2.2, the disabled ICMP path returns `tun.ErrDrop` in
`mihomo/listener/sing_tun/prepare.go`; it must not fall through to the TUN's
synthetic echo reply. ICMP is not forwarded through the private home overlay.
`HomeStatus()` reports the configured `tcpFallbackMode`, but the upstream
transport has no public relay-connected snapshot, so the API makes no such
connection claim. The smart-split integration test decodes the exact packaged
MRS files and validates routing and DNS against the Java-generated fixtures.
