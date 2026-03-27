# WebSocket Relay Load Test Results

Test date: 2026-03-27
Test script: `scripts/loadtest-ws.js` (in api-key-proxy repo)
Target: `wss://portunus-ws-test.apps.aisi-test.org.uk/ws/echo`
Profile: Ramping 2 -> 20 -> 50 -> 100 -> 25 -> 0 VUs over 7 minutes
Messages per connection: 10 (1KB each)

## Results by Portunus Backend Scale

| Metric | Cold (4 instances) | Warm (auto-scaled) | 80 instances |
|--------|-------------------|-------------------|--------------|
| **Iterations** | 2,453 | 11,551 | **27,665** |
| **Errors** | 71 | 25 | **39** |
| **Upgrade latency p95** | 6.11s | 2.59s | **557ms** |
| **Message RTT median** | 4.95s | 402ms | **382ms** |
| **Message RTT p95** | 27.5s | 10.95s | **1.13s** |
| **Throughput (msg/s)** | 111 | 548 | **1,313** |
| **Total messages** | 49,080 | 231,020 | **553,380** |

## Key Findings

- **Autoscaling works but takes ~5 minutes to react** — cold starts with 4 instances saturate CPU at 100 concurrent connections, causing upstream failures. Once scaled, performance is excellent.
- **Per-instance sweet spot is ~25 concurrent connections** — keeps CPU well under saturation. Configurable via `WS_MAX_CONNECTIONS_PER_INSTANCE`.
- **At production scale (80 instances), the system handles 100 concurrent WS connections at 1,313 msg/s** with sub-second median latency.
- **Errors are concentrated at peak ramp** — the 39 errors at 80 instances all occurred during the 100 VU peak, not during steady-state.
- **ws-echo bottleneck at low scale** — the echo server (256 CPU, 512 MiB) needed autoscaling to avoid being the bottleneck in load tests.
