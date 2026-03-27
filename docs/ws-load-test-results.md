# Load Test Results: WebSocket vs HTTP

Test date: 2026-03-27
Staging environment: 80 Portunus backend instances
VU profile: Ramping 2 -> 20 -> 50 -> 100 -> 25 -> 0 over 7 minutes

## HTTP vs WebSocket Comparison (80 instances)

| Metric | HTTP (1KB POST) | WebSocket (10x 1KB echo) |
|--------|-----------------|--------------------------|
| **Iterations** | 85,398 | 27,665 |
| **Success rate** | 98.7% | 99.9% |
| **Errors** | 1,129 | 39 |
| **Latency median** | 92ms | 452ms |
| **Latency p95** | 325ms | 1.49s |
| **Throughput** | 203 req/s | 66 iter/s (1,313 msg/s) |
| **Data transferred** | 96 MB sent | 366 MB sent |

Note: Each WS iteration opens a connection, sends 10 messages, receives 10 echoes, and closes — so it does ~20x the work of a single HTTP request. Adjusted for messages, WS throughput (1,313 msg/s) is ~6.5x HTTP (203 req/s).

## WebSocket Results by Portunus Backend Scale

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

- **WS relay performs well alongside HTTP** — at 80 instances, both protocols handle 100 concurrent VUs comfortably.
- **Autoscaling works but takes ~5 minutes to react** — cold starts with 4 instances saturate CPU at 100 concurrent connections. Once scaled, performance is excellent.
- **Per-instance sweet spot is ~25 concurrent WS connections** — keeps CPU well under saturation. Configurable via `WS_MAX_CONNECTIONS_PER_INSTANCE`.
- **At production scale (80 instances), the system handles 100 concurrent WS connections at 1,313 msg/s** with sub-second median latency.
- **Errors are concentrated at peak ramp** — not during steady-state.
- **WS connections are long-lived but mostly idle in real usage** — the load test hammers messages continuously, which is worst-case. Real OpenAI Realtime API usage would have much lower per-connection CPU cost.
