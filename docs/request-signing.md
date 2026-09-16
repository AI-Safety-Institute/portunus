# Request-signing timeouts

KMS signing uses explicit SDK connection, read and retry limits so a stalled
request does not retain a worker through the SDK's longer default retry window.
The caller's credentials and the signed content are unchanged.

| Variable | Default | Meaning |
|---|---|---|
| `SIGNING_KMS_CONNECT_TIMEOUT_S` | `2` | Connection timeout per attempt, in seconds |
| `SIGNING_KMS_READ_TIMEOUT_S` | `5` | Socket read timeout per attempt, in seconds |
| `SIGNING_KMS_MAX_ATTEMPTS` | `2` | Total attempts, including the initial request |

These settings apply to the signing client independently of general AWS SDK
retry settings. Increasing them can outlast the proxy's request deadline and
delay shutdown; keep them within the deployment's request and termination
budgets. Standard SDK retry backoff also contributes to elapsed time.

Cancelling an asynchronous request does not terminate its running signing
thread. Python waits for running executor threads at process exit, including
after a nonblocking executor shutdown. The SDK limits let ordinary stalled
network operations finish, but they are not a strict wall-clock process-exit
guarantee: DNS resolution, repeated partial reads or other thread stalls can
outlast the asynchronous drain budget. The container's termination deadline
remains the final backstop.
