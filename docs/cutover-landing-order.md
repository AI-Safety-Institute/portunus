# gRPC cutover — landing order, pre-flip checklist, and rollback

This is the single consolidated ordering document for landing portunus #19 and
cutting traffic over to the blue (Envoy gRPC sidecar) fleet. It corrects two
errors that circulated in earlier PR bodies (the `num_chunks` sentinel location
and the WebSocket close-code claim) — treat this document as authoritative over
any PR-body prose it contradicts.

## 1. Portunus repo landing order

Land in this order, rebasing each onto the previous:

1. **#34** — Envoy 1.31 → 1.36 base-image bump (de-risks the jump alone).
2. **#35** — SIGTERM drain in `entrypoint.sh` (ships the drain to *current*
   prod first). ⚠️ #35 sets `DRAIN_TIME_S=60` but the **legacy** proxy stack's
   ECS `stopTimeout` is still **30s** — the drain gets SIGKILL'd (exit 137) at
   ~28s until the stopTimeout is raised. The akp PR that bumps the legacy
   `.portunus-source` ref **must also raise the legacy `stop_timeout` to 120s**
   (blue already locks 120s via synth test); land them as one change.
3. **#31 (rebased)** — supply-chain pinning, with digests **re-resolved for
   v1.36.0** and for #19's new multi-stage `portunus/Dockerfile` base images.
   ⚠️ #31 and #34/#19 collide textually on `proxy/Dockerfile`'s `FROM` line.
   The correct resolution is always **v1.36.x, digest-pinned**. Both the proxy
   image build (`RUN envoy --version | grep -q '/1\.36\.'`) and
   `entrypoint.sh` now assert the running version, so a bad resolution turns
   red instead of shipping the 1.31 shutdown-SIGSEGV Envoy silently.
4. **models.py ports on the #19 branch, before rebase** — #17
   (`vnd.amazon.eventstream` decode), #24 (truncation guard; closed-unmerged,
   port by hand), #26 (Brotli — the `Brotli>=1.1.0` runtime dep is already in
   `portunus/pyproject.toml`), **and #36** (`zlib.error` on corrupt gzip —
   missing from earlier checklists). `portunus/tests/test_models_decode.py`
   must be restored on the branch first so a forgotten port fails CI.
5. **#19** (rebased on #22) — this PR.

## 2. akp (api-key-proxy) deploy order — all BEFORE any cutover flip

`aisitok #38 → akp #154, #156, #155 → akp #152 (+#158) → akp #136 → akp #159`

### The `num_chunks=0` sentinel lives in akp #154, NOT #136

Earlier prose (including #19's PR body) said the Glue-side sentinel handling
("treat `num_chunks=0` as *derive total at aggregation time*") was "folded into
akp #136". **akp #136's own body says it was split out to akp #154 and #136
touches zero ETL files.** The blue fleet emits `num_chunks=0` on **every** HTTP
body record, unconditionally. If a provider is flipped while the old reassembly
is live, the legacy ETL drops every chunk past `chunk_id=0` — **silent,
per-provider, 100% HTTP token-usage loss** until someone notices the usage
graph dip.

**Tripwire (do not rely on the runbook prose):** the cutover is just a
synth-time env var (`CUTOVER="anthropic=blue"`), so add a mechanical guard —
the ETL deploy (#154) writes an SSM parameter / stack export
(e.g. `portunus-etl-sentinel-version`), and akp's `_parse_cutover` refuses to
synthesise a shadow rule unless it is importable. Until that lands, the flip
runbook MUST include an explicit "verify akp #154 is deployed to this
environment" step, and a first-hour canary alarm on body-record ingest rate
per cut-over provider (>X% drop vs pre-flip baseline).

### Platform changes that must land before the bake — akp #177 is the gate

The platform-side fixes exist ONLY in the **DRAFT akp PR #177**
(`AI-Safety-Institute/api-key-proxy#177`, branch
`danl/portunus-proxy-ops-hardening`, based on #136's branch). Until #177 is
**merged and deployed** to an environment, none of the drain/detection work in
this repo functions there — the 10s deregistration delay still cuts every
stream, containers still stop simultaneously, and the ALB still health-checks
`/ping` (Envoy liveness only).

> **HARD LANDING GATE: do not set `CUTOVER` for ANY provider in an
> environment until akp #177 is merged (or folded into #136) and deployed to
> that environment.** Preferred: fold #177's commits into #136 itself so the
> blue fleet cannot exist without them — a #136-without-#177 deploy is exactly
> the topology every reproduced C3 failure ran against. Add "verify #177
> content deployed (task def has Envoy→Portunus DependsOn + target group has
> `deregistration_delay=120` + health check path `/healthz`)" to the flip
> runbook alongside the #154 check in §2.

See `shared/akp-changes.md` for the precise change spec. Summary:

- **ALB `deregistration_delay` ≥ `DRAIN_TIME_S`** (60–120s) on the proxy
  target groups. platform-lib-cdk hardcodes 10s and ECS deregisters *before*
  SIGTERM, so today the ALB severs every stream older than ~10s before the
  Envoy drain even starts. Compose tests cannot catch this (no ALB).
- **ECS `container_dependencies`: Envoy `dependsOn` Portunus `HEALTHY`** so
  ECS stops Envoy *first* and Portunus only after Envoy exits. Without it both
  get SIGTERM simultaneously: Portunus exits at grace (~30s) while Envoy drains
  to 60s → the drained tail is proxied *unobserved* (silent audit gap) and
  mid-drain requests 403. Safe to depend on because the ECS liveness probe
  targets the Redis-independent `""` health service (below).
- **ALB health check → `/healthz`** (not `/ping`): `/healthz` is gated on
  Portunus's **`"readiness"`** gRPC health service (Redis-derived, debounced),
  so a dead — or SERVING-but-denying (Redis-down) — Portunus is pulled from
  ALB rotation in seconds. **Liveness/readiness are split deliberately**: the
  ECS container probe (`grpc_health_probe`, service `""`) checks liveness
  only (listener up, not draining, Redis-independent), so a correlated Redis
  outage takes the fleet out of rotation but does NOT ECS-recycle it — which
  would otherwise deadlock against the container dependency above.
- **Publish-queue flush-reserve + byte-bounding, redaction-denylist
  restoration** (portunus-side, this repo) and a **task-stop disruption test**
  asserting Portunus-first stop order and the observed WS close code.

## 3. WebSocket close semantics — the honest version

On drain-budget expiry and at the 55-min `max_stream_duration` cap, WS clients
receive a **TCP FIN → close code 1006 (abnormal closure)**, *not* a clean
`1001 Going Away`. Portunus cannot inject a close frame: it is not in the WS
data path (`observability_mode: true` — Envoy ignores its responses), and
Envoy has no close-frame drain either. A clean 1001 requires a WASM (or Lua)
close-frame injector — **tracked as a follow-up, not delivered by this stack**.
What IS delivered: frames flow until budget expiry, and 1006 triggers SDK
reconnect-with-backoff (an improvement over today's instant RST, but slower
than the reconnect-immediately behaviour a 1001 would give). Any PR body or
runbook claiming "Portunus emits WS 1001 before terminating" is wrong; sign
off on 1006-at-expiry explicitly or build the WASM filter before calling the
zero-downtime invariant done.

## 4. Rollback — it is NOT "flip the ALB rule back"

The ALB shadow rule is CDK-managed and **re-asserted on every deploy** (by
design — that is what fixed the old "manual flip silently reverted" failure).
Consequences:

- **Sanctioned rollback** = remove the provider from `CUTOVER` (a synth-time
  env var in the deploy pipeline) **and run the deploy pipeline**. Expect
  minutes-to-tens-of-minutes, and note it depends on CI/CD being healthy.
  Pre-stage a one-click "rollback" pipeline run per provider before each flip.
- **The manual `aws elbv2 modify-rule` flip is a trap**: it works for seconds
  worth of relief, then the next deploy of *anything* silently re-cutovers the
  provider. If used in an emergency, it MUST be paired with an immediate
  `CUTOVER` edit; the incident runbook should otherwise forbid it.
- **Data-level rollback is safe** (verified): the legacy KDS audit path is
  untouched until akp #159; legacy and blue Redis cache keys are disjoint
  (rollback = a cold-cache STS/Secrets burst, not misbehaviour); blue-era
  audit stays readable in the shared Glue tables.
- **Exception — cache flush**: the blue runbook's `FLUSHDB` hits the *shared*
  ElastiCache and also nukes the legacy fleet's cache. See the blast-radius
  warning in `docs/runbooks/flush-auth-cache.md`.
