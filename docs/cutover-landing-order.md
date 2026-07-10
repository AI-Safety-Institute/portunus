# gRPC cutover — landing order, pre-flip checklist, bake plan, rollback

The single authoritative ordering document for landing portunus #19 and cutting
traffic over to the blue (Envoy gRPC sidecar) fleet. It supersedes the ordering
prose in any PR body it contradicts — including #19's own (corrections to apply
to that body are in the appendix).

**Status snapshot (2026-07-09).** The akp ETL prerequisites are **merged**
(see §2 — note the PR renumbering). Not yet landed: the portunus stack itself
(§1), akp #177 (the platform-topology gate, still a draft), akp #155 (Glue
failure alarm), and akp #159 (teardown, last). No `CUTOVER` flip is permitted
until every §3 box is ticked for the target environment.

## 1. Portunus repo landing order

**Simplified (2026-07-10): #22 was absorbed into #19 and #31 is already on
`main`.** #19 is now based on `main` (not stacked on #22), and current `main`
has been merged into its branch — `mergeable_state: clean`. So the "rebase the
#22→#19 stack + hand-port decode + resolve #31 collision" dance is **done**;
what remains:

1. **#34** — Envoy 1.31 → 1.36 base-image bump. **Optional-but-recommended to
   land first for *current-prod* value** (de-risks the jump alone). #19 already
   carries v1.36, so if you skip straight to #19 this folds in.
2. **#35** — SIGTERM drain in `entrypoint.sh`. Also standalone current-prod
   value (fixes the mid-stream-cut-on-deploy incident class). ⚠️ #35 sets
   `DRAIN_TIME_S=60` but the **legacy** proxy stack's ECS `stopTimeout` is still
   **30s** — the drain gets SIGKILL'd (exit 137) at ~28s until it's raised. The
   akp PR that bumps the legacy `.portunus-source-legacy` ref **must also raise
   the legacy `stop_timeout` to 120s** (blue already locks 120s via synth test);
   land them as one change.
3. **#19** (based on `main`) — this PR. Now self-contained: it carries the
   Kinesis→Firehose migration (absorbed from the closed #22), Envoy 1.36, the
   drain work, **and** the `models.py` decode ports (#17 + #24 + #26 + #36, with
   `test_models_decode.py` restored on the branch — a forgotten port fails CI,
   not a checklist). `Brotli>=1.1.0` is in `portunus/pyproject.toml`; akp #163
   (merged 2026-07-07) gives Glue the `brotli` package. The Envoy-version
   tripwires (build-time `envoy --version`, runtime `entrypoint.sh` re-assert,
   akp CI `test_envoy_dockerfile_pins_1_36`) guard against a 1.31 regression.

> **Absorbed / already-landed:** #22 (closed — its Firehose migration lives in
> #19) and #31 (supply-chain pinning — already merged to `main`; its Envoy pin
> was v1.31, deliberately overridden to v1.36 on the #19 branch).

**At #19-merge:** tag a release and **repin akp #136's `pyproject.toml`** from
the `dl/grpc-ext-authz-ext-proc-services` branch to that tag *before* the
branch is deleted, or akp's synth (`portunus.models` imports) breaks.

## 2. akp (api-key-proxy) order — ETL merged; #177 is the remaining gate

### 2a. ETL prerequisites — MERGED (verify deployed, don't re-land)

⚠️ **PR renumbering** — earlier prose (including #19's body and older
revisions of this doc) cites akp #154/#156/#152/#158. All four are
**closed unmerged**; the work landed as a stacked split, all merged to akp
`main` 2026-07-07/08 (and akp auto-deploys `main` to prod):

| Merged PR | Carries | Replaces |
|---|---|---|
| aisitok **#38** (2026-06-30) | OpenAI Realtime `response.done` WS usage parsing | — |
| akp **#163** | `brotli` in the Glue log-analysis job (unblocks portunus #26) | — |
| akp **#164** | Off-heap body reassembly **including the `num_chunks=0` sentinel branch** | #137 → #154 → #152 |
| akp **#165** | Fail-closed dedup + whole-second window floor | #156 → #152 |
| akp **#166** | `portunus_frames` WS usage table (HTTP-only joined-logs) | #139 → #152 |

(#158's quarantine mechanism was dropped — off-heap reassembly is the OOM fix.)

**Why the sentinel matters:** the blue fleet emits `num_chunks=0` on **every**
HTTP body record. A pre-#164 ETL drops every chunk of such a body, and the
inner join then eliminates the whole record — **silent, per-provider, 100%
HTTP token-usage loss** for any provider flipped against an old ETL. The flip
runbook therefore verifies the *deployed* Glue job version (§3), not PR state.

### 2b. Remaining, in order

1. **akp #155** (open) — Glue failure/timeout on the CW dashboard. Land before
   the bake: it's the alarm that surfaces ETL breakage during it.
2. **akp #136** (draft) — blue fleet + declarative ALB cutover. Merge is a
   traffic no-op (`DEPLOY_BLUE_SLOT` opt-in, `CUTOVER` empty). **Gate: fold
   akp #177 into #136** (or merge #177 first) — see below.
3. Per-provider `CUTOVER` flips (§4), each gated on §3.
4. **akp #159** — legacy-fleet teardown. Post-cutover only, after green-drain;
   it removes the data-level rollback safety net (§5).

### 2c. HARD LANDING GATE — akp #177

The platform-topology fixes exist ONLY in **draft akp #177**
(`danl/portunus-proxy-ops-hardening`, based on #136's branch):

- **ECS `container_dependencies`**: Envoy `DependsOn` Portunus `HEALTHY`, so
  ECS stops Envoy *first*. Without it both SIGTERM simultaneously: Portunus
  exits at grace while Envoy drains on → the drained tail is proxied
  *unobserved* (silent audit gap, reproduced) and mid-drain requests 403.
- **ALB `deregistration_delay` 10s → 120s**. ECS deregisters *before* SIGTERM,
  so the platform-lib-cdk 10s default severs every stream older than ~10s
  before the 60s Envoy drain even starts. Compose tests cannot catch this.
- **ALB health check `/ping` → `/healthz`** (interval 10s, thresholds 2/2).
  `/healthz` is gated on Portunus's **`"readiness"`** gRPC health service
  (Redis-derived, debounced), so a dead — or SERVING-but-denying (Redis-down)
  — Portunus is pulled from rotation in ~20s instead of 403ing for ~105s+.
  **Liveness/readiness are split deliberately**: the ECS container probe
  (`grpc_health_probe`, service `""`) is liveness only (Redis-independent), so
  a correlated Redis outage de-pools the fleet from the ALB but does NOT
  ECS-recycle it — recycling would deadlock against the container dependency.
- **`GRPC_GRACEFUL_SHUTDOWN_SECONDS=90`** (< 120s stop_timeout) plus synth
  tests locking all of the above and the proxy-key secret wiring.

> **Do not set `CUTOVER` for ANY provider in an environment until #177 is
> merged (preferred: folded into #136 so the blue fleet cannot exist without
> it) and deployed to that environment.** A #136-without-#177 deploy is
> exactly the topology every reproduced C3 failure ran against.

## 3. Pre-flip checklist — ALL boxes, per environment, before ANY flip

- [ ] **ETL sentinel live**: the Glue `process_raw_data` job in this
  environment is a post-#166 version (akp `main` ≥ 2026-07-08). Until the SSM
  tripwire (below) exists, this is a mandatory manual check.
- [ ] **#177 content deployed** — verify the *live* resources, not PR state:
  task def has Envoy→Portunus `DependsOn HEALTHY`; target group has
  `deregistration_delay.timeout_seconds=120`; ALB health check path is
  `/healthz`; Portunus env has `GRPC_GRACEFUL_SHUTDOWN_SECONDS=90`.
- [ ] **Portunus image** is the post-review #19: liveness/readiness split,
  `/healthz` gated on `"readiness"`, redaction denylist restored,
  byte-bounded publish queue + flush reserve, Envoy 1.36 tripwires.
- [ ] **akp `pyproject.toml` repinned** to #19's release tag (not the branch).
- [ ] **First-hour ingest canary armed**: alarm on the blue slot's
  request/response-body Firehose `IncomingRecords` dropping >50% vs the
  provider's pre-flip baseline within the first hour → immediate-rollback
  signal.
- [ ] **Rollback pre-staged**: a one-click pipeline run per provider with the
  provider removed from `CUTOVER` (§5).

**SSM tripwire (specced in #177's body, not yet built):** the ETL deploy
writes `/portunus/etl-sentinel-version` (≥1 = sentinel live) and
`PortunusFleetStack` refuses to synthesise a shadow rule unless it resolves —
turning a flip-against-stale-ETL into a pipeline failure instead of silent
token loss. Build it before the flips get routine; until then the checklist
line above is the only guard. (SSM lookups cache in `cdk.context.json`;
`cdk context --reset` once after the parameter first appears.)

## 4. Per-provider bake plan

Flip one provider at a time: **Anthropic first** (highest volume, exercises
the signing path), bake **24–48h**, then **OpenAI**, then the remainder —
`spark-bedrock` and the NCSC pair (`anthropic-ncsc`, `openai-ncsc`) **last**:
the middleware-fronted NCSC proxies keep `health_check=None`, so a broken
Portunus there is detected only by the ~105s ECS probe (§6).

Per flip:

1. Record the provider's pre-flip baselines: body-stream `IncomingRecords`,
   4xx/5xx rate, p99 latency.
2. Add the provider to `CUTOVER` (synth-time env var) and run the deploy
   pipeline. Confirm the shadow rule (priority band 1–99) serves blue.
3. First hour: watch the ingest canary, per-target-group 403/5xx rate, and
   `/healthz` flaps.
4. Through the bake: trigger one deploy/scale-in and confirm drain behaviour
   (no mid-stream cuts <60s, no audit-loss ERROR with a healthy sink);
   watch the Portunus container `MemoryUtilization` alarm (~75%).
5. Bake clean 24–48h before the next provider.

## 5. Rollback — it is NOT "flip the ALB rule back"

The ALB shadow rule is CDK-managed and **re-asserted on every deploy** (by
design — that is what fixed the old "manual flip silently reverted" failure).
Consequences:

- **Sanctioned rollback** = remove the provider from `CUTOVER` **and run the
  deploy pipeline**. Expect minutes-to-tens-of-minutes, and note it depends on
  CI/CD being healthy. Pre-stage a one-click rollback run per provider before
  each flip (§3).
- **The manual `aws elbv2 modify-rule` flip is a trap**: it buys seconds of
  relief, then the next deploy of *anything* silently re-cutovers the
  provider. If used in an emergency, it MUST be paired with an immediate
  `CUTOVER` edit; the incident runbook should otherwise forbid it.
- **Data-level rollback is safe until akp #159** (verified): the legacy KDS
  audit path is untouched; legacy and blue Redis cache keys are disjoint
  (rollback = a cold-cache STS/Secrets burst, not misbehaviour); blue-era
  audit stays readable in the shared Glue tables. #159 removes this net —
  hence it lands last, post-green-drain.
- **Exception — cache flush**: the blue runbook's `FLUSHDB` hits the *shared*
  ElastiCache and also nukes the legacy fleet's cache — including the fleet
  you are rolling back *to*. See `docs/runbooks/flush-auth-cache.md`.

## 6. Known gaps — sign off explicitly, don't rediscover at 2am

- **WS drain close code is 1006, not 1001.** On drain-budget expiry and at
  the 55-min `max_stream_duration` cap, WS clients get a TCP FIN → **close
  code 1006 (abnormal closure)** and recover via SDK reconnect-with-backoff.
  Portunus cannot inject a close frame (`observability_mode: true` — it is
  not in the WS data path) and Envoy has no close-frame drain; a clean 1001
  needs a WASM/Lua filter — **a follow-up, not delivered by this stack**.
  Still a strict improvement over today's instant mid-frame RST. Any prose
  claiming "Portunus emits WS 1001" is wrong (appendix, correction 1).
- **NCSC middleware detection gap**: `anthropic-ncsc` / `openai-ncsc`
  health-check the nginx allowlist sidecar, not `/healthz`; a broken Portunus
  there rides the ~105s ECS probe. Acknowledged follow-up in #177.
- **SSM tripwire not built** (§3) — flip ordering vs ETL is checklist-enforced
  until it is.
- **Legacy drain SIGKILL**: until the legacy-ref-bump akp PR raises legacy
  `stop_timeout` to 120s (§1.3), legacy tasks SIGKILL the #35 drain at ~28s.
  Bounded, known, strictly better than no drain.

## Appendix — #19 PR-body corrections (apply to the PR body, then delete this section)

1. **WS close code.** Delete "Portunus emits a WebSocket 1001 'Going Away'
   close before terminating, so SDKs reconnect immediately…". Replace with
   the §6 semantics (frames flow until budget expiry; TCP FIN → 1006; SDK
   reconnect-with-backoff; 1001 = WASM follow-up). In the mermaid diagram:
   `Side->>Client: WS 1001 "Going Away"` → `Envoy->>Client: TCP FIN (client
   sees 1006, SDK reconnects)`.
2. **Sentinel location.** Delete "the Glue `num_chunks=0` sentinel handling is
   folded into akp #136 (from the closed #137/#140)". Replace with: the
   sentinel landed via **akp #164** (the #137→#154→#152→#164 lineage; #136
   touches zero ETL files) and is on akp `main` as of 2026-07-08; the flip
   runbook still verifies the deployed ETL version per environment (§3).
3. **Rollback.** Delete "Rollback = flip the ALB rule back; no DNS or
   customer-config change". Replace with: rollback = remove the provider from
   `CUTOVER` and run the deploy pipeline (no DNS/customer change, but it is a
   CDK deploy; a manual `elbv2` edit is silently re-cutover by the next deploy
   unless `CUTOVER` is edited too). Data-level rollback is safe until akp
   #159; `FLUSHDB` is fleet-wide across both fleets (§5).
4. **models.py port list** must read **#17 + #24 + #26 + #36**, with
   `portunus/tests/test_models_decode.py` restored on the branch (§1.5).
