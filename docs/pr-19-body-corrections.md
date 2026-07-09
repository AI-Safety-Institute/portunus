# PR #19 body — required corrections (apply before merge)

The current #19 PR body overpromises in three places. The text below is
drop-in replacement prose; the mechanics behind each correction are in
`docs/cutover-landing-order.md`. (This file exists because the review branch
is integrated by the maintainer — whoever edits the PR body should apply these
and then delete this file.)

## 1. WebSocket drain close code — replace the "WS 1001" claim

**Delete** (from the drain narrative + the mermaid diagram):

> Portunus emits a WebSocket 1001 "Going Away" close before terminating, so
> SDKs reconnect immediately instead of backing off.

**Replace with:**

> During drain, established WebSocket sessions keep flowing until the client
> closes or the `DRAIN_TIME_S` budget expires; at expiry (and at the 55-min
> `max_stream_duration` cap) the connection is torn down with a TCP FIN, which
> clients observe as **close code 1006 (abnormal closure)** and recover via
> SDK reconnect-with-backoff. Portunus cannot inject a close frame — it is not
> in the WS data path (`ext_proc observability_mode: true`; Envoy ignores its
> responses) — and Envoy has no close-frame drain. A clean **1001 would
> require a WASM filter, tracked as a follow-up** (see the admissions in
> `proxy/entrypoint.sh` and `proxy/envoy.yaml`). This is still a strict
> improvement over the pre-drain behaviour (instant RST mid-frame).

Also update the mermaid sequence diagram: `Side->>Client: WS 1001 "Going
Away"` → `Envoy->>Client: TCP FIN (client sees 1006, SDK reconnects)`.

## 2. `num_chunks=0` sentinel location — #136 → #154

**Delete:**

> the Glue `num_chunks=0` sentinel handling is folded into akp #136 (from the
> closed #137/#140)

**Replace with:**

> the Glue `num_chunks=0` sentinel handling was **split out to akp #154**
> (akp #136 touches zero ETL files — see #136's own description). **akp #154
> must be deployed before any provider is flipped**, or the legacy reassembly
> silently drops every HTTP body chunk past `chunk_id=0` for that provider.
> The flip runbook carries an explicit "verify #154 deployed" step until the
> synth-time SSM tripwire lands (see `docs/cutover-landing-order.md` §2).

## 3. Rollback paragraph — replace "flip the ALB rule back"

**Delete:**

> Rollback = flip the ALB rule back; no DNS or customer-config change.

**Replace with:**

> Rollback = remove the provider from `CUTOVER` and run the deploy pipeline
> (no DNS or customer-config change, but it is a CDK deploy, not a rule flip —
> the shadow rule is re-asserted every deploy, so a manual `elbv2` edit is
> silently re-cutover by the next deploy unless `CUTOVER` is edited too).
> Data-level rollback is safe: the legacy audit path is untouched until akp
> #159 and cache key schemes are disjoint. Caveat: the cache-flush runbook's
> `FLUSHDB` is fleet-wide across BOTH fleets (shared ElastiCache) — see
> `docs/runbooks/flush-auth-cache.md`.

## 4. Manual-port checklist — add #36

The models.py port list must read **#17 + #24 + #26 + #36** (the #36
`zlib.error` corrupt-gzip catch was missing from the checklist), with
`portunus/tests/test_models_decode.py` restored on the branch so the port is
CI-enforced rather than checklist-enforced.
