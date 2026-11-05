# Flush the Portunus auth cache

## When

After rotating or revoking credentials, when waiting for cached results to
expire is too slow. A cached result can otherwise live for up to
min(`CACHE_DURATION`, the caller's credential expiry).

Update the credentials first: a flush does not revoke upstream credentials,
end in-flight requests or WebSocket sessions, or cancel authentication already
in progress.

## How

Run `portunus flush-auth-cache --yes` **once**, as a one-off task of the
Portunus task definition with the command overridden:

```bash
aws ecs run-task \
  --cluster <cluster> \
  --task-definition <portunus-task-definition> \
  --launch-type FARGATE \
  --network-configuration 'awsvpcConfiguration={subnets=[<subnet-id>],securityGroups=[<security-group-id>]}' \
  --overrides '{"containerOverrides":[{"name":"<portunus-container>","command":["portunus","flush-auth-cache","--yes"]}]}'
```

The command prints the Redis host, port and database it flushes (never the
password), then `Auth cache flushed.` and exits 0. A non-zero exit means
nothing was confirmed as flushed: check the container log and Redis
connectivity before retrying. If the task definition has other essential
containers, they keep the one-off task running; stop it once the flush has
exited.

Alternatively, use ECS Exec into any one running task and run
`portunus flush-auth-cache` there; without `--yes` it asks for confirmation.

The flush hits the shared Redis, so one run applies to every task at once,
however many there are. It flushes database 0, the only Redis database
Portunus uses (the database number is not configurable).

## Important: in-process caches are not wiped

Each task also keeps an in-process cache in front of Redis, which the flush
does not touch. Its entries live for at most `AUTH_LOCAL_CACHE_TTL_SECONDS`
(default 30 s), so for up to 30 s after the flush some tasks may still use the
old credential. If that is too long, restart the tasks.

## Afterwards

Expect a short spike in STS and Secrets Manager calls while the caches refill.

## Warning

`FLUSHDB` deletes every key in that Redis database, including other
applications' keys if they share it.
