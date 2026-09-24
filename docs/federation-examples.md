# Federation worked examples

For a secret of type `anthropic_wif`, `openai_wif`, `openrouter_wif` or `gcp_wif`, Portunus mints a short-lived provider token instead of returning a stored key. The [README](../README.md#secret-formats) defines each type. This document walks one deployment through every provider with the same example values throughout:

| Value | Example |
|---|---|
| AWS account | `123456789012` |
| Federation role | `arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team` |
| Caller roles | `arn:aws:iam::123456789012:role/example-callers/*` |
| STS interface endpoint | `vpce-0123456789abcdef0` |
| STS issuer URL | `https://<uuid>.tokens.sts.global.api.aws`, shown under IAM → Account settings once outbound identity federation is enabled |
| Proxy hostnames | `<provider>.proxy.example.org` |

Portunus settings are at their defaults unless stated: `FEDERATION_ROLE_PATH_PREFIX=/portunus-fed/`, tag keys `portunus:user`, `portunus:principal`, `portunus:session`, `portunus:project`, `API_KEY_HEADER=authorization`, `API_KEY_PREFIX="Bearer "`. `FEDERATION_ALLOWED_ACCOUNT_IDS` lists `123456789012` and `FEDERATION_STS_ENDPOINT_URL` names the interface endpoint.

## The flow

1. **Encode.** `portunus encode-credentials <secret ARN>` assumes the caller's own role with a session policy and base64-encodes the temporary credentials with the secret ARN. See [Encoding a payload](#encoding-a-payload) and each provider's *Encode and call*.
2. **Request.** The client sends the payload in `API_KEY_HEADER` after `API_KEY_PREFIX`. The proxy's Lua filter POSTs `{"payload": ..., "target_host": <TARGET_HOST>}` to Portunus `/authorise`.
3. **Cache read.** Portunus looks the payload up in Redis (SHA-256 of the payload). A hit returns the cached token.
4. **Identity and secret.** On a miss: `GetCallerIdentity` with the payload credentials, `GetSecretValue` on the secret ARN, parse. The secret's `host` must equal the proxy's `TARGET_HOST`. See each provider's *Secret*.
5. **Federation role.** `federation_role_arn` must be in `FEDERATION_ALLOWED_ACCOUNT_IDS` and under `FEDERATION_ROLE_PATH_PREFIX`. Portunus assumes it with the caller's credentials at `FEDERATION_STS_ENDPOINT_URL` (`RoleSessionName` = the caller's IAM role name, `DurationSeconds` 3600). See [The AWS side](#the-aws-side).
6. **Identity proof.** `GetWebIdentityToken` from the federation session for the secret's `audience`, tagged with the four tag keys; for GCP the audience is the pool provider's resource name. Permissions in [The AWS side](#the-aws-side); parameters in each provider's *What Portunus sends*.
7. **Exchange.** The proof is posted to the provider's token endpoint, which checks it against a rule (Anthropic), mapping (OpenAI), policy (OpenRouter) or pool provider (GCP). See each provider's *Provider configuration*.
8. **Inject.** `/authorise` returns the token with `output_header: "authorization"` and `output_prefix: "Bearer "`. The proxy writes `authorization: Bearer <token>`, removes the inbound `API_KEY_HEADER` when it differs, and forwards.
9. **Cache write.** The token is cached until the earlier of `CACHE_DURATION` (86400 s unless set) and 60 s before it expires. Concurrent misses for one payload share one mint per process.

### Encoding a payload

```text
portunus encode-credentials SECRET_ARN [--policy FILE_OR_JSON] [--federation-role-path /portunus-fed/] [--session-name portunus]
```

`portunus` is the package's console script (`uv run portunus …` in this repo). It calls `GetCallerIdentity`, derives the caller's role ARN from the session ARN, and calls `AssumeRole` on that same role with `RoleSessionName` `portunus`, `DurationSeconds` 43200 and a session policy of two statements: `secretsmanager:GetSecretValue` on `SECRET_ARN`, and `sts:AssumeRole` on `arn:aws:iam::<caller account>:role/portunus-fed/*` (Sid `PortunusFederationAssumeRole`). `--policy` replaces the whole session policy; `--federation-role-path` changes the path in the default one; `--session-name` replaces the `RoleSessionName`. The caller role's trust policy must admit its own sessions and its `MaxSessionDuration` must be at least 12 h. The payload is `base64(JSON)` with `credentials` (`access_key_id`, `secret_access_key`, `session_token`), `expiration` and `secret_arn`.

The identity token's tags for such a payload: `portunus:principal` is the caller's role name, `portunus:session` is the session name, `portunus` by default, `portunus:user` is the caller's STS source identity when its session carries one, else the role name, and `portunus:project` is `<project>` for a role named `UserProfile_<name>_<project>`, else empty.

## The AWS side

One role per grant, under `/portunus-fed/<team>/`, named `portunus-fed-<grant>@<type>.<slug>` (role names are unique per account, so the scope is repeated in the name; the prefix lets the deployer's role-management policy match the role by name, see below). Three documents matter: the trust policy (which callers may assume it, and only through the STS endpoint Portunus uses), the inline policy (issue identity tokens for one audience, for at most 1800 s, tagged with the four keys) and a permissions boundary (a ceiling of those two STS actions). Callers need an identity policy allowing `sts:AssumeRole` on the prefix.

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: Portunus federation role for one grant.

Parameters:
  RoleName:
    Type: String
    Default: portunus-fed-example-grant@teams.example-team
  CallerRoleArnPattern:
    Type: String
    Default: arn:aws:iam::123456789012:role/example-callers/*
    Description: aws:PrincipalArn pattern of the roles that may assume the federation role.
  StsVpcEndpointId:
    Type: String
    Default: vpce-0123456789abcdef0
    Description: The STS interface endpoint Portunus uses (FEDERATION_STS_ENDPOINT_URL).
  ProviderAudience:
    Type: String
    Default: https://api.anthropic.com
    Description: The secret's audience.

Resources:
  FederationRoleBoundary:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Path: /portunus-fed/
      Description: Ceiling for Portunus federation roles.
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - sts:GetWebIdentityToken
              - sts:TagGetWebIdentityToken
            Resource: '*'

  FederationRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      Path: /portunus-fed/teams/example-team/
      MaxSessionDuration: 3600
      PermissionsBoundary: !Ref FederationRoleBoundary
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
            Action: sts:AssumeRole
            Condition:
              ArnLike:
                'aws:PrincipalArn': !Ref CallerRoleArnPattern
              StringEquals:
                'aws:SourceVpce': !Ref StsVpcEndpointId
      Policies:
        - PolicyName: IssueIdentityToken
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: sts:GetWebIdentityToken
                Resource: '*'
                Condition:
                  'ForAllValues:StringEquals':
                    'sts:IdentityTokenAudience':
                      - !Ref ProviderAudience
                  NumericLessThanEquals:
                    'sts:DurationSeconds': 1800
              - Effect: Allow
                Action: sts:TagGetWebIdentityToken
                Resource: '*'
                Condition:
                  'ForAllValues:StringEquals':
                    'aws:TagKeys':
                      - 'portunus:user'
                      - 'portunus:principal'
                      - 'portunus:session'
                      - 'portunus:project'

Outputs:
  FederationRoleArn:
    Value: !GetAtt FederationRole.Arn
```

Substitute the deployment's `FEDERATION_*_TAG_KEY` values for the four tag keys. Drop the `aws:SourceVpce` condition if Portunus reaches STS over the public regional endpoint. Whatever deploys the template needs its role-management permissions (`iam:GetRole`, `iam:DeleteRole`, `iam:PutRolePolicy`, …) on a name pattern as well as the path, `arn:aws:iam::123456789012:role/portunus-fed/*` and `arn:aws:iam::123456789012:role/portunus-fed-*`: IAM authorises by-name calls on a role that does not exist yet (the pre-create `GetRole`, a rollback `DeleteRole`) against `role/<name>` with no path.

### Caller identity policy

Attach to each caller role. The CLI's default session policy carries the same statement; a session's permissions are the intersection of the two.

```json
{
  "Sid": "PortunusFederationAssumeRole",
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/*"
}
```

### What breaks when a piece is missing

- Trust policy does not match the caller (`aws:PrincipalArn`), or the AssumeRole call did not arrive through `StsVpcEndpointId`: 403 `Could not assume federation role (AccessDenied)`.
- Caller identity policy lacks `sts:AssumeRole` on the prefix, or the payload was encoded with a session policy without it: the same 403.
- `MaxSessionDuration` below 3600: 403 `Could not assume federation role (ValidationError)`.
- `ProviderAudience` differs from the secret's `audience`: 403 `Could not issue identity token (AccessDenied)`.
- `sts:DurationSeconds` cap below 900 (Anthropic, OpenRouter, GCP) or 1800 (OpenAI): the same 403.
- `sts:TagGetWebIdentityToken` missing, or `aws:TagKeys` not listing every key Portunus sends: the same 403.
- Identity token requested for longer than the federation session's remaining life: 403 `Could not issue identity token (SessionDurationEscalationException)`. Portunus keeps the session at 3600 s, above every token lifetime it requests.
- Outbound identity federation not enabled on the account: 403 `Could not issue identity token (OutboundWebIdentityFederationDisabledException)`.
- Boundary missing: nothing fails; the role can later be widened beyond the two actions.

## Anthropic

### Secret

```json
{
  "type": "anthropic_wif",
  "host": "api.anthropic.com",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team",
  "federation_rule_id": "fdrl_01J8ZQ2M9K3N4P5R6S7T8V9W0X",
  "organization_id": "3f1c9d2e-7b4a-4c6d-9e8f-0a1b2c3d4e5f",
  "service_account_id": "svac_01J8ZQ2M9K3N4P5R6S7T8V9W0Y",
  "workspace_id": "wrkspc_01J8ZQ2M9K3N4P5R6S7T8V9W0Z",
  "audience": "https://api.anthropic.com"
}
```

Portunus requires all four identifiers to be non-empty; `audience` defaults to `https://api.anthropic.com`; unknown fields are rejected.

### Provider configuration

Claude Console → Settings → Workload identity. The Connect workload wizard creates all three resources:

- Federation issuer (`fdis_…`): issuer URL = the account's STS issuer URL, JWKS `discovery`.
- Service account (`svac_…`): a member of workspace `wrkspc_…`.
- Federation rule (`fdrl_…`): `match.subject_prefix` = `arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team` (exact; a trailing `*` makes it a prefix match), `match.audience` = `https://api.anthropic.com`, target = the service account, `token_lifetime_seconds` 60–86400 (API default 3600, wizard default 600). The exchange names the rule by id; Anthropic does not search rules. Per-caller conditions go in `condition` (CEL, one variable `claims`), e.g. `claims["https://sts.amazonaws.com/"]["request_tags"]["portunus:project"] == "example-project"`.

### What Portunus sends

- `AssumeRole` on the federation role, 3600 s.
- `GetWebIdentityToken`: `Audience` `["https://api.anthropic.com"]`, `SigningAlgorithm` `RS256`, `DurationSeconds` 900, `Tags` the four keys. The JWT's `iss` is the STS issuer URL, `sub` the federation role's IAM ARN, `aud` the audience, `jti` unique; the tags sit under `"https://sts.amazonaws.com/"` → `request_tags`.
- `POST https://api.anthropic.com/v1/oauth/token`, JSON: `grant_type` `urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion` (the JWT), `federation_rule_id`, `organization_id`, `service_account_id`, `workspace_id`.
- Back: `access_token` (`sk-ant-oat01-…`), `expires_in`. Anthropic's lifetime is the lesser of the rule's `token_lifetime_seconds` and twice the JWT's remaining life, so at most 1800 s here. Cached for `expires_in − 60` s. Every mint issues a fresh JWT; Anthropic treats `jti` as single-use.

### Encode and call

```bash
PAYLOAD=$(portunus encode-credentials \
  arn:aws:secretsmanager:eu-west-2:123456789012:secret:anthropic-example-team)

curl -sS https://anthropic.proxy.example.org/v1/messages \
  -H "authorization: Bearer $PAYLOAD" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model": "<model>", "max_tokens": 64, "messages": [{"role": "user", "content": "ping"}]}'
```

200 from Anthropic. The upstream request carries `authorization: Bearer sk-ant-oat01-…`; the payload never leaves the proxy. If the proxy's `API_KEY_HEADER` is `x-api-key`, send the payload there instead; the proxy removes it and adds `authorization`.

## OpenAI

### Secret

```json
{
  "type": "openai_wif",
  "host": "api.openai.com",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team",
  "identity_provider_id": "idp_0123456789abcdef",
  "service_account_id": "user-Ab12Cd34Ef56Gh78Ij90Kl",
  "audience": "https://api.openai.com/v1"
}
```

Both ids must match `^[A-Za-z0-9_-]+$`; `audience` defaults to `https://api.openai.com/v1`. Service accounts created in the dashboard may show a `user-…` id rather than `svc_acct_…`; either is accepted.

### Provider configuration

platform.openai.com → Organization Settings → Security → Workload Identity Provider:

- Provider (`idp_…`): OIDC Issuer URL = the STS issuer URL (trailing slash ignored), Audience = `https://api.openai.com/v1`, JWKS by discovery.
- Mapping under the provider: key `sub`, value `arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team`, target service account = `service_account_id`. Matching is exact except one trailing `*` after a non-empty prefix. A token is issued only if exactly one enabled mapping matches every configured attribute. Derived attributes come from CEL transformations over `assertion`, e.g. `assertion["https://sts.amazonaws.com/"]["request_tags"]["portunus:user"]`.
- OpenAI checks the JWT header (`kid`, `alg`) and claims `iss`, `aud`, `sub`, `exp`, `iat`.

### What Portunus sends

- `GetWebIdentityToken`: `Audience` `["https://api.openai.com/v1"]`, `SigningAlgorithm` `ES384`, `DurationSeconds` 1800, the four tags.
- `POST https://auth.openai.com/oauth/token`, JSON: `grant_type` `urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type` `urn:ietf:params:oauth:token-type:jwt`, `subject_token`, `identity_provider_id`, `service_account_id`.
- Back: `access_token`, `expires_in` (`expires_at`, `scope`, `token_type` are ignored). OpenAI's lifetime is at most one hour and never past the subject token's `exp`, so about 1800 s. Cached for about 1740 s.

### Encode and call

```bash
PAYLOAD=$(portunus encode-credentials \
  arn:aws:secretsmanager:eu-west-2:123456789012:secret:openai-example-team)

curl -sS https://openai.proxy.example.org/v1/responses \
  -H "authorization: Bearer $PAYLOAD" \
  -H "content-type: application/json" \
  -d '{"model": "<model>", "input": "ping"}'
```

200 from OpenAI; the upstream request carries `authorization: Bearer <OpenAI access token>`.

## OpenRouter

### Secret

```json
{
  "type": "openrouter_wif",
  "host": "openrouter.ai",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team",
  "federation_policy_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "audience": "https://openrouter.ai/api/v1"
}
```

`federation_policy_id` is the policy's UUID; `audience` defaults to `https://openrouter.ai/api/v1`.

### Provider configuration

openrouter.ai → Settings → Workload identity (Business and Enterprise plans):

- Issuer: Issuer URL = the STS issuer URL (must equal `iss` exactly; `https://` only), JWKS from `<issuer>/.well-known/openid-configuration`.
- Policy: Issuer; Subject = `arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team` (exact match on `sub`); Audience = `https://openrouter.ai/api/v1` (required, exact); Acts as API key = a workspace API key owned by the organisation, which receives the usage. A policy needs Subject or Condition. Prefix matching exists only through the CEL Condition, e.g. `subject.startsWith("arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/")` (variables `subject`, `audience`, `scopes`, `token_type`; no `matches()`). The policy's id is shown under its name.
- Subject tokens must be RS256 or ES256 and carry `iss`, `sub`, `aud`, `exp`.

### What Portunus sends

- `GetWebIdentityToken`: `Audience` `["https://openrouter.ai/api/v1"]`, `SigningAlgorithm` `RS256`, `DurationSeconds` 900, the four tags.
- `POST https://openrouter.ai/api/v1/oauth/token`, `application/x-www-form-urlencoded`: `grant_type` `urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type` `urn:ietf:params:oauth:token-type:jwt`, `subject_token`, `federation_policy_id`.
- Back: `access_token` (an ES256 JWT whose `sub` is the federation role ARN, with `federation_policy_id` and `federation_issuer_id`), `expires_in` at most 900 and never past the subject token. Cached for at most 840 s.

### Encode and call

```bash
PAYLOAD=$(portunus encode-credentials \
  arn:aws:secretsmanager:eu-west-2:123456789012:secret:openrouter-example-team)

curl -sS https://openrouter.proxy.example.org/api/v1/chat/completions \
  -H "authorization: Bearer $PAYLOAD" \
  -H "content-type: application/json" \
  -d '{"model": "<model>", "messages": [{"role": "user", "content": "ping"}]}'
```

200 from OpenRouter; the upstream request carries `authorization: Bearer <OpenRouter access token>` and usage lands on the policy's API key.

## Google Cloud

### Secret

```json
{
  "type": "gcp_wif",
  "host": "aiplatform.googleapis.com",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team",
  "audience": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/providers/example-oidc",
  "service_account": "example-sa@example-project.iam.gserviceaccount.com",
  "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
  "token_lifetime_seconds": 3600
}
```

`audience` must match `//iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`; `service_account` is an email; `scopes` (default shown, at least one) and `token_lifetime_seconds` (600–3600, default 3600) are optional.

### Provider configuration

The pool provider is an OIDC provider whose issuer is the STS issuer URL; Google fetches the JWKS from `<issuer>/.well-known/openid-configuration`. `--allowed-audiences` must be set: the token's `aud` is the secret's `audience`, `//iam.googleapis.com/…`, and without the flag Google expects `https://iam.googleapis.com/…`. `sub` is the federation role's IAM ARN with its path, `arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team`, which a longer path can push past the 127-character limit on `google.subject`, so the mapping keeps the part after `role/portunus-fed/`, and the attribute condition matches the role path. The four tags sit under the `https://sts.amazonaws.com/` claim as `request_tags`, so the caller can be kept in an attribute:

```bash
gcloud iam workload-identity-pools create example-pool --location=global

gcloud iam workload-identity-pools providers create-oidc example-oidc \
  --location=global --workload-identity-pool=example-pool \
  --issuer-uri="https://<uuid>.tokens.sts.global.api.aws" \
  --allowed-audiences="//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/providers/example-oidc" \
  --attribute-mapping="google.subject=assertion.sub.extract('role/portunus-fed/{role}'),attribute.user=assertion['https://sts.amazonaws.com/']['request_tags']['portunus:user']" \
  --attribute-condition="assertion.sub.startsWith('arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/')"

gcloud iam service-accounts add-iam-policy-binding example-sa@example-project.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/subject/teams/example-team/portunus-fed-example-grant@teams.example-team"
```

The same provider in Terraform:

```hcl
resource "google_iam_workload_identity_pool_provider" "example_oidc" {
  workload_identity_pool_id          = "example-pool"
  workload_identity_pool_provider_id = "example-oidc"
  attribute_mapping = {
    "google.subject" = "assertion.sub.extract('role/portunus-fed/{role}')"
    "attribute.user" = "assertion['https://sts.amazonaws.com/']['request_tags']['portunus:user']"
  }
  attribute_condition = "assertion.sub.startsWith('arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/')"
  oidc {
    issuer_uri        = "https://<uuid>.tokens.sts.global.api.aws"
    allowed_audiences = ["//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/providers/example-oidc"]
  }
}
```

The member uses the project number. The service account also needs the roles the upstream API requires (`roles/aiplatform.user` for Vertex AI). The federation role is the one in [The AWS side](#the-aws-side) with `ProviderAudience` set to the pool provider resource name.

### What Portunus sends

- `AssumeRole` on the federation role, 3600 s.
- `GetWebIdentityToken`: `Audience` `["//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/providers/example-oidc"]`, `SigningAlgorithm` `RS256`, `DurationSeconds` 900, the four tags. As for Anthropic, the JWT's `sub` is the federation role's IAM ARN and the tags sit under `"https://sts.amazonaws.com/"` → `request_tags`.
- `POST https://sts.googleapis.com/v1/token`, form: `grant_type` `urn:ietf:params:oauth:grant-type:token-exchange`, `audience` (the pool provider), `scope` `https://www.googleapis.com/auth/iam`, `requested_token_type` `urn:ietf:params:oauth:token-type:access_token`, `subject_token_type` `urn:ietf:params:oauth:token-type:jwt`, `subject_token` (the JWT).
- `POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/example-sa@example-project.iam.gserviceaccount.com:generateAccessToken` with the federated token as bearer, JSON `{"scope": <scopes>, "lifetime": "3600s"}`.
- Back: `accessToken`, `expireTime`. Cached for the lesser of `CACHE_DURATION` and `token_lifetime_seconds − 60`, so 3540 s at the defaults.

### Encode and call

```bash
PAYLOAD=$(portunus encode-credentials \
  arn:aws:secretsmanager:eu-west-2:123456789012:secret:vertex-example-team)

curl -sS "https://vertex.proxy.example.org/v1/projects/example-project/locations/global/publishers/google/models/<model>:generateContent" \
  -H "authorization: Bearer $PAYLOAD" \
  -H "content-type: application/json" \
  -d '{"contents": [{"role": "user", "parts": [{"text": "ping"}]}]}'
```

200 from Vertex AI; the upstream request carries `authorization: Bearer ya29.…` for `example-sa`.

## Failures

Every error from the proxy carries `x-portunus-error: true` and the body `{"error": {"message": "<message>", "x_amzn_trace_id": "<id>"}}`; the id matches `trace_id` in Portunus's `/authorise` log lines. The Lua filter passes Portunus's status and message through unchanged.

| Client sees | Cause | Where to look |
|---|---|---|
| 401 `Authorization header is required`, `Invalid authorization format` | No `API_KEY_HEADER`, or its value does not start with `API_KEY_PREFIX` | Proxy (Envoy) logs; Portunus is not called |
| 401 `Failed to decode authorization payload: …`, `Validation error in payload: …`, `Valid AWS credentials are required for authentication` | Payload is not base64 JSON with `credentials.access_key_id`, `credentials.secret_access_key` and `secret_arn` | Re-run `encode-credentials` |
| 401 `AWS credentials have expired`, `Failed to get caller identity with provided credentials` | The 12 h session is over, or STS rejects the credentials | Portunus `STS client error`; CloudTrail `GetCallerIdentity` |
| 401 `Token minting requires an assumed-role caller` | Payload credentials belong to an IAM user or root | Encode from an assumed role |
| 401 `Caller role name is not a valid session name`, `Caller … cannot be used as a session tag` | Role name outside `[\w+=,.@-]{2,64}`; role name, session name, source identity or project outside `[\w .:/=+\-@]` (a `,` fails) | Rename, or set a different `SourceIdentity` |
| 403 `Failed to get secret from Secrets Manager: …` | Session policy or secret resource policy denies `GetSecretValue`; wrong ARN | Portunus `Failed to get secret from Secrets Manager`; CloudTrail `GetSecretValue` `AccessDenied` |
| 403 `Secret has an unsupported type or invalid fields` | Unknown `type`, missing or unknown field, pattern failure (`identity_provider_id`, pool provider, email, `token_lifetime_seconds` range) | Portunus `Secret of type '…' failed validation: <field>: <error>` |
| 403 `API key is not valid for target host` | Secret `host` ≠ proxy `TARGET_HOST` | Portunus `Host mismatch: proxy=…, secret=…` |
| 403 `Token minting is disabled: …`, `federation_role_arn is not …` | `FEDERATION_ALLOWED_ACCOUNT_IDS` unset, account not listed, path not under `FEDERATION_ROLE_PATH_PREFIX`, or a malformed ARN | Portunus environment against the secret |
| 403 `Could not assume federation role (AccessDenied)` | Trust policy: `aws:PrincipalArn` pattern misses the caller, or `aws:SourceVpce` absent because STS was not reached through the endpoint. Caller identity policy without `sts:AssumeRole` on the prefix. Payload encoded with a session policy lacking `PortunusFederationAssumeRole` (payloads live 12 h and stay cached) | Portunus `AssumeRole on federation role failed (AccessDenied)`; CloudTrail `AssumeRole` with `errorCode` `AccessDenied` in the role's account |
| 403 `Could not assume federation role (ValidationError)` | Role `MaxSessionDuration` below 3600 | Same log line; CloudTrail `AssumeRole` |
| 403 `Could not issue identity token (AccessDenied)` | Identity policy: audience not in `sts:IdentityTokenAudience`; `sts:DurationSeconds` cap below 900 or 1800; `sts:TagGetWebIdentityToken` missing or `aws:TagKeys` not listing a `FEDERATION_*_TAG_KEY`; boundary too narrow | Portunus `GetWebIdentityToken failed (AccessDenied)`; CloudTrail `GetWebIdentityToken` |
| 403 `Could not issue identity token (OutboundWebIdentityFederationDisabledException)` | Outbound identity federation not enabled on the account | IAM → Account settings |
| 403 `Could not issue identity token (SessionDurationEscalationException)` | Token requested for longer than the federation session's remaining life | `FEDERATION_SESSION_SECONDS` against the identity token lifetimes in `federation_service.py` |
| 403 `Token exchange with api.anthropic.com returned HTTP 401` | Every Anthropic denial is an opaque 401: `iss` ≠ issuer URL, `sub` fails `subject_prefix`, `aud` ≠ rule audience, rule id unknown or archived, service account not in the workspace, `workspace_id` missing for a multi-workspace rule, replayed `jti` | Portunus log line with the response body; Claude Console → Settings → Workload identity → authentication history (`match_subject_prefix`, `workspace_id_required`, `jti_reused`) |
| 403 `Token exchange with OpenAI returned HTTP 4xx` | Provider id unknown or disabled; no enabled mapping matches `sub`, or more than one does; transformation failure; `aud` or `iss` mismatch | Portunus log line with the response body; OpenAI console → Workload Identity Provider |
| 403 `Token exchange with OpenRouter returned HTTP 400` | `invalid_grant` "The subject token was not accepted": issuer, `sub`, `aud` or Condition mismatch; policy paused or deleted; entitlement removed | Portunus log line with the response body; OpenRouter → Settings → Workload identity |
| 403 `Google STS exchange for <sa> returned HTTP 400` | `iss` ≠ `--issuer-uri`; `aud` not in `--allowed-audiences`, or `audience` ≠ provider resource name; attribute condition false; mapped `google.subject` over 127 characters | Portunus log line with the response body |
| 403 `Impersonation of <sa> returned HTTP 403` | `roles/iam.workloadIdentityUser` not bound to the mapped `google.subject`; IAM Credentials API disabled | Portunus log line with the response body; the service account's IAM policy |
| 403 `… returned a malformed response` | 200 without `access_token`/`expires_in` (or `accessToken`/`expireTime`), or a non-JSON body | Portunus `… returned a malformed body` |
| 503 `STS is unavailable` | STS endpoint unreachable or slow (2 s connect, 3 s read, one attempt) | Portunus `AssumeRole on federation role failed: <exception>` or `GetWebIdentityToken failed: <exception>`; endpoint DNS and security groups |
| 503 `<step> is unavailable`, `<step> returned HTTP 5xx` or `429` | Provider transport failure, outage or rate limit (4 s per exchange call; 3 s per Google hop) | Portunus log line; provider status |
| 503 `Token minting timed out` | AssumeRole, proof and exchange together exceeded 6 s | Portunus `Token minting exceeded 6 s` |
| 503 `Authorization timed out. Proxy overloaded.` | The whole `/authorise` exceeded 9 s | Portunus `Authorization processing timed out` |
| 502 `Authorization service unreachable` | The proxy could not reach Portunus | Proxy logs; Portunus health |
