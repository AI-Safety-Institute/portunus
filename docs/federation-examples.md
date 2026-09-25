# Federation grant walkthrough

A federation grant is an IAM role plus a Secrets Manager secret. The role (the *federation role*) is what Portunus assumes on a caller's behalf so that STS will issue an identity token for one lab. The secret (the *config secret*, type `anthropic_wif`, `openai_wif`, `openrouter_wif` or `gcp_wif`) names that role and the lab-side object the role is registered against; it holds no key. The [README](../README.md#secret-formats) defines the secret types and what Portunus does with them on each request. This document sets up one grant per provider, using these values throughout:

| Value | Example |
|---|---|
| AWS account | `123456789012` |
| Federation role | `arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team` |
| Caller roles | `arn:aws:iam::123456789012:role/example-callers/*` |
| STS interface endpoint | `vpce-0123456789abcdef0` |
| STS issuer URL | `https://<uuid>.tokens.sts.global.api.aws` |
| Proxy hostnames | `<provider>.proxy.example.org` |

Portunus runs at its defaults (`FEDERATION_ROLE_PATH_PREFIX=/portunus-fed/`, tag keys `portunus:user`, `portunus:principal`, `portunus:session`, `portunus:project` and `portunus:attributed_to`, `API_KEY_HEADER=authorization`, `API_KEY_PREFIX="Bearer "`) with `FEDERATION_ALLOWED_ACCOUNT_IDS=123456789012` and `FEDERATION_STS_ENDPOINT_URL` set to the interface endpoint.

Each grant takes five steps: create the federation role, register it with the lab, write the config secret, encode a payload from a caller role, make a request through the proxy. On a request, Portunus assumes the role with the caller's credentials, has STS issue an identity token (a JWT whose `sub` is the role ARN and whose tags describe the caller), exchanges it at the lab for a provider token and injects that as `authorization: Bearer …`. Caching, the 403/503 mapping and each type's exchange sequence are in the README under [Secret formats](../README.md#secret-formats).

## Once per deployment

1. Enable outbound web identity federation on account `123456789012` (IAM → Account settings). The page then shows the account's token issuer URL, `https://<uuid>.tokens.sts.global.api.aws`; every lab registration below uses it.
2. Allow callers to assume federation roles: attach the statement below to each caller role. The CLI's default session policy carries the same statement, and a session gets the intersection of the two.

<details><summary>Caller identity policy</summary>

```json
{
  "Sid": "PortunusFederationAssumeRole",
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/*"
}
```

</details>

## Anthropic

### 1. Create the federation role

Deploy the template below with `ProviderAudience=https://api.anthropic.com`. The same template serves every provider; only the audience changes. It creates the role and three policy documents:

- Trust policy: roles matching `CallerRoleArnPattern` may assume it, and only through `StsVpcEndpointId`. Drop the `aws:SourceVpce` condition if Portunus reaches STS over the public endpoint.
- Inline policy: `sts:GetWebIdentityToken` for `ProviderAudience` only and for at most 1800 s, plus `sts:TagGetWebIdentityToken` for the five tag keys Portunus may send. Substitute the deployment's `FEDERATION_*_TAG_KEY` values if they differ.
- Permissions boundary: those two actions and nothing else, so the role cannot be widened later.

Note: whatever deploys the template needs its IAM role permissions on `arn:aws:iam::123456789012:role/portunus-fed-*` as well as `…:role/portunus-fed/*`. IAM authorises calls on a role that does not exist yet (`GetRole` before create, `DeleteRole` on rollback) by bare name, without the path.

<details><summary>CloudFormation: federation role, inline policy and boundary</summary>

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
  StsVpcEndpointId:
    Type: String
    Default: vpce-0123456789abcdef0
  ProviderAudience:
    Type: String
    Default: https://api.anthropic.com

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
                      - 'portunus:attributed_to'

Outputs:
  FederationRoleArn:
    Value: !GetAtt FederationRole.Arn
```

</details>

### 2. Register with the lab

Claude Console → Settings → Workload identity → Connect workload → AWS. The wizard creates three objects; the secret needs the rule, service account and workspace ids plus the organisation id.

- Federation issuer (`fdis_…`)
  - Issuer URL: `https://<uuid>.tokens.sts.global.api.aws`
  - JWKS: discovery
- Service account (`svac_…`), a member of workspace `wrkspc_…`
- Federation rule (`fdrl_…`)
  - Subject prefix: `arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team`. Note: matched exactly; only a trailing `*` makes it a prefix.
  - Audience: `https://api.anthropic.com`
  - Target: the service account
  - Token lifetime: 60–86400 s (wizard default 600). Note: the issued token lives for the lesser of this and twice the identity token's remaining life, so at most 1800 s here.
  - Condition: `claims["https://sts.amazonaws.com/"]["aws_account"] == "123456789012"`. Note: Anthropic recommends this account pin as a guard against a loosened prefix; the caller tags are reachable from the same variable, `claims["https://sts.amazonaws.com/"]["request_tags"]["portunus:project"]`.

### 3. Write the config secret

The four ids are required; `audience` defaults to `https://api.anthropic.com`. `attribution` (`full` here, the default) is accepted by every provider's secret and chooses what the lab learns about the caller; see [Attribution](#attribution).

<details><summary>Secret: anthropic_wif</summary>

```json
{
  "type": "anthropic_wif",
  "host": "api.anthropic.com",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team",
  "federation_rule_id": "fdrl_01J8ZQ2M9K3N4P5R6S7T8V9W0X",
  "organization_id": "3f1c9d2e-7b4a-4c6d-9e8f-0a1b2c3d4e5f",
  "service_account_id": "svac_01J8ZQ2M9K3N4P5R6S7T8V9W0Y",
  "workspace_id": "wrkspc_01J8ZQ2M9K3N4P5R6S7T8V9W0Z",
  "audience": "https://api.anthropic.com",
  "attribution": "full"
}
```

</details>

### 4. Encode a payload

With a caller role's credentials in the environment:

```bash
PAYLOAD=$(portunus encode-credentials arn:aws:secretsmanager:eu-west-2:123456789012:secret:anthropic-example-team)
```

`portunus` is this package's console script. It assumes the caller's own role for 12 h under a session policy that allows reading that secret and assuming roles under `/portunus-fed/`, and base64-encodes the temporary credentials with the secret ARN. Its options are described in the README under [Caching and the federation role](../README.md#caching-and-the-federation-role). The command is the same for every provider; only the secret ARN changes.

### 5. Make a request

```bash
curl -sS https://anthropic.proxy.example.org/v1/messages \
  -H "authorization: Bearer $PAYLOAD" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model": "<model>", "max_tokens": 64, "messages": [{"role": "user", "content": "ping"}]}'
```

200 from Anthropic, served with an `sk-ant-oat01-…` token for the service account.

## OpenAI

### 1. Create the federation role

The [template above](#1-create-the-federation-role) with `ProviderAudience=https://api.openai.com/v1`.

### 2. Register with the lab

platform.openai.com → Organization settings → Security → Workload identity provider.

- Provider (`idp_…`)
  - OIDC issuer URL: `https://<uuid>.tokens.sts.global.api.aws`
  - Audience: `https://api.openai.com/v1`. Note: must equal the secret's `audience`.
  - JWKS: discovery
- Mapping, under the provider
  - Attribute: `sub`
  - Value: `arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team`. Note: exact match; a single trailing `*` after a non-empty prefix is the only wildcard, and a token is issued only when exactly one enabled mapping matches.
  - Service account: the account whose id goes in the secret. Note: accounts created in the dashboard may show a `user-…` id rather than `svc_acct_…`; either is accepted.
  - Note: the caller tags are reachable in a CEL transformation as `assertion["https://sts.amazonaws.com/"]["request_tags"]["portunus:user"]`.

### 3. Write the config secret

Both ids are required and match `[A-Za-z0-9_-]+`; `audience` defaults to `https://api.openai.com/v1`.

<details><summary>Secret: openai_wif</summary>

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

</details>

### 4. Encode a payload

As for [Anthropic](#4-encode-a-payload), with secret `openai-example-team`.

### 5. Make a request

```bash
curl -sS https://openai.proxy.example.org/v1/responses \
  -H "authorization: Bearer $PAYLOAD" \
  -H "content-type: application/json" \
  -d '{"model": "<model>", "input": "ping"}'
```

200 from OpenAI, served with an access token for the mapped service account.

## OpenRouter

### 1. Create the federation role

The [template above](#1-create-the-federation-role) with `ProviderAudience=https://openrouter.ai/api/v1`.

### 2. Register with the lab

openrouter.ai → Settings → Workload identity. Note: Business and Enterprise plans only.

- Issuer
  - Issuer URL: `https://<uuid>.tokens.sts.global.api.aws`. Note: must equal the token's `iss` exactly.
  - JWKS: fetched from `<issuer>/.well-known/openid-configuration`
- Policy (its UUID goes in the secret)
  - Issuer: the one above
  - Subject: `arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team`. Note: exact match on `sub`. Prefix matching exists only through the CEL Condition, e.g. `subject.startsWith("arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/")`; its variables are `subject`, `audience`, `scopes` and `token_type`, so the caller tags are not reachable here.
  - Audience: `https://openrouter.ai/api/v1`
  - Acts as API key: a workspace API key owned by the organisation. Usage lands on it.
  - Note: OpenRouter accepts RS256 or ES256 subject tokens (Portunus sends RS256) and issues its own token for at most 15 minutes.

### 3. Write the config secret

`federation_policy_id` is the policy's UUID; `audience` defaults to `https://openrouter.ai/api/v1`.

<details><summary>Secret: openrouter_wif</summary>

```json
{
  "type": "openrouter_wif",
  "host": "openrouter.ai",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team",
  "federation_policy_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "audience": "https://openrouter.ai/api/v1"
}
```

</details>

### 4. Encode a payload

As for [Anthropic](#4-encode-a-payload), with secret `openrouter-example-team`.

### 5. Make a request

```bash
curl -sS https://openrouter.proxy.example.org/api/v1/chat/completions \
  -H "authorization: Bearer $PAYLOAD" \
  -H "content-type: application/json" \
  -d '{"model": "<model>", "messages": [{"role": "user", "content": "ping"}]}'
```

200 from OpenRouter, served with an access token acting as the policy's API key.

## Google Cloud

### 1. Create the federation role

The [template above](#1-create-the-federation-role) with `ProviderAudience=//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/providers/example-oidc`, the pool provider's resource name.

### 2. Register with the lab

A workload identity pool with one OIDC provider, and a service account the mapped principal may impersonate. Project number `123456789`, project id `example-project`.

- Provider `example-oidc` in pool `example-pool`
  - Issuer URI: `https://<uuid>.tokens.sts.global.api.aws`
  - Allowed audiences: the provider's own resource name (the secret's `audience`). Note: required; the token's `aud` is `//iam.googleapis.com/…` and without the flag Google expects `https://iam.googleapis.com/…`.
  - Attribute mapping: `google.subject=assertion.sub.extract('role/portunus-fed/{role}')`. Note: `sub` is the full role ARN, which a long path can push past the 127-character limit on `google.subject`; `extract` keeps the part after the prefix. The caller tags are reachable as `assertion['https://sts.amazonaws.com/']['request_tags']['portunus:user']`.
  - Attribute condition: `assertion.sub.startsWith('arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/')`
- Service account `example-sa@example-project.iam.gserviceaccount.com`
  - `roles/iam.workloadIdentityUser` for the mapped principal, `principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/subject/teams/example-team/portunus-fed-example-grant@teams.example-team`
  - The roles the upstream API needs, `roles/aiplatform.user` for Vertex AI

<details><summary>gcloud: pool, provider and binding</summary>

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

</details>

### 3. Write the config secret

`audience` is the pool provider's resource name and `service_account` an email; `scopes` (default shown) and `token_lifetime_seconds` (600–3600, default 3600) are optional.

<details><summary>Secret: gcp_wif</summary>

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

</details>

### 4. Encode a payload

As for [Anthropic](#4-encode-a-payload), with secret `vertex-example-team`.

### 5. Make a request

```bash
curl -sS "https://vertex.proxy.example.org/v1/projects/example-project/locations/global/publishers/google/models/<model>:generateContent" \
  -H "authorization: Bearer $PAYLOAD" \
  -H "content-type: application/json" \
  -d '{"contents": [{"role": "user", "parts": [{"text": "ping"}]}]}'
```

200 from Vertex AI, served with a `ya29.…` access token for `example-sa`.

## Attribution

Every config secret accepts `attribution`, which decides what the identity token's tags say about the caller. For a payload encoded from role `UserProfile_example_example-project` (no source identity, session `portunus`, project `example-project`), the lab sees under `request_tags`:

| `attribution` | Tags |
|---|---|
| `full` (default) | `portunus:user` = `UserProfile_example_example-project`<br>`portunus:principal` = `UserProfile_example_example-project`<br>`portunus:session` = `portunus`<br>`portunus:project` = `example-project` |
| `pseudonymous` | `portunus:attributed_to` = `caf25aecec46a3862e83a35fb1c0bb8ab7e5c86d07503a02d75719f3fb4ad004` |
| `none` | *(no tags)* |

The `pseudonymous` handle is the hex digest of HMAC-SHA256 over the federation role ARN, a newline and the user value, keyed by `FEDERATION_ATTRIBUTION_KEY` (`example-attribution-key-0123456789abcdef` in the row above); the tag key is `FEDERATION_ATTRIBUTION_TAG_KEY`.

- It is stable for one caller under one grant, so the lab can aggregate that caller's usage or condition on the handle, and different for the same caller under another grant. The principal, session and project are not in the input and not sent.
- Only Portunus can resolve it, from the mint log line below. Rotating the key changes every handle.
- A `pseudonymous` secret on a deployment without the key fails every mint with 500 until the key is set.
- `none` passes no `Tags` to `GetWebIdentityToken`, so the federation role needs no `sts:TagGetWebIdentityToken`.
- In every mode the JWT's `sub` is the federation role ARN, so `teams/example-team` and `portunus-fed-example-grant` are visible to the lab.
- A lab-side mapping or condition that reads `portunus:user`, `portunus:principal`, `portunus:session` or `portunus:project` fails or maps to nothing for a `pseudonymous` grant. Use `portunus:attributed_to`, or `sub`, for such grants.

### Correlating a lab's records

Labs treat the identity token's `jti` as single-use and record it when they exchange it, so it is the correlation id for incident reports in every `attribution` mode. Portunus reads the `jti` from the token it minted and writes one log line per mint: `Minted AnthropicWifSecret token: jti=<jti> attributed_to=<handle> role=<arn> user=<user> principal=<principal> session=<session> project=<project>`, with the same values as structured fields `identity_token_id`, `attribution`, `attribution_handle`, `federation_role_arn`, `user`, `principal`, `session` and `project`. `attributed_to` is omitted unless `pseudonymous`.

A lab's report quotes a `jti` or a handle. The mint line names the caller and the time; the caller's requests for the token's lifetime are then found through the per-request logs, whose `metadata` records carry the principal, session and project. Nothing is recorded per request for this: the `jti` identifies one mint, and the handle is constant for one caller under one grant and recomputable from the key.

Neither the token nor `FEDERATION_ATTRIBUTION_KEY` is logged.

## Reference

| | Anthropic | OpenAI | OpenRouter | Google Cloud |
|---|---|---|---|---|
| Identity token | RS256, 900 s | ES384, 1800 s | RS256, 900 s | RS256, 900 s |
| Exchange | `POST https://api.anthropic.com/v1/oauth/token`, JWT bearer grant | `POST https://auth.openai.com/oauth/token`, token exchange (JSON) | `POST https://openrouter.ai/api/v1/oauth/token`, token exchange (form) | `POST https://sts.googleapis.com/v1/token`, then `iamcredentials.googleapis.com …:generateAccessToken` |
| Lab-side object | Federation rule (`fdrl_…`) | Mapping under an identity provider (`idp_…`) | Federation policy (UUID) | Pool provider and service-account binding |
| Provider token lifetime | Lesser of the rule's lifetime and 2 × the identity token's remaining life; ≤ 1800 s | ≤ 1 h and never past the identity token's `exp`; ~1800 s | ≤ 900 s | `token_lifetime_seconds`, 600–3600 s |
| Where the lab reads the caller tags | CEL `claims["https://sts.amazonaws.com/"]["request_tags"]` | CEL `assertion["https://sts.amazonaws.com/"]["request_tags"]` | Not readable; `sub` only | Attribute mapping `assertion['https://sts.amazonaws.com/']['request_tags']` |
