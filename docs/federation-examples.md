# Federation grant walkthrough

A federation grant lets Portunus mint a short-lived lab token for a caller
instead of storing a lab API key. Each grant has two parts:

- **A federation role.** Portunus assumes this IAM role with the caller's
  credentials, and asks STS for a signed identity token (a JWT) that names the
  role.
- **A config secret.** This Secrets Manager secret names the role and the
  lab-side ids. It holds no key.

The lab trusts our AWS account's token issuer and maps the role to one of its
own identities. The [README](../README.md#secret-formats) covers what Portunus
does on each request. This page sets up one grant for each lab.

The examples use these values:

| | |
|---|---|
| AWS account | `123456789012` |
| Federation role | `arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team` |
| Caller roles | `arn:aws:iam::123456789012:role/example-callers/*` |
| STS VPC endpoint | `vpce-0123456789abcdef0` |
| Token issuer | `https://<uuid>.tokens.sts.global.api.aws` |
| Proxies | `<lab>.proxy.example.org` |

Portunus runs with `FEDERATION_ALLOWED_ACCOUNT_IDS=123456789012`,
`FEDERATION_STS_ENDPOINT_URL` set to the VPC endpoint, and defaults for
everything else.

## Once per account

1. **Enable outbound web identity federation** under IAM → Account settings.
   The page then shows the account's token issuer URL. Every lab registers
   this URL.
2. **Let callers assume federation roles.** Attach this statement to each
   caller role:

   ```json
   {
     "Effect": "Allow",
     "Action": "sts:AssumeRole",
     "Resource": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/*"
   }
   ```

## The federation role

One template serves every lab. Only `ProviderAudience` changes:

| Lab | `ProviderAudience` |
|---|---|
| Anthropic | `https://api.anthropic.com` |
| OpenAI | `https://api.openai.com/v1` |
| OpenRouter | `https://openrouter.ai/api/v1` |
| Google Cloud | The pool provider's resource name, `//iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>` |

The template's three policies do the following:

- **Trust policy:** only the caller roles can assume the role, and only through
  the STS VPC endpoint, so only Portunus can mint.
- **Inline policy:** the role can request identity tokens for its one audience,
  tagged with the four caller tags Portunus sends.
- **Permissions boundary:** the role can never do anything else.

The deployer also needs IAM permissions on the bare name
`role/portunus-fed-*`, not just the path `role/portunus-fed/*`. IAM checks
calls on a role that doesn't exist yet against the name alone.

<details><summary>CloudFormation template</summary>

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

</details>

## Calling a grant

The payload and request steps are the same for every lab. First encode a
payload with the caller's credentials:

```bash
PAYLOAD=$(portunus encode-credentials <config secret ARN>)
```

Then send it through the lab's proxy wherever the lab expects its API key.
Each lab section below shows a request.

## Anthropic

**Register.** In the Claude Console, go to Settings → Workload identity →
Connect workload → AWS. The wizard creates an issuer, a service account in a
workspace, and a federation rule. Set the rule up like this:

- Subject prefix: the role ARN. It matches exactly unless it ends in `*`.
- Audience: `https://api.anthropic.com`
- Condition: `claims["https://sts.amazonaws.com/"]["aws_account"] == "123456789012"`

Tokens last up to 30 minutes, capped at twice the JWT's remaining life.

<details><summary>Config secret</summary>

```json
{
  "type": "anthropic_wif",
  "host": "api.anthropic.com",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team",
  "federation_rule_id": "fdrl_01J8ZQ2M9K3N4P5R6S7T8V9W0X",
  "organization_id": "3f1c9d2e-7b4a-4c6d-9e8f-0a1b2c3d4e5f",
  "service_account_id": "svac_01J8ZQ2M9K3N4P5R6S7T8V9W0Y",
  "workspace_id": "wrkspc_01J8ZQ2M9K3N4P5R6S7T8V9W0Z"
}
```

</details>

```bash
curl https://anthropic.proxy.example.org/v1/messages \
  -H "authorization: Bearer $PAYLOAD" -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model": "<model>", "max_tokens": 64, "messages": [{"role": "user", "content": "ping"}]}'
```

## OpenAI

**Register.** On platform.openai.com, go to Organization settings → Security →
Workload identity provider. Add a provider with:

- Issuer: the token issuer URL
- Audience: `https://api.openai.com/v1`

Under the provider, add a mapping from `sub` = the role ARN to a service
account. Exactly one enabled mapping must match.

Tokens last as long as the JWT does, 30 minutes.

<details><summary>Config secret</summary>

```json
{
  "type": "openai_wif",
  "host": "api.openai.com",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team",
  "identity_provider_id": "idp_0123456789abcdef",
  "service_account_id": "user-Ab12Cd34Ef56Gh78Ij90Kl"
}
```

</details>

```bash
curl https://openai.proxy.example.org/v1/responses \
  -H "authorization: Bearer $PAYLOAD" -H "content-type: application/json" \
  -d '{"model": "<model>", "input": "ping"}'
```

## OpenRouter

**Register.** This needs a Business or Enterprise plan. On openrouter.ai, go to
Settings → Workload identity:

- Add an issuer with the token issuer URL.
- Add a policy with subject = the role ARN, audience =
  `https://openrouter.ai/api/v1`, and a workspace API key to act as. Usage is
  billed to that key.

Tokens last up to 15 minutes. OpenRouter can't read the caller tags.

<details><summary>Config secret</summary>

```json
{
  "type": "openrouter_wif",
  "host": "openrouter.ai",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team",
  "federation_policy_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7"
}
```

</details>

```bash
curl https://openrouter.proxy.example.org/api/v1/chat/completions \
  -H "authorization: Bearer $PAYLOAD" -H "content-type: application/json" \
  -d '{"model": "<model>", "messages": [{"role": "user", "content": "ping"}]}'
```

## Google Cloud

**Register.** Create a workload identity pool with an OIDC provider that trusts
the token issuer. Then let the mapped principal impersonate a service account
that can call the API (`roles/aiplatform.user` for Vertex AI). Set the
provider's allowed audience to its own resource name: Google's default uses an
`https://` form that won't match the JWT.

Portunus exchanges the JWT at Google STS, then impersonates the service
account. Tokens last `token_lifetime_seconds`, between 600 and 3600 seconds.

<details><summary>gcloud</summary>

```bash
gcloud iam workload-identity-pools create example-pool --location=global

gcloud iam workload-identity-pools providers create-oidc example-oidc \
  --location=global --workload-identity-pool=example-pool \
  --issuer-uri="https://<uuid>.tokens.sts.global.api.aws" \
  --allowed-audiences="//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/providers/example-oidc" \
  --attribute-mapping="google.subject=assertion.sub.extract('role/portunus-fed/{role}')" \
  --attribute-condition="assertion.sub.startsWith('arn:aws:iam::123456789012:role/portunus-fed/')"

gcloud iam service-accounts add-iam-policy-binding example-sa@example-project.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/*"
```

`extract` keeps `google.subject` under Google's 127-character limit.

</details>

<details><summary>Config secret</summary>

```json
{
  "type": "gcp_wif",
  "host": "aiplatform.googleapis.com",
  "federation_role_arn": "arn:aws:iam::123456789012:role/portunus-fed/teams/example-team/portunus-fed-example-grant@teams.example-team",
  "audience": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/providers/example-oidc",
  "service_account": "example-sa@example-project.iam.gserviceaccount.com"
}
```

</details>

```bash
curl "https://vertex.proxy.example.org/v1/projects/example-project/locations/global/publishers/google/models/<model>:generateContent" \
  -H "authorization: Bearer $PAYLOAD" -H "content-type: application/json" \
  -d '{"contents": [{"role": "user", "parts": [{"text": "ping"}]}]}'
```

## Reference

| | Anthropic | OpenAI | OpenRouter | Google Cloud |
|---|---|---|---|---|
| JWT | RS256, 900 s | ES384, 1800 s | RS256, 900 s | RS256, 900 s |
| Lab-side object | Federation rule | Provider + `sub` mapping | Issuer + policy | Pool provider + service account binding |
| Token lifetime | ≤ 30 min | 30 min | ≤ 15 min | 10–60 min |
| Caller tags visible to lab | Yes | Yes, via CEL | No | Yes, via attribute mapping |
