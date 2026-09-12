"""Tests for parsing typed Secrets Manager secrets."""

import json
import logging

import pytest

from portunus.exceptions import AuthenticationError
from portunus.models import (
    AnthropicWifSecret,
    SecretsManagerAuthPayload,
    SigningKey,
)
from portunus.services.secret_validation_service import (
    SecretValidationService,
    parse_secret,
)

ROLE_ARN = "arn:aws:iam::123456789012:role/portunus-fed/example-grant/example-grant@projects.example"  # noqa: E501
WIF_SECRET = {
    "type": "anthropic_wif",
    "host": "api.example.com",
    "federation_role_arn": ROLE_ARN,
    "federation_rule_id": "fr_example",
    "organization_id": "org_example",
    "service_account_id": "sa_example",
    "workspace_id": "ws_example",
}


class TestParseSecret:
    def test_plaintext_is_the_api_key(self):
        secret = parse_secret("sk-plaintext")

        assert isinstance(secret, SecretsManagerAuthPayload)
        assert secret.api_key == "sk-plaintext"
        assert secret.host is None

    def test_legacy_json_without_type(self):
        raw = json.dumps(
            {
                "secret": "sk-legacy",
                "host": "api.example.com",
                "signing_key": {"provider_id": "key1", "kms_key_arn": "arn:kms"},
            }
        )

        secret = parse_secret(raw)

        assert isinstance(secret, SecretsManagerAuthPayload)
        assert secret.api_key == "sk-legacy"
        assert secret.host == "api.example.com"
        assert secret.signing_key == SigningKey(
            provider_id="key1", kms_key_arn="arn:kms"
        )

    @pytest.mark.parametrize(
        "raw", ['{"apiKey": "sk", "other": 1}', '["sk"]', '"sk"', "42"]
    )
    def test_unrecognised_json_without_type_is_used_verbatim(self, raw: str):
        secret = parse_secret(raw)

        assert isinstance(secret, SecretsManagerAuthPayload)
        assert secret.api_key == raw

    def test_explicit_static_type(self):
        secret = parse_secret('{"type": "static", "secret": "sk-typed"}')

        assert isinstance(secret, SecretsManagerAuthPayload)
        assert secret.api_key == "sk-typed"

    def test_typed_secret_with_invalid_fields_is_not_used_as_a_key(self):
        with pytest.raises(AuthenticationError):
            parse_secret('{"type": "static"}')

    def test_anthropic_wif_secret(self):
        secret = parse_secret(json.dumps(WIF_SECRET))

        assert isinstance(secret, AnthropicWifSecret)
        assert secret.host == "api.example.com"
        assert secret.federation_role_arn == ROLE_ARN
        assert secret.federation_rule_id == "fr_example"
        assert secret.organization_id == "org_example"
        assert secret.service_account_id == "sa_example"
        assert secret.workspace_id == "ws_example"
        assert secret.audience == "https://api.anthropic.com"
        assert secret.token_duration_seconds == 3600
        assert secret.signing_key is None

    def test_anthropic_wif_overrides(self):
        raw = json.dumps(
            {
                **WIF_SECRET,
                "audience": "https://api.example.com",
                "token_duration_seconds": 600,
                "signing_key": {"provider_id": "key1", "kms_key_arn": "arn:kms"},
            }
        )

        secret = parse_secret(raw)

        assert isinstance(secret, AnthropicWifSecret)
        assert secret.audience == "https://api.example.com"
        assert secret.token_duration_seconds == 600
        assert secret.signing_key == SigningKey(
            provider_id="key1", kms_key_arn="arn:kms"
        )

    @pytest.mark.parametrize(
        "changes",
        [
            {"workspace_id": None},
            {"workspace_id": ""},
            {"host": None},
            {"host": ""},
            {"federation_role_arn": None},
            {"organization_id": ""},
            {"audience": ""},
            {"token_duration_seconds": 30},
            {"token_duration_seconds": 7200},
        ],
    )
    def test_anthropic_wif_missing_or_invalid_fields_raise(self, changes: dict):
        data = {k: v for k, v in {**WIF_SECRET, **changes}.items() if v is not None}

        with pytest.raises(AuthenticationError):
            parse_secret(json.dumps(data))

    def test_unknown_type_raises(self):
        with pytest.raises(AuthenticationError):
            parse_secret('{"type": "gcp_workload_identity", "host": "x"}')

    def test_validation_logs_omit_secret_contents(self, caplog):
        caplog.set_level(logging.INFO, logger="api.access")

        with pytest.raises(AuthenticationError):
            parse_secret('{"type": "static", "apiKey": "sk-live-typed"}')
        with pytest.raises(AuthenticationError):
            parse_secret('{"type": "other", "secret": "sk-live-unknown-type"}')
        parse_secret('{"apiKey": "sk-live-untyped"}')

        assert "static.secret: missing" in caplog.text
        for value in ("sk-live-typed", "sk-live-unknown-type", "sk-live-untyped"):
            assert value not in caplog.text


class TestValidateSecretForMintTypes:
    def setup_method(self):
        self.service = SecretValidationService()

    def test_matching_target_returns_mint_secret(self):
        secret = self.service.validate_secret(json.dumps(WIF_SECRET), "api.example.com")

        assert isinstance(secret, AnthropicWifSecret)

    def test_host_mismatch_is_rejected(self):
        with pytest.raises(AuthenticationError, match="not valid for target host"):
            self.service.validate_secret(json.dumps(WIF_SECRET), "api.other.example")

    def test_unknown_target_is_rejected(self):
        with pytest.raises(AuthenticationError, match="target host unknown"):
            self.service.validate_secret(json.dumps(WIF_SECRET), None)

    def test_static_extraction_refuses_mint_secrets(self):
        with pytest.raises(AuthenticationError, match="token minting"):
            self.service.validate_and_extract_api_key(
                json.dumps(WIF_SECRET), "api.example.com"
            )

    def test_static_extraction_still_returns_stored_keys(self):
        api_key, signing_key = self.service.validate_and_extract_api_key(
            '{"secret": "sk", "host": "api.example.com"}', "api.example.com"
        )

        assert (api_key, signing_key) == ("sk", None)
