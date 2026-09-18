"""Tests for target host validation functionality."""

import pytest

from portunus.exceptions import AuthenticationError
from portunus.models import SecretsManagerAuthPayload, SigningKey
from portunus.services.secret_validation_service import SecretValidationService


class TestTargetValidation:
    """Test target validation logic in validation service."""

    def setup_method(self):
        """Set up test fixtures."""
        self.validation_service = SecretValidationService()

    def _stored_key(
        self, secret: str, target_host: str | None
    ) -> SecretsManagerAuthPayload:
        result = self.validation_service.validate_secret(secret, target_host)
        assert isinstance(result, SecretsManagerAuthPayload)
        return result

    def test_plaintext_secret_no_validation(self):
        """Plaintext secrets should work without validation."""
        secret = self._stored_key("plaintext-api-key", "any-target")
        assert secret.api_key == "plaintext-api-key"
        assert secret.signing_key is None

    def test_json_secret_without_host_no_validation(self):
        """JSON secrets without host field should work without validation."""
        secret = self._stored_key('{"secret": "test-key"}', "any-target")
        assert secret.api_key == "test-key"
        assert secret.signing_key is None

    def test_json_secret_with_matching_host_success(self):
        """JSON secrets with matching host should work."""
        secret = self._stored_key(
            '{"secret": "test-key", "host": "api.example.com"}', "api.example.com"
        )
        assert secret.api_key == "test-key"
        assert secret.signing_key is None

    def test_json_secret_with_mismatched_host_fails(self):
        """JSON secrets with mismatched host should fail."""
        secret = '{"secret": "test-key", "host": "api.example.com"}'
        with pytest.raises(
            AuthenticationError, match="API key is not valid for target host"
        ):
            self.validation_service.validate_secret(secret, "api.different.com")

    def test_json_secret_with_host_but_no_target_fails(self):
        """JSON secrets with host but no target should fail."""
        secret = '{"secret": "test-key", "host": "api.example.com"}'
        with pytest.raises(
            AuthenticationError,
            match="API key has host restriction but target host unknown",
        ):
            self.validation_service.validate_secret(secret, None)

    def test_json_secret_with_signing_key_succeeds(self):
        """JSON secrets with valid signing key should work."""
        secret = self._stored_key(
            '{"secret": "test-key", "signing_key": {"kms_key_arn": "arn:...", "provider_id": "key123"}}',  # noqa: E501
            "any-target",
        )
        assert secret.api_key == "test-key"
        assert secret.signing_key == SigningKey(
            provider_id="key123", kms_key_arn="arn:..."
        )

    def test_non_schema_json_returns_full_json(self):
        """JSON that doesn't match our schema should return the full JSON."""
        raw = '{"apiKey": "test-key", "other": "data"}'
        secret = self._stored_key(raw, "any-target")
        assert secret.api_key == raw
        assert secret.signing_key is None
