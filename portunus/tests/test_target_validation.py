"""Tests for target host validation functionality."""

import pytest

from portunus.exceptions import AuthenticationError
from portunus.models import SigningKey
from portunus.services.auth_service import validate_and_extract_api_key


class TestTargetValidation:
    """Test target validation logic for the host-restriction enforcement."""

    def test_plaintext_secret_no_validation(self):
        """Plaintext secrets should work without validation."""
        api_key, signing_key = validate_and_extract_api_key(
            "plaintext-api-key", "any-target"
        )
        assert api_key == "plaintext-api-key"
        assert signing_key is None

    def test_json_secret_without_host_no_validation(self):
        """JSON secrets without host field should work without validation."""
        secret = '{"secret": "test-key"}'
        api_key, signing_key = validate_and_extract_api_key(secret, "any-target")
        assert api_key == "test-key"
        assert signing_key is None

    def test_json_secret_with_matching_host_success(self):
        """JSON secrets with matching host should work."""
        secret = '{"secret": "test-key", "host": "api.example.com"}'
        api_key, signing_key = validate_and_extract_api_key(secret, "api.example.com")
        assert api_key == "test-key"
        assert signing_key is None

    def test_json_secret_with_mismatched_host_fails(self):
        """JSON secrets with mismatched host should fail."""
        secret = '{"secret": "test-key", "host": "api.example.com"}'
        with pytest.raises(
            AuthenticationError, match="API key is not valid for target host"
        ):
            validate_and_extract_api_key(secret, "api.different.com")

    def test_json_secret_with_host_but_no_target_fails(self):
        """JSON secrets with host but no target should fail."""
        secret = '{"secret": "test-key", "host": "api.example.com"}'
        with pytest.raises(
            AuthenticationError,
            match="API key has host restriction but target host unknown",
        ):
            validate_and_extract_api_key(secret, None)

    def test_json_secret_with_signing_key_succeeds(self):
        """JSON secrets with valid signing key should work."""
        secret = '{"secret": "test-key", "signing_key": {"kms_key_arn": "arn:...", "provider_id": "key123"}}'  # noqa E501
        api_key, signing_key = validate_and_extract_api_key(secret, "any-target")
        assert api_key == "test-key"
        assert signing_key == SigningKey(provider_id="key123", kms_key_arn="arn:...")

    def test_non_schema_json_returns_full_json(self):
        """JSON that doesn't match our schema should return the full JSON."""
        secret = '{"apiKey": "test-key", "other": "data"}'
        api_key, signing_key = validate_and_extract_api_key(secret, "any-target")
        assert api_key == secret
        assert signing_key is None
