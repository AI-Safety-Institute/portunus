"""Tests for the pluggable backend architecture."""

import pytest

from portunus.backends.aws.identity import parse_identity_from_arn
from portunus.backends.noop.publisher import NoopPublisher
from portunus.backends.protocols import AuthBackend, StreamPublisher


class TestProtocolCompliance:
    """Verify implementations satisfy the Protocol contracts."""

    def test_noop_publisher_is_stream_publisher(self):
        publisher = NoopPublisher()
        assert isinstance(publisher, StreamPublisher)

    def test_aws_auth_backend_is_auth_backend(self):
        from portunus.backends.aws.auth import AwsAuthBackend

        backend = AwsAuthBackend()
        assert isinstance(backend, AuthBackend)

    def test_kinesis_publisher_is_stream_publisher(self):
        from portunus.backends.aws.publisher import (
            KinesisPublisher,
        )

        publisher = KinesisPublisher()
        assert isinstance(publisher, StreamPublisher)


class TestNoopPublisher:
    """Tests for the NoopPublisher."""

    @pytest.mark.asyncio
    async def test_publish_returns_true(self):
        publisher = NoopPublisher()
        result = await publisher.publish("test-stream", {"key": "value"}, "pk-123")
        assert result is True

    @pytest.mark.asyncio
    async def test_publish_handles_empty_data(self):
        publisher = NoopPublisher()
        result = await publisher.publish("stream", {}, "pk")
        assert result is True


class TestIdentityParsing:
    """Tests for configurable ARN identity parsing."""

    def test_no_pattern_returns_none_project(self):
        """Without a role pattern, project should be None."""
        result = parse_identity_from_arn(
            "arn:aws:sts::123456789012:"
            "assumed-role/UserProfile_Name_myproject/session",
            role_pattern=None,
        )
        assert result.principal == "assumed-role/UserProfile_Name_myproject"
        assert result.session_name == "session"
        assert result.project is None

    def test_aisi_pattern_extracts_project(self):
        """The AISI UserProfile_ pattern extracts project."""
        pattern = r"^UserProfile_[^_]+_(?P<project>.+)$"
        result = parse_identity_from_arn(
            "arn:aws:sts::123456789012:"
            "assumed-role/UserProfile_Name_myproject/session",
            role_pattern=pattern,
        )
        assert result.project == "myproject"

    def test_aisi_pattern_with_underscores_in_project(self):
        """Project names with underscores are preserved."""
        pattern = r"^UserProfile_[^_]+_(?P<project>.+)$"
        result = parse_identity_from_arn(
            "arn:aws:sts::123456789012:"
            "assumed-role/UserProfile_Name_proj_abc/session",
            role_pattern=pattern,
        )
        assert result.project == "proj_abc"

    def test_custom_pattern(self):
        """A custom regex pattern works for non-AISI orgs."""
        # e.g. role name like "team-engineering-prod"
        pattern = r"^team-(?P<project>[^-]+)-"
        result = parse_identity_from_arn(
            "arn:aws:sts::123456789012:" "assumed-role/team-engineering-prod/session",
            role_pattern=pattern,
        )
        assert result.project == "engineering"

    def test_pattern_no_match_returns_none_project(self):
        """If the pattern doesn't match the role, project is None."""
        pattern = r"^UserProfile_[^_]+_(?P<project>.+)$"
        result = parse_identity_from_arn(
            "arn:aws:sts::123456789012:" "assumed-role/SomeOtherRole/session",
            role_pattern=pattern,
        )
        assert result.principal == "assumed-role/SomeOtherRole"
        assert result.project is None

    def test_non_assumed_role_arn(self):
        """Non assumed-role ARNs return no principal info."""
        result = parse_identity_from_arn(
            "arn:aws:iam::123456789012:user/test-user",
            role_pattern=r"^UserProfile_[^_]+_(?P<project>.+)$",
        )
        assert result.account_id == "123456789012"
        assert result.principal is None
        assert result.project is None

    def test_empty_arn(self):
        result = parse_identity_from_arn("")
        assert result.account_id == "unknown"
        assert result.principal is None
        assert result.project is None

    def test_basic_fields_always_populated(self):
        """account_id and arn are always set."""
        result = parse_identity_from_arn(
            "arn:aws:sts::999888777666:" "assumed-role/MyRole/my-session",
            role_pattern=None,
        )
        assert result.arn.startswith("arn:aws:sts::")
        assert result.account_id == "999888777666"
        assert result.session_name == "my-session"


class TestBackendFactory:
    """Tests for the backend factory functions."""

    def test_get_auth_backend_aws(self):
        from portunus.backends import get_auth_backend
        from portunus.config import get_config

        cfg = get_config()
        backend = get_auth_backend(cfg)
        assert isinstance(backend, AuthBackend)

    def test_get_stream_publisher_kinesis(self):
        from portunus.backends import get_stream_publisher
        from portunus.config import get_config

        cfg = get_config()
        publisher = get_stream_publisher(cfg)
        assert isinstance(publisher, StreamPublisher)

    def test_get_stream_publisher_noop(self):
        from portunus.backends import get_stream_publisher
        from portunus.config import PortunusConfig

        cfg = PortunusConfig(log_backend="noop")
        publisher = get_stream_publisher(cfg)
        assert isinstance(publisher, NoopPublisher)

    def test_unknown_auth_backend_raises(self):
        from portunus.backends import get_auth_backend
        from portunus.config import PortunusConfig

        cfg = PortunusConfig(auth_backend="nonexistent")
        with pytest.raises(ValueError, match="nonexistent"):
            get_auth_backend(cfg)

    def test_unknown_log_backend_raises(self):
        from portunus.backends import get_stream_publisher
        from portunus.config import PortunusConfig

        cfg = PortunusConfig(log_backend="nonexistent")
        with pytest.raises(ValueError, match="nonexistent"):
            get_stream_publisher(cfg)
