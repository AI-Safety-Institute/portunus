"""
Unit tests to ensure schema consistency across.

1. Portunus data generation (dataclass field names and types)
2. CDK Glue table definitions (source and joined tables)
3. Glue ETL processing (field transformations and prefixing)

These tests prevent runtime schema mismatches that would cause data pipeline failures.
"""

from typing import Set

from portunus.models import (
    JoinedLogRecord,
    MetadataRecord,
    RequestBodyRecord,
    RequestHeadersRecord,
    RequestTrailersRecord,
    ResponseBodyRecord,
    ResponseHeadersRecord,
    ResponseTrailersRecord,
)


class TestSourceRecordSchemas:
    """Test that source record schemas are consistent with their to_dict() output."""

    def test_metadata_record_to_dict_matches_schema(self):
        """Ensure MetadataRecord.to_dict() keys match glue_schema() fields."""
        schema_fields = {col["name"] for col in MetadataRecord.glue_schema()}

        # Create a sample record with all fields populated
        record = MetadataRecord(
            request_id="test-123",
            timestamp="2025-01-01T00:00:00Z",
            published_at="2025-01-01T00:00:01Z",
            account_id="123456789012",
            principal="assumed-role/TestRole",
            principal_arn="arn:aws:sts::123456789012:assumed-role/TestRole/session",
            project="test-project",
            session_name="test-session",
            secret_arn="arn:aws:secretsmanager:eu-west-2:123456789012:secret:projects/test-project/api-key-aB3xY1",
        )

        dict_keys = set(record.to_dict().keys())

        # All keys in to_dict() should be in the schema
        assert dict_keys == schema_fields, (
            f"Mismatch between to_dict() keys and schema fields.\n"
            f"Extra in to_dict(): {dict_keys - schema_fields}\n"
            f"Missing from to_dict(): {schema_fields - dict_keys}"
        )

    def test_request_headers_record_to_dict_matches_schema(self):
        """Ensure RequestHeadersRecord.to_dict() keys match glue_schema() fields."""
        schema_fields = {col["name"] for col in RequestHeadersRecord.glue_schema()}

        record = RequestHeadersRecord(
            request_id="test-123",
            raw_headers={"content-type": "YXBwbGljYXRpb24vanNvbg=="},
            timestamp="2025-01-01T00:00:00Z",
            published_at="2025-01-01T00:00:01Z",
        )

        dict_keys = set(record.to_dict().keys())

        assert dict_keys == schema_fields, (
            f"Mismatch for RequestHeadersRecord.\n"
            f"Extra: {dict_keys - schema_fields}\n"
            f"Missing: {schema_fields - dict_keys}"
        )

    def test_request_body_record_to_dict_matches_schema(self):
        """Ensure RequestBodyRecord.to_dict() keys match glue_schema() fields."""
        schema_fields = {col["name"] for col in RequestBodyRecord.glue_schema()}

        record = RequestBodyRecord(
            request_id="test-123",
            body="eyJ0ZXN0IjogImRhdGEifQ==",
            body_size=100,
            timestamp="2025-01-01T00:00:00Z",
            chunk_id=0,
            num_chunks=1,
            published_at="2025-01-01T00:00:01Z",
        )

        dict_keys = set(record.to_dict().keys())

        assert dict_keys == schema_fields, (
            f"Mismatch for RequestBodyRecord.\n"
            f"Extra: {dict_keys - schema_fields}\n"
            f"Missing: {schema_fields - dict_keys}"
        )

    def test_response_headers_record_to_dict_matches_schema(self):
        """Ensure ResponseHeadersRecord.to_dict() keys match glue_schema() fields."""
        schema_fields = {col["name"] for col in ResponseHeadersRecord.glue_schema()}

        record = ResponseHeadersRecord(
            request_id="test-123",
            raw_headers={":status": "MjAw"},
            timestamp="2025-01-01T00:00:00Z",
            published_at="2025-01-01T00:00:01Z",
        )

        dict_keys = set(record.to_dict().keys())

        assert dict_keys == schema_fields, (
            f"Mismatch for ResponseHeadersRecord.\n"
            f"Extra: {dict_keys - schema_fields}\n"
            f"Missing: {schema_fields - dict_keys}"
        )

    def test_response_body_record_to_dict_matches_schema(self):
        """Ensure ResponseBodyRecord.to_dict() keys match glue_schema() fields."""
        schema_fields = {col["name"] for col in ResponseBodyRecord.glue_schema()}

        record = ResponseBodyRecord(
            request_id="test-123",
            body="eyJyZXN1bHQiOiAib2sifQ==",
            body_size=50,
            timestamp="2025-01-01T00:00:00Z",
            chunk_id=0,
            num_chunks=1,
            published_at="2025-01-01T00:00:01Z",
        )

        dict_keys = set(record.to_dict().keys())

        assert dict_keys == schema_fields, (
            f"Mismatch for ResponseBodyRecord.\n"
            f"Extra: {dict_keys - schema_fields}\n"
            f"Missing: {schema_fields - dict_keys}"
        )


class TestGlueJobTransformations:
    """Test that JoinedLogRecord schema matches expected Glue job output.

    The Glue job (pipelines/process_raw_data.py) performs these transformations:
    1. Drops 'record_type' from all streams
    2. Drops 'published_at' from headers/trailers (but keeps metadata_published_at)
    3. Adds prefixes: metadata_, request_headers_, request_body_, response_headers_,
       response_body_
    4. Keeps 'request_id' and 'timestamp' unprefixed (used for joins)
    5. For body records: drops body_size, chunk_id, num_chunks (only keeps first chunk)
    6. Adds etl_processed_at
    7. Adds partition columns (not in JoinedLogRecord dataclass, added by Glue)
    """

    def _get_expected_joined_fields(self) -> Set[str]:
        """Calculate expected field names based on Glue transformations."""
        expected = set()

        # Core fields (unprefixed)
        expected.add("request_id")
        expected.add("timestamp")

        # Metadata fields (with metadata_ prefix, excluding record_type)
        metadata_fields = {col["name"] for col in MetadataRecord.glue_schema()}
        metadata_fields.remove("record_type")  # Dropped by Glue
        for field in metadata_fields:
            if field not in ["request_id", "timestamp"]:  # Skip unprefixed fields
                expected.add(f"metadata_{field}")

        # Request headers (with request_headers_ prefix,
        # excluding record_type and published_at)
        req_headers_fields = {col["name"] for col in RequestHeadersRecord.glue_schema()}
        req_headers_fields.remove("record_type")
        req_headers_fields.remove("published_at")
        for field in req_headers_fields:
            if field != "request_id":  # Skip join key
                expected.add(f"request_headers_{field}")

        # Request body (with request_body_ prefix)
        # After reassembly, keeps: body, body_size, timestamp, num_chunks, truncated
        # Drops: chunk_id (consumed during reassembly), record_type, published_at
        expected.add("request_body_body")
        expected.add("request_body_body_size")
        expected.add("request_body_timestamp")
        expected.add("request_body_num_chunks")
        expected.add("request_body_truncated")

        # Response headers (with response_headers_ prefix, excluding
        # record_type and published_at)
        resp_headers_fields = {
            col["name"] for col in ResponseHeadersRecord.glue_schema()
        }
        resp_headers_fields.remove("record_type")
        resp_headers_fields.remove("published_at")
        for field in resp_headers_fields:
            if field != "request_id":  # Skip join key
                expected.add(f"response_headers_{field}")

        # Response body (with response_body_ prefix)
        # After reassembly, keeps: body, body_size, timestamp, num_chunks, truncated
        # Drops: chunk_id (consumed during reassembly), record_type, published_at
        expected.add("response_body_body")
        expected.add("response_body_body_size")
        expected.add("response_body_timestamp")
        expected.add("response_body_num_chunks")
        expected.add("response_body_truncated")

        # ETL metadata
        expected.add("etl_processed_at")

        # Decoded fields (added during ETL processing)
        expected.add("request_headers_decoded")
        expected.add("request_body_decoded")
        expected.add("response_headers_decoded")
        expected.add("response_body_decoded")

        # Decode failure tracking fields (added during ETL processing)
        expected.add("request_headers_decode_failure")
        expected.add("request_body_decode_failure")
        expected.add("response_headers_decode_failure")
        expected.add("response_body_decode_failure")

        return expected

    def test_joined_record_schema_matches_glue_transformations(self):
        """Ensure JoinedLogRecord.glue_schema() matches expected Glue job output."""
        # Get actual schema fields from JoinedLogRecord
        actual_fields = {col["name"] for col in JoinedLogRecord.glue_schema()}

        # Calculate expected fields based on Glue transformations
        expected_fields = self._get_expected_joined_fields()

        # Partition columns are now part of the schema (as Optional fields)
        # They're derived from timestamp during ETL and included in the complete record
        partition_columns = set(JoinedLogRecord.partition_key_names())
        expected_fields.update(partition_columns)

        # Check for mismatches
        extra_fields = actual_fields - expected_fields
        missing_fields = expected_fields - actual_fields

        assert not extra_fields, (
            f"JoinedLogRecord has unexpected fields: {extra_fields}\n"
            f"These fields don't match the Glue job output."
        )

        assert not missing_fields, (
            f"JoinedLogRecord is missing expected fields: {missing_fields}\n"
            f"These fields should be produced by the Glue job."
        )

    def test_metadata_arn_field_naming(self):
        """CRITICAL: Verify principal_arn field is correctly prefixed in joined schema.

        This test ensures MetadataRecord has 'principal_arn' field which becomes
        'metadata_principal_arn' in JoinedLogRecord after the Glue job adds prefix.
        """
        metadata_schema = {col["name"] for col in MetadataRecord.glue_schema()}
        joined_schema = {col["name"] for col in JoinedLogRecord.glue_schema()}

        # Check if 'principal_arn' exists in metadata schema
        assert (
            "principal_arn" in metadata_schema
        ), "MetadataRecord should have 'principal_arn' field"

        # The Glue job adds 'metadata_' prefix to all metadata fields
        # (except request_id, timestamp). So 'principal_arn' should become
        # 'metadata_principal_arn' in the joined record
        expected_name = "metadata_principal_arn"

        # Check what's actually in the joined schema
        assert expected_name in joined_schema, (
            f"MISSING FIELD: JoinedLogRecord should have '{expected_name}' "
            f"but it's not in schema.\nAvailable metadata "
            f"fields: {[f for f in joined_schema if f.startswith('metadata_')]}"
        )

        # Make sure the wrong name doesn't exist
        wrong_name = "metadata_arn"
        assert wrong_name not in joined_schema, (
            f"INCORRECT FIELD: JoinedLogRecord has '{wrong_name}' "
            f"but should have '{expected_name}'.\n"
            f"The source field in MetadataRecord should be 'principal_arn', not 'arn'."
        )

    def test_metadata_secret_arn_field_naming(self):
        """Verify secret_arn is preserved as metadata_secret_arn in joined schema."""
        metadata_schema = {col["name"] for col in MetadataRecord.glue_schema()}
        joined_schema = {col["name"] for col in JoinedLogRecord.glue_schema()}

        assert (
            "secret_arn" in metadata_schema
        ), "MetadataRecord should have 'secret_arn' field"

        expected_name = "metadata_secret_arn"
        assert expected_name in joined_schema, (
            f"MISSING FIELD: JoinedLogRecord should have '{expected_name}' "
            f"but it's not in schema.\nAvailable metadata "
            f"fields: {[f for f in joined_schema if f.startswith('metadata_')]}"
        )

    def test_body_chunk_fields_handling(self):
        """Verify body chunk fields are properly handled in joined schema.

        The Glue job reassembles chunks and includes body_size, num_chunks, truncated.
        chunk_id is dropped during reassembly (consumed to order chunks).
        """
        joined_schema = {col["name"] for col in JoinedLogRecord.glue_schema()}

        # These fields SHOULD appear in joined schema (kept after reassembly)
        kept_fields = [
            "request_body_body_size",
            "request_body_num_chunks",
            "request_body_truncated",
            "response_body_body_size",
            "response_body_num_chunks",
            "response_body_truncated",
        ]

        for field in kept_fields:
            assert field in joined_schema, (
                f"Field '{field}' should be in JoinedLogRecord schema. "
                f"The Glue job keeps this field after chunk reassembly."
            )

        # chunk_id should NOT appear (consumed during reassembly)
        chunk_id_fields = [
            "request_body_chunk_id",
            "response_body_chunk_id",
        ]

        for field in chunk_id_fields:
            assert field not in joined_schema, (
                f"Field '{field}' should not be in JoinedLogRecord schema. "
                f"The Glue job drops chunk_id during reassembly."
            )

    def test_published_at_handling(self):
        """Verify published_at is only kept from metadata, not from headers/trailers."""
        joined_schema = {col["name"] for col in JoinedLogRecord.glue_schema()}

        # Should have metadata_published_at
        assert (
            "metadata_published_at" in joined_schema
        ), "JoinedLogRecord should have 'metadata_published_at'"

        # Should NOT have published_at from other streams
        unwanted_fields = [
            "request_headers_published_at",
            "request_body_published_at",
            "response_headers_published_at",
            "response_body_published_at",
        ]

        for field in unwanted_fields:
            assert field not in joined_schema, (
                f"Field '{field}' should not be in JoinedLogRecord. "
                f"The Glue job drops published_at from non-metadata streams."
            )


class TestSchemaTypes:
    """Test that field types are consistent across schemas."""

    def test_timestamp_types_in_joined_schema(self):
        """Verify timestamp fields use correct types in joined schema.

        Source tables have 'string' timestamps, but Glue converts them to
        'timestamp' type.
        """
        joined_schema = {
            col["name"]: col["type"] for col in JoinedLogRecord.glue_schema()
        }

        # Main timestamp should be timestamp type
        assert (
            joined_schema["timestamp"] == "timestamp"
        ), "Main 'timestamp' field should be 'timestamp' type (converted by Glue)"

        # Stream-specific timestamps should also be timestamp type
        timestamp_fields = [
            "request_headers_timestamp",
            "request_body_timestamp",
            "response_headers_timestamp",
            "response_body_timestamp",
        ]

        for field in timestamp_fields:
            assert field in joined_schema, f"Missing timestamp field: {field}"
            assert joined_schema[field] == "timestamp", (
                f"Field '{field}' should be 'timestamp' type, "
                f"got '{joined_schema[field]}'"
            )

    def test_map_types_for_headers(self):
        """Verify headers use map<string,string> type consistently."""
        # Source schemas
        req_headers_schema = {
            col["name"]: col["type"] for col in RequestHeadersRecord.glue_schema()
        }
        resp_headers_schema = {
            col["name"]: col["type"] for col in ResponseHeadersRecord.glue_schema()
        }
        joined_schema = {
            col["name"]: col["type"] for col in JoinedLogRecord.glue_schema()
        }

        # Source tables should use map<string,string> for raw_headers
        assert req_headers_schema["raw_headers"] == "map<string,string>"
        assert resp_headers_schema["raw_headers"] == "map<string,string>"

        # Joined table should preserve map type with prefix
        assert joined_schema["request_headers_raw_headers"] == "map<string,string>"
        assert joined_schema["response_headers_raw_headers"] == "map<string,string>"

    def test_bigint_types_in_source_schemas(self):
        """Verify numeric fields use bigint in source schemas."""
        req_body_schema = {
            col["name"]: col["type"] for col in RequestBodyRecord.glue_schema()
        }
        resp_body_schema = {
            col["name"]: col["type"] for col in ResponseBodyRecord.glue_schema()
        }

        # Body size and chunk fields should be bigint
        numeric_fields = ["body_size", "chunk_id", "num_chunks"]

        for field in numeric_fields:
            assert req_body_schema[field] == "bigint", (
                f"RequestBodyRecord.{field} should be 'bigint', "
                f"got '{req_body_schema[field]}'"
            )
            assert resp_body_schema[field] == "bigint", (
                f"ResponseBodyRecord.{field} should be 'bigint', "
                f"got '{resp_body_schema[field]}'"
            )


class TestSchemaCompleteness:
    """Test that all necessary fields are present in schemas."""

    def test_all_source_records_have_required_fields(self):
        """Verify all source record schemas have essential fields."""
        required_fields = {"record_type", "request_id", "timestamp", "published_at"}

        record_classes = [
            MetadataRecord,
            RequestHeadersRecord,
            RequestBodyRecord,
            RequestTrailersRecord,
            ResponseHeadersRecord,
            ResponseBodyRecord,
            ResponseTrailersRecord,
        ]

        for record_class in record_classes:
            schema_fields = {col["name"] for col in record_class.glue_schema()}
            missing = required_fields - schema_fields

            assert (
                not missing
            ), f"{record_class.__name__} is missing required fields: {missing}"

    def test_joined_record_has_all_prefixed_streams(self):
        """Verify record includes fields from all streams with correct prefixes."""
        joined_schema = {col["name"] for col in JoinedLogRecord.glue_schema()}

        # Each stream should have at least one field with the expected prefix
        expected_prefixes = [
            "metadata_",
            "request_headers_",
            "request_body_",
            "response_headers_",
            "response_body_",
        ]

        for prefix in expected_prefixes:
            matching_fields = [f for f in joined_schema if f.startswith(prefix)]
            assert matching_fields, (
                f"JoinedLogRecord has no fields with prefix '{prefix}'. "
                f"Expected to see transformed fields from that stream."
            )


# Integration test helpers
def simulate_glue_field_transformation(
    source_record_class,
    prefix: str,
    skip_fields: Set[str] | None = None,
    drop_fields: Set[str] | None = None,
) -> Set[str]:
    """Simulate the field transformations performed by the Glue job.

    Args:
        source_record_class: The source record class (e.g., MetadataRecord)
        prefix: Prefix to add to fields (e.g., "metadata_")
        skip_fields: Fields to not prefix (e.g., {"request_id", "timestamp"})
        drop_fields: Fields to drop completely (e.g., {"record_type", "published_at"})

    Returns:
        Set of expected output field names after transformation
    """
    skip_fields = skip_fields or set()
    drop_fields = drop_fields or set()

    source_fields = {col["name"] for col in source_record_class.glue_schema()}

    output_fields = set()
    for field in source_fields:
        if field in drop_fields:
            continue
        if field in skip_fields:
            output_fields.add(field)
        else:
            output_fields.add(f"{prefix}{field}")

    return output_fields


class TestGlueSimulation:
    """Test schema transformations using simulation of Glue job logic."""

    def test_metadata_transformation_simulation(self):
        """Simulate metadata field transformations and verify against joined schema."""
        expected = simulate_glue_field_transformation(
            MetadataRecord,
            prefix="metadata_",
            skip_fields={"request_id", "timestamp"},
            drop_fields={"record_type"},
        )

        joined_schema = {col["name"] for col in JoinedLogRecord.glue_schema()}

        # Filter to only metadata fields
        actual_metadata_fields = {f for f in joined_schema if f.startswith("metadata_")}

        # Also add the unprefixed fields that came from metadata
        if "request_id" in joined_schema:
            expected.add("request_id")
        if "timestamp" in joined_schema:
            expected.add("timestamp")

        metadata_expected = {f for f in expected if f.startswith("metadata_")}

        missing = metadata_expected - actual_metadata_fields
        extra = actual_metadata_fields - metadata_expected

        assert not missing, f"Missing metadata fields in JoinedLogRecord: {missing}"
        assert not extra, f"Extra metadata fields in JoinedLogRecord: {extra}"

    def test_request_headers_transformation_simulation(self):
        """Simulate request headers transformations and verify against joined schema."""
        expected = simulate_glue_field_transformation(
            RequestHeadersRecord,
            prefix="request_headers_",
            skip_fields={"request_id"},
            drop_fields={"record_type", "published_at"},
        )
        # Add decoded field that's added during ETL
        expected.add("request_headers_decoded")
        # Add decode failure tracking field that's added during ETL
        expected.add("request_headers_decode_failure")

        joined_schema = {col["name"] for col in JoinedLogRecord.glue_schema()}
        actual = {f for f in joined_schema if f.startswith("request_headers_")}

        expected_prefixed = {f for f in expected if f.startswith("request_headers_")}

        missing = expected_prefixed - actual
        extra = actual - expected_prefixed

        assert not missing, f"Missing request_headers fields: {missing}"
        assert not extra, f"Extra request_headers fields: {extra}"

    def test_response_headers_transformation_simulation(self):
        """Simulate response header transformations and verify against joined schema."""
        expected = simulate_glue_field_transformation(
            ResponseHeadersRecord,
            prefix="response_headers_",
            skip_fields={"request_id"},
            drop_fields={"record_type", "published_at"},
        )
        # Add decoded field that's added during ETL
        expected.add("response_headers_decoded")
        # Add decode failure tracking field that's added during ETL
        expected.add("response_headers_decode_failure")

        joined_schema = {col["name"] for col in JoinedLogRecord.glue_schema()}
        actual = {f for f in joined_schema if f.startswith("response_headers_")}

        expected_prefixed = {f for f in expected if f.startswith("response_headers_")}

        missing = expected_prefixed - actual
        extra = actual - expected_prefixed

        assert not missing, f"Missing response_headers fields: {missing}"
        assert not extra, f"Extra response_headers fields: {extra}"
