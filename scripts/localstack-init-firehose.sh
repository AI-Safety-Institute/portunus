#!/bin/bash
# LocalStack initialization for the Firehose direct-PUT audit pipeline.
# Mirrors the akp Firehose stack: portunus writes records straight to
# Firehose delivery streams (no Kinesis Data Streams), which buffer to
# S3. Buffer hints below are aggressively short so smoke tests can
# assert on S3 contents within seconds; production hints (5 MiB / 60s)
# live in the akp CDK.

set -e

echo "Initializing Firehose audit-pipeline resources..."

STREAM_NAMES=(
    "metadata"
    "request-headers"
    "request-body"
    "request-trailers"
    "response-headers"
    "response-body"
    "response-trailers"
    "ws-summary"
)

echo "  Creating S3 bucket for logs..."
awslocal s3 mb s3://portunus-logs-local 2>/dev/null \
    || echo "  Bucket portunus-logs-local already exists"

echo "  Creating Firehose direct-PUT delivery streams..."
for stream in "${STREAM_NAMES[@]}"; do
    firehose_name="portunus-firehose-${stream}"

    awslocal firehose create-delivery-stream \
        --delivery-stream-name "${firehose_name}" \
        --delivery-stream-type DirectPut \
        --s3-destination-configuration \
            "RoleARN=arn:aws:iam::000000000000:role/firehose-role,\
BucketARN=arn:aws:s3:::portunus-logs-local,\
Prefix=logs/${stream}/,\
ErrorOutputPrefix=errors/${stream}/,\
CompressionFormat=UNCOMPRESSED,\
BufferingHints={SizeInMBs=1,IntervalInSeconds=1}" \
        2>/dev/null \
        || echo "    Firehose ${firehose_name} already exists"
done

echo "✓ Firehose audit-pipeline resources initialized"
echo "  - S3 bucket: portunus-logs-local"
echo "  - Firehose direct-PUT streams: ${#STREAM_NAMES[@]} (1s/1MiB buffer for fast smoke tests)"
