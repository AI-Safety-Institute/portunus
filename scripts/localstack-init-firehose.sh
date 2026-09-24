#!/bin/bash
# LocalStack initialization for the audit pipeline.
# Mirrors the akp stack: portunus packs records into Kinesis Data Streams,
# each read by a Firehose delivery stream that buffers to S3 (in prod it
# also deaggregates the packs; S3 objects are newline-delimited JSON either
# way). Buffer hints below are aggressively short so smoke tests can
# assert on S3 contents within seconds; production hints live in the akp CDK.

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

echo "  Creating Kinesis data streams + Firehose delivery streams..."
for stream in "${STREAM_NAMES[@]}"; do
    kds_name="portunus-audit-${stream}"
    firehose_name="portunus-firehose-${stream}"

    awslocal kinesis create-stream --stream-name "${kds_name}" \
        --stream-mode-details StreamMode=ON_DEMAND 2>/dev/null \
        || echo "    Stream ${kds_name} already exists"
    awslocal kinesis wait stream-exists --stream-name "${kds_name}"

    awslocal firehose create-delivery-stream \
        --delivery-stream-name "${firehose_name}" \
        --delivery-stream-type KinesisStreamAsSource \
        --kinesis-stream-source-configuration \
            "KinesisStreamARN=arn:aws:kinesis:eu-west-2:000000000000:stream/${kds_name},\
RoleARN=arn:aws:iam::000000000000:role/firehose-role" \
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
echo "  - Kinesis -> Firehose streams: ${#STREAM_NAMES[@]} (1s/1MiB buffer for fast smoke tests)"
