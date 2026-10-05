#!/bin/bash
# LocalStack initialization for Kinesis Stack resources
# Corresponds to infra/stacks/kinesis_stack.py
# Buffer hints below are aggressively short so smoke tests can assert on S3
# contents within seconds.

set -e

echo "Initializing Firehose audit-pipeline resources..."

# Define stream names
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

# Create S3 bucket for logs
echo "  Creating S3 bucket for logs..."
awslocal s3 mb s3://portunus-logs-local 2>/dev/null \
    || echo "  Bucket portunus-logs-local already exists"

# Kinesis first, so every stream exists within a few seconds of LocalStack
# coming up and the backend's stream lookups stop failing early. The AWS CLI's
# stream-exists waiter sleeps 10 s between attempts, so poll the status
# ourselves instead.
echo "  Creating Kinesis data streams..."
for stream in "${STREAM_NAMES[@]}"; do
    kds_name="portunus-stream-${stream}"
    awslocal kinesis create-stream --stream-name "${kds_name}" \
        --stream-mode-details StreamMode=ON_DEMAND 2>/dev/null \
        || echo "    Stream ${kds_name} already exists"
done
for stream in "${STREAM_NAMES[@]}"; do
    kds_name="portunus-stream-${stream}"
    until [ "$(awslocal kinesis describe-stream-summary --stream-name "${kds_name}" \
        --query StreamDescriptionSummary.StreamStatus --output text 2>/dev/null)" = "ACTIVE" ]; do
        sleep 0.5
    done
done

# LocalStack takes ~25 s to start the Kinesis listener behind each
# KinesisStreamAsSource delivery stream (a DirectPut one takes ~1 s). The cost
# is per stream and not CPU-bound, so create them concurrently: sequentially
# the seven took over three minutes, past the test fixture's init wait.
echo "  Creating Firehose delivery streams (concurrently)..."
for stream in "${STREAM_NAMES[@]}"; do
    (
        kds_name="portunus-stream-${stream}"
        firehose_name="portunus-firehose-${stream}"
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
    ) &
done
wait

# The "already exists" fallbacks above also swallow real failures, so check
# the outcome once rather than trusting seven exit codes.
existing=" $(awslocal firehose list-delivery-streams \
    --query DeliveryStreamNames --output text | tr '\t' ' ') "
for stream in "${STREAM_NAMES[@]}"; do
    firehose_name="portunus-firehose-${stream}"
    case "${existing}" in
        *" ${firehose_name} "*) ;;
        *)
            echo "ERROR: Firehose ${firehose_name} was not created" >&2
            exit 1
            ;;
    esac
done

echo "✓ Firehose audit-pipeline resources initialized"
echo "  - S3 bucket: portunus-logs-local"
echo "  - Kinesis -> Firehose streams: ${#STREAM_NAMES[@]} (1s/1MiB buffer for fast smoke tests)"
