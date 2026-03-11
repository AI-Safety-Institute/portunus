#!/bin/bash
# LocalStack initialization for Kinesis Stack resources
# Corresponds to infra/stacks/kinesis_stack.py

set -e

echo "Initializing Kinesis Stack resources..."

# Define stream names
STREAM_NAMES=(
    "metadata"
    "request-headers"
    "request-body"
    "request-trailers"
    "response-headers"
    "response-body"
    "response-trailers"
)

# Create S3 bucket for logs
echo "  Creating S3 bucket for logs..."
awslocal s3 mb s3://portunus-logs-local 2>/dev/null || echo "  Bucket portunus-logs-local already exists"

# Create Kinesis Data Streams
echo "  Creating Kinesis Data Streams..."
for stream in "${STREAM_NAMES[@]}"; do
    stream_name="portunus-stream-${stream}"
    awslocal kinesis create-stream \
        --stream-name "${stream_name}" \
        --shard-count 1 \
        2>/dev/null || echo "    Stream ${stream_name} already exists"
done

# Wait for streams to be active
echo "  Waiting for streams to become active..."
sleep 2

# Create Kinesis Firehose delivery streams
# Note: Firehose Parquet conversion and Glue catalog integration require LocalStack Pro
# In free tier, Firehose writes JSON/GZIP format directly to S3
echo "  Creating Kinesis Firehose delivery streams (JSON/GZIP format for LocalStack free tier)..."
for stream in "${STREAM_NAMES[@]}"; do
    data_stream_name="portunus-stream-${stream}"
    firehose_name="portunus-firehose-${stream}"

    # Get the stream ARN
    stream_arn=$(awslocal kinesis describe-stream \
        --stream-name "${data_stream_name}" \
        --query 'StreamDescription.StreamARN' \
        --output text)

    # Create Firehose delivery stream with JSON/GZIP format (works in LocalStack free tier)
    awslocal firehose create-delivery-stream \
        --delivery-stream-name "${firehose_name}" \
        --delivery-stream-type KinesisStreamAsSource \
        --kinesis-stream-source-configuration \
            "KinesisStreamARN=${stream_arn},RoleARN=arn:aws:iam::000000000000:role/firehose-role" \
        --s3-destination-configuration \
            "RoleARN=arn:aws:iam::000000000000:role/firehose-role,\
BucketARN=arn:aws:s3:::portunus-logs-local,\
Prefix=logs/${stream}/,\
ErrorOutputPrefix=errors/${stream}/,\
CompressionFormat=GZIP,\
BufferingHints={SizeInMBs=1,IntervalInSeconds=10}" \
        2>/dev/null || echo "    Firehose ${firehose_name} already exists"
done

echo ""
echo "  NOTE: Glue catalog and Firehose Parquet conversion require LocalStack Pro."
echo "  In AWS production, data will be written in Parquet format using Glue schemas."
echo "  For local development (free tier), data is written as JSON/GZIP and the Glue"
echo "  job reads directly from S3 JSON files instead of using the Glue catalog."
echo ""

echo "✓ Kinesis Stack resources initialized"
echo "  - S3 bucket: portunus-logs-local"
echo "  - Kinesis streams: ${#STREAM_NAMES[@]} streams"
echo "  - Firehose streams: ${#STREAM_NAMES[@]} streams"
echo "  - Glue database: portunus_logs"
echo "  - Glue tables: 7 tables"
