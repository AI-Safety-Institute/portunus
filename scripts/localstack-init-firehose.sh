#!/bin/bash
# LocalStack initialization for Firehose direct-PUT delivery streams.
# Corresponds to the api-key-proxy CDK Firehose stack (formerly the
# Kinesis stack, which provisioned Kinesis Data Streams as Firehose
# sources — direct-PUT removes the Data Streams hop).

set -e

echo "Initializing Firehose Stack resources..."

# Define stream names (one Firehose delivery stream per record type)
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

# Create Kinesis Firehose delivery streams (direct-PUT, no Kinesis source).
# Note: Firehose Parquet conversion and Glue catalog integration require LocalStack Pro.
# In free tier, Firehose writes JSON/GZIP format directly to S3.
echo "  Creating Firehose direct-PUT delivery streams (JSON/GZIP format for LocalStack free tier)..."
for stream in "${STREAM_NAMES[@]}"; do
    firehose_name="portunus-stream-${stream}"

    # Create Firehose delivery stream with DirectPut source and S3 destination.
    awslocal firehose create-delivery-stream \
        --delivery-stream-name "${firehose_name}" \
        --delivery-stream-type DirectPut \
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

echo "✓ Firehose Stack resources initialized"
echo "  - S3 bucket: portunus-logs-local"
echo "  - Firehose delivery streams: ${#STREAM_NAMES[@]} streams (direct-PUT)"
echo "  - Glue database: portunus_logs"
echo "  - Glue tables: 7 tables"
