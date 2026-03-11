#!/bin/bash
# LocalStack initialization for Async Analysis Stack resources
# Corresponds to infra/stacks/async_analysis_stack.py

set -e

echo "Initializing Async Analysis Stack resources..."

# Create S3 bucket for joined data
echo "  Creating S3 bucket for joined data..."
awslocal s3 mb s3://portunus-joined-data-local 2>/dev/null || echo "  Bucket portunus-joined-data-local already exists"

# Note: Glue database portunus_logs is shared with Kinesis Stack
# No separate database needed

echo "✓ Async Analysis Stack resources initialized"
echo "  - S3 bucket: portunus-joined-data-local"
