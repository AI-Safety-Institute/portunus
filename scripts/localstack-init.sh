#!/bin/bash
# LocalStack initialization script - header for init process
# This runs automatically when LocalStack container starts
#
# Note: LocalStack automatically runs all scripts in ready.d/ in alphabetical order.
# The individual stack init scripts (01-init-kinesis.sh, 02-init-async-analysis.sh)
# will run after this header script.

set -e

echo "=========================================="
echo "Initializing LocalStack resources for Portunus..."
echo "=========================================="
echo ""

echo "Waiting for LocalStack API to be ready..."
while ! awslocal secretsmanager list-secrets >/dev/null 2>&1; do
  echo 'waiting for LocalStack...'
  sleep 2
done

echo "Creating test secret for API key"
awslocal secretsmanager create-secret \
  --name test-api-key \
  --secret-string xyz \
  --region eu-west-2 \
  2>/dev/null || true

echo ""
