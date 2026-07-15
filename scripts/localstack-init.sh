#!/bin/bash
# First LocalStack init script (ready.d runs in alphabetical order, so this
# 00- header runs before 01-init-firehose.sh / 02-init-async-analysis.sh).

set -e

echo "=========================================="
echo "Initializing LocalStack resources for Portunus..."
echo "=========================================="
echo ""

echo "Waiting for LocalStack API to be ready..."
while ! awslocal kms list-keys >/dev/null 2>&1; do
  echo 'waiting for LocalStack...'
  sleep 2
done

echo "Creating test KMS key and alias"
awslocal kms create-alias \
  --alias-name alias/test-key \
  --target-key-id $(awslocal kms create-key \
      --key-spec ECC_NIST_P256 \
      --key-usage SIGN_VERIFY \
      --query 'KeyMetadata.Arn' \
      --output text)

echo "Creating test secret for API key"
awslocal secretsmanager create-secret \
  --name test-api-key \
  --secret-string xyz \
  --region eu-west-2 \
  2>/dev/null || true

echo ""
