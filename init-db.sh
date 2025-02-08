#!/bin/bash
set -e

# Define multiple databases
DATABASES="infisical idp idp_test"

# Loop through and create each database
for db in $DATABASES; do
    echo "Creating database: $db"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<EOSQL
CREATE DATABASE $db;
EOSQL
done