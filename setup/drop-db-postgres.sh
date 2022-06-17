#!/bin/bash
#
# Script to drop the identity_registry database in PostgreSQL
#
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Drop DB-user and DB..."
echo "Enter your sudo password if prompted"
sudo -u postgres psql -f "$DIR/drop-db-and-user-postgres.sql"
