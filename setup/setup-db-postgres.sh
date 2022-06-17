#!/bin/bash
#
# Script to setup the identity_registry database in PostgreSQL
#
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Creating DB-user and DB..."
echo "Enter your sudo password if prompted"
sudo -u postgres psql -f "$DIR/create-database-and-user-postgres.sql"
