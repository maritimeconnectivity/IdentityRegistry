#!/bin/bash
#
# Script to insert an organization into the identity registry DB, used for bootstrapping.
#
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Creating organization..."
PGPASSWORD=idreg psql -d identity_registry -U idreg -f "$DIR/create-mc-org.sql"
