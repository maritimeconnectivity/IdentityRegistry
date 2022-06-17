#!/bin/bash
#
# Script to insert an organization into the identity registry DB, used for bootstrapping.
#
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Creating organization..."
mysql -D identity_registry --user=idreg --password=idreg < "$DIR/create-mc-org.sql"

