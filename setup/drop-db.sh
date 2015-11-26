#!/bin/bash
#
# Script to drop the identity_registry database in MySQL/MariaDB
#
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Drop DB-user and DB..."
echo "Enter mysql root password if prompted"
mysql -u root -p < "$DIR/drop-db-and-user.sql"
