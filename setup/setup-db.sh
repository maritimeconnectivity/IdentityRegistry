#!/bin/bash
#
# Script to setup the identity_registry database in MySQL/MariaDB
#
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Creating DB-user and DB..."
echo "Enter mysql root password if prompted"
mysql -u root -p < "$DIR/create-database-and-user.sql"
mysql -u root -p < "$DIR/create-tables.sql"
mysql -u root -p < "$DIR/create-mc-org.sql"
