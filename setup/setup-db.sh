#!/bin/bash
#
# Script to setup the identity_registry database in MySQL/MariaDB
#
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Creating DB-user and DB..."
echo "Enter mysql root password if prompted"
mysql -u root -p < "$DIR/create-database-and-user.sql"

echo "Create tables..."
mysql -D identity_registry --user=idreg --password=idreg < "$DIR/create-tables.sql"
