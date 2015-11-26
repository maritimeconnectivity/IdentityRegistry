#!/bin/bash
#
# Script to drop the identity_registry database in MySQL/MariaDB
#
echo "Drop DB-user and DB..."
echo "Enter mysql root password if prompted"
mysql -u root -p < drop-db-and-user.sql
