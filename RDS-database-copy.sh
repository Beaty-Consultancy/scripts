#!/bin/bash

# File Name:    RDS-database-copy.sh
# Description:  MySQL dump a database from an RDS service and clean up the file so it can be imported into another RDS service.
# Version:      1
# Author:       Ricky Beaty
# Date:         29/05/2023
# Prerequisites Install MySQL client if it isn't already in plcase.
#               sudo apt install mysql-client

#######################################

username= # RDS username
RDShost= # RDS endpoint
password= # RDS password
database= # The MySQL database to export

filename="${database}.sql"
zipfile="${database}.zip"

mysqldump -u $username -h $RDShost -p$password --lock-tables=false $database > $filename

# Remove junk that RDS doesn't like
awk '!/@@/' $filename > temp && mv temp $filename
awk '!/character_set_client/' $filename > temp && mv temp $filename
awk '!/TIME_ZONE/' $filename > temp && mv temp $filename
awk '!/SQL_MODE=@OLD_SQL_MODE/' $filename > temp && mv temp $filename
awk '!/FOREIGN_KEY_CHECKS/' $filename > temp && mv temp $filename
awk '!/UNIQUE_CHECKS/' $filename > temp && mv temp $filename
awk '!/CHARACTER_SET_CLIENT/' $filename > temp && mv temp $filename
awk '!/CHARACTER_SET_RESULTS/' $filename > temp && mv temp $filename
awk '!/COLLATION_CONNECTION/' $filename > temp && mv temp $filename
awk '!/SQL_NOTES/' $filename > temp && mv temp $filename
awk '!/SQL_NOTES/' $filename > temp && mv temp $filename

# Temporarily remove constraints
sed -i '1s/^/SET @OLD_FOREIGN_KEY_CHECKS = @@FOREIGN_KEY_CHECKS;\n/' $filename
sed -i '1s/^/SET FOREIGN_KEY_CHECKS = 0;\n/' $filename
echo "SET FOREIGN_KEY_CHECKS = 1;" >> $filename

zip $zipfile $filename