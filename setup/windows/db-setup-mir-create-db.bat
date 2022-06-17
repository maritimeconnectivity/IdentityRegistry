@title MIR DB setup - Create database
@echo off

if not exist "logs" mkdir logs

@call set-env.bat

@set SQL_FILE=create-database-and-user-mysql.sql
if exist logs\%SQL_FILE%.log del logs\%SQL_FILE%.log
if exist logs\%SQL_FILE%-err.log del logs\%SQL_FILE%-err.log

@call %MYSQL_HOME%\bin\mysql -u root < "..\%SQL_FILE%" > logs\%SQL_FILE%.log 2> logs\%SQL_FILE%-err.log

pause
