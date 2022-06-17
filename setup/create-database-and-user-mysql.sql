
CREATE DATABASE identity_registry CHARACTER SET utf8 COLLATE utf8_general_ci;

CREATE USER 'idreg'@'localhost' IDENTIFIED BY 'idreg';
GRANT ALL PRIVILEGES ON identity_registry.* TO 'idreg'@'localhost' WITH GRANT OPTION;
CREATE USER 'idreg'@'%' IDENTIFIED BY 'idreg';
GRANT ALL PRIVILEGES ON identity_registry.* TO 'idreg'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
