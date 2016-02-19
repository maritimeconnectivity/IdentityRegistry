CREATE TABLE `organizations` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255),
  `short_name` VARCHAR(10),
  `email` VARCHAR(255),
  `address` VARCHAR(1000),
  `country` VARCHAR(64),
  `type` VARCHAR(64),
  `url` VARCHAR(512),
  `oidc_well_known_url` VARCHAR(512),
  `oidc_client_name`VARCHAR(512),
  `oidc_client_secret`VARCHAR(512),
  `password_hash` VARCHAR(512),
  `logo` BLOB,
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  UNIQUE (`short_name`)
);

CREATE TABLE `vessels` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `vessel_org_id` VARCHAR(512),
  `name` VARCHAR(255),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY  (`id`),
  FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`)
);

CREATE TABLE `vessel_attributes` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_vessel` INT,
  `attribute_name` VARCHAR(512),
  `attribute_value` VARCHAR(512),
  `start` DATETIME,
  `end` DATETIME,
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`id_vessel`) REFERENCES vessels(`id`)
);

CREATE TABLE `users` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `user_org_id` VARCHAR(512),
  `email` VARCHAR(255),
  `first_name` VARCHAR(255),
  `last_name` VARCHAR(255),
  `id_keycloak` VARCHAR(255),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`)
);

CREATE TABLE `devices` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `device_org_id` VARCHAR(512),
  `name` VARCHAR(255),
  `id_keycloak` VARCHAR(255),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`)
);

CREATE TABLE `certificates` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_vessel` INT,
  `id_user` INT,
  `id_device` INT,
  `certificate` MEDIUMTEXT,
  `start` DATETIME,
  `end` DATETIME,
  `revoked` BOOLEAN,
  `revoke_reason` VARCHAR(64),
  `revoked_at` DATETIME,
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`id_vessel`) REFERENCES vessels(`id`),
  FOREIGN KEY (`id_user`) REFERENCES users(`id`),
  FOREIGN KEY (`id_device`) REFERENCES devices(`id`)
);
