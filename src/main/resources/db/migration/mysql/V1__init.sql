CREATE TABLE `logos` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `image` MEDIUMBLOB,
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`)
);

CREATE TABLE `organizations` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255),
  `mrn` VARCHAR(255),
  `email` VARCHAR(255),
  `address` VARCHAR(1000),
  `country` VARCHAR(64),
  `type` VARCHAR(64),
  `url` VARCHAR(512),
  `id_logo` INT,
  `approved` BOOLEAN,
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  UNIQUE (`mrn`),
  FOREIGN KEY (`id_logo`) REFERENCES logos(`id`)
);

CREATE TABLE `identity_provider_attributes` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `attribute_name` VARCHAR(512),
  `attribute_value` VARCHAR(4000),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`)
);

CREATE TABLE `roles` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `role_name` VARCHAR(512),
  `permission` VARCHAR(512),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY  (`id`),
  FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`)
);

CREATE TABLE `vessels` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `name` VARCHAR(255),
  `permissions` VARCHAR(4000),
  `mrn` VARCHAR(255),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY  (`id`),
  UNIQUE (`mrn`),
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
  `email` VARCHAR(255),
  `permissions` VARCHAR(4000),
  `mrn` VARCHAR(255),
  `first_name` VARCHAR(255),
  `last_name` VARCHAR(255),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  UNIQUE (`mrn`),
  FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`)
);

CREATE TABLE `devices` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `name` VARCHAR(255),
  `permissions` VARCHAR(4000),
  `mrn` VARCHAR(255),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  UNIQUE (`mrn`),
  FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`)
);

CREATE TABLE `services` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `name` VARCHAR(255),
  `permissions` VARCHAR(4000),
  `mrn` VARCHAR(255),
  `oidc_access_type` VARCHAR(255),
  `oidc_client_id` VARCHAR(255),
  `oidc_client_secret` VARCHAR(255),
  `oidc_redirect_uri` VARCHAR(255),
  `cert_domain_name` VARCHAR(255),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  UNIQUE (`mrn`),
  FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`)
);

CREATE TABLE `certificates` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_vessel` INT,
  `id_user` INT,
  `id_device` INT,
  `id_service` INT,
  `id_organization` INT,
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
  FOREIGN KEY (`id_device`) REFERENCES devices(`id`),
  FOREIGN KEY (`id_service`) REFERENCES services(`id`),
  FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`)
);
