CREATE TABLE `organizations` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255),
  `short_name` VARCHAR(10),
  `email` VARCHAR(255),
  `address` VARCHAR(1000),
  `country` VARCHAR(64),
  `type` VARCHAR(64),
  `url` VARCHAR(512),
  `password_hash` VARCHAR(512),
  `logo` BLOB,
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY  (`id`)
);

CREATE TABLE `ships` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `ship_org_id` VARCHAR(512),
  `name` VARCHAR(255),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY  (`id`)
);

CREATE TABLE `ship_attributes` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_ship` INT,
  `attribute_name` VARCHAR(512),
  `attribute_value` VARCHAR(512),
  `start` DATETIME,
  `end` DATETIME,
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY  (`id`)
);

CREATE TABLE `users` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `user_org_id` VARCHAR(512),
  `email` VARCHAR(255),
  `name` VARCHAR(255),
  `id_keycloak` VARCHAR(255),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY  (`id`)
);

CREATE TABLE `certificates` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_ship` INT,
  `id_user` INT,
  `id_device` INT,
  `certificate` MEDIUMTEXT,
  `start` DATETIME,
  `end` DATETIME,
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY  (`id`)
);

ALTER TABLE `users` ADD CONSTRAINT `users_fk1` FOREIGN KEY (`id_org`) REFERENCES organizations(`id`);
ALTER TABLE `ships` ADD CONSTRAINT `ships_fk1` FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`);
ALTER TABLE `ship_attributes` ADD CONSTRAINT `ship_attributes_fk1` FOREIGN KEY (`id_ship`) REFERENCES ships(`id`);
ALTER TABLE `certificates` ADD CONSTRAINT `certificates_fk1` FOREIGN KEY (`id_ship`) REFERENCES ships(`id`);
ALTER TABLE `certificates` ADD CONSTRAINT `certificates_fk2` FOREIGN KEY (`id_user`) REFERENCES users(`id`);

