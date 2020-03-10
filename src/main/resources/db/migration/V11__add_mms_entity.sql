CREATE TABLE `mmses` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_organization` INT,
  `name` VARCHAR(255),
  `permissions` VARCHAR(4000),
  `mrn` VARCHAR(255),
  `mrn_subsidiary` VARCHAR(255),
  `url` VARCHAR(255) NOT NULL,
  `home_mms_url` VARCHAR(255),
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  UNIQUE (`mrn`),
  UNIQUE (`mrn_subsidiary`),
  FOREIGN KEY (`id_organization`) REFERENCES organizations(`id`)
);

ALTER TABLE `certificates` ADD COLUMN `id_mms` INT;

ALTER TABLE `certificates` ADD FOREIGN KEY (`id_mms`) REFERENCES mmses(`id`);