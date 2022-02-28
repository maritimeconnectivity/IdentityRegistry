CREATE TABLE `acting_on_behalf` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `id_acting` INT,
  `id_on_behalf_of` INT,
  `created_at` DATETIME,
  `updated_at` DATETIME,
  PRIMARY KEY (`id`),
  FOREIGN KEY (`id_acting`) REFERENCES organizations(`id`),
  FOREIGN KEY (`id_on_behalf_of`) REFERENCES organizations(`id`)
);