CREATE TABLE `vessel_images` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `image` MEDIUMBLOB,
    `created_at` DATETIME,
    `updated_at` DATETIME,
    PRIMARY KEY (`id`)
);

ALTER TABLE `vessels` ADD COLUMN `id_image` INT;

ALTER TABLE `vessels` ADD FOREIGN KEY (`id_image`) REFERENCES vessel_images(`id`);