ALTER TABLE `services` ADD COLUMN `id_vessel` INT;

ALTER TABLE `services` ADD FOREIGN KEY (`id_vessel`) REFERENCES vessels(`id`);
