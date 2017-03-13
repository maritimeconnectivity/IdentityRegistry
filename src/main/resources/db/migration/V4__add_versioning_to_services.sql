ALTER TABLE `services` ADD COLUMN `instance_version` varchar(32);

UPDATE `services` set `instance_version`= '1.0';

ALTER TABLE `services` DROP INDEX `mrn`;

ALTER TABLE `services` ADD UNIQUE INDEX `mrn_version` (`mrn`, `instance_version`);
