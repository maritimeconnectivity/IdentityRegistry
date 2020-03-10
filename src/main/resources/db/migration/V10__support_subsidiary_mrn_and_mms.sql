ALTER TABLE `vessels` ADD COLUMN `mrn_subsidiary` VARCHAR(255);
ALTER TABLE `vessels` ADD CONSTRAINT UNIQUE (`mrn_subsidiary`);
ALTER TABLE `vessels` ADD COLUMN `home_mms_url` VARCHAR(255);

ALTER TABLE `users` ADD COLUMN `mrn_subsidiary` VARCHAR(255);
ALTER TABLE `users` ADD CONSTRAINT UNIQUE (`mrn_subsidiary`);
ALTER TABLE `users` ADD COLUMN `home_mms_url` VARCHAR(255);

ALTER TABLE `organizations` ADD COLUMN `mrn_subsidiary` VARCHAR(255);
ALTER TABLE `organizations` ADD CONSTRAINT UNIQUE (`mrn_subsidiary`);
ALTER TABLE `organizations` ADD COLUMN `home_mms_url` VARCHAR(255);

ALTER TABLE `devices` ADD COLUMN `mrn_subsidiary` VARCHAR(255);
ALTER TABLE `devices` ADD CONSTRAINT UNIQUE (`mrn_subsidiary`);
ALTER TABLE `devices` ADD COLUMN `home_mms_url` VARCHAR(255);

ALTER TABLE `services` ADD COLUMN `mrn_subsidiary` VARCHAR(255);
ALTER TABLE `services` ADD UNIQUE INDEX `mrn_subsidiary_version` (`mrn_subsidiary`, `instance_version`);
ALTER TABLE `services` ADD COLUMN `home_mms_url` VARCHAR(255);