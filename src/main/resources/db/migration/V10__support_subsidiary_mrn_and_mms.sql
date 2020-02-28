ALTER TABLE `vessels` ADD COLUMN `mrn_subsidiary` VARCHAR(255);
ALTER TABLE `vessels` ADD COLUMN `home_mms_url` VARCHAR(255);

ALTER TABLE `users` ADD COLUMN `mrn_subsidiary` VARCHAR(255);
ALTER TABLE `users` ADD COLUMN `home_mms_url` VARCHAR(255);

ALTER TABLE `organizations` ADD COLUMN `mrn_subsidiary` VARCHAR(255);
ALTER TABLE `organizations` ADD COLUMN `home_mms_url` VARCHAR(255);

ALTER TABLE `devices` ADD COLUMN `mrn_subsidiary` VARCHAR(255);
ALTER TABLE `devices` ADD COLUMN `home_mms_url` VARCHAR(255);

ALTER TABLE `services` ADD COLUMN `mrn_subsidiary` VARCHAR(255);
ALTER TABLE `services` ADD COLUMN `home_mms_url` VARCHAR(255);